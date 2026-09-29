using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Headers;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AAuth.Server;

/// <summary>
/// The response of a held invocation. The resource retains it, keyed by the
/// auth token's <c>jti</c>, and answers a repeated presentation of that token
/// from it (§Deferred Delivery).
/// </summary>
/// <param name="StatusCode">The HTTP status of the invocation's response.</param>
/// <param name="ContentType">The response content type, if any.</param>
/// <param name="Body">The exact response body.</param>
public sealed record HeldInvocationResult(int StatusCode, string? ContentType, byte[] Body)
{
    /// <summary>A JSON result with the given status.</summary>
    public static HeldInvocationResult Json(object value, int statusCode = StatusCodes.Status200OK)
        => new(statusCode, "application/json", System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(value));

    /// <summary>Write this exact result as the HTTP response.</summary>
    public IResult ToResult() => new RetainedResult(this);
}

/// <summary>
/// Runs an invocation at most once per grant — the auth token's <c>jti</c> — and
/// answers a repeated presentation of that token from the retained result until
/// the token's <c>exp</c> (R3 per-call single use; §Deferred Delivery). A fresh
/// signature over the same token does not execute again.
/// </summary>
/// <remarks>In-memory; state is lost on restart.</remarks>
public sealed class AAuthSingleUseGrants(TimeProvider? timeProvider = null)
{
    private readonly ConcurrentDictionary<string, Record> _records = new(StringComparer.Ordinal);
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Execute under the grant <paramref name="jti"/> once; later calls with the
    /// same <paramref name="jti"/> before <paramref name="expiresAt"/> get the same result.
    /// </summary>
    public async Task<HeldInvocationResult> ExecuteOnceAsync(string jti, DateTimeOffset expiresAt,
        Func<CancellationToken, Task<HeldInvocationResult>> execute, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(jti);
        ArgumentNullException.ThrowIfNull(execute);
        var now = _time.GetUtcNow();
        foreach (var (key, stale) in _records)
            if (stale.Result is not null && stale.ExpiresAt <= now) _records.TryRemove(key, out _);
        var record = _records.GetOrAdd(jti, _ => new Record(expiresAt));
        await record.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return record.Result ??= await execute(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            record.Gate.Release();
        }
    }

    private sealed class Record(DateTimeOffset expiresAt)
    {
        public DateTimeOffset ExpiresAt { get; } = expiresAt;
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public HeldInvocationResult? Result { get; set; }
    }
}

internal sealed class RetainedResult(HeldInvocationResult result) : IResult
{
    public Task ExecuteAsync(HttpContext httpContext)
    {
        httpContext.Response.StatusCode = result.StatusCode;
        if (result.ContentType is not null) httpContext.Response.ContentType = result.ContentType;
        return httpContext.Response.Body.WriteAsync(result.Body).AsTask();
    }
}

/// <summary>
/// Holds resource invocations delivered as <c>202 Accepted</c> with
/// <c>requirement=auth-token</c> (§Deferred Delivery), instead of a <c>401</c>
/// the agent retries. The agent obtains an auth token, then polls the pending
/// URL with signed <c>GET</c> requests. The first poll presenting a valid auth
/// token runs the invocation once. Its result is retained until that token's
/// <c>exp</c>, and a repeated presentation of the same token is answered from it
/// rather than executing again.
/// </summary>
/// <remarks>
/// In-memory; state is lost on restart. Map the poll endpoint with
/// <see cref="AAuthHeldInvocationExtensions.MapAAuthHeldInvocations"/> behind the
/// resource's AAuth verification, so the auth token is verified for this resource.
/// </remarks>
public sealed class AAuthHeldInvocations
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;

    /// <summary>Create a held-invocation store.</summary>
    /// <param name="pathPrefix">The poll path prefix; pending URLs are <c>{pathPrefix}/{id}</c>.</param>
    /// <param name="pendingLifetime">How long an unexecuted invocation is held. Default 10 minutes.</param>
    /// <param name="timeProvider">Clock; defaults to the system clock.</param>
    public AAuthHeldInvocations(string pathPrefix = "/aauth/held", TimeSpan? pendingLifetime = null, TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(pathPrefix);
        PathPrefix = "/" + pathPrefix.Trim('/');
        PendingLifetime = pendingLifetime ?? TimeSpan.FromMinutes(10);
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>The poll path prefix.</summary>
    public string PathPrefix { get; }

    /// <summary>How long an unexecuted invocation is held.</summary>
    public TimeSpan PendingLifetime { get; }

    /// <summary>
    /// Hold an invocation and answer <c>202</c> with the pending <c>Location</c>
    /// and <c>AAuth-Requirement: requirement=auth-token</c>.
    /// </summary>
    /// <param name="resourceToken">The resource token the agent presents to its PS. Its <c>agent_jkt</c> binds the poller.</param>
    /// <param name="requiredScopes">Scopes the auth token must carry before the invocation runs.</param>
    /// <param name="execute">Runs the held invocation. Called at most once.</param>
    public IResult Hold(string resourceToken, IReadOnlyCollection<string> requiredScopes,
        Func<HttpContext, CancellationToken, Task<HeldInvocationResult>> execute)
    {
        ArgumentException.ThrowIfNullOrEmpty(resourceToken);
        ArgumentNullException.ThrowIfNull(requiredScopes);
        ArgumentNullException.ThrowIfNull(execute);
        var agentJkt = (string?)TokenVerifier.DecodeJsonSegment(resourceToken.Split('.')[1], "payload")["agent_jkt"]
            ?? throw new ArgumentException("The resource token names no agent_jkt.", nameof(resourceToken));
        Purge();
        var id = Guid.NewGuid().ToString("N");
        var entry = new Entry(resourceToken, agentJkt, requiredScopes.ToArray(), execute, _time.GetUtcNow() + PendingLifetime);
        _entries[id] = entry;
        return new PendingResult(PathPrefix + "/" + id, resourceToken);
    }

    /// <summary>
    /// Answer a poll of <c>{PathPrefix}/{id}</c>: <c>202</c> until an auth token is
    /// presented, then the invocation's result, retained per auth-token <c>jti</c>.
    /// </summary>
    public async Task<IResult> PollAsync(HttpContext context, string id)
    {
        ArgumentNullException.ThrowIfNull(context);
        context.Response.Headers.CacheControl = "no-store";
        if (!_entries.TryGetValue(id, out var entry))
            return AAuthProblemDetails.Create("unknown_pending", statusCode: StatusCodes.Status404NotFound);
        var verified = context.GetAAuthVerification();
        // The poller must hold the key the resource token was issued to.
        if (verified is null || verified.Jkt != entry.AgentJkt)
            return AAuthProblemDetails.Create("unknown_pending", statusCode: StatusCodes.Status404NotFound);
        var now = _time.GetUtcNow();
        var assertion = context.Features.Get<AAuthVerifiedAssertion>();
        if (verified is not { TokenType: AAuthTokenType.AuthToken, IssuerVerified: true }
            || assertion is null || (string?)assertion.Token.Payload["jti"] is not { Length: > 0 } jti)
        {
            // No auth token yet: keep holding while the invocation is pending.
            return entry.Consumed || entry.PendingExpiresAt <= now
                ? AAuthProblemDetails.Create("expired", statusCode: StatusCodes.Status410Gone)
                : new PendingResult(PathPrefix + "/" + id, entry.ResourceToken);
        }

        await entry.Gate.WaitAsync(context.RequestAborted).ConfigureAwait(false);
        try
        {
            foreach (var expired in entry.Results.Where(result => result.Value.ExpiresAt <= now).Select(result => result.Key).ToArray())
                entry.Results.Remove(expired);
            if (entry.Results.TryGetValue(jti, out var retained))
                return new RetainedResult(retained.Result);
            if (entry.Consumed || entry.PendingExpiresAt <= now)
                return AAuthProblemDetails.Create("expired", statusCode: StatusCodes.Status410Gone);
            if (!entry.RequiredScopes.All(verified.Scopes.Contains))
                return AAuthProblemDetails.Create("insufficient_scope", statusCode: StatusCodes.Status403Forbidden);

            var result = await entry.Execute(context, context.RequestAborted).ConfigureAwait(false);
            entry.Consumed = true;
            entry.Results[jti] = (result, assertion.Token.ExpiresAt);
            return new RetainedResult(result);
        }
        finally
        {
            entry.Gate.Release();
        }
    }

    // Drop entries that can no longer be executed or replayed.
    private void Purge()
    {
        var now = _time.GetUtcNow();
        foreach (var (id, entry) in _entries)
            if ((entry.Consumed || entry.PendingExpiresAt <= now) && entry.Results.Values.All(result => result.ExpiresAt <= now))
                _entries.TryRemove(id, out _);
    }

    private sealed class Entry(string resourceToken, string agentJkt, string[] requiredScopes,
        Func<HttpContext, CancellationToken, Task<HeldInvocationResult>> execute, DateTimeOffset pendingExpiresAt)
    {
        public string ResourceToken { get; } = resourceToken;
        public string AgentJkt { get; } = agentJkt;
        public string[] RequiredScopes { get; } = requiredScopes;
        public Func<HttpContext, CancellationToken, Task<HeldInvocationResult>> Execute { get; } = execute;
        public DateTimeOffset PendingExpiresAt { get; } = pendingExpiresAt;
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public bool Consumed { get; set; }
        public Dictionary<string, (HeldInvocationResult Result, DateTimeOffset ExpiresAt)> Results { get; } = new(StringComparer.Ordinal);
    }

    private sealed class PendingResult(string location, string resourceToken) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            httpContext.Response.StatusCode = StatusCodes.Status202Accepted;
            httpContext.Response.Headers.Location = location;
            httpContext.Response.Headers.RetryAfter = "1";
            httpContext.Response.Headers.CacheControl = "no-store";
            httpContext.Response.Headers[AAuthConstants.Headers.AAuthRequirement] = AAuthRequirementHeader.FormatAuthToken(resourceToken);
            return httpContext.Response.WriteAsJsonAsync(new { status = "pending" });
        }
    }
}

/// <summary>Maps the poll endpoint of <see cref="AAuthHeldInvocations"/>.</summary>
public static class AAuthHeldInvocationExtensions
{
    /// <summary>Map <c>GET {PathPrefix}/{id}</c> to <see cref="AAuthHeldInvocations.PollAsync"/>.</summary>
    public static IEndpointConventionBuilder MapAAuthHeldInvocations(this IEndpointRouteBuilder endpoints, AAuthHeldInvocations held)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(held);
        return endpoints.MapGet(held.PathPrefix + "/{id}", (HttpContext context, string id) => held.PollAsync(context, id));
    }
}
