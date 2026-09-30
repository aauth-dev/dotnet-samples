using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using AAuth.Headers;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AAuth.Server;

/// <summary>
/// The response of a held invocation. The resource retains it, keyed by the
/// auth token's <c>jti</c>, and answers a repeated presentation of that token
/// from it (§Deferred Delivery). Serializable, so a shared store can hold it.
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

/// <summary>The outcome of <see cref="IAAuthSingleUseGate.TryClaimAsync"/>.</summary>
/// <param name="Claimed">The caller owns the execution and must complete or release it.</param>
/// <param name="Result">The retained result when the grant already executed.</param>
public readonly record struct SingleUseClaim(bool Claimed, HeldInvocationResult? Result);

/// <summary>
/// Runs an invocation at most once per grant — the auth token's <c>jti</c> — and
/// answers a repeated presentation from the retained result until the token's
/// <c>exp</c> (R3 per-call single use; §Deferred Delivery). Implement it over a
/// shared store to keep single use across instances.
/// </summary>
public interface IAAuthSingleUseGate
{
    /// <summary>
    /// Claim <paramref name="key"/>. Returns <c>Claimed</c> for the one caller that must execute,
    /// the retained result once it completed, or neither while another caller executes.
    /// </summary>
    ValueTask<SingleUseClaim> TryClaimAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);

    /// <summary>Retain the result of a claimed execution until the claim's expiry.</summary>
    ValueTask CompleteAsync(string key, HeldInvocationResult result, CancellationToken cancellationToken = default);

    /// <summary>Give up a claim whose execution failed, so the grant can be retried.</summary>
    ValueTask ReleaseAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>The retained result for <paramref name="key"/>, if any.</summary>
    ValueTask<HeldInvocationResult?> GetResultAsync(string key, CancellationToken cancellationToken = default);
}

/// <summary>Helpers over <see cref="IAAuthSingleUseGate"/>.</summary>
public static class AAuthSingleUseGateExtensions
{
    /// <summary>
    /// Execute once per <paramref name="jti"/> and return the retained result on every
    /// later presentation. A caller that finds another execution in progress waits for it.
    /// </summary>
    public static async Task<HeldInvocationResult> ExecuteOnceAsync(this IAAuthSingleUseGate gate, string jti,
        DateTimeOffset expiresAt, Func<CancellationToken, Task<HeldInvocationResult>> execute,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(gate);
        ArgumentException.ThrowIfNullOrEmpty(jti);
        ArgumentNullException.ThrowIfNull(execute);
        while (true)
        {
            var claim = await gate.TryClaimAsync(jti, expiresAt, cancellationToken).ConfigureAwait(false);
            if (claim.Result is { } retained) return retained;
            if (claim.Claimed)
            {
                HeldInvocationResult result;
                try
                {
                    result = await execute(cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    await gate.ReleaseAsync(jti, CancellationToken.None).ConfigureAwait(false);
                    throw;
                }
                await gate.CompleteAsync(jti, result, cancellationToken).ConfigureAwait(false);
                return result;
            }
            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken).ConfigureAwait(false);
        }
    }
}

/// <summary>In-memory <see cref="IAAuthSingleUseGate"/>; state is lost on restart and not shared across instances.</summary>
public sealed class InMemorySingleUseGate(TimeProvider? timeProvider = null) : IAAuthSingleUseGate
{
    private readonly ConcurrentDictionary<string, Record> _records = new(StringComparer.Ordinal);
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <inheritdoc/>
    public ValueTask<SingleUseClaim> TryClaimAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        var now = _time.GetUtcNow();
        foreach (var (stale, record) in _records)
            if (record.Result is not null && record.ExpiresAt <= now) _records.TryRemove(stale, out _);
        var created = new Record(expiresAt);
        var current = _records.GetOrAdd(key, created);
        lock (current)
        {
            if (current.Result is not null) return ValueTask.FromResult(new SingleUseClaim(false, current.Result));
            if (current.InProgress) return ValueTask.FromResult(new SingleUseClaim(false, null));
            current.InProgress = true;
            return ValueTask.FromResult(new SingleUseClaim(true, null));
        }
    }

    /// <inheritdoc/>
    public ValueTask CompleteAsync(string key, HeldInvocationResult result, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (_records.TryGetValue(key, out var record))
        {
            lock (record)
            {
                record.Result = result;
                record.InProgress = false;
            }
        }
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask ReleaseAsync(string key, CancellationToken cancellationToken = default)
    {
        if (_records.TryGetValue(key, out var record))
            lock (record) record.InProgress = false;
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<HeldInvocationResult?> GetResultAsync(string key, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(_records.TryGetValue(key, out var record) && record.ExpiresAt > _time.GetUtcNow()
            ? record.Result : null);

    private sealed class Record(DateTimeOffset expiresAt)
    {
        public DateTimeOffset ExpiresAt { get; } = expiresAt;
        public bool InProgress { get; set; }
        public HeldInvocationResult? Result { get; set; }
    }
}

/// <summary>
/// A parked invocation (§Deferred Delivery). Serializable: the code that runs it is the
/// endpoint's <see cref="AAuthHeldInvocationExtensions.WithHeldInvocation{TBuilder}"/>
/// registration, found by <see cref="Operation"/>, and never stored.
/// </summary>
/// <param name="Id">The pending id in the poll URL.</param>
/// <param name="Operation">The registered operation name that executes it.</param>
/// <param name="ResourceToken">The resource token the auth token must answer.</param>
/// <param name="AgentJkt">The agent key the resource token is bound to; only it may poll.</param>
/// <param name="RequiredScopes">Scopes the auth token must carry.</param>
/// <param name="PendingExpiresAt">When an unexecuted invocation is dropped.</param>
/// <param name="State">Request data the operation needs, captured when held.</param>
public sealed record HeldInvocation(string Id, string Operation, string ResourceToken, string AgentJkt,
    IReadOnlyList<string> RequiredScopes, DateTimeOffset PendingExpiresAt, JsonObject? State = null)
{
    /// <summary>The auth token <c>jti</c> that consumed it, once executed.</summary>
    public string? ConsumedBy { get; init; }
}

/// <summary>Stores parked invocations. Implement it over a shared store to hold invocations across instances.</summary>
public interface IAAuthHeldInvocationStore
{
    /// <summary>Park an invocation.</summary>
    ValueTask AddAsync(HeldInvocation invocation, CancellationToken cancellationToken = default);

    /// <summary>Look up a parked invocation.</summary>
    ValueTask<HeldInvocation?> GetAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically mark the invocation consumed by <paramref name="jti"/>, retained until
    /// <paramref name="retainUntil"/>. True only for the call that consumes it.
    /// </summary>
    ValueTask<bool> TryConsumeAsync(string id, string jti, DateTimeOffset retainUntil, CancellationToken cancellationToken = default);
}

/// <summary>In-memory <see cref="IAAuthHeldInvocationStore"/>; state is lost on restart and not shared across instances.</summary>
public sealed class InMemoryHeldInvocationStore(TimeProvider? timeProvider = null) : IAAuthHeldInvocationStore
{
    private readonly ConcurrentDictionary<string, (HeldInvocation Invocation, DateTimeOffset? RetainUntil)> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <inheritdoc/>
    public ValueTask AddAsync(HeldInvocation invocation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        Purge();
        _entries[invocation.Id] = (invocation, null);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<HeldInvocation?> GetAsync(string id, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(_entries.TryGetValue(id, out var entry) ? entry.Invocation : null);

    /// <inheritdoc/>
    public ValueTask<bool> TryConsumeAsync(string id, string jti, DateTimeOffset retainUntil, CancellationToken cancellationToken = default)
    {
        while (_entries.TryGetValue(id, out var entry))
        {
            if (entry.Invocation.ConsumedBy is not null) return ValueTask.FromResult(false);
            var consumed = (entry.Invocation with { ConsumedBy = jti }, (DateTimeOffset?)retainUntil);
            if (_entries.TryUpdate(id, consumed, entry)) return ValueTask.FromResult(true);
        }
        return ValueTask.FromResult(false);
    }

    // Drop entries that can no longer be executed or replayed.
    private void Purge()
    {
        var now = _time.GetUtcNow();
        foreach (var (id, entry) in _entries)
        {
            if (entry.RetainUntil is { } retained ? retained <= now : entry.Invocation.PendingExpiresAt <= now)
                _entries.TryRemove(id, out _);
        }
    }
}

/// <summary>Options for <see cref="IAAuthHeldInvocations"/>.</summary>
public sealed class AAuthHeldInvocationOptions
{
    /// <summary>The poll path prefix; pending URLs are <c>{PathPrefix}/{id}</c>.</summary>
    public string PathPrefix { get; set; } = "/aauth/held";

    /// <summary>How long an unexecuted invocation is held unless its endpoint sets its own lifetime.</summary>
    public TimeSpan PendingLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Clock for pending expiry.</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
}

/// <summary>
/// Holds an invocation behind a <c>202</c> until the agent returns with an auth token,
/// runs it once, and answers a repeated presentation of that token from the retained
/// result rather than executing again (§Deferred Delivery). Map the poll endpoint with
/// <see cref="AAuthHeldInvocationExtensions.MapAAuthHeldInvocations"/> behind the
/// resource's AAuth verification, so the auth token is verified for this resource.
/// </summary>
public interface IAAuthHeldInvocations
{
    /// <summary>The poll path prefix.</summary>
    string PathPrefix { get; }

    /// <summary>
    /// Park the current request's invocation. The endpoint must declare its operation with
    /// <see cref="AAuthHeldInvocationExtensions.WithHeldInvocation{TBuilder}"/>; <paramref name="state"/>
    /// carries the request data that operation needs.
    /// </summary>
    Task<IResult> HoldAsync(HttpContext context, string resourceToken, IReadOnlyCollection<string> requiredScopes,
        JsonObject? state = null);

    /// <summary>Answer a poll of <c>{PathPrefix}/{id}</c>.</summary>
    Task<IResult> PollAsync(HttpContext context, string id);
}

/// <summary>An endpoint's held-invocation operation: the code a poll runs, registered in process.</summary>
public sealed record HeldInvocationEndpointMetadata(string Operation,
    Func<HttpContext, JsonObject?, CancellationToken, Task<HeldInvocationResult>> Execute, TimeSpan? PendingLifetime = null);

internal sealed class AAuthHeldInvocations(IOptions<AAuthHeldInvocationOptions> options, IAAuthHeldInvocationStore store,
    IAAuthSingleUseGate gate, EndpointDataSource endpoints) : IAAuthHeldInvocations
{
    private readonly AAuthHeldInvocationOptions _options = options.Value;
    private Dictionary<string, HeldInvocationEndpointMetadata>? _operations;

    public string PathPrefix => "/" + _options.PathPrefix.Trim('/');

    public async Task<IResult> HoldAsync(HttpContext context, string resourceToken, IReadOnlyCollection<string> requiredScopes,
        JsonObject? state = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(resourceToken);
        ArgumentNullException.ThrowIfNull(requiredScopes);
        var operation = context.GetEndpoint()?.Metadata.GetMetadata<HeldInvocationEndpointMetadata>()
            ?? throw new InvalidOperationException("The endpoint declares no held invocation; add WithHeldInvocation(...) to it.");
        var agentJkt = (string?)TokenVerifier.DecodeJsonSegment(resourceToken.Split('.')[1], "payload")["agent_jkt"]
            ?? throw new ArgumentException("The resource token names no agent_jkt.", nameof(resourceToken));
        var id = Guid.NewGuid().ToString("N");
        var lifetime = operation.PendingLifetime ?? _options.PendingLifetime;
        await store.AddAsync(new HeldInvocation(id, operation.Operation, resourceToken, agentJkt, requiredScopes.ToArray(),
            _options.TimeProvider.GetUtcNow() + lifetime, state?.DeepClone().AsObject()), context.RequestAborted).ConfigureAwait(false);
        return new PendingResult(PathPrefix + "/" + id, resourceToken);
    }

    public async Task<IResult> PollAsync(HttpContext context, string id)
    {
        ArgumentNullException.ThrowIfNull(context);
        context.Response.Headers.CacheControl = "no-store";
        var entry = await store.GetAsync(id, context.RequestAborted).ConfigureAwait(false);
        var verified = context.GetAAuthVerification();
        // The poller must hold the key the resource token was issued to.
        if (entry is null || verified is null || verified.Jkt != entry.AgentJkt)
            return AAuthProblemDetails.Create("unknown_pending", statusCode: StatusCodes.Status404NotFound);
        var now = _options.TimeProvider.GetUtcNow();
        var assertion = context.Features.Get<AAuthVerifiedAssertion>();
        if (verified is not { TokenType: AAuthTokenType.AuthToken, IssuerVerified: true }
            || assertion is null || (string?)assertion.Token.Payload["jti"] is not { Length: > 0 } jti)
        {
            // No auth token yet: keep holding while the invocation is pending.
            return entry.ConsumedBy is not null || entry.PendingExpiresAt <= now
                ? Expired()
                : new PendingResult(PathPrefix + "/" + id, entry.ResourceToken);
        }

        var key = id + ":" + jti;
        if (await gate.GetResultAsync(key, context.RequestAborted).ConfigureAwait(false) is { } retained)
            return new RetainedResult(retained);
        if (entry.ConsumedBy is { } consumer ? consumer != jti : entry.PendingExpiresAt <= now)
            return Expired();
        if (!entry.RequiredScopes.All(verified.Scopes.Contains))
            return AAuthProblemDetails.Create("insufficient_scope", statusCode: StatusCodes.Status403Forbidden);

        // Claim this auth token's execution first: a concurrent poll with the same token waits
        // for its result instead of consuming the invocation again.
        while (true)
        {
            var claim = await gate.TryClaimAsync(key, assertion.Token.ExpiresAt, context.RequestAborted).ConfigureAwait(false);
            if (claim.Result is { } completed) return new RetainedResult(completed);
            if (claim.Claimed) break;
            await Task.Delay(TimeSpan.FromMilliseconds(25), context.RequestAborted).ConfigureAwait(false);
        }

        HeldInvocationResult result;
        try
        {
            // Consumed already means an earlier execution whose retained result has lapsed: never run twice.
            if (!await store.TryConsumeAsync(id, jti, assertion.Token.ExpiresAt, context.RequestAborted).ConfigureAwait(false))
            {
                await gate.ReleaseAsync(key, CancellationToken.None).ConfigureAwait(false);
                return Expired();
            }
            result = await Operation(entry.Operation).Execute(context, entry.State, context.RequestAborted).ConfigureAwait(false);
        }
        catch
        {
            await gate.ReleaseAsync(key, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        await gate.CompleteAsync(key, result, context.RequestAborted).ConfigureAwait(false);
        return new RetainedResult(result);
    }

    private static IResult Expired() => AAuthProblemDetails.Create("expired", statusCode: StatusCodes.Status410Gone);

    private HeldInvocationEndpointMetadata Operation(string name)
    {
        var operations = _operations ??= endpoints.Endpoints
            .Select(endpoint => endpoint.Metadata.GetMetadata<HeldInvocationEndpointMetadata>())
            .OfType<HeldInvocationEndpointMetadata>()
            .GroupBy(metadata => metadata.Operation, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Count() == 1 ? group.Single()
                : throw new InvalidOperationException($"Held invocation operation '{group.Key}' is registered by more than one endpoint."),
                StringComparer.Ordinal);
        return operations.TryGetValue(name, out var operation)
            ? operation
            : throw new InvalidOperationException($"No endpoint registers held invocation operation '{name}'.");
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

internal sealed class RetainedResult(HeldInvocationResult result) : IResult
{
    public Task ExecuteAsync(HttpContext httpContext)
    {
        httpContext.Response.StatusCode = result.StatusCode;
        if (result.ContentType is not null) httpContext.Response.ContentType = result.ContentType;
        return httpContext.Response.Body.WriteAsync(result.Body).AsTask();
    }
}

/// <summary>Registers and maps held invocations.</summary>
public static class AAuthHeldInvocationExtensions
{
    /// <summary>
    /// Register <see cref="IAAuthHeldInvocations"/> with the in-memory
    /// <see cref="IAAuthHeldInvocationStore"/> and <see cref="IAAuthSingleUseGate"/> defaults
    /// (register your own first to share them across instances).
    /// </summary>
    public static IServiceCollection AddAAuthHeldInvocations(this IServiceCollection services,
        Action<AAuthHeldInvocationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        var options = services.AddOptions<AAuthHeldInvocationOptions>();
        if (configure is not null) options.Configure(configure);
        services.TryAddSingleton<IAAuthSingleUseGate>(sp =>
            new InMemorySingleUseGate(sp.GetRequiredService<IOptions<AAuthHeldInvocationOptions>>().Value.TimeProvider));
        services.TryAddSingleton<IAAuthHeldInvocationStore>(sp =>
            new InMemoryHeldInvocationStore(sp.GetRequiredService<IOptions<AAuthHeldInvocationOptions>>().Value.TimeProvider));
        services.TryAddSingleton<IAAuthHeldInvocations>(sp => ActivatorUtilities.CreateInstance<AAuthHeldInvocations>(sp));
        return services;
    }

    /// <summary>
    /// Declare the operation this endpoint holds: <paramref name="execute"/> runs when the agent
    /// returns with an auth token, with the state captured by <see cref="IAAuthHeldInvocations.HoldAsync"/>.
    /// <paramref name="operation"/> must be unique and stable across instances.
    /// </summary>
    public static TBuilder WithHeldInvocation<TBuilder>(this TBuilder builder, string operation,
        Func<HttpContext, JsonObject?, CancellationToken, Task<HeldInvocationResult>> execute, TimeSpan? pendingLifetime = null)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentException.ThrowIfNullOrEmpty(operation);
        ArgumentNullException.ThrowIfNull(execute);
        return builder.WithMetadata(new HeldInvocationEndpointMetadata(operation, execute, pendingLifetime));
    }

    /// <summary>Map <c>GET {PathPrefix}/{id}</c> to <see cref="IAAuthHeldInvocations.PollAsync"/>.</summary>
    public static IEndpointConventionBuilder MapAAuthHeldInvocations(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var services = endpoints.ServiceProvider;
        var held = services.GetService<IAAuthHeldInvocations>()
            ?? throw new InvalidOperationException("MapAAuthHeldInvocations requires AddAAuthHeldInvocations.");
        if (services.GetService<ILoggerFactory>() is { } loggers)
            AAuthServerRoles.WarnOnInMemoryDefaults(services, loggers.CreateLogger("AAuth.HeldInvocations"), "Held invocations",
                held.PathPrefix, services.GetService<IAAuthHeldInvocationStore>(), services.GetService<IAAuthSingleUseGate>());
        return endpoints.MapGet(held.PathPrefix + "/{id}", (HttpContext context, string id) => held.PollAsync(context, id));
    }
}
