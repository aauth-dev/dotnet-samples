using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Errors;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Server;

/// <summary>
/// Extension methods to map a POST /revoke endpoint for AAuth token revocation
/// (§Token Revocation).
/// </summary>
public static class RevocationEndpoint
{
    /// <summary>
    /// Map the revocation endpoint of the resource registered with <c>AddAAuthResource</c>, at the
    /// path of its <see cref="AAuthResourceOptions.RevocationEndpoint"/>. It verifies the caller
    /// (<c>jwks_uri</c>, <c>jwks</c> or <c>self-jwt</c>), records revocations in the resource's
    /// token inventory (the DI <see cref="IJtiStore"/>), and cascades through the resource's
    /// <see cref="IAAuthRevocationService"/>. Accepts any verified issuer unless
    /// <see cref="AAuthResourceOptions.ConfigureRevocation"/> narrows <see cref="AAuthRevocationOptions.IsAcceptedIssuer"/>.
    /// </summary>
    public static WebApplication MapAAuthResourceRevocation(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);
        var options = app.Services.GetService<Microsoft.Extensions.Options.IOptions<AAuthResourceOptions>>()?.Value
            ?? throw new InvalidOperationException("MapAAuthResourceRevocation requires AddAAuthResource.");
        if (options.RevocationEndpoint is not { } endpoint)
            throw new InvalidOperationException("MapAAuthResourceRevocation requires AAuthResourceOptions.RevocationEndpoint.");
        MapIssuerRevocationCore(app, app, static _ => true, app.Services.GetRequiredService<AAuthRevocationService>(),
            new Uri(endpoint).AbsolutePath, options.ConfigureRevocation);
        return app;
    }

    // `routes` and `inScope` confine the endpoint and its middleware to one role instance's host.
    internal static IJtiStore MapIssuerRevocationCore(WebApplication app, IEndpointRouteBuilder routes,
        Func<HttpContext, bool> inScope, AAuthRevocationService service, string path, Action<AAuthRevocationOptions>? configure)
    {
        var metadata = app.Services.GetRequiredService<AAuth.Discovery.MetadataClient>();
        var inventory = service.Inventory;
        var egressPolicy = service.EgressPolicy;
        var clock = service.Clock;
        app.Use(async (context, next) =>
        {
            if (inScope(context)) context.Items[AAuthVerificationMiddleware.TokenStoreItemKey] = inventory;
            await next();
        });
        var jwks = app.Services.GetRequiredService<AAuth.Discovery.JwksClient>();
        var resolver = app.Services.GetService<AAuth.HttpSig.ISignatureKeyResolver>()
            ?? new AAuth.HttpSig.DefaultSignatureKeyResolver(jwks, metadata);
        app.UseWhen(context => inScope(context) && context.Request.Path == path, branch => branch.Use(next =>
            new AAuthVerificationMiddleware(next, app.Services.GetService<AAuth.HttpSig.AAuthVerifier>() ?? new(),
                resolver, metadata, jwks, new AAuthVerificationOptions
                {
                    EgressPolicy = egressPolicy, AcceptedSchemes = ["jwks_uri", "jwks", "self-jwt"],
                    RequiredComponents = ["content-type", "content-digest"],
                    TimeProvider = clock,
                }).InvokeAsync));
        // Deferred-revocation polls are bodyless signed GETs.
        app.UseWhen(context => inScope(context) && context.Request.Path.StartsWithSegments(path.TrimEnd('/') + "/pending"), branch => branch.Use(next =>
            new AAuthVerificationMiddleware(next, app.Services.GetService<AAuth.HttpSig.AAuthVerifier>() ?? new(),
                resolver, metadata, jwks, new AAuthVerificationOptions
                {
                    EgressPolicy = egressPolicy, AcceptedSchemes = ["jwks_uri", "jwks", "self-jwt"],
                    TimeProvider = clock,
                }).InvokeAsync));

        var options = new AAuthRevocationOptions { IsAcceptedIssuer = AAuthTrust.Any };
        configure?.Invoke(options);
        if (options.RevokeGrantAsync is not null)
            throw new InvalidOperationException("A role's revocation endpoint delivers through its IAAuthRevocationService; RevokeGrantAsync applies to MapAAuthRevocationEndpoint only.");
        MapRevocationEndpointCore(routes, service, options, path);
        return inventory;
    }

    /// <summary>
    /// Map the revocation endpoint over the DI-registered <see cref="IJtiStore"/>. The endpoint
    /// accepts a signed POST with a JSON body <c>{ "jti": "...", "exp": 1788727813 }</c> and
    /// records <c>(verified caller, jti)</c> as revoked, seen or not, then cascades to the grants
    /// recorded against it and answers <c>200</c> once each downstream call is terminal.
    /// </summary>
    /// <remarks>
    /// Per §Token Revocation the endpoint MUST verify the caller's identity via HTTP
    /// Message Signatures; the issuer is that identity, never a body member. Map this
    /// endpoint <b>behind</b> AAuth verification (<c>UseAAuthVerification</c> or
    /// <c>UseAAuth</c>) so the verified caller identity is available; accept callers via
    /// <see cref="AAuthRevocationOptions.IsAcceptedIssuer"/> (deny-by-default: without it every
    /// caller is answered <c>unsupported_iss</c>).
    /// </remarks>
    public static IEndpointRouteBuilder MapAAuthRevocationEndpoint(
        this IEndpointRouteBuilder endpoints,
        string path = "/revoke",
        Action<AAuthRevocationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var store = endpoints.ServiceProvider.GetService<IJtiStore>()
            ?? throw new InvalidOperationException("MapAAuthRevocationEndpoint requires a registered IJtiStore.");
        return endpoints.MapRevocationEndpointCore(store, configure, path);
    }

    internal static IEndpointRouteBuilder MapRevocationEndpointCore(
        this IEndpointRouteBuilder endpoints,
        IJtiStore jtiStore,
        Action<AAuthRevocationOptions>? configure,
        string path)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(jtiStore);

        var options = new AAuthRevocationOptions();
        configure?.Invoke(options);
        return MapRevocationEndpointCore(endpoints,
            new AAuthRevocationService(jtiStore, TimeProvider.System, options.RevokeGrantAsync), options, path);
    }

    private static IEndpointRouteBuilder MapRevocationEndpointCore(IEndpointRouteBuilder endpoints,
        AAuthRevocationService service, AAuthRevocationOptions options, string path)
    {
        var jtiStore = service.Inventory;
        var limiter = options.Limits is { } limits ? new RevocationIssuerLimiter(limits, service.Clock) : null;
        var pending = new RevocationPendingStore(service.Clock);
        var stopping = endpoints.ServiceProvider.GetService<Microsoft.Extensions.Hosting.IHostApplicationLifetime>()?.ApplicationStopping
            ?? CancellationToken.None;
        var pendingPath = path.TrimEnd('/') + "/pending";

        endpoints.MapPost(path, async (HttpContext context) =>
        {
            var cancellationToken = context.RequestAborted;
            var verified = context.Features.Get<AAuthVerificationResult>();
            if (verified is null)
            {
                return AAuthProblemDetails.SignatureFailure(SignatureErrorCode.InvalidSignature);
            }

            // MUST at every recipient, not only when the host's verifier was configured to demand it.
            if (!verified.CoveredComponents.IsSupersetOf(RevocationClient.CoveredContent))
                return AAuthProblemDetails.MissingCoverage(RevocationClient.CoveredContent);

            // The caller signs as a server; its verified identity is the issuer of the token it revokes.
            var callerId = verified.Scheme is "jwks_uri" or "jwks" or "self-jwt" ? verified.Issuer : null;
            if (callerId is null)
                return Error(RevocationErrorCode.UnsupportedIss, "revocations are accepted only from a server signature (jwks_uri, jwks, or self-jwt).");
            if (options.IsAcceptedIssuer?.Invoke(callerId) != true)
                return Error(RevocationErrorCode.UnsupportedIss, $"revocations from '{callerId}' are not accepted.");

            string? jti = null;
            long? exp = null;
            try
            {
                var body = await context.Request.ReadFromJsonAsync<JsonElement>(cancellationToken);
                if (body.ValueKind == JsonValueKind.Object)
                {
                    if (body.TryGetProperty("jti", out var jtiElement) && jtiElement.ValueKind == JsonValueKind.String)
                        jti = jtiElement.GetString();
                    if (body.TryGetProperty("exp", out var expElement) && expElement.ValueKind == JsonValueKind.Number
                        && expElement.TryGetInt64(out var seconds))
                        exp = seconds;
                }
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException)
            {
                // Malformed JSON or a non-JSON Content-Type: answered 400 below.
            }

            if (string.IsNullOrWhiteSpace(jti) || exp is not { } expSeconds || expSeconds <= 0)
                return Error(RevocationErrorCode.InvalidRequest, "a JSON body with a 'jti' string and an integer 'exp' is required.");
            if (expSeconds > (service.Clock.GetUtcNow() + options.MaxTokenLifetime + ClockSkew).ToUnixTimeSeconds())
                return Error(RevocationErrorCode.InvalidRequest, "'exp' is later than the longest token lifetime this recipient accepts.");

            var token = new TokenKey(callerId, jti);
            var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expSeconds);
            if (limiter?.TryAdmit(callerId, jti, expiresAt + ClockSkew) is { } retryAfter)
            {
                context.Response.Headers.RetryAfter = retryAfter.ToString(System.Globalization.CultureInfo.InvariantCulture);
                return Error(RevocationErrorCode.RateLimited, $"'{callerId}' has sent more revocations than this recipient accepts for now.");
            }
            try
            {
                await jtiStore.RevokeAsync(token, expiresAt, cancellationToken);
            }
            catch (InvalidOperationException)
            {
                return Error(RevocationErrorCode.ServerError, "the revocation could not be recorded.");
            }

            // A recipient with nothing downstream MUST NOT answer 202.
            var starts = await service.StartsAsync(token, expiresAt, cancellationToken);
            if (!await service.HasDownstreamAsync(starts, cancellationToken))
                return Results.Ok();
            // The cascade outlives the request when it is deferred.
            var cascade = CascadeAsync(starts, stopping);
            if (await HoldAsync(cascade, context, options.DeferAfter)) return await cascade;
            return Pending(context, pendingPath + "/" + pending.Add(callerId, cascade));
        }).WithMetadata(new AAuth.Server.Endpoints.AAuthEndpointRequirement
        {
            Mode = AAuthAccessMode.IdentityOnly,
            AcceptedSchemes = ["jwt", "jwks_uri", "jwks", "self-jwt"],
        });

        // The poller signs a bodyless GET under the identity that made the revocation; any other gets 404.
        endpoints.MapGet(pendingPath + "/{id}", async (HttpContext context, string id) =>
        {
            var verified = context.Features.Get<AAuthVerificationResult>();
            var callerId = verified?.Scheme is "jwks_uri" or "jwks" or "self-jwt" ? verified.Issuer : null;
            if (callerId is null || pending.Find(id, callerId) is not { } cascade)
                return AAuthProblemDetails.Create("not_found", statusCode: StatusCodes.Status404NotFound);
            if (await HoldAsync(cascade, context, options.DeferAfter)) return await cascade;
            return Pending(context, pendingPath + "/" + id);
        }).WithMetadata(new AAuth.Server.Endpoints.AAuthEndpointRequirement
        {
            Mode = AAuthAccessMode.IdentityOnly,
            AcceptedSchemes = ["jwks_uri", "jwks", "self-jwt"],
        });

        async Task<IResult> CascadeAsync(IReadOnlyList<AAuthRevocationService.CascadeSource> starts, CancellationToken cancellationToken)
        {
            var result = await service.WalkAsync(starts, new(StringComparer.Ordinal), cancellationToken);
            if (!options.ReportDownstream || result.Downstream.Count == 0)
                return Results.Ok();
            var downstream = new JsonArray();
            foreach (var outcome in result.Downstream)
            {
                var entry = new JsonObject { ["recipient"] = outcome.Recipient };
                if (outcome.Error is { } failure) entry["error"] = RevocationError.ToWireCode(failure);
                downstream.Add(entry);
            }
            return Results.Json(new JsonObject { ["downstream"] = downstream }, statusCode: StatusCodes.Status200OK);
        }

        return endpoints;
    }

    // Hold for the caller's Prefer: wait, capped at the recipient's own hold.
    private static async Task<bool> HoldAsync(Task<IResult> cascade, HttpContext context, TimeSpan maximum)
    {
        var hold = PreferWait(context.Request.Headers["Prefer"].ToString()) is { } wait && wait < maximum ? wait : maximum;
        try { await cascade.WaitAsync(hold, context.RequestAborted); return true; }
        catch (TimeoutException) { return false; }
    }

    internal static TimeSpan? PreferWait(string prefer)
    {
        foreach (var preference in prefer.Split(',', StringSplitOptions.TrimEntries))
            if (preference.StartsWith("wait=", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(preference.AsSpan(5), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var seconds))
                return TimeSpan.FromSeconds(seconds);
        return null;
    }

    private static IResult Pending(HttpContext context, string location)
    {
        context.Response.Headers.Location = location;
        context.Response.Headers.RetryAfter = "0";
        context.Response.Headers.CacheControl = "no-store";
        return Results.Json(new JsonObject { ["status"] = "pending" }, statusCode: StatusCodes.Status202Accepted);
    }

    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    private static IResult Error(RevocationErrorCode code, string detail)
        => AAuthProblemDetails.Create(RevocationError.ToWireCode(code), detail, statusCode: RevocationError.StatusCode(code));
}
