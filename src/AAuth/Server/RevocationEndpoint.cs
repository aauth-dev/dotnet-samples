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
    /// Map a verified revocation endpoint for a token-issuing server (PS, AS, or resource)
    /// that cascades over the returned inventory, signing downstream revocations as
    /// <paramref name="issuer"/>. Accepts any verified issuer unless <paramref name="configure"/>
    /// narrows <see cref="AAuthRevocationOptions.IsAcceptedIssuer"/>.
    /// </summary>
    public static IJtiStore MapAAuthIssuerRevocation(this WebApplication app, string issuer, string dwk,
        AAuth.Crypto.IAAuthKey signingKey, string signingKid, string path,
        AAuth.Discovery.AAuthEgressPolicy egressPolicy, TimeProvider clock, Action<AAuthRevocationOptions>? configure,
        IJtiStore? inventory = null)
    {
        inventory ??= app.Services.GetService<IJtiStore>() ?? new InMemoryJtiStore(clock);
        var metadata = app.Services.GetRequiredService<AAuth.Discovery.MetadataClient>();
        var client = app.Services.GetService<RevocationClient>();
        if (client is null)
        {
            var signing = new AAuth.HttpSig.AAuthSigningHandler(signingKey,
                new AAuth.HttpSig.JwksUriSignatureKeyProvider(issuer, dwk, signingKid))
            {
                InnerHandler = AAuth.Discovery.AAuthHttpTransport.CreateHandler(egressPolicy),
            };
            var http = AAuth.Discovery.AAuthHttpTransport.AttachPolicy(new System.Net.Http.HttpClient(signing),
                egressPolicy, AAuth.Discovery.AAuthTransportContract.EnforcesEgressPolicy);
            app.Lifetime.ApplicationStopped.Register(http.Dispose);
            client = new RevocationClient(http);
        }
        app.Use(async (context, next) =>
        {
            context.Items[AAuthVerificationMiddleware.TokenStoreItemKey] = inventory;
            await next();
        });
        var jwks = app.Services.GetRequiredService<AAuth.Discovery.JwksClient>();
        var resolver = app.Services.GetService<AAuth.HttpSig.ISignatureKeyResolver>()
            ?? new AAuth.HttpSig.DefaultSignatureKeyResolver(jwks, metadata);
        app.UseWhen(context => context.Request.Path == path, branch => branch.Use(next =>
            new AAuthVerificationMiddleware(next, app.Services.GetService<AAuth.HttpSig.AAuthVerifier>() ?? new(),
                resolver, metadata, jwks, new AAuthVerificationOptions
                {
                    EgressPolicy = egressPolicy, AcceptedSchemes = ["jwks_uri", "jwks", "self-jwt"],
                    RequiredComponents = ["content-type", "content-digest"],
                    Clock = () => clock.GetUtcNow(),
                }).InvokeAsync));

        async Task<RevocationDownstreamError?> RevokeAtAsync(TokenGrant grant, string recipientDwk, CancellationToken cancellationToken)
        {
            var document = await metadata.FetchAsync(metadata.GetUrl(grant.Resource, recipientDwk), cancellationToken);
            if ((string?)document["revocation_endpoint"] is not { } endpoint) return RevocationDownstreamError.RevocationUnsupported;
            var endpointUri = egressPolicy.ValidateUrl(endpoint, endpoint: true);
            if (endpointUri.GetLeftPart(UriPartial.Authority) != new Uri(grant.Resource).GetLeftPart(UriPartial.Authority))
                return RevocationDownstreamError.RevocationUnsupported;
            return (await client.RevokeAsync(endpointUri, grant.Token.TokenId, grant.ExpiresAt, cancellationToken)).Failure;
        }

        app.MapAAuthRevocationEndpoint(inventory, options =>
        {
            options.IsAcceptedIssuer = AAuthTrust.Any;
            options.Issuer = issuer;
            options.Clock = clock;
            options.RevokeGrantAsync = (grant, cancellationToken) => RevokeAtAsync(grant, "aauth-resource.json", cancellationToken);
            options.RevokeAtAccessServerAsync = (grant, cancellationToken) =>
                RevokeAtAsync(grant, AAuth.Tokens.AuthTokenBuilder.AccessDwk, cancellationToken);
            configure?.Invoke(options);
        }, path);
        return inventory;
    }

    /// <summary>
    /// Map the revocation endpoint with no accepted issuers configured (every
    /// caller is answered <c>unsupported_iss</c> — see <see cref="AAuthRevocationOptions"/>). Prefer the
    /// <see cref="MapAAuthRevocationEndpoint(IEndpointRouteBuilder, IJtiStore, Action{AAuthRevocationOptions}, string)"/>
    /// overload to declare whose revocations are accepted.
    /// </summary>
    public static IEndpointRouteBuilder MapAAuthRevocationEndpoint(
        this IEndpointRouteBuilder endpoints,
        IJtiStore jtiStore,
        string path = "/revoke")
        => endpoints.MapAAuthRevocationEndpoint(jtiStore, configure: null, path);

    /// <summary>
    /// Map the revocation endpoint. The endpoint accepts a signed POST with a JSON
    /// body <c>{ "jti": "...", "exp": 1788727813 }</c> and records <c>(verified caller, jti)</c>
    /// as revoked in the <see cref="IJtiStore"/>, seen or not, then cascades to the grants
    /// recorded against it and answers <c>200</c> once each downstream call is terminal.
    /// </summary>
    /// <remarks>
    /// Per §Token Revocation the endpoint MUST verify the caller's identity via HTTP
    /// Message Signatures; the issuer is that identity, never a body member. Map this
    /// endpoint <b>behind</b> AAuth verification (<c>UseAAuthVerification</c> or
    /// <c>UseAAuth</c>) so the verified caller identity is available; accept callers via
    /// <see cref="AAuthRevocationOptions.IsAcceptedIssuer"/> (deny-by-default).
    /// </remarks>
    public static IEndpointRouteBuilder MapAAuthRevocationEndpoint(
        this IEndpointRouteBuilder endpoints,
        IJtiStore jtiStore,
        Action<AAuthRevocationOptions>? configure,
        string path = "/revoke")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(jtiStore);

        var options = new AAuthRevocationOptions();
        configure?.Invoke(options);

        endpoints.MapPost(path, async (HttpContext context) =>
        {
            var cancellationToken = context.RequestAborted;
            var verified = context.Features.Get<AAuthVerificationResult>();
            if (verified is null)
            {
                return AAuthProblemDetails.Create(
                    "invalid_request", "revocation requires a verified AAuth signature (map /revoke behind UseAAuthVerification).",
                    statusCode: StatusCodes.Status401Unauthorized);
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
            if (expSeconds > (options.Clock.GetUtcNow() + options.MaxTokenLifetime + ClockSkew).ToUnixTimeSeconds())
                return Error(RevocationErrorCode.InvalidRequest, "'exp' is later than the longest token lifetime this recipient accepts.");

            var token = new TokenKey(callerId, jti);
            var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expSeconds);
            try
            {
                await jtiStore.RevokeAsync(token, expiresAt, cancellationToken);
            }
            catch (InvalidOperationException)
            {
                return Error(RevocationErrorCode.ServerError, "the revocation could not be recorded.");
            }

            var outcomes = new Dictionary<string, RevocationDownstreamError?>(StringComparer.Ordinal);
            var visited = new HashSet<TokenKey> { token };
            var federated = new HashSet<(TokenKey, string)>();
            var remaining = new Queue<(TokenKey Token, DateTimeOffset ExpiresAt)>();
            remaining.Enqueue((token, expiresAt));
            while (remaining.TryDequeue(out var source))
            {
                foreach (var grant in await jtiStore.GetGrantsAsync(source.Token, cancellationToken))
                {
                    var own = options.Issuer is null || grant.Token.Issuer == options.Issuer;
                    // Four-party: a token another server issued against one of ours is terminated by
                    // revoking ours at that AS, which cascades to what it issued (#revocation-cascade).
                    if (!own && source.Token.Issuer == options.Issuer && federated.Add((source.Token, grant.Token.Issuer)))
                        Record(outcomes, grant.Token.Issuer, await DeliverAsync(options.RevokeAtAccessServerAsync,
                            new TokenGrant(source.Token, grant.Token.Issuer, source.ExpiresAt), cancellationToken));
                    if (!visited.Add(grant.Token)) continue;
                    remaining.Enqueue((grant.Token, grant.ExpiresAt));
                    await jtiStore.RevokeAsync(grant.Token, grant.ExpiresAt, cancellationToken);
                    if (own)
                        Record(outcomes, grant.Resource, await DeliverAsync(options.RevokeGrantAsync, grant, cancellationToken));
                }
            }

            if (!options.ReportDownstream || outcomes.Count == 0)
                return Results.Ok();
            var downstream = new JsonArray();
            foreach (var (recipient, error) in outcomes)
            {
                var entry = new JsonObject { ["recipient"] = recipient };
                if (error is { } failure) entry["error"] = RevocationError.ToWireCode(failure);
                downstream.Add(entry);
            }
            return Results.Json(new JsonObject { ["downstream"] = downstream }, statusCode: StatusCodes.Status200OK);
        }).WithMetadata(new AAuth.Server.Endpoints.AAuthEndpointRequirement
        {
            Mode = AAuthAccessMode.IdentityOnly,
            AcceptedSchemes = ["jwt", "jwks_uri", "jwks", "self-jwt"],
        });

        return endpoints;
    }

    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    private static IResult Error(RevocationErrorCode code, string detail)
        => AAuthProblemDetails.Create(RevocationError.ToWireCode(code), detail, statusCode: RevocationError.StatusCode(code));

    private static async Task<RevocationDownstreamError?> DeliverAsync(
        Func<TokenGrant, CancellationToken, Task<RevocationDownstreamError?>>? revoke, TokenGrant grant, CancellationToken cancellationToken)
    {
        if (revoke is null) return RevocationDownstreamError.RevocationUnsupported;
        try
        {
            return await revoke(grant, cancellationToken);
        }
        catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or AAuthMetadataException or ArgumentException
            or InvalidOperationException or JsonException || ex is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return RevocationDownstreamError.RevocationUnavailable;
        }
    }

    // Keep the worst outcome per recipient: unavailable (retryable) over unsupported over recorded.
    private static void Record(Dictionary<string, RevocationDownstreamError?> outcomes, string recipient, RevocationDownstreamError? error)
    {
        if (!outcomes.TryGetValue(recipient, out var current) || current is null
            || error == RevocationDownstreamError.RevocationUnavailable)
            outcomes[recipient] = error ?? current;
    }
}
