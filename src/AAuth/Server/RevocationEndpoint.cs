using System;
using System.Text.Json;
using System.Threading.Tasks;
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
    public static IJtiStore MapAAuthIssuerRevocation(this WebApplication app, string issuer, string dwk,
        AAuth.Crypto.IAAuthKey signingKey, string signingKid, string path,
        AAuth.Discovery.AAuthEgressPolicy egressPolicy, TimeProvider clock, Action<AAuthRevocationOptions>? configure)
    {
        var inventory = app.Services.GetService<IJtiStore>() ?? new InMemoryJtiStore(clock);
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
                    Clock = () => clock.GetUtcNow(),
                }).InvokeAsync));
        app.MapAAuthRevocationEndpoint(inventory, options =>
        {
            options.AllowTokenIssuer = true;
            options.RevokeGrantAsync = async (grant, cancellationToken) =>
            {
                var document = await metadata.FetchAsync(metadata.GetUrl(grant.Resource, "aauth-resource.json"), cancellationToken);
                var endpoint = (string?)document["revocation_endpoint"];
                if (endpoint is null) return false;
                var endpointUri = egressPolicy.ValidateUrl(endpoint, endpoint: true);
                if (endpointUri.GetLeftPart(UriPartial.Authority) != new Uri(grant.Resource).GetLeftPart(UriPartial.Authority))
                    return false;
                return await client.RevokeAsync(endpointUri, grant.Token, cancellationToken) == System.Net.HttpStatusCode.OK;
            };
            configure?.Invoke(options);
        }, path);
        return inventory;
    }

    /// <summary>
    /// Map the revocation endpoint with no authorized revokers configured (every
    /// caller is denied — see <see cref="AAuthRevocationOptions"/>). Prefer the
    /// <see cref="MapAAuthRevocationEndpoint(IEndpointRouteBuilder, IJtiStore, Action{AAuthRevocationOptions}, string)"/>
    /// overload to declare who may revoke.
    /// </summary>
    public static IEndpointRouteBuilder MapAAuthRevocationEndpoint(
        this IEndpointRouteBuilder endpoints,
        IJtiStore jtiStore,
        string path = "/revoke")
        => endpoints.MapAAuthRevocationEndpoint(jtiStore, configure: null, path);

    /// <summary>
    /// Map the revocation endpoint. The endpoint accepts a signed POST with a JSON
    /// body <c>{ "iss": "...", "jti": "..." }</c> and marks the token revoked in the
    /// <see cref="IJtiStore"/>.
    /// </summary>
    /// <remarks>
    /// Per §Token Revocation (L2302) the endpoint MUST verify the caller's identity
    /// via HTTP Message Signatures and MUST only accept revocation from the issuer of
    /// the token or a trusted Person Server. Map this endpoint <b>behind</b> AAuth
    /// verification (<c>UseAAuthVerification</c> or a <c>RequireAAuthSignature</c>
    /// endpoint) so the verified caller identity is available; authorize callers via
    /// <see cref="AAuthRevocationOptions"/> (deny-by-default).
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
            // §Token Revocation (L2302): MUST verify the caller's identity via HTTP
            // Message Signatures. Read the verified result produced by AAuth
            // verification middleware; absence means the request was not verified.
            var verified = context.Features.Get<AAuthVerificationResult>();
            if (verified is null)
            {
                return AAuthProblemDetails.Create(
                    "invalid_request", "revocation requires a verified AAuth signature (map /revoke behind UseAAuthVerification).",
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            string? issuer = null;
            string? jti = null;
            try
            {
                var body = await context.Request.ReadFromJsonAsync<JsonElement>(context.RequestAborted);
                if (body.ValueKind == JsonValueKind.Object)
                {
                    if (body.TryGetProperty("iss", out var issuerEl) && issuerEl.ValueKind == JsonValueKind.String)
                        issuer = issuerEl.GetString();
                    if (body.TryGetProperty("jti", out var jtiEl) && jtiEl.ValueKind == JsonValueKind.String)
                        jti = jtiEl.GetString();
                }
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException)
            {
                // Malformed JSON (JsonException) or a missing/non-JSON Content-Type
                // (InvalidOperationException from ReadFromJsonAsync) — fall through to 400.
            }

            if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(jti))
            {
                return AAuthProblemDetails.Create(
                    "invalid_request", "a JSON body with an 'iss' string and a 'jti' string is required.",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var token = new TokenKey(issuer, jti);
            var callerId = verified.Scheme is "jwks_uri" or "jwks" or "self-jwt"
                ? verified.Issuer
                : null;
            if (callerId is null || !options.IsAuthorizedRevoker(callerId, token))
            {
                return AAuthProblemDetails.Create(
                    "untrusted_revoker", $"'{callerId}' is not authorized to revoke this token.",
                    statusCode: StatusCodes.Status403Forbidden);
            }

            if (!await jtiStore.RevokeAsync(token, context.RequestAborted))
                return AAuthProblemDetails.Create("unknown_token", "The token pair is not recognized.",
                    statusCode: StatusCodes.Status404NotFound);

            var complete = true;
            var visited = new HashSet<TokenKey> { token };
            var remaining = new Queue<TokenKey>();
            remaining.Enqueue(token);
            while (remaining.TryDequeue(out var source))
            {
                foreach (var grant in await jtiStore.GetGrantsAsync(source, context.RequestAborted))
                {
                    if (!visited.Add(grant.Token)) continue;
                    remaining.Enqueue(grant.Token);
                    await jtiStore.RevokeAsync(grant.Token, context.RequestAborted);
                    try
                    {
                        if (options.RevokeGrantAsync is null || !await options.RevokeGrantAsync(grant, context.RequestAborted))
                            complete = false;
                    }
                    catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or AAuth.Errors.AAuthMetadataException
                        or ArgumentException or InvalidOperationException || ex is OperationCanceledException && !context.RequestAborted.IsCancellationRequested)
                    {
                        complete = false;
                    }
                }
            }
            if (!complete)
                return AAuthProblemDetails.Create("revocation_incomplete", "Local revocation is effective, but not every resource confirmed revocation. Retry this request.",
                    statusCode: StatusCodes.Status502BadGateway);

            // 200 OK whether the token was revoked or was already invalid.
            return Results.Ok();
        }).WithMetadata(new AAuth.Server.Endpoints.AAuthEndpointRequirement
        {
            Mode = AAuthAccessMode.IdentityOnly,
            AcceptedSchemes = ["jwt", "jwks_uri", "jwks", "self-jwt"],
        });

        return endpoints;
    }
}
