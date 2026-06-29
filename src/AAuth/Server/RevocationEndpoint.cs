using System;
using System.Text.Json;
using System.Threading.Tasks;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AAuth.Server;

/// <summary>
/// Extension methods to map a POST /revoke endpoint for AAuth token revocation
/// (§Token Revocation).
/// </summary>
public static class RevocationEndpoint
{
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
    /// body <c>{ "jti": "..." }</c> and marks the token revoked in the
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
                return Results.Json(
                    new { error = "invalid_request", error_description = "revocation requires a verified AAuth signature (map /revoke behind UseAAuthVerification)." },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            // §Token Revocation (L2302): MUST only accept revocation from the issuer
            // of the token or a trusted PS. Deny-by-default per AAuthRevocationOptions.
            var callerId = verified.Issuer ?? verified.Agent ?? verified.Subject ?? verified.Jkt;
            if (callerId is null || !options.IsAuthorizedRevoker(callerId))
            {
                return Results.Json(
                    new { error = "untrusted_revoker", error_description = $"'{callerId}' is not authorized to revoke tokens at this resource." },
                    statusCode: StatusCodes.Status403Forbidden);
            }

            // §Token Revocation request body: { "jti": "..." }.
            string? jti = null;
            try
            {
                var body = await context.Request.ReadFromJsonAsync<JsonElement>(context.RequestAborted);
                if (body.ValueKind == JsonValueKind.Object
                    && body.TryGetProperty("jti", out var jtiEl)
                    && jtiEl.ValueKind == JsonValueKind.String)
                {
                    jti = jtiEl.GetString();
                }
            }
            catch (JsonException)
            {
                // fall through to the 400 below
            }

            if (string.IsNullOrEmpty(jti))
            {
                return Results.Json(
                    new { error = "invalid_request", error_description = "a JSON body with a 'jti' string is required." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            await jtiStore.RevokeAsync(jti, context.RequestAborted);

            // 200 OK whether the token was revoked or was already invalid.
            return Results.Ok();
        });

        return endpoints;
    }
}
