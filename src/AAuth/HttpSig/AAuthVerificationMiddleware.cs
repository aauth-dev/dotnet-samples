using System;
using System.Linq;
using System.Threading.Tasks;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

/// <summary>
/// ASP.NET Core middleware that verifies the AAuth HTTP signature on each
/// inbound request and exposes the parsed token via <see cref="HttpContext.Items"/>.
/// </summary>
/// <remarks>
/// Layering:
/// <list type="number">
/// <item>Pull <c>Signature</c>, <c>Signature-Input</c>, <c>Signature-Key</c> headers.</item>
/// <item><see cref="SignatureKeyParser"/> decodes the carrier JWT and exposes <c>cnf.jwk</c>.</item>
/// <item><see cref="AAuthVerifier"/> verifies the RFC 9421 signature against that key.</item>
/// <item>The downstream pipeline can read <see cref="ContextItemKey"/> to inspect claims.</item>
/// </list>
/// Token-level verification (JWKS lookup, <c>aud</c>/<c>scope</c> checks) is
/// the responsibility of route handlers via <see cref="TokenVerifier"/> —
/// this middleware only ensures the request is signed by the key bound in
/// the carrier token's <c>cnf.jwk</c>.
/// </remarks>
public sealed class AAuthVerificationMiddleware
{
    /// <summary><see cref="HttpContext.Items"/> key for the parsed token.</summary>
    public const string ContextItemKey = "AAuth.ParsedSignatureKey";

    private readonly RequestDelegate _next;
    private readonly AAuthVerifier _verifier;

    /// <summary>Create the middleware.</summary>
    public AAuthVerificationMiddleware(RequestDelegate next, AAuthVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(verifier);
        _next = next;
        _verifier = verifier;
    }

    /// <inheritdoc cref="RequestDelegate"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var req = context.Request;

        // Surface missing-signature as 401 with no body so the resource can
        // attach AAuth-Requirement from its own handler. This keeps the
        // middleware policy-free.
        if (!TryGetSingle(req, "Signature", out var signature) ||
            !TryGetSingle(req, "Signature-Input", out var signatureInput) ||
            !TryGetSingle(req, SignatureKeyHeader.Name, out var signatureKey))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        SignatureKeyParser.ParsedSignatureKey parsed;
        try
        {
            parsed = SignatureKeyParser.Parse(signatureKey);
            // RFC 9421 §2.2.7: @path is the wire form. ASP.NET's PathBase +
            // Path is the decoded form; PathBase.Value + Path.Value preserves
            // the original encoding. Use Path.ToUriComponent() for safety.
            var path = (req.PathBase + req.Path).ToUriComponent();
            if (string.IsNullOrEmpty(path)) { path = "/"; }

            _verifier.Verify(
                method: req.Method,
                authority: req.Host.ToString(),
                path: path,
                signatureKey: signatureKey,
                signatureInput: signatureInput,
                signatureHeader: signature,
                publicKey: parsed.ConfirmationKey);
        }
        catch (AAuthVerificationException)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        context.Items[ContextItemKey] = parsed;
        await _next(context).ConfigureAwait(false);
    }

    private static bool TryGetSingle(HttpRequest request, string headerName, out string value)
    {
        value = string.Empty;
        if (!request.Headers.TryGetValue(headerName, out var values) || values.Count == 0)
        {
            return false;
        }
        // Multi-value AAuth signature headers are not yet defined (see the
        // Phase 1 "compose multiple signers" follow-up). Reject for now so
        // an attacker can't sneak a second labelled signature past us.
        if (values.Count != 1 || values[0] is null)
        {
            return false;
        }
        value = values[0]!;
        return true;
    }
}

/// <summary>Extension method for plugging <see cref="AAuthVerificationMiddleware"/> in.</summary>
public static class AAuthVerificationMiddlewareExtensions
{
    /// <summary>Add the AAuth HTTP-signature verification middleware to the pipeline.</summary>
    public static IApplicationBuilder UseAAuthVerification(
        this IApplicationBuilder app,
        AAuthVerifier? verifier = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<AAuthVerificationMiddleware>(verifier ?? new AAuthVerifier());
    }
}
