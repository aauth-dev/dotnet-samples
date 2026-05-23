using System;
using System.Linq;
using System.Threading.Tasks;
using AAuth.Errors;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

/// <summary>
/// ASP.NET Core middleware that verifies the AAuth HTTP signature on each
/// inbound request and exposes the parsed scheme info via <see cref="HttpContext.Items"/>.
/// </summary>
/// <remarks>
/// Layering:
/// <list type="number">
/// <item>Pull <c>Signature</c>, <c>Signature-Input</c>, <c>Signature-Key</c> headers.</item>
/// <item><see cref="SignatureKeyParser.ParseAny"/> decodes the scheme and extracts key references.</item>
/// <item><see cref="ISignatureKeyResolver"/> resolves the public key (inline, JWKS, or lookup).</item>
/// <item><see cref="AAuthVerifier"/> verifies the RFC 9421 signature against that key.</item>
/// <item>The downstream pipeline can read <see cref="ContextItemKey"/> to inspect claims.</item>
/// </list>
/// Token-level verification (JWKS lookup, <c>aud</c>/<c>scope</c> checks) is
/// the responsibility of route handlers via <see cref="TokenVerifier"/> —
/// this middleware only ensures the request is signed by the key resolved from
/// the Signature-Key header.
/// </remarks>
public sealed class AAuthVerificationMiddleware
{
    /// <summary><see cref="HttpContext.Items"/> key for the parsed Signature-Key info.</summary>
    public const string ContextItemKey = "AAuth.ParsedSignatureKey";

    /// <summary>Algorithms this server supports, emitted in <c>supported_algorithms</c> on unsupported_algorithm errors.</summary>
    private static readonly string[] SupportedAlgorithms = ["EdDSA"];

    private readonly RequestDelegate _next;
    private readonly AAuthVerifier _verifier;
    private readonly ISignatureKeyResolver _resolver;

    /// <summary>Create the middleware.</summary>
    public AAuthVerificationMiddleware(RequestDelegate next, AAuthVerifier verifier, ISignatureKeyResolver? resolver = null)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(verifier);
        _next = next;
        _verifier = verifier;
        _resolver = resolver ?? new DefaultSignatureKeyResolver();
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
            context.Response.Headers[SignatureError.HeaderName] =
                SignatureError.Format(SignatureErrorCode.InvalidRequest);
            return;
        }

        IAAuthKey publicKey;
        SignatureKeyParser.ParsedSignatureKeyInfo parsedInfo;
        try
        {
            parsedInfo = SignatureKeyParser.ParseAny(signatureKey);
            var resolution = await _resolver.ResolveAsync(parsedInfo, context.RequestAborted)
                .ConfigureAwait(false);
            publicKey = resolution.PublicKey;

            var path = (req.PathBase + req.Path).ToUriComponent();
            if (string.IsNullOrEmpty(path)) { path = "/"; }

            _verifier.Verify(
                method: req.Method,
                authority: req.Host.ToString(),
                path: path,
                signatureKey: signatureKey,
                signatureInput: signatureInput,
                signatureHeader: signature,
                publicKey: publicKey,
                authorization: req.Headers.Authorization.FirstOrDefault());
        }
        catch (AAuthVerificationException ex)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            var errorCode = ClassifyVerificationError(ex);
            context.Response.Headers[SignatureError.HeaderName] = errorCode == SignatureErrorCode.UnsupportedAlgorithm
                ? SignatureError.Format(errorCode, supportedAlgorithms: SupportedAlgorithms)
                : SignatureError.Format(errorCode);
            return;
        }

        context.Items[ContextItemKey] = parsedInfo;

        // Replay detection: if a JTI store is attached, check for replay.
        // JTI is available for schemes that carry a JWT (jwt, jkt-jwt).
        var tokenId = parsedInfo.Payload?["jti"]?.GetValue<string>();
        if (context.Items.TryGetValue(JtiStoreItemKey, out var storeObj) &&
            storeObj is IJtiStore jtiStore &&
            tokenId is { Length: > 0 } jti)
        {
            var expNode = parsedInfo.Payload?["exp"];
            var expiration = expNode is not null
                ? DateTimeOffset.FromUnixTimeSeconds(expNode.GetValue<long>())
                : DateTimeOffset.UtcNow.AddMinutes(5);
            if (!await jtiStore.TryRecordAsync(jti, expiration, context.RequestAborted))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers[SignatureError.HeaderName] =
                    SignatureError.Format(SignatureErrorCode.InvalidJwt);
                return;
            }
            if (await jtiStore.IsRevokedAsync(jti, context.RequestAborted))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers[SignatureError.HeaderName] =
                    SignatureError.Format(SignatureErrorCode.InvalidJwt);
                return;
            }
        }

        await _next(context).ConfigureAwait(false);
    }

    /// <summary>Internal key for JTI store stashed in HttpContext.Items by the UseAAuthVerification overload.</summary>
    internal const string JtiStoreItemKey = "AAuth.JtiStore";

    private static SignatureErrorCode ClassifyVerificationError(AAuthVerificationException ex)
    {
        var msg = ex.Message;
        if (msg.Contains("covered components", StringComparison.OrdinalIgnoreCase))
            return SignatureErrorCode.InvalidInput;
        // Algorithm mismatch: key uses a different curve/type than Ed25519
        if (msg.Contains("not a valid Ed25519 OKP key", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("not an Ed25519 OKP key", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("Unsupported or missing 'alg'", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("Unsupported 'alg'", StringComparison.OrdinalIgnoreCase))
            return SignatureErrorCode.UnsupportedAlgorithm;
        if (msg.Contains("freshness window", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("signature verification failed", StringComparison.OrdinalIgnoreCase))
            return SignatureErrorCode.InvalidSignature;
        if (msg.Contains("unknown key", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("key not found", StringComparison.OrdinalIgnoreCase))
            return SignatureErrorCode.UnknownKey;
        if (msg.Contains("scheme is not", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("Unsupported Signature-Key scheme", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("cnf.jwk", StringComparison.OrdinalIgnoreCase) ||

            msg.Contains("jkt parameter does not match", StringComparison.OrdinalIgnoreCase))
            return SignatureErrorCode.InvalidKey;
        if (msg.Contains("not a compact JWS", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("missing the 'cnf'", StringComparison.OrdinalIgnoreCase))
            return SignatureErrorCode.InvalidJwt;
        if (msg.Contains("URI must use https", StringComparison.OrdinalIgnoreCase))
            return SignatureErrorCode.InvalidKey;
        return SignatureErrorCode.InvalidSignature;
    }

    private static bool TryGetSingle(HttpRequest request, string headerName, out string value)
    {
        value = string.Empty;
        if (!request.Headers.TryGetValue(headerName, out var values) || values.Count == 0)
        {
            return false;
        }
        // Multi-value AAuth signature headers are not yet defined (see the
        // "compose multiple signers" follow-up). Reject for now so
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
    /// <summary>
    /// Add the AAuth HTTP-signature verification middleware to the pipeline.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <param name="verifier">Optional verifier instance.</param>
    /// <param name="jtiStore">Optional JTI store for replay detection.</param>
    /// <param name="resolver">Optional resolver for key resolution from Signature-Key header.
    /// Defaults to <see cref="DefaultSignatureKeyResolver"/> which handles all schemes.</param>
    public static IApplicationBuilder UseAAuthVerification(
        this IApplicationBuilder app,
        AAuthVerifier? verifier = null,
        IJtiStore? jtiStore = null,
        ISignatureKeyResolver? resolver = null)
    {
        ArgumentNullException.ThrowIfNull(app);

        if (jtiStore is not null)
        {
            // Stash JTI store so the middleware can access it via HttpContext.Items.
            app.Use(async (context, next) =>
            {
                context.Items[AAuthVerificationMiddleware.JtiStoreItemKey] = jtiStore;
                await next();
            });
        }

        var resolvedVerifier = verifier
            ?? app.ApplicationServices.GetService(typeof(AAuthVerifier)) as AAuthVerifier
            ?? new AAuthVerifier();
        var resolvedResolver = resolver
            ?? app.ApplicationServices.GetService(typeof(ISignatureKeyResolver)) as ISignatureKeyResolver;

        return app.Use(next =>
        {
            var mw = new AAuthVerificationMiddleware(next, resolvedVerifier, resolvedResolver);
            return mw.InvokeAsync;
        });
    }
}
