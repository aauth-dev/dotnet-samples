using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AAuth.R3;

/// <summary>Maps signature-verified R3 document/proposal endpoints.</summary>
public static class R3DocumentEndpoint
{
    public static IEndpointRouteBuilder MapR3Document(
        this IEndpointRouteBuilder endpoints,
        string pattern,
        Func<HttpContext, byte[]?> getBytes,
        Func<R3VerifiedFetcher, bool> isTrustedFetcher)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrEmpty(pattern);
        ArgumentNullException.ThrowIfNull(getBytes);
        ArgumentNullException.ThrowIfNull(isTrustedFetcher);

        endpoints.MapGet(pattern, async (HttpContext context) =>
        {
            R3VerifiedFetcher fetcher;
            try
            {
                fetcher = await VerifyFetcherAsync(context);
            }
            catch (Exception ex) when (ex is R3FetchVerificationException or AAuthVerificationException)
            {
                return Results.Json(new { error = "invalid_signature", detail = ex.Message }, statusCode: StatusCodes.Status401Unauthorized);
            }

            if (!isTrustedFetcher(fetcher))
            {
                return Results.Json(new { error = "untrusted_fetcher" }, statusCode: StatusCodes.Status403Forbidden);
            }

            var bytes = getBytes(context);
            return bytes is null
                ? Results.NotFound()
                : Results.Bytes(bytes, "application/json");
        });
        return endpoints;
    }

    public static async Task<R3VerifiedFetcher> VerifyFetcherAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var request = context.Request;
        if (!TrySingleHeader(request, AAuthConstants.Headers.SignatureKey, out var signatureKey)
            || !TrySingleHeader(request, AAuthConstants.Headers.SignatureInput, out var signatureInput)
            || !TrySingleHeader(request, AAuthConstants.Headers.Signature, out var signature))
        {
            throw new R3FetchVerificationException("Missing AAuth HTTP signature headers.");
        }

        var parsed = SignatureKeyParser.ParseAny(signatureKey);
        IAAuthKey publicKey;
        if (parsed.Scheme == AAuthConstants.Schemes.JwksUri)
        {
            var jwks = context.RequestServices.GetService(typeof(JwksClient)) as JwksClient
                ?? throw new R3FetchVerificationException("JwksClient is required to resolve jwks_uri fetch signatures.");
            if (string.IsNullOrWhiteSpace(parsed.JwksUri) || string.IsNullOrWhiteSpace(parsed.Kid))
            {
                throw new R3FetchVerificationException("jwks_uri Signature-Key is missing uri or kid.");
            }
            publicKey = await jwks.ResolveKeyAsync(new Uri(parsed.JwksUri), parsed.Kid, context.RequestAborted)
                ?? throw new R3FetchVerificationException("jwks_uri Signature-Key key was not found.");
        }
        else
        {
            publicKey = parsed.ConfirmationKey
                ?? throw new R3FetchVerificationException($"Signature-Key scheme '{parsed.Scheme}' did not provide a confirmation key.");
        }

        var verifier = context.RequestServices.GetService(typeof(AAuthVerifier)) as AAuthVerifier ?? new AAuthVerifier();
        var path = (request.PathBase + request.Path).ToUriComponent();
        if (string.IsNullOrEmpty(path))
        {
            path = "/";
        }

        verifier.Verify(
            request.Method,
            request.Host.ToString(),
            path,
            signatureKey,
            signatureInput,
            signature,
            publicKey,
            request.Headers.Authorization.FirstOrDefault());

        return new R3VerifiedFetcher(
            parsed.Scheme,
            parsed.JwksUri is null ? null : new Uri(parsed.JwksUri),
            parsed.Kid,
            parsed.Jkt ?? publicKey.ComputeJwkThumbprint(),
            parsed);
    }

    private static bool TrySingleHeader(HttpRequest request, string headerName, out string value)
    {
        value = string.Empty;
        if (!request.Headers.TryGetValue(headerName, out var values) || values.Count != 1 || values[0] is null)
        {
            return false;
        }
        value = values[0]!;
        return true;
    }
}

public sealed record R3VerifiedFetcher(
    string Scheme,
    Uri? JwksUri,
    string? Kid,
    string? KeyThumbprint,
    SignatureKeyParser.ParsedSignatureKeyInfo ParsedKey);

public sealed class R3FetchVerificationException : Exception
{
    public R3FetchVerificationException(string message) : base(message) { }
    public R3FetchVerificationException(string message, Exception inner) : base(message, inner) { }
}
