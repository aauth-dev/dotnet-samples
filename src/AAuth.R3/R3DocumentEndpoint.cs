using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth;
using AAuth.Errors;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AAuth.R3;

/// <summary>Maps signature-verified R3 document/proposal endpoints.</summary>
public static class R3DocumentEndpoint
{
    public static IEndpointRouteBuilder MapR3Document(this IEndpointRouteBuilder endpoints,
        string pattern, Func<HttpContext, byte[]?> getBytes, R3DocumentReaderPolicy readerPolicy)
    {
        ArgumentNullException.ThrowIfNull(readerPolicy);
        return endpoints.MapR3Document(pattern, getBytes, readerPolicy.Allows);
    }

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
                fetcher = await VerifyFetcherAsync(context, candidate => isTrustedFetcher(candidate));
            }
            catch (R3UntrustedJwksUriException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_fetcher", statusCode: StatusCodes.Status403Forbidden);
            }
            catch (Exception ex) when (ex is R3FetchVerificationException or AAuthVerificationException)
            {
                return AAuth.Server.AAuthProblemDetails.Create("invalid_signature", ex.Message, statusCode: StatusCodes.Status401Unauthorized);
            }

            if (!isTrustedFetcher(fetcher))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_fetcher", statusCode: StatusCodes.Status403Forbidden);
            }

            var bytes = getBytes(context);
            return bytes is null
                ? Results.NotFound()
                : Results.Bytes(bytes, "application/json");
        });
        return endpoints;
    }

    public static async Task<R3VerifiedFetcher> VerifyFetcherAsync(
        HttpContext context,
        Func<R3VerifiedFetcher, bool>? isAllowedJwksUri = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        var verifier = context.RequestServices.GetService(typeof(AAuthVerifier)) as AAuthVerifier ?? new AAuthVerifier();
        var metadata = context.RequestServices.GetService(typeof(MetadataClient)) as MetadataClient;
        var jwks = context.RequestServices.GetService(typeof(JwksClient)) as JwksClient;
        var authenticated = false;
        var middleware = new AAuthVerificationMiddleware(_ => { authenticated = true; return Task.CompletedTask; },
            verifier, new DefaultSignatureKeyResolver(jwks, metadata), metadata, jwks,
            new AAuthVerificationOptions { EgressPolicy = metadata?.Policy ?? AAuth.Discovery.AAuthEgressPolicy.Production, AcceptedSchemes = ["jwks_uri"],
                RequireBodyCoverage = true });
        await middleware.InvokeAsync(context);
        if (!authenticated)
            throw new R3FetchVerificationException("R3 fetch signature verification failed.");
        var parsed = context.GetAAuthParsedKey()!;
        var fetcher = new R3VerifiedFetcher(parsed.Scheme, parsed.Identifier!, parsed.Kid,
            context.Features.Get<AAuthVerificationResult>()!.Jkt, parsed);
        if (isAllowedJwksUri is null || !isAllowedJwksUri(fetcher))
            throw new R3UntrustedJwksUriException("Authenticated signer is not authorized for this R3 document.");
        return fetcher;
    }

    /// <summary>
    /// Records the current request's signature for replay defence on a state-changing
    /// mint (mirrors <c>AAuthVerificationMiddleware</c> §Freshness and Replay). Returns
    /// <c>false</c> if the same signature was already recorded within the freshness window
    /// (a verbatim replay). A no-op returning <c>true</c> when no <see cref="AAuth.Server.IJtiStore"/>
    /// is registered. Call this ONLY on paths that are not legitimately re-issued (the
    /// granted immediate-mint branch) — never on idempotent/re-polled paths, which would
    /// false-positive on byte-identical signatures.
    /// </summary>
    public static async Task<bool> TryRecordMintSignatureAsync(HttpContext context, string? keyThumbprint)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.RequestServices.GetService(typeof(AAuth.Server.IJtiStore)) is not AAuth.Server.IJtiStore jtiStore)
        {
            return true;
        }
        var verified = context.GetAAuthVerification();
        if (verified?.ReplayIdentity is not { } replayIdentity || verified.ReplayExpiresAt is not { } replayExpiry
            || keyThumbprint != verified.Jkt)
            return false;
        return await jtiStore.TryRecordRequestAsync(replayIdentity, replayExpiry, context.RequestAborted);
    }
}

public sealed record R3VerifiedFetcher(
    string Scheme,
    string Identifier,
    string? Kid,
    string? KeyThumbprint,
    SignatureKeyParser.ParsedSignatureKeyInfo ParsedKey);

public class R3FetchVerificationException : Exception
{
    public R3FetchVerificationException(string message) : base(message) { }
    public R3FetchVerificationException(string message, Exception inner) : base(message, inner) { }
}

public sealed class R3UntrustedJwksUriException : R3FetchVerificationException
{
    public R3UntrustedJwksUriException(string message) : base(message) { }
}
