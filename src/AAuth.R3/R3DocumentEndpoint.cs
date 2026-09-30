using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth;
using AAuth.Errors;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AAuth.R3;

/// <summary>Maps signature-verified R3 document/proposal endpoints.</summary>
public static class R3DocumentEndpoint
{
    /// <summary>
    /// Register the R3 document reader policy and the in-memory <see cref="IR3DocumentEntitlements"/>
    /// default (register your own first to share entitlements across instances).
    /// </summary>
    public static IServiceCollection AddAAuthR3Documents(this IServiceCollection services,
        Func<IServiceProvider, R3DocumentReaderPolicy> readerPolicy)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(readerPolicy);
        services.TryAddSingleton(readerPolicy);
        services.TryAddSingleton<IR3DocumentEntitlements, InMemoryR3DocumentEntitlements>();
        return services;
    }

    /// <summary>
    /// Map an R3 document using the DI-registered <see cref="R3DocumentReaderPolicy"/>. A Person
    /// Server reads only documents it is entitled to (<see cref="IR3DocumentEntitlements"/>, or the
    /// policy's <see cref="R3DocumentReaderPolicy.IsEntitledPersonServer"/>); others look absent.
    /// </summary>
    public static IEndpointRouteBuilder MapR3Document(this IEndpointRouteBuilder endpoints,
        string pattern, Func<HttpContext, byte[]?> getBytes)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(getBytes);
        var readerPolicy = endpoints.ServiceProvider.GetService<R3DocumentReaderPolicy>()
            ?? throw new InvalidOperationException("MapR3Document requires AddAAuthR3Documents.");
        var entitlements = endpoints.ServiceProvider.GetService<IR3DocumentEntitlements>();
        return endpoints.MapR3DocumentCore(pattern, async context =>
        {
            var bytes = getBytes(context);
            if (bytes is null
                || context.GetAAuthParsedKey() is not { Dwk: AAuthConstants.DwkFiles.Person, Identifier: { } personServer })
                return bytes;
            if (entitlements is null && readerPolicy.IsEntitledPersonServer is null) return bytes;
            var entitled = readerPolicy.IsEntitledPersonServer?.Invoke(context, personServer) == true
                || entitlements is not null && await entitlements.IsEntitledAsync(R3Hash.ComputeS256(bytes), personServer,
                    context.RequestAborted).ConfigureAwait(false);
            return entitled ? bytes : null;
        }, readerPolicy.Allows);
    }

    public static IEndpointRouteBuilder MapR3Document(
        this IEndpointRouteBuilder endpoints,
        string pattern,
        Func<HttpContext, byte[]?> getBytes,
        Func<R3VerifiedFetcher, bool> isTrustedFetcher)
    {
        ArgumentNullException.ThrowIfNull(getBytes);
        return endpoints.MapR3DocumentCore(pattern, context => ValueTask.FromResult(getBytes(context)), isTrustedFetcher);
    }

    private static IEndpointRouteBuilder MapR3DocumentCore(
        this IEndpointRouteBuilder endpoints,
        string pattern,
        Func<HttpContext, ValueTask<byte[]?>> getBytes,
        Func<R3VerifiedFetcher, bool> isTrustedFetcher)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrEmpty(pattern);
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
                var code = ex switch
                {
                    AAuthVerificationException signature => signature.Code,
                    R3FetchVerificationException fetch => fetch.Code,
                    _ => AAuth.Errors.SignatureErrorCode.InvalidSignature,
                };
                return AAuth.Server.AAuthProblemDetails.SignatureFailure(code,
                    acceptedSchemes: code == AAuth.Errors.SignatureErrorCode.UnsupportedScheme
                        ? [AAuthConstants.Schemes.JwksUri] : null);
            }

            if (!isTrustedFetcher(fetcher))
            {
                return AAuth.Server.AAuthProblemDetails.Create("untrusted_fetcher", statusCode: StatusCodes.Status403Forbidden);
            }

            var bytes = await getBytes(context).ConfigureAwait(false);
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
        {
            if (!SignatureError.TryParse(context.Response.Headers[SignatureError.HeaderName].ToString(), out var code))
                code = SignatureErrorCode.InvalidSignature;
            if (code == SignatureErrorCode.InvalidSignature
                && context.Request.Headers.TryGetValue(AAuthConstants.Headers.SignatureKey, out var signatureKey))
            {
                try
                {
                    if (SignatureKeyHeader.Parse(signatureKey.ToString()).Scheme != AAuthConstants.Schemes.JwksUri)
                        code = SignatureErrorCode.UnsupportedScheme;
                }
                catch (AAuthVerificationException) { }
            }
            throw new R3FetchVerificationException("R3 fetch signature verification failed.", code);
        }
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
    internal SignatureErrorCode Code { get; }
    public R3FetchVerificationException(string message) : this(message, null, SignatureErrorCode.InvalidSignature) { }
    public R3FetchVerificationException(string message, Exception inner) : this(message, inner, SignatureErrorCode.InvalidSignature) { }
    internal R3FetchVerificationException(string message, SignatureErrorCode code) : this(message, null, code) { }
    private R3FetchVerificationException(string message, Exception? inner, SignatureErrorCode code) : base(message, inner)
        => Code = code;
}

public sealed class R3UntrustedJwksUriException : R3FetchVerificationException
{
    public R3UntrustedJwksUriException(string message) : base(message) { }
}
