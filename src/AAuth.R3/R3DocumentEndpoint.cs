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
                fetcher = await VerifyFetcherAsync(context, candidate => isTrustedFetcher(candidate));
            }
            catch (R3UntrustedJwksUriException)
            {
                return Results.Json(new { error = "untrusted_fetcher" }, statusCode: StatusCodes.Status403Forbidden);
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

    public static async Task<R3VerifiedFetcher> VerifyFetcherAsync(
        HttpContext context,
        Func<R3VerifiedFetcher, bool>? isAllowedJwksUri = null)
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
            if (isAllowedJwksUri is null)
            {
                throw new R3UntrustedJwksUriException("jwks_uri Signature-Key requires an explicit trust predicate.");
            }
            if (string.IsNullOrWhiteSpace(parsed.JwksUri) || string.IsNullOrWhiteSpace(parsed.Kid))
            {
                throw new R3FetchVerificationException("jwks_uri Signature-Key is missing uri or kid.");
            }
            if (!Uri.TryCreate(parsed.JwksUri, UriKind.Absolute, out var jwksUri)
                || !R3FetchClient.IsHttpOrHttps(jwksUri)
                || (!string.Equals(jwksUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) && !jwksUri.IsLoopback)
                || (isAllowedJwksUri is not null
                    && !isAllowedJwksUri(new R3VerifiedFetcher(
                        parsed.Scheme,
                        jwksUri,
                        parsed.Kid,
                        parsed.Jkt,
                        parsed))))
            {
                throw new R3UntrustedJwksUriException("jwks_uri Signature-Key is not trusted.");
            }
            publicKey = await jwks.ResolveKeyAsync(jwksUri, parsed.Kid, context.RequestAborted)
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

        // Replay defence is NOT applied here: this path is shared by the idempotent GET
        // callers (document fetch, /pending polls) and by the /token proposal branch,
        // all of which are legitimately re-issued — rapid sub-second re-polls even share
        // one whole-second `created` ⇒ byte-identical signatures. Only the state-changing
        // *granted immediate-mint* branch guards against replay, via
        // TryRecordMintSignatureAsync (called from the /token handler).
        return new R3VerifiedFetcher(
            parsed.Scheme,
            parsed.JwksUri is null ? null : new Uri(parsed.JwksUri),
            parsed.Kid,
            parsed.Jkt ?? publicKey.ComputeJwkThumbprint(),
            parsed);
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
        if (!TrySingleHeader(context.Request, AAuthConstants.Headers.SignatureInput, out var signatureInput)
            || !TrySingleHeader(context.Request, AAuthConstants.Headers.Signature, out var signature)
            || ParseSignatureCreated(signatureInput) is not { } createdSeconds)
        {
            return true;
        }
        var verifier = context.RequestServices.GetService(typeof(AAuthVerifier)) as AAuthVerifier ?? new AAuthVerifier();
        var replayKey = $"{keyThumbprint}|{signature}";
        var replayExpiry = DateTimeOffset.FromUnixTimeSeconds(createdSeconds) + verifier.MaxAge;
        return await jtiStore.TryRecordAsync(replayKey, replayExpiry, context.RequestAborted);
    }

    // Parse the numeric `created` parameter from a Signature-Input value.
    // Mirrors AAuthVerificationMiddleware so the R3 self-verification path applies
    // the same freshness-window bound to replay entries.
    private static long? ParseSignatureCreated(string signatureInput)
    {
        const string Marker = "created=";
        var idx = signatureInput.IndexOf(Marker, StringComparison.Ordinal);
        if (idx < 0)
        {
            return null;
        }
        var start = idx + Marker.Length;
        var end = start;
        if (end < signatureInput.Length && signatureInput[end] == '-')
        {
            end++;
        }
        while (end < signatureInput.Length && char.IsDigit(signatureInput[end]))
        {
            end++;
        }
        return long.TryParse(signatureInput.AsSpan(start, end - start), out var created)
            ? created
            : null;
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

public class R3FetchVerificationException : Exception
{
    public R3FetchVerificationException(string message) : base(message) { }
    public R3FetchVerificationException(string message, Exception inner) : base(message, inner) { }
}

public sealed class R3UntrustedJwksUriException : R3FetchVerificationException
{
    public R3UntrustedJwksUriException(string message) : base(message) { }
}
