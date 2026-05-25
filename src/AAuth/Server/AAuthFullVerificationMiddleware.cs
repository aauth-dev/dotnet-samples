using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

/// <summary>
/// ASP.NET Core middleware that performs BOTH HTTP signature PoP verification
/// AND JWT issuer signature verification in a single pass. This closes the
/// security gap where <see cref="AAuthVerificationMiddleware"/> only verifies
/// proof-of-possession but not the issuer's JWT signature.
/// </summary>
/// <remarks>
/// <list type="number">
/// <item>Pull Signature, Signature-Input, Signature-Key headers.</item>
/// <item>Parse the scheme and resolve the public key (HTTP sig verification).</item>
/// <item>Verify the RFC 9421 signature (PoP).</item>
/// <item>For jwt/jkt-jwt schemes: detect token type from <c>typ</c> header claim.</item>
/// <item>For <c>aa-agent+jwt</c>: verify JWT signature against AP JWKS.</item>
/// <item>For <c>aa-auth+jwt</c>: verify JWT signature against PS/AS JWKS, validate
///   <c>aud</c>, verify PoP binding (<c>cnf.jwk</c>), require <c>act</c> claim.</item>
/// <item>Store <see cref="FullVerificationResult"/> in HttpContext.Items.</item>
/// </list>
/// </remarks>
public sealed class AAuthFullVerificationMiddleware
{
    /// <summary><see cref="HttpContext.Items"/> key for the full verification result.</summary>
    public const string ContextItemKey = "AAuth.FullVerificationResult";

    private readonly RequestDelegate _next;
    private readonly AAuthVerifier _verifier;
    private readonly ISignatureKeyResolver _resolver;
    private readonly MetadataClient _metadata;
    private readonly JwksClient _jwks;
    private readonly FullVerificationOptions _options;

    /// <summary>Create the middleware.</summary>
    public AAuthFullVerificationMiddleware(
        RequestDelegate next,
        AAuthVerifier verifier,
        ISignatureKeyResolver resolver,
        MetadataClient metadata,
        JwksClient jwks,
        FullVerificationOptions options)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(jwks);
        ArgumentNullException.ThrowIfNull(options);
        _next = next;
        _verifier = verifier;
        _resolver = resolver;
        _metadata = metadata;
        _jwks = jwks;
        _options = options;
    }

    /// <inheritdoc cref="RequestDelegate"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var req = context.Request;

        if (!TryGetSingle(req, "Signature", out var signature) ||
            !TryGetSingle(req, "Signature-Input", out var signatureInput) ||
            !TryGetSingle(req, SignatureKeyHeader.Name, out var signatureKey))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers[SignatureError.HeaderName] =
                SignatureError.Format(SignatureErrorCode.InvalidRequest);
            return;
        }

        // Step 1-3: Parse scheme, resolve public key, verify HTTP signature.
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
            context.Response.Headers[SignatureError.HeaderName] =
                SignatureError.Format(ClassifyVerificationError(ex));
            return;
        }

        // Replay detection (same as base middleware).
        var tokenId = parsedInfo.Payload?["jti"]?.GetValue<string>();
        if (context.Items.TryGetValue(AAuthVerificationMiddleware.JtiStoreItemKey, out var storeObj) &&
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

        // Step 4-6: JWT issuer verification (for jwt and jkt-jwt schemes with carrier tokens).
        if (_options.RequireIssuerVerification &&
            parsedInfo.Scheme is "jwt" or "jkt-jwt" &&
            parsedInfo.Jwt is not null &&
            parsedInfo.Header is not null &&
            parsedInfo.Payload is not null)
        {
            var typ = (string?)parsedInfo.Header["typ"];
            try
            {
                if (typ == AgentTokenBuilder.TokenType)
                {
                    await VerifyAgentTokenIssuerAsync(parsedInfo, context.RequestAborted)
                        .ConfigureAwait(false);
                }
                else if (typ == AuthTokenBuilder.TokenType)
                {
                    await VerifyAuthTokenIssuerAsync(parsedInfo, publicKey, context.RequestAborted)
                        .ConfigureAwait(false);
                }
                // Other token types (e.g. resource tokens in jkt-jwt naming JWTs) are not
                // verified at this layer — they require different trust chains.
            }
            catch (TokenVerificationException ex)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers[SignatureError.HeaderName] =
                    SignatureError.Format(SignatureErrorCode.InvalidJwt);
                context.Response.Headers["AAuth-Error"] = ex.Message;
                return;
            }
        }

        // Store both the parsed info and the full verification result.
        context.Items[AAuthVerificationMiddleware.ContextItemKey] = parsedInfo;
        context.Items[ContextItemKey] = new FullVerificationResult
        {
            Scheme = parsedInfo.Scheme,
            TokenType = (string?)parsedInfo.Header?["typ"],
            Issuer = (string?)parsedInfo.Payload?["iss"],
            Agent = (string?)parsedInfo.Payload?["agent"],
            Subject = (string?)parsedInfo.Payload?["sub"],
            Scope = (string?)parsedInfo.Payload?["scope"],
            IssuerVerified = _options.RequireIssuerVerification &&
                parsedInfo.Scheme is "jwt" or "jkt-jwt",
        };

        // Store typed verification result in HttpContext.Features for
        // AAuthAuthenticationHandler and authorization policies.
        var tokenType = (string?)parsedInfo.Header?["typ"];
        var level = DetermineLevel(parsedInfo.Scheme, tokenType);
        var scopeString = (string?)parsedInfo.Payload?["scope"];
        var scopes = ParseScopes(scopeString);
        var actSub = parsedInfo.Payload?["act"]?["sub"]?.GetValue<string>();

        context.Features.Set(new AAuthVerificationResult
        {
            Level = level,
            Scheme = parsedInfo.Scheme,
            TokenType = tokenType,
            Issuer = (string?)parsedInfo.Payload?["iss"],
            Agent = tokenType == AuthTokenBuilder.TokenType
                ? (string?)parsedInfo.Payload?["agent"]
                : (string?)parsedInfo.Payload?["sub"],
            Subject = (string?)parsedInfo.Payload?["sub"],
            Scopes = scopes,
            ActorSubject = actSub,
            Jkt = parsedInfo.ConfirmationKey?.ComputeJwkThumbprint()
                ?? parsedInfo.Jkt,
            IssuerVerified = _options.RequireIssuerVerification &&
                parsedInfo.Scheme is "jwt" or "jkt-jwt",
        });

        await _next(context).ConfigureAwait(false);
    }

    private async Task VerifyAgentTokenIssuerAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info,
        CancellationToken ct)
    {
        var payload = info.Payload!;
        var header = info.Header!;

        var iss = (string?)payload["iss"]
            ?? throw new TokenVerificationException("Agent token is missing 'iss'.");
        if (!AAuthUrl.IsHttpsOrLoopback(iss))
            throw new TokenVerificationException("Agent token 'iss' must be an absolute https:// URL (or http://localhost).");

        // Check issuer allow-list.
        if (_options.TrustedAgentProviderIssuers is { } trusted && !trusted.Contains(iss))
            throw new TokenVerificationException($"Agent token issuer '{iss}' is not in the trusted issuers list.");

        var kid = (string?)header["kid"]
            ?? throw new TokenVerificationException("Agent token header is missing 'kid'.");

        // Self-issued agent tokens: iss == agent server URL, key is cnf.jwk (self-signed).
        // AP-issued: iss == AP URL, verify against AP's JWKS.
        var cnf = payload["cnf"] as JsonObject;
        var cnfJwk = cnf?["jwk"] as JsonObject;

        // Check if self-issued: verify signature with the embedded cnf.jwk.
        // A self-issued agent token can be verified by checking if the kid
        // matches the cnf.jwk thumbprint.
        if (cnfJwk is not null && info.ConfirmationKey is not null)
        {
            var thumbprint = info.ConfirmationKey.ComputeJwkThumbprint();
            if (kid == thumbprint)
            {
                // Self-issued: verify signature with cnf.jwk (already done as HTTP sig
                // verified with the same key). Structural check is sufficient.
                var verifier = new TokenVerifier();
                verifier.Verify(
                    info.Jwt!,
                    (AAuthKey)info.ConfirmationKey,
                    AgentTokenBuilder.TokenType,
                    AgentTokenBuilder.AgentDwk);
                return;
            }
        }

        // AP-issued: resolve AP JWKS and verify JWT signature.
        var metadataUrl = MetadataClient.BuildUrl(iss, AgentTokenBuilder.AgentDwk);
        JsonObject metadataDoc;
        try
        {
            metadataDoc = await _metadata.FetchAsync(metadataUrl, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new TokenVerificationException($"Failed to fetch AP metadata from {metadataUrl}.", ex);
        }

        var jwksUriRaw = (string?)metadataDoc["jwks_uri"]
            ?? throw new TokenVerificationException($"AP metadata at {metadataUrl} is missing 'jwks_uri'.");
        if (!Uri.TryCreate(jwksUriRaw, UriKind.Absolute, out var jwksUri))
            throw new TokenVerificationException($"AP metadata 'jwks_uri' is not an absolute URL: {jwksUriRaw}");
        if (!AAuthUrl.IsHttpsOrLoopback(jwksUriRaw))
            throw new TokenVerificationException(
                $"AP metadata 'jwks_uri' must be https (or http://localhost): {jwksUriRaw}");

        var issuerKey = await _jwks.ResolveKeyAsync(jwksUri, kid, ct).ConfigureAwait(false)
            ?? throw new TokenVerificationException($"No key with kid '{kid}' at {jwksUri}.");

        var tokenVerifier = new TokenVerifier();
        tokenVerifier.Verify(info.Jwt!, issuerKey, AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk);
    }

    private async Task VerifyAuthTokenIssuerAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info,
        IAAuthKey httpSignatureKey,
        CancellationToken ct)
    {
        var payload = info.Payload!;
        var header = info.Header!;

        var iss = (string?)payload["iss"]
            ?? throw new TokenVerificationException("Auth token is missing 'iss'.");
        if (!AAuthUrl.IsHttpsOrLoopback(iss))
            throw new TokenVerificationException("Auth token 'iss' must be an absolute https:// URL (or http://localhost).");

        // Check issuer allow-list.
        if (_options.TrustedAuthTokenIssuers is { } trusted && !trusted.Contains(iss))
            throw new TokenVerificationException($"Auth token issuer '{iss}' is not in the trusted issuers list.");

        var kid = (string?)header["kid"]
            ?? throw new TokenVerificationException("Auth token header is missing 'kid'.");

        // Resolve dwk for metadata URL.
        var dwk = (string?)payload["dwk"]
            ?? throw new TokenVerificationException("Auth token is missing 'dwk'.");
        if (dwk != AuthTokenBuilder.PersonDwk && dwk != AuthTokenBuilder.AccessDwk)
            throw new TokenVerificationException(
                $"Auth token 'dwk' must be '{AuthTokenBuilder.PersonDwk}' or '{AuthTokenBuilder.AccessDwk}', got '{dwk}'.");

        // Fetch issuer JWKS.
        var metadataUrl = MetadataClient.BuildUrl(iss, dwk);
        JsonObject metadataDoc;
        try
        {
            metadataDoc = await _metadata.FetchAsync(metadataUrl, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new TokenVerificationException($"Failed to fetch issuer metadata from {metadataUrl}.", ex);
        }

        var jwksUriRaw = (string?)metadataDoc["jwks_uri"]
            ?? throw new TokenVerificationException($"Issuer metadata at {metadataUrl} is missing 'jwks_uri'.");
        if (!Uri.TryCreate(jwksUriRaw, UriKind.Absolute, out var jwksUri))
            throw new TokenVerificationException($"Issuer metadata 'jwks_uri' is not an absolute URL: {jwksUriRaw}");
        if (!AAuthUrl.IsHttpsOrLoopback(jwksUriRaw))
            throw new TokenVerificationException(
                $"Issuer metadata 'jwks_uri' must be https (or http://localhost): {jwksUriRaw}");

        var issuerKey = await _jwks.ResolveKeyAsync(jwksUri, kid, ct).ConfigureAwait(false)
            ?? throw new TokenVerificationException($"No key with kid '{kid}' at {jwksUri}.");

        // Full auth token verification: signature + aud + PoP + act.
        var expectedAudience = _options.ResourceIdentifier;
        var expectedAgent = (string?)payload["agent"]
            ?? throw new TokenVerificationException("Auth token is missing 'agent'.");

        var tokenVerifier = new TokenVerifier();
        tokenVerifier.VerifyAuthToken(
            info.Jwt!,
            issuerKey,
            expectedAudience ?? (string?)payload["aud"] ?? "",
            (AAuthKey)httpSignatureKey,
            expectedAgent,
            expectedDwk: dwk);
    }

    private static SignatureErrorCode ClassifyVerificationError(AAuthVerificationException ex)
    {
        var msg = ex.Message;
        if (msg.Contains("covered components", StringComparison.OrdinalIgnoreCase))
            return SignatureErrorCode.InvalidInput;
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
            return false;
        if (values.Count != 1 || values[0] is null)
            return false;
        value = values[0]!;
        return true;
    }

    private static AAuthLevel DetermineLevel(string scheme, string? tokenType)
    {
        if (scheme == "hwk")
            return AAuthLevel.Pseudonymous;
        if (tokenType == AuthTokenBuilder.TokenType)
            return AAuthLevel.Authorized;
        return AAuthLevel.Identified;
    }

    private static HashSet<string> ParseScopes(string? scopeString)
    {
        if (string.IsNullOrWhiteSpace(scopeString))
            return new HashSet<string>();
        return new HashSet<string>(
            scopeString.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            StringComparer.Ordinal);
    }
}

/// <summary>
/// Result of full verification (HTTP sig + JWT issuer verification).
/// Stored in <see cref="HttpContext.Items"/> under
/// <see cref="AAuthFullVerificationMiddleware.ContextItemKey"/>.
/// </summary>
public sealed class FullVerificationResult
{
    /// <summary>The Signature-Key scheme (jwt, hwk, jwks_uri, jkt-jwt).</summary>
    public required string Scheme { get; init; }

    /// <summary>Token type from JWT <c>typ</c> header (aa-agent+jwt, aa-auth+jwt), or null for non-JWT schemes.</summary>
    public string? TokenType { get; init; }

    /// <summary>Issuer (<c>iss</c>) from the JWT, or null for non-JWT schemes.</summary>
    public string? Issuer { get; init; }

    /// <summary>Agent identifier from the JWT, or null.</summary>
    public string? Agent { get; init; }

    /// <summary>Subject (<c>sub</c>) from the JWT, or null.</summary>
    public string? Subject { get; init; }

    /// <summary>Scope (<c>scope</c>) from the JWT, or null.</summary>
    public string? Scope { get; init; }

    /// <summary>Whether the JWT issuer's signature was verified against JWKS.</summary>
    public bool IssuerVerified { get; init; }
}
