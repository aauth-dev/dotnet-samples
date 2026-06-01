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
/// ASP.NET Core middleware that verifies AAuth HTTP signatures (RFC 9421 PoP)
/// and JWT issuer signatures in a single pass.
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
/// <item>Store <see cref="VerificationResult"/> in HttpContext.Items.</item>
/// </list>
/// </remarks>
public sealed class AAuthVerificationMiddleware
{
    /// <summary><see cref="HttpContext.Items"/> key for the <see cref="VerificationResult"/>.</summary>
    public const string ContextItemKey = "AAuth.VerificationResult";

    /// <summary><see cref="HttpContext.Items"/> key for the parsed <see cref="SignatureKeyParser.ParsedSignatureKeyInfo"/>.</summary>
    public const string ParsedInfoItemKey = "AAuth.ParsedSignatureKey";

    /// <summary>Internal key for JTI store stashed in HttpContext.Items.</summary>
    internal const string JtiStoreItemKey = "AAuth.JtiStore";

    /// <summary>Algorithms this server supports, emitted in unsupported_algorithm errors.</summary>
    private static readonly string[] SupportedAlgorithms = ["EdDSA", "ES256"];

    private readonly RequestDelegate _next;
    private readonly AAuthVerifier _verifier;
    private readonly ISignatureKeyResolver _resolver;
    private readonly MetadataClient? _metadata;
    private readonly JwksClient? _jwks;
    private readonly AAuthVerificationOptions _options;

    /// <summary>Create the middleware.</summary>
    public AAuthVerificationMiddleware(
        RequestDelegate next,
        AAuthVerifier verifier,
        ISignatureKeyResolver resolver,
        MetadataClient? metadata,
        JwksClient? jwks,
        AAuthVerificationOptions options)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(options);
        _next = next;
        _verifier = verifier;
        _resolver = resolver;
        _metadata = metadata;
        _jwks = jwks;
        _options = options;
        _tokenVerifier = CreateTokenVerifier(options);
    }

    private readonly TokenVerifier _tokenVerifier;

    private static TokenVerifier CreateTokenVerifier(AAuthVerificationOptions options)
    {
        return new TokenVerifier
        {
            MaxActDepth = options.MaxActDepth,
            ClockSkew = options.ClockSkew,
            Clock = options.Clock ?? (() => DateTimeOffset.UtcNow),
        };
    }

    /// <inheritdoc cref="RequestDelegate"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var req = context.Request;

        if (!TryGetSingle(req, AAuthConstants.Headers.Signature, out var signature) ||
            !TryGetSingle(req, AAuthConstants.Headers.SignatureInput, out var signatureInput) ||
            !TryGetSingle(req, AAuthConstants.Headers.SignatureKey, out var signatureKey))
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
            var errorCode = ClassifyVerificationError(ex);
            context.Response.Headers[SignatureError.HeaderName] = errorCode == SignatureErrorCode.UnsupportedAlgorithm
                ? SignatureError.Format(errorCode, supportedAlgorithms: SupportedAlgorithms)
                : SignatureError.Format(errorCode);
            return;
        }

        // Replay detection.
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

        // Naming JWT expiration check: for jkt-jwt scheme, reject expired naming JWTs
        // regardless of RequireIssuerVerification. The naming JWT has a short lifetime
        // (typically 5 min) to limit the window of delegation from the durable key.
        if (parsedInfo.Scheme == AAuthConstants.Schemes.JktJwt &&
            parsedInfo.Payload?["exp"] is JsonNode expClaim)
        {
            var now = (_options.Clock ?? (() => DateTimeOffset.UtcNow))();
            var expTime = DateTimeOffset.FromUnixTimeSeconds(expClaim.GetValue<long>());
            if (now > expTime + _options.ClockSkew)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers[SignatureError.HeaderName] =
                    SignatureError.Format(SignatureErrorCode.InvalidJwt);
                context.Response.Headers[AAuthConstants.Headers.AAuthError] = "Naming JWT has expired.";
                return;
            }
        }

        // Step 4-6: JWT issuer verification (for jwt and jkt-jwt schemes with carrier tokens).
        if (_options.RequireIssuerVerification &&
            parsedInfo.Scheme is AAuthConstants.Schemes.Jwt or AAuthConstants.Schemes.JktJwt &&
            parsedInfo.Jwt is not null &&
            parsedInfo.Header is not null &&
            parsedInfo.Payload is not null)
        {
            if (_metadata is null || _jwks is null)
                throw new InvalidOperationException(
                    "RequireIssuerVerification is enabled but MetadataClient/JwksClient are not registered. " +
                    "Register them in DI or set RequireIssuerVerification = false.");

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
                context.Response.Headers[AAuthConstants.Headers.AAuthError] = ex.Message;
                return;
            }
        }

        // Store both the parsed info and the verification result.
        context.Items[ParsedInfoItemKey] = parsedInfo;
        context.Items[ContextItemKey] = new VerificationResult
        {
            Scheme = parsedInfo.Scheme,
            TokenType = (string?)parsedInfo.Header?["typ"],
            Issuer = (string?)parsedInfo.Payload?["iss"],
            Agent = (string?)parsedInfo.Payload?["agent"],
            Subject = (string?)parsedInfo.Payload?["sub"],
            Scope = (string?)parsedInfo.Payload?["scope"],
            IssuerVerified = _options.RequireIssuerVerification &&
                parsedInfo.Scheme is AAuthConstants.Schemes.Jwt or AAuthConstants.Schemes.JktJwt,
        };

        // Store typed verification result in HttpContext.Features for
        // AAuthAuthenticationHandler and authorization policies.
        var tokenType = (string?)parsedInfo.Header?["typ"];
        var tokenTypeEnum = AAuthTokenTypeExtensions.ParseTokenType(tokenType);
        var level = DetermineLevel(parsedInfo.Scheme, tokenType);
        var scopeString = (string?)parsedInfo.Payload?["scope"];
        var scopes = ParseScopes(scopeString);
        var roles = ParseStringArray(parsedInfo.Payload?["roles"]);
        var groups = ParseStringArray(parsedInfo.Payload?["groups"]);
        var actSub = parsedInfo.Payload?["act"]?["sub"]?.GetValue<string>();

        context.Features.Set(new AAuthVerificationResult
        {
            Level = level,
            Scheme = parsedInfo.Scheme,
            TokenType = tokenTypeEnum,
            Issuer = (string?)parsedInfo.Payload?["iss"],
            Agent = tokenType == AuthTokenBuilder.TokenType
                ? (string?)parsedInfo.Payload?["agent"]
                : (string?)parsedInfo.Payload?["sub"],
            Subject = (string?)parsedInfo.Payload?["sub"],
            Scopes = scopes,
            Roles = roles,
            Groups = groups,
            ActorSubject = actSub,
            Jkt = parsedInfo.ConfirmationKey?.ComputeJwkThumbprint()
                ?? parsedInfo.Jkt,
            IssuerVerified = _options.RequireIssuerVerification &&
                parsedInfo.Scheme is AAuthConstants.Schemes.Jwt or AAuthConstants.Schemes.JktJwt,
        });

        // Set UpstreamAuthTokenFeature for aa-auth+jwt tokens so that
        // call-chaining middleware can read the verified upstream token
        // without re-parsing Signature-Key.
        if (tokenType == AuthTokenBuilder.TokenType &&
            parsedInfo.Jwt is not null &&
            _options.RequireIssuerVerification &&
            parsedInfo.Scheme is AAuthConstants.Schemes.Jwt or AAuthConstants.Schemes.JktJwt)
        {
            context.Features.Set(new UpstreamAuthTokenFeature(parsedInfo.Jwt));
        }

        // Enrich the current Activity with AAuth verification tags for
        // OpenTelemetry-compatible tracing (no hard OTel dependency).
        var activity = System.Diagnostics.Activity.Current;
        if (activity is not null)
        {
            activity.SetTag(AAuthDiagnostics.TagScheme, parsedInfo.Scheme);
            activity.SetTag(AAuthDiagnostics.TagLevel, level.ToString());
            activity.SetTag(AAuthDiagnostics.TagTokenType, tokenType);
            if (parsedInfo.Payload?["iss"] is not null)
                activity.SetTag(AAuthDiagnostics.TagIssuer, (string?)parsedInfo.Payload["iss"]);
            var agent = tokenType == AuthTokenBuilder.TokenType
                ? (string?)parsedInfo.Payload?["agent"]
                : (string?)parsedInfo.Payload?["sub"];
            if (agent is not null)
                activity.SetTag(AAuthDiagnostics.TagAgent, agent);
            if (scopeString is not null)
                activity.SetTag(AAuthDiagnostics.TagScope, scopeString);
            activity.SetTag(AAuthDiagnostics.TagIssuerVerified,
                _options.RequireIssuerVerification && parsedInfo.Scheme is AAuthConstants.Schemes.Jwt or AAuthConstants.Schemes.JktJwt);
        }

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
                _tokenVerifier.Verify(
                    info.Jwt!,
                    info.ConfirmationKey,
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
            metadataDoc = await _metadata!.FetchAsync(metadataUrl, ct).ConfigureAwait(false);
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

        var issuerKey = await _jwks!.ResolveKeyAsync(jwksUri, kid, ct).ConfigureAwait(false)
            ?? throw new TokenVerificationException($"No key with kid '{kid}' at {jwksUri}.");

        _tokenVerifier.Verify(info.Jwt!, issuerKey, AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk);
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

        // Fail-closed issuer namespacing: a PS-asserted auth token is trusted
        // only when its issuer is in the configured allow-list. An unset or
        // empty allow-list rejects ALL auth tokens — the resource MUST declare
        // which Person Servers it trusts before it will honor their claims.
        var trusted = _options.TrustedAuthTokenIssuers;
        if (trusted is null || trusted.Count == 0 || !trusted.Contains(iss))
            throw new TokenVerificationException(
                $"Auth token issuer '{iss}' is not in the trusted issuers list " +
                "(set AAuthVerificationOptions.TrustedAuthTokenIssuers to the Person Servers this resource trusts).");

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
            metadataDoc = await _metadata!.FetchAsync(metadataUrl, ct).ConfigureAwait(false);
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

        var issuerKey = await _jwks!.ResolveKeyAsync(jwksUri, kid, ct).ConfigureAwait(false)
            ?? throw new TokenVerificationException($"No key with kid '{kid}' at {jwksUri}.");

        // Full auth token verification: signature + aud + PoP + act.
        var expectedAudience = _options.ResourceIdentifier;
        var expectedAgent = (string?)payload["agent"]
            ?? throw new TokenVerificationException("Auth token is missing 'agent'.");

        if (expectedAudience is not null)
        {
            // Full verification: signature, aud binding, PoP, and act.
            _tokenVerifier.VerifyAuthToken(
                info.Jwt!,
                issuerKey,
                expectedAudience,
                httpSignatureKey,
                expectedAgent,
                expectedDwk: dwk);
        }
        else
        {
            // Signature is verified but aud is not validated because
            // ResourceIdentifier was not configured. PoP and act are
            // still checked via the underlying Verify + manual checks.
            var verified = _tokenVerifier.Verify(
                info.Jwt!, issuerKey,
                AuthTokenBuilder.TokenType, dwk, expectedAudience: null);

            // §Step 7: cnf.jwk matches HTTP signature key.
            var cnf = verified.Payload["cnf"] as JsonObject;
            var jwk = cnf?["jwk"] as JsonObject;
            if (jwk is null)
                throw new TokenVerificationException("Auth token is missing 'cnf.jwk'.");
            var tokenKey = KeyFactory.TryFromJwk(jwk)
                ?? throw new TokenVerificationException("Auth token 'cnf.jwk' is not a supported key type.");
            if (tokenKey.ComputeJwkThumbprint() != httpSignatureKey.ComputeJwkThumbprint())
                throw new TokenVerificationException("Auth token 'cnf.jwk' does not match the HTTP signature key.");

            // §Step 8: act.sub matches agent.
            var act = verified.Payload["act"] as JsonObject;
            if (act is null)
                throw new TokenVerificationException("Auth token is missing required 'act' claim.");
            if ((string?)act["sub"] != expectedAgent)
                throw new TokenVerificationException("Auth token 'act.sub' does not match expected agent.");
        }
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
        if (scheme == AAuthConstants.Schemes.Hwk)
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

    private static HashSet<string> ParseStringArray(System.Text.Json.Nodes.JsonNode? node)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        if (node is System.Text.Json.Nodes.JsonArray array)
        {
            foreach (var item in array)
            {
                if (item is not null && item.GetValueKind() == System.Text.Json.JsonValueKind.String)
                {
                    set.Add(item.GetValue<string>());
                }
            }
        }
        return set;
    }
}

/// <summary>
/// Result of AAuth verification (HTTP sig + JWT issuer verification).
/// Stored in <see cref="HttpContext.Items"/> under
/// <see cref="AAuthVerificationMiddleware.ContextItemKey"/>.
/// </summary>
public sealed class VerificationResult
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
