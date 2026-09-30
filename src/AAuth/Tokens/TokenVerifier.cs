using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Identifiers;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Tokens;

/// <summary>
/// Verifies AAuth JWTs (<c>aa-agent+jwt</c>, <c>aa-resource+jwt</c>,
/// <c>aa-auth+jwt</c>): structural checks, signature verification, and the
/// standard temporal / audience / binding claims.
/// </summary>
public sealed class TokenVerifier
{
    public AAuthEgressPolicy EgressPolicy { get; init; } = AAuthEgressPolicy.Production;
    /// <summary>Time source for temporal checks.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>
    /// How far a JWT <c>iat</c> may be ahead of this verifier's clock before it is
    /// refused with <c>clock_skew</c>. <c>exp</c> has no tolerance (§Common
    /// Verification). Default: the 60-second signature validity window.
    /// </summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Optional resolver for the verifier's own issuer keys, by (<c>iss</c>, <c>kid</c>).
    /// A server verifying person or auth tokens it issued itself (a PS checking a
    /// presented person token) resolves them here instead of fetching its own JWKS.
    /// Returns <see langword="null"/> for any other issuer.
    /// </summary>
    public Func<string, string, IAAuthKey?>? LocalIssuerKeys { get; init; }

    /// <summary>Copy this verifier's policy, clock and skew, resolving <paramref name="issuer"/>'s keys locally.</summary>
    public TokenVerifier WithLocalIssuer(string issuer, AAuthSigningKeySet keys)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentNullException.ThrowIfNull(keys);
        return new TokenVerifier
        {
            EgressPolicy = EgressPolicy,
            TimeProvider = TimeProvider,
            ClockSkew = ClockSkew,
            LocalIssuerKeys = (iss, kid) => string.Equals(iss, issuer, StringComparison.Ordinal)
                && keys.TryGetSigner(kid, out var key) ? key : LocalIssuerKeys?.Invoke(iss, kid),
        };
    }

    /// <summary>Parsed claims from a verified token.</summary>
    public sealed record VerifiedToken(
        JsonObject Header,
        JsonObject Payload,
        string Issuer,
        string TokenType)
    {
        public DateTimeOffset ExpiresAt { get; } = ReadExpiration(Payload);

        private static DateTimeOffset ReadExpiration(JsonObject payload)
        {
            if (!TryGetUnixTime(payload, "exp", out var expiration))
                throw new TokenVerificationException("Token is missing a valid 'exp'.");
            try { return DateTimeOffset.FromUnixTimeSeconds(expiration); }
            catch (ArgumentOutOfRangeException ex) { throw new TokenVerificationException("Token 'exp' is out of range.", ex); }
        }

        /// <summary>The <c>mission_s256</c> claim when present, otherwise <see langword="null"/>.</summary>
        public AAuthEgressPolicy EgressPolicy { get; init; } = AAuthEgressPolicy.Production;
        public string? MissionS256 => MissionReference.Read(Payload);
        public string Jti => (string?)Payload["jti"] ?? throw new TokenVerificationException("Token is missing 'jti'.");
        public string? Subject => (string?)Payload["sub"];
        public string? Tenant => (string?)Payload["tenant"];
        public string? Account => AccountBinding.TryRead(Payload, out var account)
            ? account : throw new TokenVerificationException("Token account must be a non-empty string without control characters.");
    }

    /// <summary>
    /// Verify a token whose issuer's public key has already been resolved.
    /// </summary>
    public VerifiedToken Verify(
        string jwt,
        IAAuthKey issuerKey,
        string expectedType,
        string expectedDwk,
        string? expectedAudience = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        ArgumentNullException.ThrowIfNull(issuerKey);
        ArgumentException.ThrowIfNullOrEmpty(expectedType);
        ArgumentException.ThrowIfNullOrEmpty(expectedDwk);

        var segments = jwt.Split('.');
        var (header, payload) = ReadStructure(jwt, expectedType);

        var alg = (string?)header["alg"];
        if (alg != issuerKey.Algorithm)
        {
            throw new TokenVerificationException(
                $"Unsupported or missing 'alg' (expected '{issuerKey.Algorithm}', got '{alg}').");
        }

        var typ = (string?)header["typ"];
        if (typ != expectedType)
        {
            throw new TokenVerificationException(
                $"Unexpected 'typ' (expected '{expectedType}', got '{typ}').");
        }

        var dwk = (string?)payload["dwk"];
        if (dwk != expectedDwk)
        {
            throw new TokenVerificationException(
                $"Unexpected 'dwk' (expected '{expectedDwk}', got '{dwk}').");
        }

        byte[] signature;
        try
        {
            signature = Base64UrlEncoder.DecodeBytes(segments[2]);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            throw new TokenVerificationException("JWT signature is not valid base64url.", ex);
        }

        var signingInput = segments[0] + "." + segments[1];
        if (!issuerKey.Verify(Encoding.ASCII.GetBytes(signingInput), signature))
        {
            throw new TokenVerificationException("JWT signature verification failed.");
        }

        // Temporal claims (§Common Verification): exp has no tolerance; a future
        // iat beyond the window is clock_skew, not an invalid token.
        var now = TimeProvider.GetUtcNow();
        var nowUnix = now.ToUnixTimeSeconds();

        if (TryGetUnixTime(payload, "exp", out var exp))
        {
            if (exp <= nowUnix)
            {
                throw new TokenVerificationException(AAuth.Errors.SignatureErrorCode.ExpiredJwt, $"Token expired at {exp} (now={nowUnix}).");
            }
        }
        else
        {
            throw new TokenVerificationException("Token is missing 'exp'.");
        }

        if (TryGetUnixTime(payload, "iat", out var iat))
        {
            if (iat - (long)ClockSkew.TotalSeconds > nowUnix)
            {
                throw new TokenVerificationException(AAuth.Errors.SignatureErrorCode.ClockSkew, $"Token 'iat'={iat} is ahead of the verifier clock (now={nowUnix}).");
            }
        }

        // Audience binding (when the caller cares).
        if (expectedAudience is not null)
        {
            var aud = (string?)payload["aud"];
            if (aud != expectedAudience)
            {
                throw new TokenVerificationException(
                    $"Token 'aud' does not match expected audience (expected '{expectedAudience}', got '{aud}').");
            }
        }

        var iss = (string?)payload["iss"]
            ?? throw new TokenVerificationException("Token is missing 'iss'.");
        if (!AAuthUrl.IsHttpsOrLoopback(iss, EgressPolicy))
        {
            throw new TokenVerificationException("Token 'iss' must be an absolute https:// URL (or http://localhost).");
        }

        if (typ is AgentTokenBuilder.TokenType or PersonTokenBuilder.TokenType or AuthTokenBuilder.TokenType)
        {
            try { SignatureKeyParser.Confirmation(payload); }
            catch (AAuthVerificationException exception)
            { throw new TokenVerificationException(exception.Code, exception.Message, exception); }
        }
        return new VerifiedToken(header, payload, iss, typ) { EgressPolicy = EgressPolicy };
    }

    /// <summary>
    /// Verify an auth token with PoP binding per §Auth Token Verification. The
    /// person is identified by <c>(iss, sub)</c>; the token names no agent.
    /// </summary>
    /// <param name="jwt">Compact JWT (<c>aa-auth+jwt</c>).</param>
    /// <param name="issuerKey">Issuer's public signing key (PS or AS).</param>
    /// <param name="expectedAudience">Expected <c>aud</c> (resource's own identifier).</param>
    /// <param name="httpSignatureKey">The key that signed the HTTP request; must match <c>cnf.jwk</c>.</param>
    /// <param name="expectedDwk">
    /// Expected <c>dwk</c>. If null, accepts <c>aauth-person.json</c> or <c>aauth-access.json</c>.
    /// </param>
    /// <param name="expectedMaxScope">When set, the token's scope must be a subset of it.</param>
    public VerifiedToken VerifyAuthToken(
        string jwt,
        IAAuthKey issuerKey,
        string expectedAudience,
        IAAuthKey httpSignatureKey,
        string? expectedDwk = null,
        string? expectedMaxScope = null,
        AccountExpectation? accountExpectation = null)
    {
        ArgumentNullException.ThrowIfNull(httpSignatureKey);
        return VerifyAuthToken(jwt, issuerKey, expectedAudience, httpSignatureKey.ComputeJwkThumbprint(),
            expectedDwk, expectedMaxScope, accountExpectation);
    }

    internal VerifiedToken VerifyAuthToken(
        string jwt,
        IAAuthKey issuerKey,
        string expectedAudience,
        string confirmationThumbprint,
        string? expectedDwk,
        string? expectedMaxScope,
        AccountExpectation? accountExpectation)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        ArgumentNullException.ThrowIfNull(issuerKey);
        ArgumentException.ThrowIfNullOrEmpty(expectedAudience);
        ArgumentException.ThrowIfNullOrEmpty(confirmationThumbprint);

        var (_, peekPayload) = ReadStructure(jwt, AuthTokenBuilder.TokenType);
        var actualDwk = expectedDwk ?? (string?)peekPayload["dwk"];
        if (actualDwk is not (AuthTokenBuilder.PersonDwk or AuthTokenBuilder.AccessDwk))
            throw new TokenVerificationException(
                $"Auth token 'dwk' must be '{AuthTokenBuilder.PersonDwk}' or '{AuthTokenBuilder.AccessDwk}', got '{actualDwk}'.");

        var verified = Verify(jwt, issuerKey, AuthTokenBuilder.TokenType, actualDwk, expectedAudience);
        if (accountExpectation is not null && !AccountBinding.Matches(accountExpectation.Account, verified.Account))
            throw new TokenVerificationException("Auth token account does not match the resource's expected account.");
        RequireConfirmation(verified.Payload, confirmationThumbprint, "Auth token");

        var scope = (string?)verified.Payload["scope"];
        if (expectedMaxScope is not null && !string.IsNullOrEmpty(scope))
        {
            var allowedScopes = new HashSet<string>(expectedMaxScope.Split(' ', StringSplitOptions.RemoveEmptyEntries));
            foreach (var s in scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (!allowedScopes.Contains(s))
                {
                    throw new TokenVerificationException(
                        $"Auth token scope '{s}' exceeds allowed scope (scope narrowing violation).");
                }
            }
        }

        return verified;
    }

    /// <summary>
    /// Verify a person token per §Person Token Verification: <c>typ</c>
    /// <c>aa-person+jwt</c>, <c>dwk</c> <c>aauth-person.json</c>, <c>aud</c> is the
    /// recipient, and <c>cnf.jwk</c> matches the key that signed the request.
    /// </summary>
    public VerifiedToken VerifyPersonToken(string jwt, IAAuthKey issuerKey, string expectedAudience, IAAuthKey httpSignatureKey)
    {
        ArgumentNullException.ThrowIfNull(httpSignatureKey);
        return VerifyPersonToken(jwt, issuerKey, expectedAudience, httpSignatureKey.ComputeJwkThumbprint());
    }

    internal VerifiedToken VerifyPersonToken(string jwt, IAAuthKey issuerKey, string expectedAudience, string? confirmationThumbprint)
    {
        ArgumentException.ThrowIfNullOrEmpty(expectedAudience);
        var verified = Verify(jwt, issuerKey, PersonTokenBuilder.TokenType, PersonTokenBuilder.PersonDwk, expectedAudience);
        if (confirmationThumbprint is not null)
            RequireConfirmation(verified.Payload, confirmationThumbprint, "Person token");
        return verified;
    }

    /// <summary>Verify a person token, resolving the PS key from <c>{iss}/.well-known/aauth-person.json</c>.</summary>
    public Task<VerifiedToken> VerifyPersonTokenWithJwksAsync(
        string jwt,
        MetadataClient metadata,
        JwksClient jwks,
        string expectedAudience,
        IAAuthKey httpSignatureKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpSignatureKey);
        var thumbprint = httpSignatureKey.ComputeJwkThumbprint();
        return VerifyWithIssuerKeyAsync(jwt, PersonTokenBuilder.TokenType, metadata, jwks,
            key => VerifyPersonToken(jwt, key, expectedAudience, thumbprint), cancellationToken);
    }

    /// <summary>
    /// Verify an auth token using JWKS discovery (dual-dwk supported).
    /// Resolves the issuer's JWKS from the token's <c>dwk</c> and verifies PoP binding.
    /// </summary>
    public Task<VerifiedToken> VerifyAuthTokenWithJwksAsync(
        string jwt,
        MetadataClient metadata,
        JwksClient jwks,
        string expectedAudience,
        IAAuthKey httpSignatureKey,
        string? expectedMaxScope = null,
        CancellationToken cancellationToken = default,
        AccountExpectation? accountExpectation = null)
    {
        ArgumentNullException.ThrowIfNull(httpSignatureKey);
        var thumbprint = httpSignatureKey.ComputeJwkThumbprint();
        return VerifyWithIssuerKeyAsync(jwt, AuthTokenBuilder.TokenType, metadata, jwks,
            key => VerifyAuthToken(jwt, key, expectedAudience, thumbprint, null, expectedMaxScope, accountExpectation),
            cancellationToken);
    }

    /// <summary>
    /// Verify the <c>presented_token</c> of a token request against its verified
    /// resource token (§Resource Token Verification step 3): by <c>typ</c>, as a
    /// person token or auth token whose <c>aud</c> is the resource token's
    /// <c>iss</c> and whose <c>cnf.jwk</c> matches <c>agent_jkt</c>; then its
    /// <c>jti</c>, issuing PS, <c>sub</c>, <c>mission_s256</c> and <c>tenant</c> must
    /// match. A failure of the token itself carries <see cref="TokenCredential.Presented"/>;
    /// a pair mismatch carries <see cref="TokenCredential.Resource"/>.
    /// </summary>
    public async Task<VerifiedToken> VerifyPresentedTokenAsync(
        string presentedToken,
        VerifiedToken resourceToken,
        MetadataClient metadata,
        JwksClient jwks,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resourceToken);
        if (string.IsNullOrWhiteSpace(presentedToken))
            throw new TokenVerificationException("presented_token is required.") { Credential = TokenCredential.Presented };
        var resourceIssuer = resourceToken.Issuer;
        var agentJkt = (string?)resourceToken.Payload["agent_jkt"]
            ?? throw new TokenVerificationException("Resource token is missing 'agent_jkt'.") { Credential = TokenCredential.Resource };
        string? typ;
        try { typ = (string?)DecodeJsonSegment(presentedToken.Split('.')[0], "header")["typ"]; }
        catch (Exception exception) when (exception is TokenVerificationException or IndexOutOfRangeException)
        { throw new TokenVerificationException("presented_token is not a compact JWS.") { Credential = TokenCredential.Presented }; }

        VerifiedToken presented;
        try
        {
            presented = typ switch
            {
                PersonTokenBuilder.TokenType => await VerifyWithIssuerKeyAsync(presentedToken, typ, metadata, jwks,
                    key => VerifyPersonToken(presentedToken, key, resourceIssuer, agentJkt), cancellationToken).ConfigureAwait(false),
                AuthTokenBuilder.TokenType => await VerifyWithIssuerKeyAsync(presentedToken, typ, metadata, jwks,
                    key => VerifyAuthToken(presentedToken, key, resourceIssuer, agentJkt, null, null, null), cancellationToken).ConfigureAwait(false),
                _ => throw new TokenVerificationException("presented_token must be a person token or an auth token."),
            };
        }
        catch (TokenVerificationException exception)
        { throw new TokenVerificationException(exception.Message, exception) { Credential = TokenCredential.Presented }; }

        var presentedPersonServer = typ == PersonTokenBuilder.TokenType ? presented.Issuer : (string?)presented.Payload["ps"];
        if (presented.Jti != (string?)resourceToken.Payload["presented_jti"]
            || presentedPersonServer != (string?)resourceToken.Payload["ps"]
            || presented.Subject != resourceToken.Subject
            || presented.MissionS256 != resourceToken.MissionS256
            || presented.Tenant != resourceToken.Tenant)
            throw new TokenVerificationException("Resource token does not match its presented token.") { Credential = TokenCredential.Resource };
        return presented;
    }

    private static void RequireConfirmation(JsonObject payload, string expectedThumbprint, string label)
    {
        var jwk = (payload["cnf"] as JsonObject)?["jwk"] as JsonObject;
        if (jwk is null || !IsStructurallyCompleteJwk(jwk))
            throw new TokenVerificationException(
                $"{label} 'cnf.jwk' is absent or structurally incomplete (missing 'kty' or the members required for its key type).");
        var tokenKey = KeyFactory.TryFromJwk(jwk)
            ?? throw new TokenVerificationException($"{label} 'cnf.jwk' is not parseable as a supported public key (invalid key material).");
        if (tokenKey.ComputeJwkThumbprint() != expectedThumbprint)
            throw new TokenVerificationException($"{label} 'cnf.jwk' does not match the signing key (PoP binding mismatch).");
    }

    // Resolve the issuer key named by the token's iss/dwk/kid, verify, and retry
    // once after a forced JWKS refresh only if the key material rotated.
    private async Task<VerifiedToken> VerifyWithIssuerKeyAsync(string jwt, string tokenType,
        MetadataClient metadata, JwksClient jwks, Func<IAAuthKey, VerifiedToken> verify, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(jwks);
        var (header, payload) = ReadStructure(jwt, tokenType);
        var alg = (string?)header["alg"];
        if (alg is null || (alg != AAuthKey.Ed25519Algorithm && alg != EcdsaAAuthKey.Alg))
            throw new TokenVerificationException($"Unsupported 'alg' '{alg}'. Supported: {AAuthKey.Ed25519Algorithm}, {EcdsaAAuthKey.Alg}.");
        if ((string?)header["typ"] != tokenType)
            throw new TokenVerificationException($"Unexpected 'typ' (expected '{tokenType}', got '{(string?)header["typ"]}').");
        var dwk = (string?)payload["dwk"] ?? throw new TokenVerificationException("Token is missing 'dwk'.");
        if (tokenType == PersonTokenBuilder.TokenType ? dwk != PersonTokenBuilder.PersonDwk
            : dwk is not (AuthTokenBuilder.PersonDwk or AuthTokenBuilder.AccessDwk))
            throw new TokenVerificationException($"Unexpected 'dwk' '{dwk}' for {tokenType}.");
        var iss = (string?)payload["iss"] ?? throw new TokenVerificationException("Token is missing 'iss'.");
        if (!metadata.Policy.IsValidIdentifier(iss))
            throw new TokenVerificationException("Token 'iss' must be an absolute https:// URL (or http://localhost).");
        var kid = (string?)header["kid"] ?? throw new TokenVerificationException("Token header is missing 'kid'.");

        // A PS or AS verifying a person or auth token it issued uses its own key.
        if (LocalIssuerKeys?.Invoke(iss, kid) is { } localKey)
            return verify(localKey);

        var metadataUrl = metadata.GetUrl(iss, dwk);
        JsonObject metadataDoc;
        try { metadataDoc = await metadata.FetchAsync(metadataUrl, cancellationToken).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        { throw new TokenVerificationException($"Failed to fetch issuer metadata from {metadataUrl}.", ex); }
        var jwksUriRaw = (string?)metadataDoc["jwks_uri"]
            ?? throw new TokenVerificationException($"Issuer metadata at {metadataUrl} is missing 'jwks_uri'.");
        if (!Uri.TryCreate(jwksUriRaw, UriKind.Absolute, out var jwksUri))
            throw new TokenVerificationException($"Issuer metadata 'jwks_uri' is not an absolute URL: {jwksUriRaw}");
        metadata.Policy.ValidateJwksUrl(jwksUriRaw, iss);

        var issuerKey = await jwks.ResolveKeyAsync(jwksUri, kid, iss, cancellationToken).ConfigureAwait(false)
            ?? throw new TokenVerificationException(AAuth.Errors.SignatureErrorCode.UnknownKey, $"No key with kid '{kid}' at {jwksUri}.");
        try { return verify(issuerKey); }
        catch (TokenVerificationException)
        {
            var refreshed = await jwks.ForceRefreshKeyAsync(jwksUri, kid, iss, cancellationToken).ConfigureAwait(false);
            if (refreshed is null)
                throw new TokenVerificationException(AAuth.Errors.SignatureErrorCode.UnknownKey, $"No key with kid '{kid}' after JWKS refresh.");
            if (refreshed.ComputeJwkThumbprint() == issuerKey.ComputeJwkThumbprint()) throw;
            return verify(refreshed);
        }
    }

    /// <summary>
    /// Verify a self-issued agent token where the issuer's public key equals
    /// the <c>cnf.jwk</c> bound in the token's payload.
    /// </summary>
    public VerifiedToken VerifySelfIssuedAgentToken(string jwt, IAAuthKey confirmationKey) =>
        Verify(
            jwt,
            confirmationKey,
            AgentTokenBuilder.TokenType,
            AgentTokenBuilder.AgentDwk);

    /// <summary>
    /// Resolve the issuer's signing key via well-known metadata + JWKS, then
    /// verify the token.
    /// </summary>
    public async Task<VerifiedToken> VerifyWithJwksAsync(
        string jwt,
        MetadataClient metadata,
        JwksClient jwks,
        string expectedType,
        string expectedDwk,
        string? expectedAudience,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(jwks);

        var (header, payload) = ReadStructure(jwt, expectedType);
        var alg = (string?)header["alg"];
        if (alg is null)
        {
            throw new TokenVerificationException("Token header is missing 'alg'.");
        }
        // Validate supported algorithms.
        if (alg != AAuthKey.Ed25519Algorithm && alg != EcdsaAAuthKey.Alg)
        {
            throw new TokenVerificationException(
                $"Unsupported 'alg' '{alg}'. Supported: {AAuthKey.Ed25519Algorithm}, {EcdsaAAuthKey.Alg}.");
        }
        var typ = (string?)header["typ"];
        if (typ != expectedType)
        {
            throw new TokenVerificationException(
                $"Unexpected 'typ' (expected '{expectedType}', got '{typ}').");
        }
        var dwk = (string?)payload["dwk"];
        if (dwk != expectedDwk)
        {
            throw new TokenVerificationException(
                $"Unexpected 'dwk' (expected '{expectedDwk}', got '{dwk}').");
        }

        var iss = (string?)payload["iss"]
            ?? throw new TokenVerificationException("Token is missing 'iss'.");
        if (!metadata.Policy.IsValidIdentifier(iss))
        {
            throw new TokenVerificationException("Token 'iss' must be an absolute https:// URL (or http://localhost).");
        }
        var kid = (string?)header["kid"]
            ?? throw new TokenVerificationException("Token header is missing 'kid'.");

        var metadataUrl = metadata.GetUrl(iss, expectedDwk);
        JsonObject metadataDoc;
        try
        {
            metadataDoc = await metadata.FetchAsync(metadataUrl, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new TokenVerificationException($"Failed to fetch issuer metadata from {metadataUrl}.", ex);
        }

        var jwksUriRaw = (string?)metadataDoc["jwks_uri"]
            ?? throw new TokenVerificationException($"Issuer metadata at {metadataUrl} is missing 'jwks_uri'.");
        if (!Uri.TryCreate(jwksUriRaw, UriKind.Absolute, out var jwksUri))
        {
            throw new TokenVerificationException($"Issuer metadata 'jwks_uri' is not an absolute URL: {jwksUriRaw}");
        }
        metadata.Policy.ValidateJwksUrl(jwksUriRaw, iss);

        var issuerKey = await jwks.ResolveKeyAsync(jwksUri, kid, iss, cancellationToken).ConfigureAwait(false)
            ?? throw new TokenVerificationException($"No key with kid '{kid}' at {jwksUri}.");

        try
        {
            return Verify(jwt, issuerKey, expectedType, expectedDwk, expectedAudience);
        }
        catch (TokenVerificationException)
        {
            // Silent re-keying ([@!I-D.hardt-httpbis-signature-key]): the issuer may
            // have rotated key material under an unchanged kid, leaving a stale
            // cached key. Force one rate-limited JWKS refresh and retry only if the
            // key material actually changed; otherwise re-throw the original failure.
            var refreshed = await jwks.ForceRefreshKeyAsync(jwksUri, kid, iss, cancellationToken).ConfigureAwait(false);
            if (refreshed is null)
                throw new TokenVerificationException(AAuth.Errors.SignatureErrorCode.UnknownKey, $"No key with kid '{kid}' after JWKS refresh.");
            if (refreshed.ComputeJwkThumbprint() == issuerKey.ComputeJwkThumbprint())
            {
                throw;
            }
            return Verify(jwt, refreshed, expectedType, expectedDwk, expectedAudience);
        }
    }

    /// <summary>
    /// Verify a resource token (<c>aa-resource+jwt</c>) per §Resource Token
    /// Verification. Resolves the issuing resource's JWKS from
    /// <c>{iss}/.well-known/aauth-resource.json</c>, checks <c>typ</c>, <c>dwk</c>,
    /// signature, <c>exp</c> and <c>aud</c>, then <c>agent_jkt</c> and, when given,
    /// <c>ps</c>. Pair it with <see cref="VerifyPresentedTokenAsync"/> on a PS or AS.
    /// </summary>
    /// <param name="jwt">The compact resource token.</param>
    /// <param name="expectedAudience">The recipient's own identifier (PS or AS).</param>
    /// <param name="expectedAgentJkt">
    /// JWK thumbprint of the signing agent's key; <c>agent_jkt</c> must equal it.
    /// </param>
    /// <param name="metadata">Metadata client for issuer discovery.</param>
    /// <param name="jwks">JWKS client for key resolution.</param>
    /// <param name="subagentAgentJkt">
    /// For parent-mediated sub-agent authorization, the sub-agent's key thumbprint;
    /// <c>agent_jkt</c> is checked against it instead, because the parent signs.
    /// </param>
    /// <param name="expectedPersonServer">When set, <c>ps</c> must equal it.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<VerifiedToken> VerifyResourceTokenAsync(
        string jwt,
        string expectedAudience,
        string expectedAgentJkt,
        MetadataClient metadata,
        JwksClient jwks,
        string? subagentAgentJkt = null,
        string? expectedPersonServer = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        ArgumentException.ThrowIfNullOrEmpty(expectedAudience);
        ArgumentException.ThrowIfNullOrEmpty(expectedAgentJkt);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(jwks);

        var verified = await VerifyWithJwksAsync(
            jwt,
            metadata,
            jwks,
            ResourceTokenBuilder.TokenType,
            ResourceTokenBuilder.ResourceDwk,
            expectedAudience,
            cancellationToken).ConfigureAwait(false);

        var expectedJkt = subagentAgentJkt ?? expectedAgentJkt;
        if ((string?)verified.Payload["agent_jkt"] != expectedJkt)
        {
            throw new TokenVerificationException(
                subagentAgentJkt is null
                    ? "Resource token 'agent_jkt' does not match the agent's HTTP signature key (PoP binding mismatch)."
                    : "Resource token 'agent_jkt' does not match the sub-agent's key (sub-agent PoP binding mismatch).");
        }
        if (expectedPersonServer is not null && (string?)verified.Payload["ps"] != expectedPersonServer)
        {
            throw new TokenVerificationException(
                $"Resource token 'ps' does not name the expected Person Server (expected '{expectedPersonServer}').");
        }
        _ = verified.MissionS256;

        return verified;
    }

    // §Agent Response to Clarification: an updated_request keeps the original's
    // iss, ps, sub, agent_jkt, mission_s256 and tenant; presented_jti MAY differ.
    internal static void RequireSameResourceRequest(JsonObject original, JsonObject replacement)
    {
        foreach (var claim in new[] { "iss", "ps", "sub", "agent_jkt", "mission_s256", "tenant" })
        {
            if (!JsonNode.DeepEquals(original[claim], replacement[claim]))
                throw new TokenVerificationException($"Replacement resource token changes '{claim}'.")
                { Credential = TokenCredential.Resource };
        }
    }

    // §Request-Context Binding step 7: a cnf.jwk is structurally complete when it
    // has a `kty` and the members required for that key type. Unknown key types are
    // deferred to key decoding (which classifies them as invalid key material).
    internal static bool IsStructurallyCompleteJwk(JsonObject jwk)
    {
        var kty = SignatureKeyParser.Text(jwk, "kty");
        if (string.IsNullOrEmpty(kty))
        {
            return false;
        }
        return kty switch
        {
            "OKP" => jwk["crv"] is not null && jwk["x"] is not null,
            "EC" => jwk["crv"] is not null && jwk["x"] is not null && jwk["y"] is not null,
            "RSA" => jwk["n"] is not null && jwk["e"] is not null,
            _ => true,
        };
    }

    internal static void ValidateStructure(JsonObject header, JsonObject payload, string? tokenType, AAuthEgressPolicy policy)
    {
        foreach (var name in new[] { "alg", "typ", "kid" }) RequireText(header, name);
        RequireText(payload, "iss");
        RequireText(payload, "dwk");
        var builtin = tokenType is AgentTokenBuilder.TokenType or ResourceTokenBuilder.TokenType
            or AuthTokenBuilder.TokenType or PersonTokenBuilder.TokenType;
        foreach (var name in new[] { "exp", "iat" })
        {
            if (name == "iat" && !builtin && !payload.ContainsKey(name)) continue;
            if (!TryGetUnixTime(payload, name, out var seconds)
                || seconds < DateTimeOffset.MinValue.ToUnixTimeSeconds()
                || seconds > DateTimeOffset.MaxValue.ToUnixTimeSeconds())
                throw new TokenVerificationException($"JWT requires a valid integer '{name}' timestamp.");
        }
        if (builtin || payload.ContainsKey("jti")) RequireText(payload, "jti");
        if (!builtin) return;
        if (tokenType is AuthTokenBuilder.TokenType or PersonTokenBuilder.TokenType
            && payload["exp"]!.GetValue<long>() - payload["iat"]!.GetValue<long>() > 3600)
            throw new TokenVerificationException("Person and auth token lifetime must not exceed one hour.");
        if (!policy.IsValidIdentifier(SignatureKeyParser.Text(payload, "iss")))
            throw new TokenVerificationException("JWT 'iss' must be a valid server identifier.");
        if (!AccountBinding.TryRead(payload, out _))
            throw new TokenVerificationException("Token account must be a non-empty string without control characters.");
        foreach (var name in new[] { "aud", "sub", "agent_jkt", "scope", "parent_agent", "ps", "presented_jti", "tenant", "login_hint" })
            if (payload.ContainsKey(name)) RequireText(payload, name, allowEmpty: name == "scope" && tokenType == ResourceTokenBuilder.TokenType);
        foreach (var name in new[] { "cnf", "interaction" })
            if (payload.ContainsKey(name) && payload[name] is not JsonObject)
                throw new TokenVerificationException($"JWT claim '{name}' must be an object.");
        _ = MissionReference.Read(payload);
        if (tokenType == AgentTokenBuilder.TokenType)
        {
            var subject = RequireText(payload, "sub");
            var subjectId = ValidateAgent(subject, "sub", policy);
            var issuer = RequireText(payload, "iss");
            if (!policy.IsDevelopmentIdentifier(issuer) && "https://" + AgentId.Parse(subject, policy).Domain != issuer)
                throw new TokenVerificationException("JWT 'sub' domain must match its agent provider.");
            if (payload.ContainsKey("ps") && !policy.IsValidIdentifier(RequireText(payload, "ps")))
                throw new TokenVerificationException("JWT 'ps' must be a valid server identifier.");
            if (payload.ContainsKey("parent_agent"))
            {
                var parent = ValidateAgent(RequireText(payload, "parent_agent"), "parent_agent", policy);
                if (parent.IsSubAgent || !subjectId.IsSubAgent || subjectId.ParentAgent != parent.Value)
                    throw new TokenVerificationException("JWT 'parent_agent' must name the top-level parent derived from the sub-agent 'sub'.");
            }
            else if (subjectId.IsSubAgent)
                throw new TokenVerificationException("JWT sub-agent 'sub' requires a matching 'parent_agent'.");
        }
        else
        {
            if (!policy.IsValidIdentifier(RequireText(payload, "aud")))
                throw new TokenVerificationException("JWT 'aud' must be a valid server identifier.");
            RequireText(payload, "sub");
        }
        if (tokenType is ResourceTokenBuilder.TokenType or AuthTokenBuilder.TokenType
            && !policy.IsValidIdentifier(RequireText(payload, "ps")))
            throw new TokenVerificationException("JWT 'ps' must be a valid server identifier.");
        if (tokenType == PersonTokenBuilder.TokenType && (payload.ContainsKey("scope") || payload.ContainsKey("account")))
            throw new TokenVerificationException("Person token MUST NOT carry 'scope' or 'account'.");
        if (tokenType == ResourceTokenBuilder.TokenType)
        {
            RequireText(payload, "agent_jkt");
            RequireText(payload, "presented_jti");
            if (!payload.ContainsKey("scope"))
            {
                var uri = RequireText(payload, "r3_uri");
                var hash = RequireText(payload, "r3_s256");
                try
                {
                    policy.ValidateUrl(uri);
                    var bytes = Base64UrlEncoder.DecodeBytes(hash);
                    if (bytes.Length != 32 || Base64UrlEncoder.Encode(bytes) != hash)
                        throw new TokenVerificationException("Resource token R3 hash must be an unpadded SHA-256 digest.");
                }
                catch (Exception exception) when (exception is System.Net.Http.HttpRequestException or FormatException or ArgumentException)
                { throw new TokenVerificationException("Resource token requires scope or a valid R3 reference.", exception); }
            }
            if (payload["interaction"] is JsonObject interaction)
            {
                RequireText(interaction, "url");
                RequireText(interaction, "code");
            }
        }
        else if (payload["cnf"] is not JsonObject confirmation || confirmation["jwk"] is not JsonObject)
            throw new TokenVerificationException("JWT requires 'cnf.jwk'.");
    }

    private static string RequireText(JsonObject document, string name, bool allowEmpty = false)
    {
        var text = SignatureKeyParser.Text(document, name);
        if (text is null || !allowEmpty && string.IsNullOrWhiteSpace(text))
            throw new TokenVerificationException($"JWT '{name}' must be {(allowEmpty ? "a string" : "a non-empty string")}.");
        return text;
    }

    private static AgentId ValidateAgent(string value, string claim, AAuthEgressPolicy policy)
    {
        if (!AgentId.TryParse(value, out var id, out _, policy))
            throw new TokenVerificationException($"JWT '{claim}' must be a valid agent identifier.");
        return id;
    }

    private static bool TryGetUnixTime(JsonObject payload, string claim, out long value)
    {
        value = 0;
        if (payload[claim] is JsonValue v && v.TryGetValue<long>(out var l))
        {
            value = l;
            return true;
        }
        return false;
    }

    internal (JsonObject Header, JsonObject Payload) ReadStructure(string jwt, string tokenType)
    {
        var segments = jwt.Split('.');
        if (segments.Length != 3)
            throw new TokenVerificationException("JWT is not a compact JWS.");
        var header = DecodeJsonSegment(segments[0], "header");
        var payload = DecodeJsonSegment(segments[1], "payload");
        ValidateStructure(header, payload, tokenType, EgressPolicy);
        var signature = DecodeSegment(segments[2], "signature");
        if ((string?)header["alg"] is AAuthKey.Ed25519Algorithm or EcdsaAAuthKey.Alg && signature.Length != 64)
            throw new TokenVerificationException("JWT signature must contain 64 bytes for Ed25519 or ES256.");
        return (header, payload);
    }

    private static byte[] DecodeSegment(string segment, string label)
    {
        try
        {
            var bytes = Base64UrlEncoder.DecodeBytes(segment);
            if (bytes.Length == 0 || Base64UrlEncoder.Encode(bytes) != segment)
                throw new FormatException();
            return bytes;
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            throw new TokenVerificationException($"JWT {label} is not valid base64url.", ex);
        }
    }

    internal static JsonObject DecodeJsonSegment(string segment, string label)
    {
        var bytes = DecodeSegment(segment, label);
        try
        {
            return SignatureKeyParser.ParseJsonObject(bytes);
        }
        catch (JsonException ex)
        {
            throw new TokenVerificationException($"JWT {label} is not valid JSON.", ex);
        }
    }
}

public enum TokenCredential { Agent, Resource, Subagent, Upstream, Presented }

/// <summary>Thrown when AAuth JWT verification fails for any reason.</summary>
public sealed class TokenVerificationException : Exception
{
    public TokenCredential? Credential { get; init; }
    public AAuth.Errors.SignatureErrorCode Code { get; }
    public TokenVerificationException(AAuth.Errors.SignatureErrorCode code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    /// <summary>Create an exception with a message.</summary>
    public TokenVerificationException(string message) : this(AAuth.Errors.SignatureErrorCode.InvalidJwt, message) { }

    /// <summary>Create an exception with a message and inner exception.</summary>
    public TokenVerificationException(string message, Exception inner) : this(inner switch
    {
        TokenVerificationException token => token.Code,
        AAuthVerificationException signature => signature.Code,
        JwkValidationException key => key.Code,
        AAuth.Errors.AAuthMetadataException metadata => metadata.Code,
        _ => AAuth.Errors.SignatureErrorCode.InvalidJwt,
    }, message, inner) { }
}
