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
    /// <summary>Clock injection point.</summary>
    public Func<DateTimeOffset> Clock { get; init; } = () => DateTimeOffset.UtcNow;

    /// <summary>Tolerance applied to <c>exp</c>/<c>iat</c> checks.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Maximum depth of nested <c>act</c> claims allowed.</summary>
    public int MaxActDepth { get; init; } = 10;

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

        /// <summary>
        /// The <c>mission</c> claim ({approver, s256}) when present, otherwise
        /// <see langword="null"/> (§Resource Token, §Auth Token).
        /// </summary>
        public AAuthEgressPolicy EgressPolicy { get; init; } = AAuthEgressPolicy.Production;
        public MissionClaim? Mission => MissionClaim.FromPayload(Payload, EgressPolicy);
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

        // Temporal claims.
        var now = Clock();
        var nowUnix = now.ToUnixTimeSeconds();
        var skew = (long)ClockSkew.TotalSeconds;

        if (TryGetUnixTime(payload, "exp", out var exp))
        {
            if (exp + skew < nowUnix)
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
            if (iat - skew > nowUnix)
            {
                throw new TokenVerificationException($"Token 'iat'={iat} is in the future (now={nowUnix}).");
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

        if (typ == AgentTokenBuilder.TokenType)
        {
            try { SignatureKeyParser.Confirmation(payload); }
            catch (AAuthVerificationException exception)
            { throw new TokenVerificationException(exception.Code, exception.Message, exception); }
        }
        return new VerifiedToken(header, payload, iss, typ) { EgressPolicy = EgressPolicy };
    }

    /// <summary>
    /// Verify an auth token with full PoP binding enforcement per §Auth Token Verification.
    /// </summary>
    /// <param name="jwt">Compact JWT (<c>aa-auth+jwt</c>).</param>
    /// <param name="issuerKey">Issuer's public signing key (PS or AS).</param>
    /// <param name="expectedAudience">Expected <c>aud</c> (resource's own identifier).</param>
    /// <param name="httpSignatureKey">The public key used to sign the HTTP request (from <c>cnf.jwk</c> of the carrier token).</param>
    /// <param name="expectedAgentId">Expected agent identifier (from the request's signing context).</param>
    /// <param name="expectedDwk">
    /// Expected <c>dwk</c> value. If null, accepts either <c>aauth-person.json</c> or
    /// <c>aauth-access.json</c> (dual-dwk mode for resource verifiers that don't know which issued the token).
    /// </param>
    /// <param name="expectedMaxScope">
    /// If non-null, verifies that the auth token's scope is a subset of this value
    /// (scope narrowing: auth-token scope ⊆ resource-token scope).
    /// </param>
    public VerifiedToken VerifyAuthToken(
        string jwt,
        IAAuthKey issuerKey,
        string expectedAudience,
        IAAuthKey httpSignatureKey,
        string expectedAgentId,
        string? expectedDwk = null,
        string? expectedMaxScope = null,
        AccountExpectation? accountExpectation = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        ArgumentNullException.ThrowIfNull(issuerKey);
        ArgumentException.ThrowIfNullOrEmpty(expectedAudience);
        ArgumentNullException.ThrowIfNull(httpSignatureKey);
        ArgumentException.ThrowIfNullOrEmpty(expectedAgentId);

        // Determine which dwk to expect.
        string actualDwk;
        if (expectedDwk is not null)
        {
            actualDwk = expectedDwk;
        }
        else
        {
            // Peek at the dwk claim to decide.
            var segments = jwt.Split('.');
            if (segments.Length != 3)
                throw new TokenVerificationException("JWT is not a compact JWS.");
            var peekPayload = DecodeJsonSegment(segments[1], "payload");
            ValidateStructure(DecodeJsonSegment(segments[0], "header"), peekPayload, AuthTokenBuilder.TokenType, EgressPolicy, MaxActDepth);
            actualDwk = (string?)peekPayload["dwk"]
                ?? throw new TokenVerificationException("Token is missing 'dwk'.");
            if (actualDwk != AuthTokenBuilder.PersonDwk && actualDwk != AuthTokenBuilder.AccessDwk)
            {
                throw new TokenVerificationException(
                    $"Auth token 'dwk' must be '{AuthTokenBuilder.PersonDwk}' or '{AuthTokenBuilder.AccessDwk}', got '{actualDwk}'.");
            }
        }

        var verified = Verify(jwt, issuerKey, AuthTokenBuilder.TokenType, actualDwk, expectedAudience);
        if (accountExpectation is not null && !AccountBinding.Matches(accountExpectation.Account, verified.Account))
            throw new TokenVerificationException("Auth token account does not match the resource's expected account.");

        // §Auth Token Verification step 6: agent matches signing context.
        var agent = (string?)verified.Payload["agent"];
        if (agent != expectedAgentId)
        {
            throw new TokenVerificationException(
                $"Auth token 'agent' does not match expected agent (expected '{expectedAgentId}', got '{agent}').");
        }

        // §Request-Context Binding step 7: cnf.jwk is REQUIRED, with ordered failure
        // classification — structural completeness is checked BEFORE key decoding.
        var cnf = verified.Payload["cnf"] as JsonObject;
        var jwk = cnf?["jwk"] as JsonObject;
        if (jwk is null || !IsStructurallyCompleteJwk(jwk))
        {
            throw new TokenVerificationException(
                "Auth token 'cnf.jwk' is absent or structurally incomplete (missing 'kty' or the members required for its key type).");
        }
        // Parseable as a supported public key? If not, it is invalid key material.
        var tokenKey = KeyFactory.TryFromJwk(jwk)
            ?? throw new TokenVerificationException("Auth token 'cnf.jwk' is not parseable as a supported public key (invalid key material).");
        // PoP binding — algorithm-agnostic JWK thumbprint comparison.
        var tokenKeyThumbprint = tokenKey.ComputeJwkThumbprint();
        var httpKeyThumbprint = httpSignatureKey.ComputeJwkThumbprint();
        if (tokenKeyThumbprint != httpKeyThumbprint)
        {
            throw new TokenVerificationException(
                "Auth token 'cnf.jwk' does not match the HTTP signature key (PoP binding mismatch).");
        }

        // §Request-Context Binding step 8: act is OPTIONAL (§Delegation Chain) —
        // absent for direct authorization. When present, act.agent identifies the
        // immediate upstream agent (the delegator), NOT the presenter (whose identity
        // is the top-level `agent` claim). Verify it is a valid agent identifier and
        // the chain is well-formed within the depth limit.
        var act = verified.Payload["act"] as JsonObject;
        if (verified.Payload.ContainsKey("act") && act is null)
            throw new TokenVerificationException("invalid_act_chain: 'act' must be an object.");
        if (act is not null)
        {
            var actAgent = (string?)act["agent"];
            if (string.IsNullOrEmpty(actAgent) || !AgentId.TryParse(actAgent, out _, out _, EgressPolicy))
            {
                throw new TokenVerificationException(
                    "Auth token 'act.agent' is missing or not a valid AAuth agent identifier.");
            }
            if (!ActChainBuilder.ValidateChain(act, MaxActDepth, EgressPolicy))
            {
                throw new TokenVerificationException(
                    "invalid_act_chain: auth token 'act' must contain only valid agent identities within the depth limit.");
            }
        }

        // §Auth Token Verification step 9: at least one of sub or scope.
        var sub = (string?)verified.Payload["sub"];
        var scope = (string?)verified.Payload["scope"];
        if (sub is null && string.IsNullOrEmpty(scope))
        {
            throw new TokenVerificationException("Auth token must contain at least one of 'sub' or 'scope'.");
        }

        // Scope narrowing check.
        if (expectedMaxScope is not null && !string.IsNullOrEmpty(scope))
        {
            var allowedScopes = new HashSet<string>(expectedMaxScope.Split(' ', StringSplitOptions.RemoveEmptyEntries));
            var tokenScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (var s in tokenScopes)
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
    /// Verify an auth token using JWKS discovery (dual-dwk supported).
    /// Resolves the issuer's JWKS from the token's <c>dwk</c> and verifies PoP binding.
    /// </summary>
    public async Task<VerifiedToken> VerifyAuthTokenWithJwksAsync(
        string jwt,
        MetadataClient metadata,
        JwksClient jwks,
        string expectedAudience,
        IAAuthKey httpSignatureKey,
        string expectedAgentId,
        string? expectedMaxScope = null,
        CancellationToken cancellationToken = default,
        AccountExpectation? accountExpectation = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(jwks);

        var (header, payload) = ReadStructure(jwt, AuthTokenBuilder.TokenType);
        var alg = (string?)header["alg"];
        if (alg is null || (alg != AAuthKey.Ed25519Algorithm && alg != EcdsaAAuthKey.Alg))
            throw new TokenVerificationException($"Unsupported 'alg' '{alg}'. Supported: {AAuthKey.Ed25519Algorithm}, {EcdsaAAuthKey.Alg}.");
        var typ = (string?)header["typ"];
        if (typ != AuthTokenBuilder.TokenType)
            throw new TokenVerificationException($"Unexpected 'typ' (expected '{AuthTokenBuilder.TokenType}', got '{typ}').");
        var dwk = (string?)payload["dwk"];
        if (dwk != AuthTokenBuilder.PersonDwk && dwk != AuthTokenBuilder.AccessDwk)
            throw new TokenVerificationException(
                $"Auth token 'dwk' must be '{AuthTokenBuilder.PersonDwk}' or '{AuthTokenBuilder.AccessDwk}', got '{dwk}'.");

        var iss = (string?)payload["iss"]
            ?? throw new TokenVerificationException("Token is missing 'iss'.");
        if (!metadata.Policy.IsValidIdentifier(iss))
            throw new TokenVerificationException("Token 'iss' must be an absolute https:// URL (or http://localhost).");

        var kid = (string?)header["kid"]
            ?? throw new TokenVerificationException("Token header is missing 'kid'.");

        var metadataUrl = metadata.GetUrl(iss, dwk);
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
            throw new TokenVerificationException($"Issuer metadata 'jwks_uri' is not an absolute URL: {jwksUriRaw}");
        metadata.Policy.ValidateJwksUrl(jwksUriRaw, iss);

        var issuerKey = await jwks.ResolveKeyAsync(jwksUri, kid, iss, cancellationToken).ConfigureAwait(false)
            ?? throw new TokenVerificationException($"No key with kid '{kid}' at {jwksUri}.");

        try
        {
            return VerifyAuthToken(jwt, issuerKey, expectedAudience, httpSignatureKey, expectedAgentId,
                expectedDwk: dwk, expectedMaxScope: expectedMaxScope, accountExpectation: accountExpectation);
        }
        catch (TokenVerificationException)
        {
            // Silent re-keying ([@!I-D.hardt-httpbis-signature-key]): force one
            // rate-limited JWKS refresh and retry only if the key material rotated
            // under the same kid; otherwise re-throw the original failure.
            var refreshed = await jwks.ForceRefreshKeyAsync(jwksUri, kid, iss, cancellationToken).ConfigureAwait(false);
            if (refreshed is null)
                throw new TokenVerificationException(AAuth.Errors.SignatureErrorCode.UnknownKey, $"No key with kid '{kid}' after JWKS refresh.");
            if (refreshed.ComputeJwkThumbprint() == issuerKey.ComputeJwkThumbprint())
            {
                throw;
            }
            return VerifyAuthToken(jwt, refreshed, expectedAudience, httpSignatureKey, expectedAgentId,
                expectedDwk: dwk, expectedMaxScope: expectedMaxScope, accountExpectation: accountExpectation);
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
    /// Verify a resource token (<c>aa-resource+jwt</c>) presented by an agent,
    /// per §"Resource Token Verification". Resolves the issuing resource's JWKS
    /// from <c>{iss}/.well-known/aauth-resource.json</c> and enforces the recipient
    /// checks: <c>typ</c>, <c>dwk</c>, signature, <c>exp</c>/<c>iat</c>, <c>aud</c>
    /// (steps 1–4 via <see cref="VerifyWithJwksAsync"/>), then <c>agent</c>,
    /// <c>agent_jkt</c>, and the optional <c>mission.approver</c> (steps 5–7).
    /// </summary>
    /// <param name="jwt">The compact resource token.</param>
    /// <param name="expectedAudience">
    /// The recipient's own identifier — the resource token's <c>aud</c> must match
    /// (e.g. the Person Server's issuer).
    /// </param>
    /// <param name="expectedAgentId">
    /// The agent identifier from the verified HTTP-signature context — must equal
    /// the token's <c>agent</c>.
    /// </param>
    /// <param name="expectedAgentJkt">
    /// The JWK thumbprint of the agent's signing key from the verified HTTP
    /// signature — must equal the token's <c>agent_jkt</c>.
    /// </param>
    /// <param name="metadata">Metadata client for issuer discovery.</param>
    /// <param name="jwks">JWKS client for key resolution.</param>
    /// <param name="expectedApprover">
    /// When a mission is present, a verifying recipient must supply the PS
    /// identifier for the <c>mission.approver</c> check (step 7): the PS's own
    /// identifier for PS-local issuance, or the authenticated sending PS at an AS.
    /// Pass <c>null</c> only when no mission is present, or when the caller is
    /// performing challenge verification as an agent rather than recipient verification.
    /// </param>
    /// <param name="subagentAgentJkt">
    /// For a parent-mediated sub-agent authorization (§Sub-Agents): the JWK
    /// thumbprint of the <b>sub-agent's</b> key (from the <c>subagent_token</c>'s
    /// <c>cnf.jwk</c>). When set, step 6 verifies <c>agent_jkt</c> against this value
    /// instead of <paramref name="expectedAgentJkt"/>, because the <b>parent</b> —
    /// not the sub-agent — signs the HTTP request. When <see langword="null"/>
    /// (the common case), step 6 checks <paramref name="expectedAgentJkt"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<VerifiedToken> VerifyResourceTokenAsync(
        string jwt,
        string expectedAudience,
        string expectedAgentId,
        string expectedAgentJkt,
        MetadataClient metadata,
        JwksClient jwks,
        string? expectedApprover = null,
        string? subagentAgentJkt = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        ArgumentException.ThrowIfNullOrEmpty(expectedAudience);
        ArgumentException.ThrowIfNullOrEmpty(expectedAgentId);
        ArgumentException.ThrowIfNullOrEmpty(expectedAgentJkt);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(jwks);

        // Steps 1–4: typ + dwk + signature (via resource JWKS) + exp/iat + aud.
        var verified = await VerifyWithJwksAsync(
            jwt,
            metadata,
            jwks,
            ResourceTokenBuilder.TokenType,
            ResourceTokenBuilder.ResourceDwk,
            expectedAudience,
            cancellationToken).ConfigureAwait(false);

        // Step 5: agent matches the signing agent.
        var agent = (string?)verified.Payload["agent"];
        if (agent != expectedAgentId)
        {
            throw new TokenVerificationException(
                $"Resource token 'agent' does not match the signing agent (expected '{expectedAgentId}', got '{agent}').");
        }

        // Step 6: agent_jkt matches the agent's signing key thumbprint. For a
        // parent-mediated sub-agent authorization the parent signs the request, so
        // agent_jkt must match the sub-agent's key (from subagent_token.cnf.jwk),
        // not the signing (parent) key (§Resource Token Verification step 6).
        var expectedJkt = subagentAgentJkt ?? expectedAgentJkt;
        var agentJkt = (string?)verified.Payload["agent_jkt"];
        if (agentJkt != expectedJkt)
        {
            throw new TokenVerificationException(
                subagentAgentJkt is null
                    ? "Resource token 'agent_jkt' does not match the agent's HTTP signature key (PoP binding mismatch)."
                    : "Resource token 'agent_jkt' does not match the sub-agent's key (sub-agent PoP binding mismatch).");
        }

        // Step 7: optional mission.approver constraint.
        if (expectedApprover is not null && verified.Payload["mission"] is JsonObject mission)
        {
            var approver = (string?)mission["approver"];
            if (approver != expectedApprover)
            {
                throw new TokenVerificationException(
                    $"Resource token 'mission.approver' does not match expected approver (expected '{expectedApprover}', got '{approver}').");
            }
        }

        return verified;
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

    internal static void ValidateStructure(JsonObject header, JsonObject payload, string? tokenType, AAuthEgressPolicy policy, int maxActDepth = 10)
    {
        foreach (var name in new[] { "alg", "typ", "kid" }) RequireText(header, name);
        RequireText(payload, "iss");
        RequireText(payload, "dwk");
        var builtin = tokenType is AgentTokenBuilder.TokenType or ResourceTokenBuilder.TokenType or AuthTokenBuilder.TokenType;
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
        if (tokenType == AuthTokenBuilder.TokenType
            && payload["exp"]!.GetValue<long>() - payload["iat"]!.GetValue<long>() > 3600)
            throw new TokenVerificationException("Auth token lifetime must not exceed one hour.");
        if (!policy.IsValidIdentifier(SignatureKeyParser.Text(payload, "iss")))
            throw new TokenVerificationException("JWT 'iss' must be a valid server identifier.");
        if (!AccountBinding.TryRead(payload, out _))
            throw new TokenVerificationException("Token account must be a non-empty string without control characters.");
        foreach (var name in new[] { "aud", "sub", "agent", "agent_jkt", "scope", "parent_agent", "ps" })
            if (payload.ContainsKey(name)) RequireText(payload, name, allowEmpty: name == "scope" && tokenType == ResourceTokenBuilder.TokenType);
        foreach (var name in new[] { "act", "cnf", "mission", "interaction" })
            if (payload.ContainsKey(name) && payload[name] is not JsonObject)
                throw new TokenVerificationException($"JWT claim '{name}' must be an object.");
        if (payload["act"] is JsonObject act && !ActChainBuilder.ValidateChain(act, maxActDepth, policy))
            throw new TokenVerificationException("invalid_act_chain: JWT requires a valid delegation chain.");
        if (payload["mission"] is JsonObject mission)
        {
            RequireText(mission, "approver");
            RequireText(mission, "s256");
            if (MissionClaim.FromPayload(payload, policy) is null)
                throw new TokenVerificationException("JWT requires a valid mission reference.");
        }
        if (tokenType == AgentTokenBuilder.TokenType)
        {
            var subject = RequireText(payload, "sub");
            ValidateAgent(subject, "sub", policy);
            var issuer = RequireText(payload, "iss");
            if (!policy.IsDevelopmentIdentifier(issuer) && "https://" + AgentId.Parse(subject, policy).Domain != issuer)
                throw new TokenVerificationException("JWT 'sub' domain must match its agent provider.");
            if (payload.ContainsKey("ps") && !policy.IsValidIdentifier(RequireText(payload, "ps")))
                throw new TokenVerificationException("JWT 'ps' must be a valid server identifier.");
            if (payload.ContainsKey("parent_agent")) ValidateAgent(RequireText(payload, "parent_agent"), "parent_agent", policy);
        }
        else
        {
            if (!policy.IsValidIdentifier(RequireText(payload, "aud")))
                throw new TokenVerificationException("JWT 'aud' must be a valid server identifier.");
            ValidateAgent(RequireText(payload, "agent"), "agent", policy);
        }
        if (tokenType == ResourceTokenBuilder.TokenType)
        {
            RequireText(payload, "agent_jkt");
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
        if (tokenType == AuthTokenBuilder.TokenType && !payload.ContainsKey("sub") && !payload.ContainsKey("scope"))
            throw new TokenVerificationException("Auth token must contain at least one of 'sub' or 'scope'.");
    }

    private static string RequireText(JsonObject document, string name, bool allowEmpty = false)
    {
        var text = SignatureKeyParser.Text(document, name);
        if (text is null || !allowEmpty && string.IsNullOrWhiteSpace(text))
            throw new TokenVerificationException($"JWT '{name}' must be {(allowEmpty ? "a string" : "a non-empty string")}.");
        return text;
    }

    private static void ValidateAgent(string value, string claim, AAuthEgressPolicy policy)
    {
        if (!AgentId.TryParse(value, out _, out _, policy))
            throw new TokenVerificationException($"JWT '{claim}' must be a valid agent identifier.");
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
        ValidateStructure(header, payload, tokenType, EgressPolicy, MaxActDepth);
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

public enum TokenCredential { Agent, Resource, Subagent, Upstream }

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
