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
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Tokens;

/// <summary>
/// Verifies AAuth JWTs (<c>aa-agent+jwt</c>, <c>aa-resource+jwt</c>,
/// <c>aa-auth+jwt</c>): structural checks, signature verification, and the
/// standard temporal / audience / binding claims.
/// </summary>
public sealed class TokenVerifier
{
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
        /// <summary>
        /// The <c>mission</c> claim ({approver, s256}) when present, otherwise
        /// <see langword="null"/> (§Resource Token, §Auth Token).
        /// </summary>
        public MissionClaim? Mission => MissionClaim.FromPayload(Payload);
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
        if (segments.Length != 3)
        {
            throw new TokenVerificationException("JWT is not a compact JWS.");
        }

        var header = DecodeJsonSegment(segments[0], "header");
        var payload = DecodeJsonSegment(segments[1], "payload");

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
        catch (Exception ex)
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
                throw new TokenVerificationException($"Token expired at {exp} (now={nowUnix}).");
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
        if (!AAuthUrl.IsHttpsOrLoopback(iss))
        {
            throw new TokenVerificationException("Token 'iss' must be an absolute https:// URL (or http://localhost).");
        }

        return new VerifiedToken(header, payload, iss, typ);
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
        string? expectedMaxScope = null)
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
            actualDwk = (string?)peekPayload["dwk"]
                ?? throw new TokenVerificationException("Token is missing 'dwk'.");
            if (actualDwk != AuthTokenBuilder.PersonDwk && actualDwk != AuthTokenBuilder.AccessDwk)
            {
                throw new TokenVerificationException(
                    $"Auth token 'dwk' must be '{AuthTokenBuilder.PersonDwk}' or '{AuthTokenBuilder.AccessDwk}', got '{actualDwk}'.");
            }
        }

        var verified = Verify(jwt, issuerKey, AuthTokenBuilder.TokenType, actualDwk, expectedAudience);

        // §Auth Token Verification step 6: agent matches signing context.
        var agent = (string?)verified.Payload["agent"];
        if (agent != expectedAgentId)
        {
            throw new TokenVerificationException(
                $"Auth token 'agent' does not match expected agent (expected '{expectedAgentId}', got '{agent}').");
        }

        // §Auth Token Verification step 7: cnf.jwk matches HTTP signature key.
        var cnf = verified.Payload["cnf"] as JsonObject;
        var jwk = cnf?["jwk"] as JsonObject;
        if (jwk is null)
        {
            throw new TokenVerificationException("Auth token is missing 'cnf.jwk'.");
        }
        // Compare via JWK thumbprint — algorithm-agnostic PoP binding check.
        var tokenKey = KeyFactory.TryFromJwk(jwk)
            ?? throw new TokenVerificationException("Auth token 'cnf.jwk' is not a supported key type.");
        var tokenKeyThumbprint = tokenKey.ComputeJwkThumbprint();
        var httpKeyThumbprint = httpSignatureKey.ComputeJwkThumbprint();
        if (tokenKeyThumbprint != httpKeyThumbprint)
        {
            throw new TokenVerificationException(
                "Auth token 'cnf.jwk' does not match the HTTP signature key (PoP binding mismatch).");
        }

        // §Auth Token Verification step 8: act is present and act.sub matches agent.
        var act = verified.Payload["act"] as JsonObject;
        if (act is null)
        {
            throw new TokenVerificationException("Auth token is missing required 'act' claim.");
        }
        var actSub = (string?)act["sub"];
        if (actSub != expectedAgentId)
        {
            throw new TokenVerificationException(
                $"Auth token 'act.sub' does not match expected agent (expected '{expectedAgentId}', got '{actSub}').");
        }

        // Walk nested act claims to enforce depth limit.
        ValidateActDepth(act, 1);

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
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwt);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(jwks);

        var segments = jwt.Split('.');
        if (segments.Length != 3)
            throw new TokenVerificationException("JWT is not a compact JWS.");

        var header = DecodeJsonSegment(segments[0], "header");
        var payload = DecodeJsonSegment(segments[1], "payload");

        // Cheap local checks first.
        var alg = (string?)header["alg"];
        if (alg is null || (alg != AAuthKey.Algorithm && alg != EcdsaAAuthKey.Alg))
            throw new TokenVerificationException($"Unsupported 'alg' '{alg}'. Supported: {AAuthKey.Algorithm}, {EcdsaAAuthKey.Alg}.");
        var typ = (string?)header["typ"];
        if (typ != AuthTokenBuilder.TokenType)
            throw new TokenVerificationException($"Unexpected 'typ' (expected '{AuthTokenBuilder.TokenType}', got '{typ}').");
        var dwk = (string?)payload["dwk"];
        if (dwk != AuthTokenBuilder.PersonDwk && dwk != AuthTokenBuilder.AccessDwk)
            throw new TokenVerificationException(
                $"Auth token 'dwk' must be '{AuthTokenBuilder.PersonDwk}' or '{AuthTokenBuilder.AccessDwk}', got '{dwk}'.");

        var iss = (string?)payload["iss"]
            ?? throw new TokenVerificationException("Token is missing 'iss'.");
        if (!AAuthUrl.IsHttpsOrLoopback(iss))
            throw new TokenVerificationException("Token 'iss' must be an absolute https:// URL (or http://localhost).");

        var kid = (string?)header["kid"]
            ?? throw new TokenVerificationException("Token header is missing 'kid'.");

        var metadataUrl = MetadataClient.BuildUrl(iss, dwk);
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
        if (!AAuthUrl.IsHttpsOrLoopback(jwksUriRaw))
            throw new TokenVerificationException(
                $"Issuer metadata 'jwks_uri' must be an absolute https:// URL (or http://localhost): {jwksUriRaw}");

        var issuerKey = await jwks.ResolveKeyAsync(jwksUri, kid, cancellationToken).ConfigureAwait(false)
            ?? throw new TokenVerificationException($"No key with kid '{kid}' at {jwksUri}.");

        return VerifyAuthToken(jwt, issuerKey, expectedAudience, httpSignatureKey, expectedAgentId,
            expectedDwk: dwk, expectedMaxScope: expectedMaxScope);
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

        var segments = jwt.Split('.');
        if (segments.Length != 3)
        {
            throw new TokenVerificationException("JWT is not a compact JWS.");
        }

        var header = DecodeJsonSegment(segments[0], "header");
        var payload = DecodeJsonSegment(segments[1], "payload");

        var alg = (string?)header["alg"];
        if (alg is null)
        {
            throw new TokenVerificationException("Token header is missing 'alg'.");
        }
        // Validate supported algorithms.
        if (alg != AAuthKey.Algorithm && alg != EcdsaAAuthKey.Alg)
        {
            throw new TokenVerificationException(
                $"Unsupported 'alg' '{alg}'. Supported: {AAuthKey.Algorithm}, {EcdsaAAuthKey.Alg}.");
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
        if (!AAuthUrl.IsHttpsOrLoopback(iss))
        {
            throw new TokenVerificationException("Token 'iss' must be an absolute https:// URL (or http://localhost).");
        }
        var kid = (string?)header["kid"]
            ?? throw new TokenVerificationException("Token header is missing 'kid'.");

        var metadataUrl = MetadataClient.BuildUrl(iss, expectedDwk);
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
        if (!AAuthUrl.IsHttpsOrLoopback(jwksUriRaw))
        {
            throw new TokenVerificationException(
                $"Issuer metadata 'jwks_uri' must be an absolute https:// URL (or http://localhost): {jwksUriRaw}");
        }

        var issuerKey = await jwks.ResolveKeyAsync(jwksUri, kid, cancellationToken).ConfigureAwait(false)
            ?? throw new TokenVerificationException($"No key with kid '{kid}' at {jwksUri}.");

        return Verify(jwt, issuerKey, expectedType, expectedDwk, expectedAudience);
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
    /// When set, the token's <c>mission.approver</c> must match (step 7). Optional —
    /// resources/PSs without a mission constraint pass <c>null</c>.
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
        if (expectedApprover is not null)
        {
            var mission = verified.Payload["mission"] as JsonObject;
            var approver = (string?)mission?["approver"];
            if (approver != expectedApprover)
            {
                throw new TokenVerificationException(
                    $"Resource token 'mission.approver' does not match expected approver (expected '{expectedApprover}', got '{approver}').");
            }
        }

        return verified;
    }

    private void ValidateActDepth(JsonObject act, int depth)
    {
        if (depth > MaxActDepth)
        {
            throw new TokenVerificationException(
                $"Nested 'act' chain exceeds maximum depth of {MaxActDepth}.");
        }
        if (act["act"] is JsonObject nestedAct)
        {
            ValidateActDepth(nestedAct, depth + 1);
        }
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

    internal static JsonObject DecodeJsonSegment(string segment, string label)
    {
        byte[] bytes;
        try
        {
            bytes = Base64UrlEncoder.DecodeBytes(segment);
        }
        catch (Exception ex)
        {
            throw new TokenVerificationException($"JWT {label} is not valid base64url.", ex);
        }

        try
        {
            return JsonNode.Parse(bytes) as JsonObject
                ?? throw new TokenVerificationException($"JWT {label} is not a JSON object.");
        }
        catch (JsonException ex)
        {
            throw new TokenVerificationException($"JWT {label} is not valid JSON.", ex);
        }
    }
}

/// <summary>Thrown when AAuth JWT verification fails for any reason.</summary>
public sealed class TokenVerificationException : Exception
{
    /// <summary>Create an exception with a message.</summary>
    public TokenVerificationException(string message) : base(message) { }

    /// <summary>Create an exception with a message and inner exception.</summary>
    public TokenVerificationException(string message, Exception inner) : base(message, inner) { }
}
