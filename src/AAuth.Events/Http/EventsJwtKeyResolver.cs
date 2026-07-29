using System;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events.Discovery;
using AAuth.Events.Tokens;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Events.Http;

/// <summary>JWT kind used by <see cref="EventsJwtKeyResolver"/>.</summary>
public enum EventsTokenKind
{
    Subscribe,
    Event,
}

/// <summary>Resolved and cryptographically verified Events token keys.</summary>
public sealed record EventsJwtKeyResolution(
    TokenVerifier.VerifiedToken VerifiedToken,
    IAAuthKey JwtIssuerKey,
    IAAuthKey HttpSignatureKey,
    string KeyId,
    Uri JwksUri);

/// <summary>Resolves Events JWT keys through policy-checked metadata and JWKS.</summary>
public sealed class EventsJwtKeyResolver
{
    private readonly MetadataClient _metadata;
    private readonly JwksClient _jwks;
    private readonly IEventsUrlPolicy _policy;
    private readonly TokenVerifier _tokenVerifier;

    /// <summary>Creates a resolver over Events-owned discovery clients.</summary>
    public EventsJwtKeyResolver(
        MetadataClient metadata,
        JwksClient jwks,
        IEventsUrlPolicy policy,
        TokenVerifier? tokenVerifier = null)
    {
        _metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        _jwks = jwks ?? throw new ArgumentNullException(nameof(jwks));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _tokenVerifier = tokenVerifier ?? new TokenVerifier();
    }

    /// <summary>Creates discovery clients over the hardened Events transport.</summary>
    public EventsJwtKeyResolver(
        HttpClient http,
        IEventsUrlPolicy? policy = null,
        TokenVerifier? tokenVerifier = null)
    {
        ArgumentNullException.ThrowIfNull(http);
        _policy = policy ?? new DefaultEventsUrlPolicy();
        _metadata = new MetadataClient(http, clock: (tokenVerifier ?? new TokenVerifier()).Clock);
        _jwks = new JwksClient(http, clock: (tokenVerifier ?? new TokenVerifier()).Clock);
        _tokenVerifier = tokenVerifier ?? new TokenVerifier();
    }

    /// <summary>Resolves a subscribe token and returns its <c>cnf.jwk</c> HTTP key.</summary>
    public Task<EventsJwtKeyResolution> ResolveSubscribeAsync(
        string compactToken,
        string expectedAudience,
        CancellationToken cancellationToken = default) =>
        ResolveAsync(compactToken, EventsTokenKind.Subscribe, expectedAudience, cancellationToken);

    /// <summary>Resolves an event token; its resource JWT key is also its HTTP key.</summary>
    public Task<EventsJwtKeyResolution> ResolveEventAsync(
        string compactToken,
        string? expectedAudience = null,
        CancellationToken cancellationToken = default) =>
        ResolveAsync(compactToken, EventsTokenKind.Event, expectedAudience, cancellationToken);

    /// <summary>Extracts and resolves the compact JWT carried by Signature-Key.</summary>
    public async Task<EventsJwtKeyResolution> ResolveRequestAsync(
        HttpRequestMessage request,
        EventsTokenKind kind,
        string? expectedAudience = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.Headers.TryGetValues(SignatureKeyHeader.Name, out var values))
            throw Failure(EventsVerificationErrorCode.MissingCoveredComponent, "Signature-Key is missing.");
        using var enumerator = values.GetEnumerator();
        if (!enumerator.MoveNext())
            throw Failure(EventsVerificationErrorCode.MalformedRequest, "Signature-Key must occur exactly once.");
        var current = enumerator.Current;
        if (enumerator.MoveNext())
            throw Failure(EventsVerificationErrorCode.MalformedRequest, "Signature-Key must occur exactly once.");
        string token;
        try { token = SignatureKeyHeader.GetJwt(current!) ?? string.Empty; }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            throw Failure(EventsVerificationErrorCode.InvalidToken, "Signature-Key is malformed.", ex);
        }
        if (token.Length == 0)
            throw Failure(EventsVerificationErrorCode.InvalidToken, "Signature-Key does not carry a jwt token.");
        return await ResolveAsync(token, kind, expectedAudience, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Resolves a token of the specified Events kind.</summary>
    public async Task<EventsJwtKeyResolution> ResolveAsync(
        string compactToken,
        EventsTokenKind kind,
        string? expectedAudience = null,
        CancellationToken cancellationToken = default)
    {
        if (kind == EventsTokenKind.Subscribe && string.IsNullOrWhiteSpace(expectedAudience))
            throw new ArgumentException("An expected audience is required.", nameof(expectedAudience));
        if (string.IsNullOrWhiteSpace(compactToken))
            throw Failure(EventsVerificationErrorCode.InvalidToken, "The compact token is empty.");
        var (header, payload) = DecodeCheap(compactToken);
        var expectedType = kind == EventsTokenKind.Subscribe
            ? AAuthEventsConstants.SubscribeTokenType : AAuthEventsConstants.EventTokenType;
        var expectedDwk = kind == EventsTokenKind.Subscribe
            ? AAuthEventsConstants.AgentDwk : AAuthEventsConstants.ResourceDwk;
        var alg = StringClaim(header, AAuthEventsConstants.AlgorithmClaim, "JWT header is missing 'alg'.");
        if (alg is not ("EdDSA" or "ES256"))
            throw Failure(EventsVerificationErrorCode.UnsupportedAlgorithm, $"Unsupported JWT algorithm '{alg}'.");
        if (StringClaim(header, AAuthEventsConstants.TypeClaim, "JWT header is missing 'typ'.") != expectedType)
            throw Failure(EventsVerificationErrorCode.InvalidToken, "JWT type does not match the Events profile.");
        var dwk = StringClaim(payload, AAuthEventsConstants.DomainKeyClaim, "JWT is missing 'dwk'.");
        if (dwk != expectedDwk)
            throw Failure(EventsVerificationErrorCode.WrongResource, "JWT dwk does not match the Events profile.");
        if (kind == EventsTokenKind.Event &&
            payload.ContainsKey(AAuthEventsConstants.ConfirmationClaim))
            throw Failure(EventsVerificationErrorCode.InvalidToken, "Event JWTs must not contain cnf.");
        if (expectedAudience is not null)
        {
            var audience = StringClaim(
                payload,
                AAuthEventsConstants.AudienceClaim,
                "JWT is missing 'aud'.");
            if (!string.Equals(audience, expectedAudience, StringComparison.Ordinal))
                throw Failure(
                    EventsVerificationErrorCode.WrongAudience,
                    "JWT audience does not match the expected audience.");
        }
        var issuer = StringClaim(payload, AAuthEventsConstants.IssuerClaim, "JWT is missing 'iss'.");
        var kid = StringClaim(header, AAuthEventsConstants.KeyIdClaim, "JWT header is missing 'kid'.");
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri))
            throw Failure(EventsVerificationErrorCode.InvalidToken, "JWT issuer is not an absolute URL.");

        var metadataUri = MetadataClient.BuildUrl(issuer, dwk);
        await EnsureUrlAsync(metadataUri, cancellationToken).ConfigureAwait(false);
        JsonObject metadata;
        try { metadata = await _metadata.FetchAsync(metadataUri, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { throw Failure(EventsVerificationErrorCode.MetadataFailure, ex.Message, ex); }
        var jwksText = (string?)metadata["jwks_uri"];
        if (!Uri.TryCreate(jwksText, UriKind.Absolute, out var jwksUri))
            throw Failure(EventsVerificationErrorCode.MetadataFailure, "Events metadata has no absolute jwks_uri.");
        await EnsureUrlAsync(jwksUri, cancellationToken).ConfigureAwait(false);

        IAAuthKey? issuerKey;
        try
        {
            issuerKey = await _jwks.ResolveKeyAsync(jwksUri, kid, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { throw Failure(EventsVerificationErrorCode.MetadataFailure, ex.Message, ex); }
        if (issuerKey is null)
            throw Failure(EventsVerificationErrorCode.UnknownKey, $"No JWKS key exists for kid '{kid}'.");
        if (issuerKey.Algorithm != alg)
        {
            var rotated = await RefreshChangedKeyAsync(
                jwksUri, kid, issuerKey, cancellationToken).ConfigureAwait(false);
            if (rotated is null || rotated.Algorithm != alg)
                throw Failure(
                    EventsVerificationErrorCode.UnsupportedAlgorithm,
                    "JWT alg does not match the JWKS key.");
            issuerKey = rotated;
        }

        TokenVerifier.VerifiedToken verified;
        try
        {
            verified = _tokenVerifier.Verify(compactToken, issuerKey, expectedType, expectedDwk, expectedAudience);
        }
        catch (TokenVerificationException ex) when (IsSignatureFailure(ex))
        {
            // A key may have rotated under an unchanged kid. Retry once only
            // when the rate-limited refresh returns different key material.
            var refreshed = await RefreshChangedKeyAsync(
                jwksUri, kid, issuerKey, cancellationToken).ConfigureAwait(false);
            if (refreshed is null)
                throw MapTokenFailure(ex);
            if (refreshed.Algorithm != alg)
                throw Failure(
                    EventsVerificationErrorCode.UnsupportedAlgorithm,
                    "JWT alg does not match the refreshed JWKS key.");
            try
            {
                verified = _tokenVerifier.Verify(compactToken, refreshed, expectedType, expectedDwk, expectedAudience);
                issuerKey = refreshed;
            }
            catch (TokenVerificationException retry)
            {
                throw MapTokenFailure(retry);
            }
        }
        catch (TokenVerificationException ex)
        {
            throw MapTokenFailure(ex);
        }

        try
        {
            ReadClaims(verified, kind);
        }
        catch (TokenVerificationException ex)
        {
            throw MapTokenFailure(ex);
        }

        IAAuthKey httpKey = issuerKey;
        if (kind == EventsTokenKind.Subscribe)
        {
            var cnf = verified.Payload[AAuthEventsConstants.ConfirmationClaim] as JsonObject;
            var jwk = cnf?[AAuthEventsConstants.JwkClaim] as JsonObject;
            if (jwk is null)
                throw Failure(EventsVerificationErrorCode.InvalidToken, "Subscribe JWT is missing cnf.jwk.");
            try { httpKey = KeyFactory.FromJwk(jwk); }
            catch (Exception ex) when (ex is ArgumentException or FormatException)
            {
                throw Failure(EventsVerificationErrorCode.InvalidToken, "Subscribe cnf.jwk is invalid.", ex);
            }
        }
        return new EventsJwtKeyResolution(verified, issuerKey, httpKey, kid, jwksUri);
    }

    private async ValueTask EnsureUrlAsync(Uri uri, CancellationToken cancellationToken)
    {
        try { await _policy.EnsureAllowedAsync(uri, cancellationToken).ConfigureAwait(false); }
        catch (EventsVerificationException) { throw; }
        catch (Exception ex) { throw Failure(EventsVerificationErrorCode.UrlPolicyRejected, ex.Message, ex); }
    }

    private async Task<IAAuthKey?> RefreshChangedKeyAsync(
        Uri jwksUri,
        string kid,
        IAAuthKey current,
        CancellationToken cancellationToken)
    {
        IAAuthKey? refreshed;
        try
        {
            refreshed = await _jwks.ForceRefreshKeyAsync(jwksUri, kid, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            throw Failure(EventsVerificationErrorCode.MetadataFailure, ex.Message, ex);
        }
        return refreshed is not null &&
               refreshed.ComputeJwkThumbprint() != current.ComputeJwkThumbprint()
            ? refreshed
            : null;
    }

    private static bool IsSignatureFailure(TokenVerificationException exception) =>
        exception.Message.Contains("signature verification failed", StringComparison.OrdinalIgnoreCase);

    private static void ReadClaims(TokenVerifier.VerifiedToken verified, EventsTokenKind kind)
    {
        try
        {
            if (kind == EventsTokenKind.Subscribe) _ = SubscribeTokenClaims.Read(verified);
            else _ = EventTokenClaims.Read(verified);
        }
        catch (TokenVerificationException) { throw; }
        catch (Exception ex) { throw new TokenVerificationException(ex.Message, ex); }
    }

    private static (JsonObject Header, JsonObject Payload) DecodeCheap(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
            throw Failure(EventsVerificationErrorCode.InvalidToken, "JWT is not compact JWS.");
        try
        {
            var header = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(parts[0])) as JsonObject;
            var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(parts[1])) as JsonObject;
            return (header ?? throw new FormatException("JWT header is not an object."),
                payload ?? throw new FormatException("JWT payload is not an object."));
        }
        catch (EventsVerificationException) { throw; }
        catch (Exception ex) { throw Failure(EventsVerificationErrorCode.InvalidToken, "JWT JSON is malformed.", ex); }
    }

    private static string StringClaim(JsonObject obj, string name, string detail) =>
        obj[name] is JsonValue value && value.TryGetValue<string>(out var result) &&
        !string.IsNullOrWhiteSpace(result)
            ? result : throw Failure(EventsVerificationErrorCode.InvalidToken, detail);

    private static EventsVerificationException MapTokenFailure(TokenVerificationException ex) =>
        ex.Message.Contains("expired", StringComparison.OrdinalIgnoreCase)
            ? Failure(EventsVerificationErrorCode.ExpiredToken, ex.Message, ex)
            : ex.Message.Contains("audience", StringComparison.OrdinalIgnoreCase)
                ? Failure(EventsVerificationErrorCode.WrongAudience, ex.Message, ex)
            : ex.Message.Contains("dwk", StringComparison.OrdinalIgnoreCase)
                ? Failure(EventsVerificationErrorCode.WrongResource, ex.Message, ex)
            : ex.Message.Contains("alg", StringComparison.OrdinalIgnoreCase)
                ? Failure(EventsVerificationErrorCode.UnsupportedAlgorithm, ex.Message, ex)
            : ex.Message.Contains("signature", StringComparison.OrdinalIgnoreCase)
                ? Failure(EventsVerificationErrorCode.InvalidSignature, ex.Message, ex)
                : Failure(EventsVerificationErrorCode.InvalidToken, ex.Message, ex);

    private static EventsVerificationException Failure(
        EventsVerificationErrorCode code, string detail, Exception? inner = null) =>
        new(code, detail, inner);
}
