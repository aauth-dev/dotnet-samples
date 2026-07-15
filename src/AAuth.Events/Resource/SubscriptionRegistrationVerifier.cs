using System.Net.Http;
using AAuth.Events.Http;
using AAuth.Events.Tokens;
using AAuth.Tokens;

namespace AAuth.Events.Resource;

/// <summary>Verified registration facts and separately exposed preferences.</summary>
public sealed record SubscriptionRegistrationVerification(
    VerifiedSubscriptionRegistration Registration,
    SignatureUnboundRegistrationBody? Preferences);

/// <summary>
/// Low-level verifier for the subscribe JWT and the exact Events registration
/// HTTP signature profile.
/// </summary>
/// <remarks>
/// This class returns typed verification exceptions and never writes an HTTP
/// response. Callers decide whether a failure is exposed as 400, 401, or 403.
/// </remarks>
public sealed class SubscriptionRegistrationVerifier
{
    private readonly EventsJwtKeyResolver _keyResolver;
    private readonly EventsHttpMessageVerifier _httpVerifier;

    /// <summary>Maximum accepted registration body size.</summary>
    public int MaxBodyBytes => _httpVerifier.MaxBodyBytes;

    /// <summary>Creates a verifier using Events discovery and HTTP verification.</summary>
    public SubscriptionRegistrationVerifier(
        EventsJwtKeyResolver keyResolver,
        EventsHttpMessageVerifier? httpVerifier = null)
    {
        _keyResolver = keyResolver ?? throw new ArgumentNullException(nameof(keyResolver));
        _httpVerifier = httpVerifier ?? new EventsHttpMessageVerifier();
    }

    /// <summary>Verifies a registration request for an endpoint context.</summary>
    public Task<SubscriptionRegistrationVerification> VerifyAsync(
        HttpRequestMessage request,
        SubscriptionEndpointContext endpoint,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        return VerifyAsync(request, endpoint.Descriptor.ResourceAudience, endpoint.Ticket is null
            ? null : GetPath(request), cancellationToken);
    }

    /// <summary>
    /// Verifies a registration request with an explicit expected resource
    /// audience and wire path.
    /// </summary>
    public async Task<SubscriptionRegistrationVerification> VerifyAsync(
        HttpRequestMessage request,
        string? expectedAudience = null,
        string? wirePath = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var kind = request.Content is null
            ? EventsHttpProfile.Bodyless
            : EventsHttpProfile.RegistrationJson;
        var resolution = await _keyResolver.ResolveRequestAsync(
            request, EventsTokenKind.Subscribe, expectedAudience, cancellationToken).ConfigureAwait(false);
        var http = await _httpVerifier.VerifyAsync(
            request, resolution.HttpSignatureKey, kind, wirePath, cancellationToken).ConfigureAwait(false);

        SubscribeTokenClaims claims;
        try
        {
            claims = SubscribeTokenClaims.Read(resolution.VerifiedToken);
        }
        catch (TokenVerificationException ex)
        {
            throw new EventsVerificationException(
                EventsVerificationErrorCode.InvalidToken, ex.Message, ex);
        }

        if (expectedAudience is not null &&
            !string.Equals(claims.Audience, expectedAudience, StringComparison.Ordinal))
            throw new EventsVerificationException(
                EventsVerificationErrorCode.WrongAudience,
                "Subscribe token audience does not match the registration resource.");

        SignatureUnboundRegistrationBody? preferences = null;
        if (kind == EventsHttpProfile.RegistrationJson)
        {
            var contentType = request.Content?.Headers.ContentType?.ToString();
            if (string.IsNullOrWhiteSpace(contentType))
                throw new EventsVerificationException(
                    EventsVerificationErrorCode.MalformedRequest, "Registration content type is missing.");
            preferences = new SignatureUnboundRegistrationBody(http.Body, contentType, MaxBodyBytes);
        }

        return new SubscriptionRegistrationVerification(
            new VerifiedSubscriptionRegistration(
                claims.Issuer,
                claims.Subject,
                claims.Audience,
                claims.Eid,
                claims.MaxUses,
                resolution.JwtIssuerKey,
                resolution.HttpSignatureKey,
                claims.IssuedAt,
                claims.ExpiresAt,
                claims.KeyId,
                http.SignatureKey),
            preferences);
    }

    /// <summary>Verifies and returns only authorization facts.</summary>
    public async Task<VerifiedSubscriptionRegistration> VerifyFactsAsync(
        HttpRequestMessage request,
        string? expectedAudience = null,
        string? wirePath = null,
        CancellationToken cancellationToken = default) =>
        (await VerifyAsync(request, expectedAudience, wirePath, cancellationToken).ConfigureAwait(false)).Registration;

    private static string? GetPath(HttpRequestMessage request) =>
        request.RequestUri?.GetComponents(UriComponents.Path, UriFormat.UriEscaped);
}
