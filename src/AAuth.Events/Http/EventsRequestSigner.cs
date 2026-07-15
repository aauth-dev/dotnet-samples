using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.HttpSig;

namespace AAuth.Events.Http;

/// <summary>Signs the exact bodyless, registration, and event Events profiles.</summary>
public sealed class EventsRequestSigner
{
    private readonly AAuthSigningHandler _handler;

    /// <summary>Creates an Events signer around the core signing handler.</summary>
    public EventsRequestSigner(
        IAAuthKey signingKey,
        Func<string> signatureKeyFactory,
        Func<DateTimeOffset>? clock = null)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(signatureKeyFactory);
        _handler = new AAuthSigningHandler(
            signingKey, new JwtSignatureKeyProvider(signatureKeyFactory), clock);
    }

    /// <summary>Creates an Events signer from an existing handler.</summary>
    public EventsRequestSigner(AAuthSigningHandler handler) =>
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));

    /// <summary>Signs the bodyless profile.</summary>
    public void SignBodyless(HttpRequestMessage request) => Sign(request, AAuthEventsConstants.BodylessHttpComponents);

    /// <summary>Signs the registration JSON profile.</summary>
    public void SignRegistration(HttpRequestMessage request)
    {
        RequireJson(request);
        Sign(request, AAuthEventsConstants.RegistrationAdditionalHttpComponents);
    }

    /// <summary>Alias for <see cref="SignRegistration"/>.</summary>
    public void SignRegistrationJson(HttpRequestMessage request) => SignRegistration(request);

    /// <summary>Signs the event JSON profile and precomputes its digest.</summary>
    public void SignEvent(HttpRequestMessage request)
    {
        RequireJson(request);
        EnsureContentDigest(request);
        Sign(request, AAuthEventsConstants.EventAdditionalHttpComponents);
    }

    /// <summary>Alias for <see cref="SignEvent"/>.</summary>
    public void SignEventJson(HttpRequestMessage request) => SignEvent(request);

    /// <summary>Signs a request using the supplied exact additional component list.</summary>
    public void Sign(HttpRequestMessage request, IReadOnlyList<string> additionalComponents)
    {
        ArgumentNullException.ThrowIfNull(request);
        RejectForbiddenHeaders(request);
        request.Options.Set(AAuthSigningHandler.AdditionalComponentsKey, additionalComponents);
        _handler.Sign(request);
    }

    /// <summary>Configures a request for asynchronous bodyless signing.</summary>
    public static void PrepareBodyless(HttpRequestMessage request) =>
        Prepare(request, AAuthEventsConstants.BodylessHttpComponents, false);

    /// <summary>Configures a request for asynchronous registration signing.</summary>
    public static void PrepareRegistration(HttpRequestMessage request) =>
        Prepare(request, AAuthEventsConstants.RegistrationAdditionalHttpComponents, true);

    /// <summary>Configures a request for asynchronous event signing.</summary>
    public static void PrepareEvent(HttpRequestMessage request) =>
        Prepare(request, AAuthEventsConstants.EventAdditionalHttpComponents, true);

    /// <summary>Signs a bodyless request with an existing core handler.</summary>
    public static void SignBodyless(HttpRequestMessage request, AAuthSigningHandler handler)
    {
        PrepareBodyless(request);
        handler.Sign(request);
    }

    /// <summary>Signs a registration request with an existing core handler.</summary>
    public static void SignRegistration(HttpRequestMessage request, AAuthSigningHandler handler)
    {
        PrepareRegistration(request);
        handler.Sign(request);
    }

    /// <summary>Signs an event request with an existing core handler.</summary>
    public static void SignEvent(HttpRequestMessage request, AAuthSigningHandler handler)
    {
        PrepareEvent(request);
        EnsureContentDigest(request);
        handler.Sign(request);
    }

    /// <summary>Creates a core signing handler for asynchronous requests.</summary>
    public static AAuthSigningHandler CreateHandler(
        IAAuthKey signingKey,
        Func<string> signatureKeyFactory,
        Func<DateTimeOffset>? clock = null)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(signatureKeyFactory);
        return new AAuthSigningHandler(
            signingKey, new JwtSignatureKeyProvider(signatureKeyFactory), clock);
    }

    private static void RequireJson(HttpRequestMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Content is null)
            throw new EventsVerificationException(
                EventsVerificationErrorCode.MalformedRequest,
                "JSON Events profiles require a request body.");
        if (!request.Content.Headers.TryGetValues("Content-Type", out var values) ||
            !string.Equals(string.Join(", ", values).Split(';', 2)[0].Trim(),
                AAuthEventsConstants.JsonMediaType, StringComparison.OrdinalIgnoreCase))
            throw new EventsVerificationException(
                EventsVerificationErrorCode.MalformedRequest,
                "Events JSON profiles require Content-Type: application/json.");
    }

    private static void EnsureContentDigest(HttpRequestMessage request)
    {
        if (request.Content!.Headers.Contains("Content-Digest")) return;
        var bytes = request.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        var hash = SHA256.HashData(bytes);
        request.Content.Headers.TryAddWithoutValidation(
            "Content-Digest", $"sha-256=:{Convert.ToBase64String(hash)}:");
    }

    private static void RejectForbiddenHeaders(HttpRequestMessage request)
    {
        if (request.Headers.Authorization is not null ||
            request.Headers.Contains("Authorization") ||
            request.Headers.Contains("AAuth-Mission"))
            throw new EventsVerificationException(
                EventsVerificationErrorCode.UnexpectedCoveredComponent,
                "Authorization and AAuth-Mission are not permitted on standardized Events requests.");
    }

    private static void Prepare(
        HttpRequestMessage request, IReadOnlyList<string> components, bool json)
    {
        ArgumentNullException.ThrowIfNull(request);
        RejectForbiddenHeaders(request);
        if (json) RequireJson(request);
        else if (request.Content is not null)
            throw new EventsVerificationException(
                EventsVerificationErrorCode.UnexpectedCoveredComponent,
                "Bodyless Events requests must not carry content.");
        request.Options.Set(AAuthSigningHandler.AdditionalComponentsKey, components);
    }
}
