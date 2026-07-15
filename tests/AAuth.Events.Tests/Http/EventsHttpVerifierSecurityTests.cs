using System.Net.Http.Headers;
using AAuth.Crypto;
using AAuth.Events.Http;

namespace AAuth.Events.Tests.Http;

public sealed class EventsHttpVerifierSecurityTests
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.FromUnixTimeSeconds(1_750_000_000);

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES256")]
    public void BodylessRegistrationAndEventProfilesRoundTrip(string algorithm)
    {
        var key = CreateKey(algorithm);
        var verifier = NewVerifier();

        using var bodyless = new HttpRequestMessage(
            HttpMethod.Post, "https://resource.example/events");
        new EventsRequestSigner(key, () => "carrier", () => Now).SignBodyless(bodyless);
        Assert.Empty(verifier.VerifyBodyless(bodyless, Public(key)).Body);

        using var registration = JsonRequest([1, 2, 3]);
        new EventsRequestSigner(key, () => "carrier", () => Now).SignRegistration(registration);
        Assert.False(registration.Content!.Headers.Contains("Content-Digest"));
        Assert.Equal([1, 2, 3], verifier.VerifyRegistration(registration, Public(key)).Body);

        using var eventRequest = JsonRequest([4, 5, 6]);
        new EventsRequestSigner(key, () => "carrier", () => Now).SignEvent(eventRequest);
        Assert.True(eventRequest.Content!.Headers.Contains("Content-Digest"));
        Assert.Equal([4, 5, 6], verifier.VerifyEvent(eventRequest, Public(key)).Body);
    }

    [Fact]
    public void VerifierRejectsStaleAndFutureCreatedTimes()
    {
        var key = AAuthKey.Generate();
        using var stale = new HttpRequestMessage(HttpMethod.Post, "https://resource.example/events");
        new EventsRequestSigner(key, () => "carrier", () => Now).SignBodyless(stale);
        var staleError = Assert.Throws<EventsVerificationException>(() =>
            NewVerifier(Now.AddSeconds(61)).VerifyBodyless(stale, Public(key)));
        Assert.Equal(EventsVerificationErrorCode.ExpiredToken, staleError.Error.Code);

        using var future = new HttpRequestMessage(HttpMethod.Post, "https://resource.example/events");
        new EventsRequestSigner(key, () => "carrier", () => Now.AddSeconds(6)).SignBodyless(future);
        var futureError = Assert.Throws<EventsVerificationException>(() =>
            NewVerifier().VerifyBodyless(future, Public(key)));
        Assert.Equal(EventsVerificationErrorCode.InvalidSignature, futureError.Error.Code);
    }

    [Theory]
    [InlineData("https://resource.example/changed", "path")]
    [InlineData("https://other.example/events", "authority")]
    public void VerifierRejectsTargetMutation(string changedUri, string _)
    {
        var key = AAuthKey.Generate();
        using var request = new HttpRequestMessage(
            HttpMethod.Post, "https://resource.example/events");
        new EventsRequestSigner(key, () => "carrier", () => Now).SignBodyless(request);
        request.RequestUri = new Uri(changedUri);

        var error = Assert.Throws<EventsVerificationException>(() =>
            NewVerifier().VerifyBodyless(request, Public(key)));
        Assert.Equal(EventsVerificationErrorCode.InvalidSignature, error.Error.Code);
    }

    [Fact]
    public void VerifierRejectsSignatureKeySubstitution()
    {
        var key = AAuthKey.Generate();
        using var request = new HttpRequestMessage(
            HttpMethod.Post, "https://resource.example/events");
        new EventsRequestSigner(key, () => "carrier", () => Now).SignBodyless(request);
        request.Headers.Remove("Signature-Key");
        request.Headers.TryAddWithoutValidation("Signature-Key", "sig=jwt;jwt=\"substituted\"");

        var error = Assert.Throws<EventsVerificationException>(() =>
            NewVerifier().VerifyBodyless(request, Public(key)));
        Assert.Equal(EventsVerificationErrorCode.InvalidSignature, error.Error.Code);
    }

    [Fact]
    public void VerifierRejectsMalformedAuthorizationHeader()
    {
        var key = AAuthKey.Generate();
        using var request = new HttpRequestMessage(
            HttpMethod.Post, "https://resource.example/events");
        new EventsRequestSigner(key, () => "carrier", () => Now).SignBodyless(request);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer");

        var error = Assert.Throws<EventsVerificationException>(() =>
            NewVerifier().VerifyBodyless(request, Public(key)));
        Assert.Equal(EventsVerificationErrorCode.UnexpectedCoveredComponent, error.Error.Code);
    }

    [Fact]
    public void VerifierEnforcesBodyLimitAndContentType()
    {
        var key = AAuthKey.Generate();
        using var oversized = JsonRequest([1, 2, 3, 4]);
        new EventsRequestSigner(key, () => "carrier", () => Now).SignEvent(oversized);
        var sizeError = Assert.Throws<EventsVerificationException>(() =>
            new EventsHttpMessageVerifier
            {
                Clock = () => Now,
                MaxBodyBytes = 3,
            }.VerifyEvent(oversized, Public(key)));
        Assert.Equal(EventsVerificationErrorCode.BodyTooLarge, sizeError.Error.Code);

        using var wrongType = new HttpRequestMessage(
            HttpMethod.Post, "https://resource.example/events")
        {
            Content = new ByteArrayContent([1]),
        };
        wrongType.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
        var typeError = Assert.Throws<EventsVerificationException>(() =>
            new EventsRequestSigner(key, () => "carrier", () => Now).SignEvent(wrongType));
        Assert.Equal(EventsVerificationErrorCode.MalformedRequest, typeError.Error.Code);
    }

    [Fact]
    public async Task AsyncVerificationObservesCancellation()
    {
        var key = AAuthKey.Generate();
        using var request = JsonRequest(new byte[1024]);
        new EventsRequestSigner(key, () => "carrier", () => Now).SignEvent(request);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            NewVerifier().VerifyAsync(
                request,
                Public(key),
                EventsHttpProfile.EventJson,
                cancellationToken: cancellation.Token));
    }

    [Fact]
    public async Task AsyncVerificationMapsMalformedHeadersToTypedFailure()
    {
        var key = AAuthKey.Generate();
        using var request = new HttpRequestMessage(
            HttpMethod.Post, "https://resource.example/events");

        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            NewVerifier().VerifyAsync(
                request,
                Public(key),
                EventsHttpProfile.Bodyless));

        Assert.Equal(EventsVerificationErrorCode.MalformedRequest, error.Error.Code);
    }

    private static EventsHttpMessageVerifier NewVerifier(DateTimeOffset? now = null) =>
        new()
        {
            Clock = () => now ?? Now,
            MaxAge = TimeSpan.FromSeconds(60),
            FutureSkew = TimeSpan.FromSeconds(5),
        };

    private static HttpRequestMessage JsonRequest(byte[] bytes)
    {
        var request = new HttpRequestMessage(
            HttpMethod.Post, "https://resource.example/events")
        {
            Content = new ByteArrayContent(bytes),
        };
        request.Content.Headers.ContentType =
            new MediaTypeHeaderValue(AAuthEventsConstants.JsonMediaType);
        return request;
    }

    private static IAAuthKey CreateKey(string algorithm) =>
        algorithm == "EdDSA" ? AAuthKey.Generate() : EcdsaAAuthKey.Generate();

    private static IAAuthKey Public(IAAuthKey key) => KeyFactory.FromJwk(key.ToPublicJwk());
}
