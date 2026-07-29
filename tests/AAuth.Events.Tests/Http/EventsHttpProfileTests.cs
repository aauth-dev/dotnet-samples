using System;
using System.Net.Http;
using System.Security.Cryptography;
using AAuth.Crypto;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using Xunit;

namespace AAuth.Events.Tests.Http;

public sealed class EventsHttpProfileTests
{
    [Fact]
    public void BodylessProfileRoundTripsAndExcludesQuery()
    {
        var key = AAuthKey.Generate();
        using var request = new HttpRequestMessage(HttpMethod.Get,
            "https://resource.example/events%2Fbatch?ignored=query");
        var signer = new EventsRequestSigner(key, () => "carrier");
        signer.SignBodyless(request);

        var verifier = new EventsHttpMessageVerifier
        {
            Clock = () => DateTimeOffset.UtcNow,
        };
        var result = verifier.Verify(
            request, AAuthKey.FromJwk(key.ToPublicJwk()), EventsHttpProfile.Bodyless);

        Assert.Equal(EventsHttpProfile.Bodyless, result.Profile);
        Assert.Empty(result.Body);
    }

    [Fact]
    public void EventProfileBindsExactBytesAndDigest()
    {
        var key = AAuthKey.Generate();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://resource.example/events");
        request.Content = new ByteArrayContent(new byte[] { 1, 2, 3, 4 });
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        var signer = new EventsRequestSigner(key, () => "carrier");
        signer.SignEvent(request);

        var result = new EventsHttpMessageVerifier().Verify(
            request, AAuthKey.FromJwk(key.ToPublicJwk()), EventsHttpProfile.EventJson);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, result.Body);

        request.Content = new ByteArrayContent(new byte[] { 4, 3, 2, 1 });
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        Assert.Throws<EventsVerificationException>(() =>
            new EventsHttpMessageVerifier().Verify(
                request, AAuthKey.FromJwk(key.ToPublicJwk()), EventsHttpProfile.EventJson));
    }

    [Fact]
    public void StandardizedProfilesRejectAuthorizationAndMission()
    {
        var key = AAuthKey.Generate();
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://resource.example/events");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "x");
        var signer = new EventsRequestSigner(key, () => "carrier");
        var error = Assert.Throws<EventsVerificationException>(() => signer.SignBodyless(request));
        Assert.Equal(EventsVerificationErrorCode.UnexpectedCoveredComponent, error.Error.Code);
    }

    [Fact]
    public void DigestParserRejectsUnsupportedAndMultipleMembers()
    {
        Assert.Throws<EventsVerificationException>(() =>
            EventsRequestBody.ParseSha256Digest("sha-512=:AQ==:"));
        Assert.Throws<EventsVerificationException>(() =>
            EventsRequestBody.ParseSha256Digest("sha-256=:AQ==:, sha-256=:AQ==:"));
    }

    [Theory]
    [InlineData("ftp://example.test")]
    [InlineData("http://192.168.1.2")]
    [InlineData("https://10.0.0.1")]
    [InlineData("https://[fe80::1]")]
    public async Task DefaultUrlPolicyRejectsUnsafeUrls(string text)
    {
        var policy = new DefaultEventsUrlPolicy();
        Assert.False(await policy.IsAllowedAsync(new Uri(text)));
    }

    [Fact]
    public async Task DefaultUrlPolicyAllowsLoopbackAndCrossOriginHttps()
    {
        var policy = new DefaultEventsUrlPolicy();
        Assert.True(await policy.IsAllowedAsync(new Uri("http://127.0.0.1:5000")));
        Assert.True(await policy.IsAllowedAsync(new Uri("https://other.example")));
    }

    [Fact]
    public async Task DefaultUrlPolicyInvokesTrustCallbackAfterBaselineChecks()
    {
        var called = false;
        var policy = new DefaultEventsUrlPolicy((uri, _) =>
        {
            called = true;
            return new ValueTask<bool>(uri.Host == "trusted.example");
        });
        Assert.False(await policy.IsAllowedAsync(new Uri("https://other.example")));
        Assert.True(called);
    }

    [Fact]
    public void VerifierRejectsDuplicateCoveredComponents()
    {
        var key = AAuthKey.Generate();
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://resource.example/events");
        var signer = new EventsRequestSigner(key, () => "carrier");
        signer.SignBodyless(request);
        request.Headers.Remove("Signature-Input");
        request.Headers.TryAddWithoutValidation(
            "Signature-Input", "sig=(\"@method\" \"@method\" \"@authority\" \"@path\" \"signature-key\");created=0");
        var error = Assert.Throws<EventsVerificationException>(() =>
            new EventsHttpMessageVerifier().Verify(request, key, EventsHttpProfile.Bodyless));
        Assert.Equal(EventsVerificationErrorCode.UnexpectedCoveredComponent, error.Error.Code);
    }
}
