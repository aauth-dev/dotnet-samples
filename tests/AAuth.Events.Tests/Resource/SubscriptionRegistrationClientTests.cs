using System.Net;
using System.Net.Http;
using AAuth.Crypto;
using AAuth.Events.Agent;
using AAuth.Events.Http;
using Xunit;

namespace AAuth.Events.Tests.Resource;

public sealed class SubscriptionRegistrationClientTests
{
    [Fact]
    public async Task BodylessRegistrationUsesOnlyEventsBaseProfile()
    {
        var key = AAuthKey.Generate();
        HttpRequestMessage? captured = null;
        using var http = new HttpClient(new CaptureHandler(request =>
        {
            captured = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"event_types\":[\"slot.available\"]}"),
            };
        }));
        var client = new SubscriptionRegistrationClient(http, key);
        var result = await client.RegisterAsync(new Uri("https://resource.example/register"), "a.b.c");

        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.NotNull(captured);
        var verified = new EventsHttpMessageVerifier().Verify(
            captured!, AAuthKey.FromJwk(key.ToPublicJwk()), EventsHttpProfile.Bodyless);
        Assert.Empty(verified.Body);
        captured!.Dispose();
    }

    [Fact]
    public async Task JsonRegistrationExposesSelectedTypes()
    {
        var key = AAuthKey.Generate();
        using var http = new HttpClient(new CaptureHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"event_types\":[\"slot.available\"]}"),
            }));
        var client = new SubscriptionRegistrationClient(http, key);
        var result = await client.RegisterJsonAsync(
            new Uri("https://resource.example/register"), "a.b.c", "{\"event_types\":[\"slot.available\"]}");

        Assert.Equal(new[] { "slot.available" }, result.SelectedEventTypes);
    }

    [Fact]
    public async Task RegistrationClientRejectsOversizedResponse()
    {
        var key = AAuthKey.Generate();
        using var http = new HttpClient(new CaptureHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    new string('x', AAuthEventsConstants.DefaultMaxBodyBytes + 1)),
            }));
        var client = new SubscriptionRegistrationClient(http, key);

        await Assert.ThrowsAsync<SubscriptionRegistrationClientException>(() =>
            client.RegisterAsync(new Uri("https://resource.example/register"), "a.b.c"));
    }

    private sealed class CaptureHandler(Func<HttpRequestMessage, HttpResponseMessage> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(callback(request));
    }
}
