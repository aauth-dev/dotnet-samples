using System.Net;
using AAuth.Events.Discovery;
using AAuth.Events.Http;

namespace AAuth.Events.Tests.Http;

public sealed class EventsHttpClientFactoryTests
{
    [Fact]
    public async Task RejectedUrlNeverReachesInnerHandler()
    {
        var inner = new CaptureHandler();
        using var client = EventsHttpClientFactory.Create(
            new DefaultEventsUrlPolicy(static _ => false),
            inner);

        var error = await Assert.ThrowsAsync<EventsVerificationException>(() =>
            client.GetAsync("https://rejected.example/metadata"));

        Assert.Equal(EventsVerificationErrorCode.UrlPolicyRejected, error.Error.Code);
        Assert.Equal(0, inner.CallCount);
    }

    [Fact]
    public async Task AllowedRequestReturnsRedirectWithoutASecondRequest()
    {
        var inner = new CaptureHandler(HttpStatusCode.Found);
        using var client = EventsHttpClientFactory.Create(
            new DefaultEventsUrlPolicy(static _ => true),
            inner);

        using var response = await client.GetAsync("https://allowed.example/metadata");

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(1, inner.CallCount);
    }

    private sealed class CaptureHandler(HttpStatusCode statusCode = HttpStatusCode.OK)
        : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return Task.FromResult(new HttpResponseMessage(statusCode)
            {
                RequestMessage = request,
            });
        }
    }
}
