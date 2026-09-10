using AAuth.Crypto;
using AAuth.Discovery;

namespace AAuth.R3.Tests;

public class R3TransportOwnershipTests
{
    [Fact]
    public async Task DisposingFetchClientPreservesReusableInjectedHandler()
    {
        var bytes = "{}"u8.ToArray();
        using var handler = new TrackingHandler(bytes);
        var key = AAuthKey.Generate();
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var client = R3FetchClient.Create(key, "https://as.test", "aauth-access.json", "key",
                handler, transportContract: AAuthTransportContract.InProcessOnly);
            Assert.Equal(bytes, await client.FetchAndVerifyAsync("https://resource.test/r3", R3Hash.ComputeS256(bytes), "https://resource.test"));
        }
        Assert.False(handler.Disposed);
        Assert.Equal(2, handler.Calls);
    }

    private sealed class TrackingHandler(byte[] bytes) : HttpMessageHandler
    {
        public bool Disposed { get; private set; }
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(Disposed, this);
            Calls++;
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) });
        }

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }
}