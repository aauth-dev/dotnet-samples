using System.Net.Http;
using AAuth.Discovery;

namespace AAuth.Testing;

internal static class TestEgress
{
    internal static AAuthEgressPolicy Policy { get; } = AAuthEgressPolicy.ForDevelopmentLoopback(
        "http://localhost", "https://localhost", "http://127.0.0.1:8080",
        "http://localhost:5000", "http://localhost:5001", "http://localhost:5002",
        "http://localhost:5003", "http://localhost:5004", "http://localhost:5005",
        "http://localhost:5100", "http://localhost:5200", "http://localhost:5240",
        "http://localhost:5300", "http://localhost:5301", "http://localhost:5400",
        "http://localhost:5500", "http://localhost:5501", "http://localhost:5555",
        "http://localhost:5556", "http://localhost:5557", "http://localhost:6000",
        "http://localhost:7000", "http://localhost:7777", "http://localhost:8888",
        "http://localhost:9997", "http://localhost:9998", "http://localhost:9999");
}

internal sealed class InProcessHttpClient : HttpClient
{
    public InProcessHttpClient(HttpMessageHandler handler, bool disposeHandler = true, AAuthEgressPolicy? policy = null) : base(handler, disposeHandler)
    {
        AAuthHttpTransport.AttachPolicy(this, policy ?? TestEgress.Policy, AAuthTransportContract.InProcessOnly);
    }
}