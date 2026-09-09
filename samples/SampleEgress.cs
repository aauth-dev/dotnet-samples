using System.Net.Http;
using AAuth.Discovery;

namespace AAuth.Samples;

internal static class SampleEgress
{
    internal static AAuthEgressPolicy Policy { get; } = new([
        "http://localhost:5000", "http://localhost:5001", "http://localhost:5002",
        "http://localhost:5003", "http://localhost:5004", "http://localhost:5005", "http://localhost:5006",
        "http://localhost:5007",
        "http://localhost:5100", "http://localhost:5200", "http://localhost:5240",
        "http://localhost:5301", "http://localhost:5400", "http://localhost:5500",
        "http://localhost:5501"], requestTimeout: System.TimeSpan.FromSeconds(45));
}

internal sealed class SampleHttpClient : HttpClient
{
    public SampleHttpClient() : this(AAuthHttpTransport.CreateHandler(SampleEgress.Policy)) { }

    public SampleHttpClient(HttpMessageHandler handler, bool disposeHandler = true) : base(handler, disposeHandler)
    {
        AAuthHttpTransport.AttachPolicy(this, SampleEgress.Policy, AAuthTransportContract.EnforcesEgressPolicy);
    }
}