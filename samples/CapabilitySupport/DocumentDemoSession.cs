using System.Net;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;

namespace AAuth.Samples.Capabilities;

public sealed class DocumentDemoSession(string provider, string person, string resource) : IDisposable
{
    private readonly AAuthKey _key = AAuthKey.Generate();
    private readonly HttpClient _http = AAuthHttpTransport.CreateClient(SampleEgress.Policy);
    private string? _agentToken;
    private string? _resourceToken;
    private string? _authToken;
    public int Step { get; private set; }
    public bool Denied { get; private set; }
    public string? ConsentUrl { get; private set; }
    public string? Result { get; private set; }
    public Func<Task>? Changed { get; set; }
    public List<ScenarioExchange> Exchanges { get; } = [];
    public static string[] Steps { get; } = ["Enroll document agent", "Request document release", "Authorize document access", "Download released document"];

    public async Task NextAsync(CancellationToken cancellationToken)
    {
        switch (Step)
        {
            case 0:
                var enrolled = await AAuthClientBuilder.Bootstrap(provider + "/enrol").WithKey(_key)
                    .WithKeyStore(new InMemoryKeyStore()).WithPersonServer(person).WithEgressPolicy(SampleEgress.Policy).EnrolAsync(cancellationToken);
                _agentToken = enrolled.AgentToken;
                break;
            case 1:
                using (var agent = Signed(_agentToken!))
                using (var response = await agent.GetAsync(resource + "/document", cancellationToken))
                {
                    if (response.StatusCode != HttpStatusCode.Unauthorized) throw new InvalidOperationException("Expected document authorization challenge.");
                    _resourceToken = AAuthRequirementHeader.Parse(response.Headers.GetValues(AAuthRequirementHeader.Name).Single()).ResourceToken!;
                    Result = ScenarioWireHandler.Claims(_resourceToken).ToJsonString(WalletDemoSession.Pretty);
                }
                break;
            case 2:
                using (var agent = Signed(_agentToken!))
                using (var metadata = new MetadataClient(_http))
                {
                    try
                    {
                        _authToken = await new TokenExchangeClient(agent, metadata).ExchangeAsync(person, _resourceToken!, new TokenExchangeRequest
                        {
                            Account = "work",
                            OnInteractionRequired = async (interaction, _) =>
                            {
                                ConsentUrl = interaction.BuildUserUrl();
                                if (Changed is not null) await Changed();
                            },
                        }, cancellationToken);
                        Result = ScenarioWireHandler.Claims(_authToken).ToJsonString(WalletDemoSession.Pretty);
                    }
                    catch (AAuthInteractionDeniedException) { Denied = true; }
                    finally { ConsentUrl = null; }
                }
                break;
            case 3:
                if (Denied) return;
                using (var authorized = Signed(_authToken!))
                using (var response = await authorized.GetAsync(resource + "/document", cancellationToken))
                {
                    response.EnsureSuccessStatusCode();
                    Result = await response.Content.ReadAsStringAsync(cancellationToken);
                }
                break;
            default: return;
        }
        Step++;
    }

    private HttpClient Signed(string token) => new AAuthClientBuilder(_key).UseJwt(token).WithEgressPolicy(SampleEgress.Policy)
        .WithInnerHandler(new ScenarioWireHandler(exchange => Exchanges.Add(exchange))
        { InnerHandler = AAuthHttpTransport.CreateHandler(SampleEgress.Policy) }, AAuthTransportContract.EnforcesEgressPolicy).Build();
    public void Dispose() => _http.Dispose();
}