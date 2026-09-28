using System.Net;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;

namespace AAuth.Samples.Capabilities;

public sealed class CatalogDemoSession(string provider, string person, string resource) : IDisposable
{
    private readonly AAuthKey _key = AAuthKey.Generate();
    private readonly HttpClient _http = AAuthHttpTransport.CreateClient(SampleEgress.Policy);
    private string? _agentToken;
    private string? _authToken;
    public int Step { get; private set; }
    public string Service { get; set; } = "destinations";
    public string OtherService => Service == "destinations" ? "experiences" : "destinations";
    public string? ConsentUrl { get; private set; }
    public string? Result { get; private set; }
    public Func<Task>? Changed { get; set; }
    public List<ScenarioExchange> Exchanges { get; } = [];
    public static string[] Steps { get; } = ["Discover catalog definition", "Authorize selected operation", "Read selected catalog",
        "Reject a sibling-operation grant", "Authorize sibling and recover"];

    public async Task NextAsync(CancellationToken cancellationToken)
    {
        switch (Step)
        {
            case 0:
                using (var metadata = new MetadataClient(_http))
                {
                    var document = await metadata.FetchAsync(metadata.GetUrl(resource, "aauth-resource.json"), cancellationToken);
                    var definition = (string)document["r3_vocabularies"]!["urn:aauth:vocabulary:openapi"]!;
                    using (var request = new HttpRequestMessage(HttpMethod.Get, definition))
                    using (var response = await AAuthHttpTransport.SendAsync(_http, request, cancellationToken))
                    {
                        response.EnsureSuccessStatusCode();
                        Result = new JsonObject
                        {
                            ["metadata"] = document,
                            ["definition"] = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken)),
                        }.ToJsonString(WalletDemoSession.Pretty);
                    }
                }
                var enrolled = await AAuthClientBuilder.Bootstrap(provider + "/enrol").WithKey(_key)
                    .WithKeyStore(new InMemoryKeyStore()).WithPersonServer(person).WithEgressPolicy(SampleEgress.Policy).EnrolAsync(cancellationToken);
                _agentToken = enrolled.AgentToken;
                break;
            case 1: _authToken = await AuthorizeAsync(Service, cancellationToken); break;
            case 2: await ReadAsync(Service, HttpStatusCode.OK, cancellationToken); break;
            case 3: await ReadAsync(OtherService, HttpStatusCode.Forbidden, cancellationToken); break;
            case 4:
                _authToken = await AuthorizeAsync(OtherService, cancellationToken);
                await ReadAsync(OtherService, HttpStatusCode.OK, cancellationToken); break;
            default: return;
        }
        Step++;
    }

    private async Task<string> AuthorizeAsync(string service, CancellationToken cancellationToken)
    {
        var url = resource + "/catalog/" + service;
        using var signed = Signed(_agentToken!);
        using var metadata = new MetadataClient(_http);
        var exchange = new TokenExchangeClient(signed, metadata);
        async Task Surface(Interaction interaction, CancellationToken _)
        {
            ConsentUrl = interaction.BuildUserUrl();
            if (Changed is not null) await Changed();
        }
        string grant;
        try
        {
            // §Person Token Required: the agent token earns a person-token requirement first.
            using (var prerequisite = await signed.GetAsync(url, cancellationToken))
            {
                if (prerequisite.StatusCode != HttpStatusCode.Unauthorized
                    || AAuthRequirementHeader.Parse(prerequisite.Headers.GetValues(AAuthRequirementHeader.Name).First()).Requirement
                        != AAuthRequirementHeader.PersonTokenRequirement)
                    throw new InvalidOperationException("Expected a catalog person-token requirement.");
            }
            var personToken = await exchange.RequestPersonTokenAsync(person, resource,
                new TokenExchangeRequest { OnInteractionRequired = Surface }, cancellationToken);
            using var personClient = Signed(personToken);
            using var challenge = await personClient.GetAsync(url, cancellationToken);
            if (challenge.StatusCode != HttpStatusCode.Unauthorized) throw new InvalidOperationException("Expected catalog challenge.");
            var token = AAuthRequirementHeader.Parse(challenge.Headers.GetValues(AAuthRequirementHeader.Name).First()).ResourceToken
                ?? throw new InvalidOperationException("Catalog challenge is missing its resource token.");
            grant = await exchange.ExchangeAsync(person, token,
                new TokenExchangeRequest { PresentedToken = personToken, OnInteractionRequired = Surface }, cancellationToken);
        }
        finally
        {
            ConsentUrl = null;
            if (Changed is not null) await Changed();
        }
        Result = ScenarioWireHandler.Claims(grant).ToJsonString(WalletDemoSession.Pretty);
        return grant;
    }

    private async Task ReadAsync(string service, HttpStatusCode expected, CancellationToken cancellationToken)
    {
        using var signed = Signed(_authToken!);
        using var response = await signed.GetAsync(resource + "/catalog/" + service, cancellationToken);
        Result = await response.Content.ReadAsStringAsync(cancellationToken);
        if (response.StatusCode != expected) throw new InvalidOperationException($"Expected HTTP {(int)expected}, got {(int)response.StatusCode}: {Result}");
    }

    private HttpClient Signed(string token) => new AAuthClientBuilder(_key).UseJwt(token).WithEgressPolicy(SampleEgress.Policy)
        .WithInnerHandler(new ScenarioWireHandler(exchange => Exchanges.Add(exchange))
        { InnerHandler = AAuthHttpTransport.CreateHandler(SampleEgress.Policy) }, AAuthTransportContract.EnforcesEgressPolicy).Build();
    public void Dispose() => _http.Dispose();
}