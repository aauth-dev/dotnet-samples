using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.Tokens;

namespace AAuth.Samples;

public sealed class FederatedWorkerScenario(IAAuthSigner providerKey, string providerKid, string provider,
    string personServer, string wallet) : IDisposable
{
    public static IReadOnlyDictionary<string, string> ScopeDescriptions { get; } =
        new Dictionary<string, string> { ["delegation.invoke"] = "Delegate a wallet lookup to the parent and worker" };
    private readonly AAuthKey _originalKey = AAuthKey.Generate();
    private readonly AAuthKey _parentKey = AAuthKey.Generate();
    private readonly AAuthKey _workerKey = AAuthKey.Generate();
    private readonly HttpClient _discovery = AAuthHttpTransport.CreateClient(SampleEgress.Policy);
    public string ParentId => $"aauth:aria@{new Uri(provider).Host}";
    public string WorkerId => $"aauth:aria+worker1@{new Uri(provider).Host}";
    public string? ParentToken { get; private set; }
    public string? WorkerToken { get; private set; }
    public string? UpstreamToken { get; private set; }
    public string? WorkerPersonToken { get; private set; }
    public string? ResourceToken { get; private set; }
    public string? AuthToken { get; private set; }
    public string? ResourceResponse { get; private set; }
    public string? InteractionUrl { get; private set; }
    public Func<Interaction, CancellationToken, Task>? OnInteraction { get; set; }

    public async Task IssueParentAsync(CancellationToken ct = default) => ParentToken = await AgentAsync(ParentId, _parentKey, ct: ct);
    public async Task IssueWorkerAsync(CancellationToken ct = default) => WorkerToken = await AgentAsync(WorkerId, _workerKey, ParentId, ct);

    // The original caller authorizes at the provider, which then acts as the
    // intermediary (§Call Chaining): the caller's auth token becomes the upstream token.
    public async Task ObtainUpstreamAsync(CancellationToken ct = default)
    {
        var originalId = $"aauth:original@{new Uri(provider).Host}";
        var originalToken = await AgentAsync(originalId, _originalKey, ct: ct);
        using var client = new AAuthClientBuilder(_originalKey).UseJwt(originalToken).WithEgressPolicy(SampleEgress.Policy).Build();
        var exchange = new TokenExchangeClient(client, new MetadataClient(_discovery));
        var personToken = await exchange.RequestPersonTokenAsync(personServer, provider,
            new TokenExchangeRequest { OnInteractionRequired = InteractAsync }, ct);
        var presented = Payload(personToken);
        var resource = await new ResourceTokenBuilder
        {
            EgressPolicy = SampleEgress.Policy, Issuer = provider, Audience = personServer,
            PersonServer = personServer, Subject = (string)presented["sub"]!, PresentedJti = (string)presented["jti"]!,
            AgentJkt = _originalKey.ComputeJwkThumbprint(), Key = providerKey, KeyId = providerKid,
            Scope = "delegation.invoke", ScopeDescriptions = ScopeDescriptions,
        }.BuildAsync(ct);
        UpstreamToken = await exchange.ExchangeAsync(personServer, resource,
            new TokenExchangeRequest { PresentedToken = personToken, OnInteractionRequired = InteractAsync }, ct);
    }

    // The worker meets the Wallet's person-token requirement; the parent obtains the
    // worker's person token (§Parent-Mediated Authorization), and the worker then
    // presents it for the Wallet's resource token.
    public async Task ObtainResourceAsync(CancellationToken ct = default)
    {
        await ObtainWorkerPersonTokenAsync(ct);
        await PresentWorkerPersonTokenAsync(ct);
    }

    public async Task ObtainWorkerPersonTokenAsync(CancellationToken ct = default)
    {
        var walletUrl = wallet.TrimEnd('/') + "/wallet";
        using (var worker = new AAuthClientBuilder(_workerKey).UseJwt(WorkerToken!).WithEgressPolicy(SampleEgress.Policy).Build())
        using (var prerequisite = await worker.GetAsync(walletUrl, ct))
        {
            if (prerequisite.StatusCode != HttpStatusCode.Unauthorized)
                throw new InvalidOperationException("Worker expected a Wallet person-token requirement.");
        }
        using var parent = new AAuthClientBuilder(_parentKey).UseJwt(ParentToken!).WithEgressPolicy(SampleEgress.Policy).Build();
        WorkerPersonToken = await new TokenExchangeClient(parent, new MetadataClient(_discovery)).RequestPersonTokenAsync(
            personServer, new Uri(wallet).GetLeftPart(UriPartial.Authority),
            new TokenExchangeRequest { SubagentToken = WorkerToken, UpstreamToken = UpstreamToken, OnInteractionRequired = InteractAsync }, ct);
    }

    public async Task PresentWorkerPersonTokenAsync(CancellationToken ct = default)
    {
        using var client = new AAuthClientBuilder(_workerKey).UseJwt(WorkerPersonToken!).WithEgressPolicy(SampleEgress.Policy).Build();
        using var response = await client.GetAsync(wallet.TrimEnd('/') + "/wallet", ct);
        if (response.StatusCode != HttpStatusCode.Unauthorized)
            throw new InvalidOperationException("Worker expected a Wallet authorization challenge.");
        ResourceToken = AAuthRequirementHeader.Parse(response.Headers.GetValues(AAuthRequirementHeader.Name).Single()).ResourceToken
            ?? throw new InvalidOperationException("Wallet challenge is missing its resource token.");
    }

    public async Task ExchangeAsync(CancellationToken ct = default)
    {
        using var client = new AAuthClientBuilder(_parentKey).UseJwt(ParentToken!).WithEgressPolicy(SampleEgress.Policy).Build();
        AuthToken = await new TokenExchangeClient(client, new MetadataClient(_discovery)).ExchangeAsync(personServer, ResourceToken!,
            new TokenExchangeRequest
            {
                PresentedToken = WorkerPersonToken, SubagentToken = WorkerToken, UpstreamToken = UpstreamToken,
                OnInteractionRequired = InteractAsync,
            }, ct);
        AgentAuthTokenValidator.Validate(AuthToken, ResourceToken!, _parentKey, ParentToken!, WorkerPersonToken!, WorkerToken, UpstreamToken);
        var payload = Payload(AuthToken);
        if ((string?)payload["dwk"] != AuthTokenBuilder.AccessDwk)
            throw new InvalidOperationException("The four-party grant must be issued by the AS.");
        if (payload["sub"] is not null && (string?)payload["sub"] == (string?)Payload(UpstreamToken!)["sub"])
            throw new InvalidOperationException("Downstream grant copied the upstream directed identity.");
    }

    public async Task CallWalletAsync(CancellationToken ct = default)
    {
        using var worker = new AAuthClientBuilder(_workerKey).UseJwt(AuthToken!).WithEgressPolicy(SampleEgress.Policy).Build();
        using var response = await worker.GetAsync(wallet.TrimEnd('/') + "/wallet", ct);
        ResourceResponse = await response.Content.ReadAsStringAsync(ct);
        response.EnsureSuccessStatusCode();
        using var parent = new AAuthClientBuilder(_parentKey).UseJwt(AuthToken!).WithEgressPolicy(SampleEgress.Policy).Build();
        using var rejected = await parent.GetAsync(wallet.TrimEnd('/') + "/wallet", ct);
        if (rejected.StatusCode != HttpStatusCode.Unauthorized)
            throw new InvalidOperationException("Wallet must reject the parent presenting the worker's token.");
    }

    private async Task InteractAsync(Interaction interaction, CancellationToken ct)
    {
        InteractionUrl = interaction.BuildUserUrl();
        if (OnInteraction is null) throw new InvalidOperationException("Interactive consent requires a browser callback.");
        await OnInteraction(interaction, ct);
    }

    private ValueTask<string> AgentAsync(string id, IAAuthKey key, string? parent = null, CancellationToken ct = default) => new AgentTokenBuilder
    {
        EgressPolicy = SampleEgress.Policy, Issuer = provider, Subject = id, Key = providerKey, KeyId = providerKid,
        ConfirmationKey = key, ParentAgent = parent, PersonServer = personServer, Lifetime = TimeSpan.FromMinutes(10),
    }.BuildAsync(ct);

    public static JsonObject Payload(string jwt) => JsonNode.Parse(
        Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]))!.AsObject();

    public void Dispose() => _discovery.Dispose();
}