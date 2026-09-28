using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.Server;

namespace AAuth.Samples.Capabilities;

public enum WalletFlow { Clarification, DirectAs, Revocation }

public sealed class WalletDemoSession(string provider, string person, string wallet, string concierge) : IDisposable
{
    private readonly AAuthKey _key = AAuthKey.Generate();
    private readonly HttpClient _http = AAuthHttpTransport.CreateClient(SampleEgress.Policy);
    private string? _agentToken;
    private string? _personToken;
    private string? _resourceToken;
    private string? _authToken;
    private TaskCompletionSource<ClarificationResponse>? _answer;
    public WalletFlow Flow { get; set; }
    public int Step { get; private set; }
    public string? Agent { get; private set; }
    public string? ConsentUrl { get; private set; }
    public string? Question { get; private set; }
    public bool Cancelled { get; private set; }
    public string? Result { get; private set; }
    public List<ScenarioExchange> Exchanges { get; } = [];
    public Func<Task>? Changed { get; set; }
    public string[] Steps => Flow switch
    {
        WalletFlow.Clarification => ["Enroll agent", "Request wallet review", "Answer AS clarification and consent", "Read approved wallet review", "Reject a charge outside the grant"],
        WalletFlow.DirectAs => ["Enroll agent", "Request concierge wallet access", "Approve upstream AS grant", "Delegate wallet read through the PS", "Reject upstream token at Wallet", "Repeat the delegated read"],
        _ => ["Enroll agent", "Request wallet access", "Approve wallet grant", "Read wallet", "Reject agent as revoker", "PS revokes issuer-qualified grant", "Reject revoked grant", "Approve a fresh grant and recover"],
    };
    private string Resource => Flow == WalletFlow.DirectAs ? concierge : wallet;
    private string Path => Flow == WalletFlow.Clarification ? "/wallet/review" : "/wallet";

    public async Task NextAsync(CancellationToken cancellationToken)
    {
        switch (Step)
        {
            case 0:
                var enrolled = await AAuthClientBuilder.Bootstrap(provider + "/enrol").WithKey(_key)
                    .WithKeyStore(new InMemoryKeyStore()).WithPersonServer(person).WithEgressPolicy(SampleEgress.Policy)
                    .EnrolAsync(cancellationToken);
                _agentToken = enrolled.AgentToken;
                Agent = enrolled.AgentId;
                Result = ScenarioWireHandler.Claims(_agentToken!).ToJsonString(Pretty);
                break;
            case 1: _resourceToken = await ChallengeAsync(Resource + Path, cancellationToken); break;
            case 2:
                try { _authToken = await ExchangeAsync(cancellationToken); }
                catch (AAuthClarificationCancelledException)
                {
                    Cancelled = true; Question = null; ConsentUrl = null;
                    Result = "Request cancelled. No auth token was issued.";
                    return;
                }
                break;
            case 3 when Flow == WalletFlow.DirectAs: await DelegateAsync(cancellationToken); break;
            case 3: await AccessAsync(Resource + Path, _authToken!, HttpStatusCode.OK, cancellationToken); break;
            case 4 when Flow == WalletFlow.Clarification:
                await AccessAsync(wallet + "/wallet/charge", _authToken!, HttpStatusCode.Forbidden, cancellationToken); break;
            case 4 when Flow == WalletFlow.DirectAs:
                await AccessAsync(wallet + "/wallet", _authToken!, HttpStatusCode.Unauthorized, cancellationToken); break;
            case 5 when Flow == WalletFlow.DirectAs:
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                await AccessAsync(concierge + "/wallet", _authToken!, HttpStatusCode.OK, cancellationToken); break;
            case 4:
                using (var signed = Signed(_agentToken!))
                {
                    var claims = ScenarioWireHandler.Claims(_authToken!);
                    var status = await new RevocationClient(signed).RevokeAsync(new Uri(wallet + "/revoke"),
                        new TokenKey((string)claims["iss"]!, (string)claims["jti"]!), cancellationToken);
                    Require(status, HttpStatusCode.Forbidden);
                }
                break;
            case 5:
                using (var signed = Signed(_agentToken!))
                    for (var attempt = 0; attempt < 2; attempt++)
                    {
                        if (attempt > 0) await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                        using var revoked = await signed.PostAsJsonAsync(person + "/local/wallet/revoke",
                            new { auth_token = _authToken }, cancellationToken);
                        Require(revoked.StatusCode, HttpStatusCode.OK);
                        Result = await revoked.Content.ReadAsStringAsync(cancellationToken);
                    }
                break;
            case 6: await AccessAsync(wallet + "/wallet", _authToken!, HttpStatusCode.Unauthorized, cancellationToken); break;
            case 7:
                _resourceToken = await ChallengeAsync(wallet + "/wallet", cancellationToken);
                var previous = (string?)ScenarioWireHandler.Claims(_authToken!)["jti"];
                _authToken = await ExchangeAsync(cancellationToken);
                if (previous == (string?)ScenarioWireHandler.Claims(_authToken)["jti"])
                    throw new InvalidOperationException("Recovery must issue a fresh grant.");
                await AccessAsync(wallet + "/wallet", _authToken, HttpStatusCode.OK, cancellationToken);
                break;
            default: return;
        }
        Step++;
    }

    public void Answer(string text) => _answer?.TrySetResult(ClarificationResponse.Respond(text));
    public void Cancel() => _answer?.TrySetResult(ClarificationResponse.Cancel());

    private async Task<string> ExchangeAsync(CancellationToken cancellationToken)
    {
        using var signed = Signed(_agentToken!);
        using var metadata = new MetadataClient(_http);
        string result;
        try
        {
            result = await new TokenExchangeClient(signed, metadata).ExchangeAsync(person, _resourceToken!, new TokenExchangeRequest
            {
                PresentedToken = _personToken,
                OnInteractionRequired = async (interaction, _) =>
                {
                    ConsentUrl = interaction.BuildUserUrl();
                    if (Changed is not null) await Changed();
                },
                OnClarificationRequired = async (question, token) =>
                {
                    _answer = new(TaskCreationOptions.RunContinuationsAsynchronously);
                    Question = question.Clarification;
                    if (Changed is not null) await Changed();
                    var answer = await _answer.Task.WaitAsync(token);
                    Question = null;
                    return answer;
                },
            }, cancellationToken);
        }
        finally
        {
            ConsentUrl = null;
            if (Changed is not null) await Changed();
        }
        Result = ScenarioWireHandler.Claims(result).ToJsonString(Pretty);
        return result;
    }

    private async Task<string> ChallengeAsync(string url, CancellationToken cancellationToken)
    {
        using (var agent = Signed(_agentToken!))
        {
            // §Person Token Required: the agent token earns a person-token requirement first.
            using (var prerequisite = await agent.GetAsync(url, cancellationToken))
            {
                Require(prerequisite.StatusCode, HttpStatusCode.Unauthorized);
                if (AAuthRequirementHeader.Parse(prerequisite.Headers.GetValues(AAuthRequirementHeader.Name).First()).Requirement
                    != AAuthRequirementHeader.PersonTokenRequirement)
                    throw new InvalidOperationException("Expected a person-token requirement.");
            }
            using var metadata = new MetadataClient(_http);
            try
            {
                _personToken = await new TokenExchangeClient(agent, metadata).RequestPersonTokenAsync(person,
                    new Uri(url).GetLeftPart(UriPartial.Authority), new TokenExchangeRequest
                    {
                        OnInteractionRequired = async (interaction, _) =>
                        {
                            ConsentUrl = interaction.BuildUserUrl();
                            if (Changed is not null) await Changed();
                        },
                    }, cancellationToken);
            }
            finally
            {
                ConsentUrl = null;
                if (Changed is not null) await Changed();
            }
        }
        using var signed = Signed(_personToken);
        using var response = await signed.GetAsync(url, cancellationToken);
        Require(response.StatusCode, HttpStatusCode.Unauthorized);
        var resource = AAuthRequirementHeader.Parse(response.Headers.GetValues("AAuth-Requirement").First()).ResourceToken
            ?? throw new InvalidOperationException("Missing resource token challenge.");
        Result = ScenarioWireHandler.Claims(resource).ToJsonString(Pretty);
        return resource;
    }

    // The Concierge chains the downstream PS consent back as its own 202 (§Interaction Chaining).
    private async Task DelegateAsync(CancellationToken cancellationToken)
    {
        using var client = new AAuthClientBuilder(_key).UseJwt(_authToken!).WithEgressPolicy(SampleEgress.Policy)
            .WithInteractionHandling(options =>
            {
                options.OnInteractionRequired = async (url, _, _) =>
                {
                    ConsentUrl = url;
                    if (Changed is not null) await Changed();
                };
                options.PollingTimeout = TimeSpan.FromMinutes(2);
                options.DefaultPollInterval = TimeSpan.FromSeconds(1);
            })
            .WithInnerHandler(new ScenarioWireHandler(exchange => Exchanges.Add(exchange))
            { InnerHandler = AAuthHttpTransport.CreateHandler(SampleEgress.Policy) }, AAuthTransportContract.EnforcesEgressPolicy).Build();
        try
        {
            using var response = await client.GetAsync(concierge + "/wallet", cancellationToken);
            Require(response.StatusCode, HttpStatusCode.OK);
            Result = await response.Content.ReadAsStringAsync(cancellationToken);
        }
        finally
        {
            ConsentUrl = null;
            if (Changed is not null) await Changed();
        }
    }

    private async Task AccessAsync(string url, string token, HttpStatusCode expected, CancellationToken cancellationToken)
    {
        using var signed = Signed(token);
        using var response = await signed.GetAsync(url, cancellationToken);
        Require(response.StatusCode, expected);
        Result = await response.Content.ReadAsStringAsync(cancellationToken);
    }

    private HttpClient Signed(string token) => new AAuthClientBuilder(_key).UseJwt(token).WithEgressPolicy(SampleEgress.Policy)
        .WithInnerHandler(new ScenarioWireHandler(exchange => Exchanges.Add(exchange))
        { InnerHandler = AAuthHttpTransport.CreateHandler(SampleEgress.Policy) }, AAuthTransportContract.EnforcesEgressPolicy).Build();

    private static void Require(HttpStatusCode actual, HttpStatusCode expected)
    {
        if (actual != expected) throw new InvalidOperationException($"Expected HTTP {(int)expected}, received {(int)actual}.");
    }

    public static JsonSerializerOptions Pretty { get; } = new() { WriteIndented = true };
    public void Dispose() => _http.Dispose();
}