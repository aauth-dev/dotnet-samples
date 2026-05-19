using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace GuidedTour;

/// <summary>
/// The tour engine: scoped per-circuit so each browser session has its own
/// agent key, token state, and step list. Steps are executed one at a time
/// via <see cref="RunNextAsync"/>; the UI rerenders after each call.
/// </summary>
public sealed class TourSession
{
    private readonly TourOptions _options;

    private AAuthKey? _agentKey;
    private string? _agentToken;
    private string? _authToken;
    private string? _resourceToken;
    private string? _tokenEndpoint;

    public TourSession(IOptions<TourOptions> options)
    {
        _options = options.Value;
    }

    /// <summary>Ordered list of step records produced so far.</summary>
    public List<StepRecord> Steps { get; } = new();

    /// <summary>Total number of steps the tour plans to run given the current configuration.</summary>
    public int TotalSteps => string.IsNullOrWhiteSpace(_options.PersonServerUrl) ? 4 : 8;

    /// <summary>True when no more steps remain.</summary>
    public bool IsComplete => Steps.Count >= TotalSteps;

    /// <summary>Reset state so the tour can be replayed from step 1.</summary>
    public void Reset()
    {
        Steps.Clear();
        _agentKey = null;
        _agentToken = null;
        _authToken = null;
        _resourceToken = null;
        _tokenEndpoint = null;
    }

    /// <summary>Run the next pending step and capture its <see cref="StepRecord"/>.</summary>
    public async Task RunNextAsync(CancellationToken ct = default)
    {
        switch (Steps.Count + 1)
        {
            case 1: Step1GenerateKey(); break;
            case 2: Step2BuildAgentToken(); break;
            case 3: await Step3FetchResourceMetadataAsync(ct); break;
            case 4: await Step4SignedGetAsync(ct); break;
            case 5: Step5ParseChallenge(); break;
            case 6: await Step6FetchPersonMetadataAsync(ct); break;
            case 7: await Step7TokenExchangeAsync(ct); break;
            case 8: await Step8RetryWithAuthTokenAsync(ct); break;
        }
    }

    // -----------------------------------------------------------------
    // Step implementations
    // -----------------------------------------------------------------

    private void Step1GenerateKey()
    {
        _agentKey = AAuthKey.Generate();
        var jwk = _agentKey.ToPublicJwk().ToJsonString(new JsonSerializerOptions { WriteIndented = true });
        Steps.Add(new StepRecord
        {
            Number = 1,
            Title = "Generate Ed25519 key",
            From = Actor.Agent,
            To = Actor.Agent,
            Narrative =
                "The agent mints a fresh Ed25519 keypair locally. Only the public " +
                "JWK travels — every signed request later proves possession of the " +
                "private key.",
            ResponseBody = jwk,
            TokenDecoded = $"JWK thumbprint:\n{_agentKey.ComputeJwkThumbprint()}",
        });
    }

    private void Step2BuildAgentToken()
    {
        _agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = _options.AgentId,
            KeyId = "tour",
            Key = _agentKey!,
            PersonServer = _options.PersonServerUrl,
        }.Build();

        Steps.Add(new StepRecord
        {
            Number = 2,
            Title = "Build agent token",
            From = Actor.Agent,
            To = Actor.Agent,
            Narrative =
                "The agent provider issues an `aa-agent+jwt` containing the agent's " +
                "public key (cnf.jwk), its identifier (sub), and — for the three-party " +
                "flow — the user's Person Server URL. The JWT is self-signed by the " +
                "agent's key in this demo.",
            TokenJwt = _agentToken,
            TokenHeader = DecodeJwt(_agentToken)?.Header,
            TokenPayload = DecodeJwt(_agentToken)?.Payload,
        });
    }

    private async Task Step3FetchResourceMetadataAsync(CancellationToken ct)
    {
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        using var client = new HttpClient(capture);
        var url = $"{_options.WhoAmIUrl.TrimEnd('/')}/.well-known/aauth-resource.json";
        await client.GetAsync(url, ct);
        var ex = capture.Last!;
        Steps.Add(new StepRecord
        {
            Number = 3,
            Title = "Discover resource metadata",
            From = Actor.Agent,
            To = Actor.Resource,
            Narrative =
                "Before signing anything, the agent fetches the resource's well-known " +
                "metadata to learn its issuer and JWKS. This call is unsigned.",
            RequestLine = $"{ex.RequestLine}  →  {url}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
        });
    }

    private async Task Step4SignedGetAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        var signing = new AAuthSigningHandler(_agentKey!, () => _agentToken!)
        {
            InnerHandler = capture,
            OnSignatureBase = (_, b) => capturedBase = b,
        };
        using var client = new HttpClient(signing);

        var resp = await client.GetAsync(_options.WhoAmIUrl, ct);
        var ex = capture.Last!;

        // On a three-party challenge, the resource_token travels in the
        // AAuth-Requirement *response header*, not the response body.
        if (resp.StatusCode == HttpStatusCode.Unauthorized &&
            resp.Headers.TryGetValues(AAuthRequirementHeader.Name, out var reqHeaders))
        {
            var parsed = AAuthRequirementHeader.Parse(reqHeaders.First());
            _resourceToken = parsed.ResourceToken;
        }

        Steps.Add(new StepRecord
        {
            Number = 4,
            Title = "Signed GET (agent token)",
            From = Actor.Agent,
            To = Actor.Resource,
            Narrative =
                "The agent signs the request per RFC 9421 using its private key, " +
                "covering @method, @authority, @path, and the signature-key header " +
                "(which carries the agent JWT). If the resource accepts the agent " +
                "identity directly, the call returns 200. Otherwise it returns 401 " +
                "with an AAuth-Requirement header and a resource_token for the next leg.",
            RequestLine = $"{ex.RequestLine}  →  {_options.WhoAmIUrl}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            SignatureBase = capturedBase,
        });
    }

    private void Step5ParseChallenge()
    {
        Steps.Add(new StepRecord
        {
            Number = 5,
            Title = "Parse 401 challenge",
            From = Actor.Resource,
            To = Actor.Agent,
            Narrative =
                "The resource's 401 response contains an `aa-resource+jwt` token. " +
                "Its `aud` claim points at the Person Server the agent must visit " +
                "next; its `dwk` and `iss` claims will travel with the token to the " +
                "PS as proof the agent isn't fabricating the destination.",
            TokenJwt = _resourceToken,
            TokenHeader = DecodeJwt(_resourceToken)?.Header,
            TokenPayload = DecodeJwt(_resourceToken)?.Payload,
            TokenDecoded = _resourceToken is null
                ? "(no resource_token in challenge — identity-based flow)"
                : null,
        });
    }

    private async Task Step6FetchPersonMetadataAsync(CancellationToken ct)
    {
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        using var client = new HttpClient(capture);
        var url = $"{_options.PersonServerUrl!.TrimEnd('/')}/.well-known/aauth-person.json";
        await client.GetAsync(url, ct);
        var ex = capture.Last!;

        // Extract token_endpoint for step 7.
        var meta = JsonNode.Parse(ex.ResponseBody);
        _tokenEndpoint = (string?)meta?["token_endpoint"];

        Steps.Add(new StepRecord
        {
            Number = 6,
            Title = "Discover Person Server metadata",
            From = Actor.Agent,
            To = Actor.PersonServer,
            Narrative =
                "Unsigned discovery to the Person Server announces the token_endpoint " +
                "the agent will POST to. The PS's JWKS will be needed later to verify " +
                "the auth_token it returns.",
            RequestLine = $"{ex.RequestLine}  →  {url}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
        });
    }

    private async Task Step7TokenExchangeAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        // The exchange request is always signed with the AGENT token, never the
        // post-exchange auth token. The PS authenticates the agent identity.
        var signing = new AAuthSigningHandler(_agentKey!, () => _agentToken!)
        {
            InnerHandler = capture,
            OnSignatureBase = (_, b) => capturedBase = b,
        };
        using var client = new HttpClient(signing);

        using var resp = await client.PostAsJsonAsync(_tokenEndpoint!, new
        {
            resource_token = _resourceToken,
        }, ct);

        var ex = capture.Last!;
        var body = JsonNode.Parse(ex.ResponseBody);
        _authToken = (string?)body?["auth_token"];

        Steps.Add(new StepRecord
        {
            Number = 7,
            Title = "Token exchange",
            From = Actor.Agent,
            To = Actor.PersonServer,
            Narrative =
                "The agent POSTs the resource_token to the PS's token_endpoint. The " +
                "request is signed with the same agent key — the PS verifies the " +
                "signature, validates the resource_token, and (in a real PS) checks " +
                "user consent. On success it returns an `aa-auth+jwt` whose `cnf.jwk` " +
                "binds the new auth token to the same agent key.",
            RequestLine = $"{ex.RequestLine}  →  {_tokenEndpoint}",
            RequestHeaders = ex.RequestHeaders,
            RequestBody = PrettyJson(ex.RequestBody),
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            SignatureBase = capturedBase,
            TokenJwt = _authToken,
            TokenHeader = DecodeJwt(_authToken)?.Header,
            TokenPayload = DecodeJwt(_authToken)?.Payload,
        });
    }

    private async Task Step8RetryWithAuthTokenAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        var signing = new AAuthSigningHandler(_agentKey!, () => _authToken!)
        {
            InnerHandler = capture,
            OnSignatureBase = (_, b) => capturedBase = b,
        };
        using var client = new HttpClient(signing);

        await client.GetAsync(_options.WhoAmIUrl, ct);
        var ex = capture.Last!;

        Steps.Add(new StepRecord
        {
            Number = 8,
            Title = "Replay GET with auth token",
            From = Actor.Agent,
            To = Actor.Resource,
            Narrative =
                "Same request as step 4, but now the signature-key header carries the " +
                "PS-issued auth_token. The resource validates that the JWT is signed " +
                "by its PS, that its `cnf.jwk` matches the request signer, and returns " +
                "the protected payload.",
            RequestLine = $"{ex.RequestLine}  →  {_options.WhoAmIUrl}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            SignatureBase = capturedBase,
        });
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static (string Header, string Payload)? DecodeJwt(string? jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt)) return null;
        var parts = jwt.Split('.');
        if (parts.Length < 2) return null;
        string Decode(string seg) =>
            System.Text.Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(seg));
        return (PrettyJson(Decode(parts[0])), PrettyJson(Decode(parts[1])));
    }

    private static string PrettyJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return json ?? string.Empty;
        try
        {
            var node = JsonNode.Parse(json);
            return node?.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) ?? json;
        }
        catch (JsonException)
        {
            return json;
        }
    }
}
