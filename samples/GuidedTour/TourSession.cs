using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Agent;
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
    private string? _pendingUrl;
    private string? _interactionUrl;
    private string? _interactionCode;
    private bool _userApproved;
    private bool _aborted;
    private TourMode _mode;

    // Background polling state (deferred mode, step 10). Mutated from
    // the polling task; the UI listens to StateChanged and re-renders.
    private CancellationTokenSource? _pollingCts;
    private Task? _pollingTask;

    public TourSession(IOptions<TourOptions> options)
    {
        _options = options.Value;
        _mode = _options.Mode;
    }

    /// <summary>Ordered list of step records produced so far.</summary>
    public List<StepRecord> Steps { get; } = new();

    /// <summary>
    /// Which flow this session is running. Mutating this resets the
    /// timeline; the UI re-syncs the PS's consent store afterwards via
    /// <see cref="PrepareConsentStateAsync"/>.
    /// </summary>
    public TourMode Mode
    {
        get => _mode;
        set
        {
            if (_mode == value) { return; }
            _mode = value;
            Reset();
        }
    }

    /// <summary>True when this configuration supports flow switching (i.e. a PS URL is set).</summary>
    public bool CanSwitchMode => !string.IsNullOrWhiteSpace(_options.PersonServerUrl);

    /// <summary>True when the configured flow is the deferred / user-consent path.</summary>
    public bool IsDeferredMode =>
        !string.IsNullOrWhiteSpace(_options.PersonServerUrl)
        && _mode == TourMode.Deferred;

    /// <summary>Total number of steps the tour plans to run given the current configuration.</summary>
    public int TotalSteps
    {
        get
        {
            if (string.IsNullOrWhiteSpace(_options.PersonServerUrl)) return 4;
            return IsDeferredMode ? 11 : 8;
        }
    }

    /// <summary>
    /// Static plan describing every step in the current flow so the
    /// sidebar can show titles + descriptions before the steps have
    /// actually run. Recorded <see cref="StepRecord"/> values take
    /// precedence in the UI for steps that have already executed.
    /// </summary>
    public IReadOnlyList<TourPlanStep> Plan
    {
        get
        {
            if (string.IsNullOrWhiteSpace(_options.PersonServerUrl)) return IdentityPlan;
            return IsDeferredMode ? DeferredPlan : AutonomousPlan;
        }
    }

    private static readonly TourPlanStep[] IdentityPlan =
    {
        new(1, "Generate Ed25519 keypair", "Agent mints the durable signing key used on every AAuth request.", Actor.Agent, Actor.Agent),
        new(2, "Build agent token", "Agent builds an aa-agent+jwt with iss / sub / cnf.jwk.", Actor.Agent, Actor.Agent),
        new(3, "Discover resource metadata", "Unsigned GET /.well-known/aauth-resource.json.", Actor.Agent, Actor.Resource),
        new(4, "Signed GET / → 200", "Resource trusts identity alone (no PS), returns 200 + claims directly.", Actor.Agent, Actor.Resource),
    };

    private static readonly TourPlanStep[] AutonomousPlan =
    {
        new(1, "Generate Ed25519 keypair", "Agent mints the durable signing key used on every AAuth request.", Actor.Agent, Actor.Agent),
        new(2, "Build agent token", "Agent builds an aa-agent+jwt with iss / sub / cnf.jwk / ps claims.", Actor.Agent, Actor.Agent),
        new(3, "Discover resource metadata", "Unsigned GET /.well-known/aauth-resource.json.", Actor.Agent, Actor.Resource),
        new(4, "Signed GET / → 401", "Resource returns 401 with a resource_token + AAuth-Requirement.", Actor.Agent, Actor.Resource),
        new(5, "Parse the 401 challenge", "Decode the AAuth-Requirement header and resource_token claims.", Actor.Agent, Actor.Agent),
        new(6, "Discover Person Server", "Unsigned GET /.well-known/aauth-person.json for token_endpoint + jwks_uri.", Actor.Agent, Actor.PersonServer),
        new(7, "Exchange at PS → 200 auth_token", "Signed POST /token with the resource_token; PS mints an aa-auth+jwt immediately.", Actor.Agent, Actor.PersonServer),
        new(8, "Replay GET / with auth_token", "Signed retry carries the auth_token in Signature-Key → 200 + claims.", Actor.Agent, Actor.Resource),
    };

    private static readonly TourPlanStep[] DeferredPlan =
    {
        new(1, "Generate Ed25519 keypair", "Agent mints the durable signing key used on every AAuth request.", Actor.Agent, Actor.Agent),
        new(2, "Build agent token", "Agent builds an aa-agent+jwt with iss / sub / cnf.jwk / ps claims.", Actor.Agent, Actor.Agent),
        new(3, "Discover resource metadata", "Unsigned GET /.well-known/aauth-resource.json.", Actor.Agent, Actor.Resource),
        new(4, "Signed GET / → 401", "Resource returns 401 with a resource_token + AAuth-Requirement.", Actor.Agent, Actor.Resource),
        new(5, "Parse the 401 challenge", "Decode the AAuth-Requirement header and resource_token claims.", Actor.Agent, Actor.Agent),
        new(6, "Discover Person Server", "Unsigned GET /.well-known/aauth-person.json for token_endpoint + jwks_uri.", Actor.Agent, Actor.PersonServer),
        new(7, "Exchange → 202 Accepted", "PS lacks consent; returns 202 + Location + interaction URL + single-use code.", Actor.Agent, Actor.PersonServer),
        new(8, "Direct user to interaction URL", "Agent surfaces the {url}?code={code} link for the user to visit.", Actor.Agent, Actor.Agent),
        new(9, "User approves at the PS", "User opens the PS consent page in a new tab and clicks Approve; PS records consent.", Actor.PersonServer, Actor.PersonServer),
        new(10, "Poll pending URL → 200 auth_token", "Signed GETs to /pending/{id} until the PS mints the auth_token.", Actor.Agent, Actor.PersonServer),
        new(11, "Replay GET / with auth_token", "Signed retry carries the auth_token in Signature-Key → 200 + claims.", Actor.Agent, Actor.Resource),
    };

    /// <summary>True when no more steps remain.</summary>
    public bool IsComplete => _aborted || Steps.Count >= TotalSteps;

    /// <summary>
    /// True when the deferred flow terminated abnormally (user denied or
    /// the polling budget expired). The UI uses this to lock the run
    /// buttons and surface a hint to <em>Reset</em>.
    /// </summary>
    public bool IsAborted => _aborted;

    /// <summary>
    /// True when the tour is parked on the "User approves" step in deferred mode
    /// and the UI should expose the "Approve as user" action button.
    /// </summary>
    public bool AwaitingUserApproval =>
        IsDeferredMode && Steps.Count + 1 == 9 && !_userApproved;

    /// <summary>The user-facing interaction URL captured during step 7 (deferred only).</summary>
    public string? UserInteractionUrl => _interactionUrl is null || _interactionCode is null
        ? null
        : new AAuth.Headers.AAuthInteraction(_interactionUrl, _interactionCode).BuildUserUrl();

    /// <summary>Path portion of the pending URL (for compact UI display).</summary>
    public string? PendingUrlPath
    {
        get
        {
            if (string.IsNullOrEmpty(_pendingUrl)) return null;
            return Uri.TryCreate(_pendingUrl, UriKind.Absolute, out var uri)
                ? uri.PathAndQuery
                : _pendingUrl;
        }
    }

    /// <summary>True while a background poll loop is running against the pending URL.</summary>
    public bool IsPolling { get; private set; }

    /// <summary>Number of poll attempts made so far in the current background loop.</summary>
    public int PollCount { get; private set; }

    /// <summary>Wall-clock timestamp the current background poll loop began.</summary>
    public DateTimeOffset? PollingStartedAt { get; private set; }

    /// <summary>
    /// Fires whenever background state changes (each poll, polling
    /// start/stop, etc.). The UI subscribes and calls
    /// <c>InvokeAsync(StateHasChanged)</c> so the spinner stays live
    /// while the user is in another tab clicking Approve / Deny.
    /// </summary>
    public event Action? StateChanged;

    /// <summary>Reset state so the tour can be replayed from step 1.</summary>
    public void Reset()
    {
        // Stop any in-flight polling first so the background task
        // doesn't race against the fresh state.
        try { _pollingCts?.Cancel(); } catch { }
        _pollingCts?.Dispose();
        _pollingCts = null;
        _pollingTask = null;
        IsPolling = false;
        PollCount = 0;
        PollingStartedAt = null;

        Steps.Clear();
        _agentKey = null;
        _agentToken = null;
        _authToken = null;
        _resourceToken = null;
        _tokenEndpoint = null;
        _pendingUrl = null;
        _interactionUrl = null;
        _interactionCode = null;
        _userApproved = false;
        _aborted = false;
    }

    /// <summary>Run the next pending step and capture its <see cref="StepRecord"/>.</summary>
    public async Task RunNextAsync(CancellationToken ct = default)
    {
        var nextStep = Steps.Count + 1;
        if (IsDeferredMode)
        {
            switch (nextStep)
            {
                case 1: Step1GenerateKey(); break;
                case 2: Step2BuildAgentToken(); break;
                case 3: await Step3FetchResourceMetadataAsync(ct); break;
                case 4: await Step4SignedGetAsync(ct); break;
                case 5: Step5ParseChallenge(); break;
                case 6: await Step6FetchPersonMetadataAsync(ct); break;
                case 7: await Step7DeferredExchangeAsync(ct); break;
                case 8: Step8DirectUserToInteraction(); break;
                case 9: Step9UserApprovesPlaceholder(); break;
                case 10:
                    // Polling may already have started in the background
                    // (the UI calls StartPendingPollAsync the moment the
                    // user opens the consent tab). If so, just await it
                    // — don't kick off a second loop.
                    if (_pollingTask is { } existing && !existing.IsCompleted)
                    {
                        await existing.ConfigureAwait(false);
                    }
                    else if (Steps.Count + 1 == 10)
                    {
                        await Step10PollPendingAsync(ct);
                    }
                    break;
                case 11: await Step11RetryWithAuthTokenAsync(ct); break;
            }
        }
        else
        {
            switch (nextStep)
            {
                case 1: Step1GenerateKey(); break;
                case 2: Step2BuildAgentToken(); break;
                case 3: await Step3FetchResourceMetadataAsync(ct); break;
                case 4: await Step4SignedGetAsync(ct); break;
                case 5: Step5ParseChallenge(); break;
                case 6: await Step6FetchPersonMetadataAsync(ct); break;
                case 7: await Step7TokenExchangeAsync(ct); break;
                case 8: await Step8RetryWithAuthTokenAsync(ct, stepNumber: 8); break;
            }
        }
    }

    /// <summary>
    /// Records step 9: the user opened the PS's interaction page in a
    /// separate browser tab and (hopefully) clicked Approve. The Guided
    /// Tour itself does not make the HTTP call here — that happens
    /// out-of-band, between the user's browser and the Person Server,
    /// exactly as the spec intends. Step 10's poll picks up the result.
    /// </summary>
    public Task RecordUserApprovalOpenedAsync(CancellationToken ct = default)
    {
        if (!IsDeferredMode) { return Task.CompletedTask; }
        if (Steps.Count + 1 != 9)
        {
            throw new InvalidOperationException(
                $"RecordUserApprovalOpenedAsync called at step {Steps.Count + 1}; only valid at step 9.");
        }

        var userUrl = UserInteractionUrl ?? "(no interaction URL captured)";
        _userApproved = true;

        Steps.Add(new StepRecord
        {
            Number = 9,
            Title = "User completes interaction at Person Server",
            From = Actor.PersonServer,
            To = Actor.PersonServer,
            Narrative =
                "The tour opened the PS's interaction URL in a new browser tab. " +
                "The Person Server rendered its consent screen (the agent + resource + " +
                "scope of this request), the user clicked **Approve**, and the PS " +
                "recorded consent in its store via `POST /interaction/approve`. " +
                "All of that happens in the user's browser → PS channel — the agent " +
                "is not on this path. The agent will discover the result on its next " +
                "poll of the pending URL (step 10).",
            ResponseBody = userUrl,
            TokenDecoded =
                $"Interaction URL opened in new tab:\n  {userUrl}\n\n" +
                "User performed (browser → PS):\n" +
                $"  GET  /interaction?code={_interactionCode}\n" +
                $"  POST /interaction/approve  (form: code={_interactionCode})",
        });
        return Task.CompletedTask;
    }

    /// <summary>
    /// Ensure MockPersonServer's consent store matches what this mode
    /// expects: revoke for deferred (so the exchange genuinely 202s),
    /// grant for autonomous (so RequireConsent=true MockPS instances
    /// still happily mint without interaction).
    /// </summary>
    public async Task PrepareConsentStateAsync(CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_options.PersonServerUrl)) { return; }
        var endpoint = IsDeferredMode ? "/admin/revoke" : "/admin/consent";
        var url = $"{_options.PersonServerUrl!.TrimEnd('/')}{endpoint}";
        using var client = new HttpClient();
        try
        {
            await client.PostAsJsonAsync(url, new
            {
                agent = _options.AgentId,
                resource = _options.WhoAmIUrl.TrimEnd('/'),
                scope = "whoami",
            }, ct);
        }
        catch
        {
            // The /admin endpoints only exist on MockPersonServer; against
            // a real PS this call will 404 / fail. That's fine — autonomous
            // mode against a real PS doesn't need it, and deferred mode
            // against a real PS won't be exercised in the demo. Swallow.
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
        // Normalize whitespace/empty PersonServerUrl to null so identity-based
        // (steps 1–4) mode works — AgentTokenBuilder treats any non-null value
        // as "present" and validates it as an https URL.
        var personServer = string.IsNullOrWhiteSpace(_options.PersonServerUrl)
            ? null
            : _options.PersonServerUrl;
        _agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = _options.AgentId,
            KeyId = "tour",
            Key = _agentKey!,
            PersonServer = personServer,
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

    private async Task Step8RetryWithAuthTokenAsync(CancellationToken ct, int stepNumber)
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
            Number = stepNumber,
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
    // Deferred-flow step variants
    // -----------------------------------------------------------------

    private async Task Step7DeferredExchangeAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
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

        // Deferred mode expects 202 + Location + AAuth-Requirement interaction.
        if (resp.StatusCode == HttpStatusCode.Accepted)
        {
            var location = resp.Headers.Location?.ToString();
            if (location is not null)
            {
                _pendingUrl = location.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? location
                    : $"{_options.PersonServerUrl!.TrimEnd('/')}{location}";
            }

            if (resp.Headers.TryGetValues(AAuthRequirementHeader.Name, out var reqVals))
            {
                foreach (var raw in reqVals)
                {
                    if (string.IsNullOrWhiteSpace(raw)) { continue; }
                    try
                    {
                        var parsed = AAuthRequirementHeader.Parse(raw);
                        var interaction = AAuth.Headers.AAuthInteraction.FromRequirement(parsed);
                        if (interaction is not null)
                        {
                            _interactionUrl = interaction.Url;
                            _interactionCode = interaction.Code;
                            break;
                        }
                    }
                    catch (FormatException) { /* try the next header value */ }
                }
            }
        }

        Steps.Add(new StepRecord
        {
            Number = 7,
            Title = "Exchange → 202 Accepted",
            From = Actor.Agent,
            To = Actor.PersonServer,
            Narrative =
                "The agent POSTs the resource_token, but this PS requires user consent. " +
                "Instead of an `aa-auth+jwt`, it returns `202 Accepted` with a `Location` " +
                "pointing at a pending URL the agent will poll, plus an " +
                "`AAuth-Requirement: requirement=interaction` header carrying the " +
                "user-facing interaction URL and a single-use code.",
            RequestLine = $"{ex.RequestLine}  →  {_tokenEndpoint}",
            RequestHeaders = ex.RequestHeaders,
            RequestBody = PrettyJson(ex.RequestBody),
            SignatureBase = capturedBase,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
        });
    }

    private void Step8DirectUserToInteraction()
    {
        var userUrl = UserInteractionUrl
            ?? "(no interaction URL captured — is MockPersonServer running with RequireConsent=true?)";

        Steps.Add(new StepRecord
        {
            Number = 8,
            Title = "Direct user to interaction URL",
            From = Actor.Agent,
            To = Actor.Agent,
            Narrative =
                "The agent now has to involve its user. It constructs the user-facing URL " +
                "as `{url}?code={code}` and surfaces it through whatever channel the " +
                "agent has — a browser redirect, a QR code on a phone agent, or just " +
                "displaying the link. The `code` is single-use and ties the upcoming " +
                "user session at the PS back to this specific pending request.",
            ResponseBody = userUrl,
            TokenDecoded = $"Interaction URL:  {_interactionUrl}\nCode:             {_interactionCode}",
        });
    }

    private void Step9UserApprovesPlaceholder()
    {
        // Placeholder branch: should not be reachable because the UI must
        // call ApproveAsUserAsync() when at step 9. Defensive fallback in
        // case "Run all" is invoked — it cannot proceed past step 9 on its
        // own, the user must click "Approve as user".
        if (!_userApproved)
        {
            throw new InvalidOperationException(
                "Step 9 requires the user to click \"Approve as user\". Call ApproveAsUserAsync() instead of RunNextAsync().");
        }
    }

    private async Task Step10PollPendingAsync(CancellationToken ct)
    {
        if (string.IsNullOrEmpty(_pendingUrl))
        {
            throw new InvalidOperationException(
                "No pending URL captured — Step 7 did not record a 202 response.");
        }

        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        string? capturedBase = null;
        var signing = new AAuthSigningHandler(_agentKey!, () => _agentToken!)
        {
            InnerHandler = capture,
            OnSignatureBase = (_, b) => capturedBase = b,
        };
        using var client = new HttpClient(signing);
        var pollerOptions = new DeferredPollerOptions
        {
            // Generous budget: in deferred mode the user has to flip to
            // another tab, read the consent screen, and click Approve.
            MaxTotalWait = TimeSpan.FromMinutes(2),
            DefaultPollInterval = TimeSpan.FromMilliseconds(500),
            MinPollInterval = TimeSpan.Zero,
        };
        var poller = new DeferredPoller(client, pollerOptions)
        {
            // Each completed poll bumps PollCount + fires StateChanged
            // so the UI spinner stays alive while the user is in their
            // PS consent tab. Runs on the polling task's thread —
            // handlers must marshal to the UI synchronization context.
            OnPoll = _ =>
            {
                PollCount++;
                StateChanged?.Invoke();
            },
        };

        IsPolling = true;
        PollCount = 0;
        PollingStartedAt = DateTimeOffset.UtcNow;
        StateChanged?.Invoke();

        HttpResponseMessage? terminal = null;
        try
        {
            terminal = await poller.PollAsync(new Uri(_pendingUrl), ct);

            // 403 access_denied → user clicked Deny on the PS consent
            // page. Record a terminal "denied" step and abort the flow.
            if (terminal.StatusCode == HttpStatusCode.Forbidden)
            {
                var deniedBody = await terminal.Content.ReadAsStringAsync(ct);
                var deniedJson = JsonNode.Parse(deniedBody) as JsonObject;
                if ((string?)deniedJson?["error"] == "access_denied")
                {
                    RecordDeniedStep(capture.Last!, capturedBase, deniedBody);
                    _aborted = true;
                    return;
                }
            }

            var ex = capture.Last!;
            var body = JsonNode.Parse(ex.ResponseBody);
            _authToken = (string?)body?["auth_token"];

            Steps.Add(new StepRecord
            {
                Number = 10,
                Title = "Poll pending URL → auth_token",
                From = Actor.Agent,
                To = Actor.PersonServer,
                Narrative =
                    "While the user clicks through the PS's interaction page, the agent " +
                    "polls the pending URL with a signed `GET`. Each request honors the " +
                    "PS's `Retry-After` cadence. Once consent is recorded the PS responds " +
                    "with `200 OK` and the long-awaited `aa-auth+jwt`, bound (via " +
                    "`cnf.jwk`) to the agent's signing key. If the user clicks **Deny** " +
                    "instead, this step records a `403 access_denied` and the flow aborts.",
                RequestLine = $"{ex.RequestLine}  →  {_pendingUrl}",
                RequestHeaders = ex.RequestHeaders,
                SignatureBase = capturedBase,
                StatusLine = ex.StatusLine,
                ResponseHeaders = ex.ResponseHeaders,
                ResponseBody = PrettyJson(ex.ResponseBody),
                TokenJwt = _authToken,
                TokenHeader = DecodeJwt(_authToken)?.Header,
                TokenPayload = DecodeJwt(_authToken)?.Payload,
            });
        }
        catch (TimeoutException tex)
        {
            // The user neither approved nor denied within the polling
            // budget — record a terminal timeout step and abort.
            RecordTimeoutStep(capture.Last, capturedBase, tex.Message);
            _aborted = true;
        }
        finally
        {
            terminal?.Dispose();
            IsPolling = false;
            StateChanged?.Invoke();
        }
    }

    /// <summary>
    /// Kicks off step 10's pending-URL poll loop as a fire-and-forget
    /// background task so the UI can keep rendering while the user is
    /// in another tab clicking Approve / Deny at the PS consent page.
    /// Subsequent calls while a poll is already in flight are no-ops.
    /// The task completes when the PS terminates (200 / 403 / 404) or
    /// the polling budget expires; the UI listens to
    /// <see cref="StateChanged"/> for per-poll updates.
    /// </summary>
    public Task StartPendingPollAsync()
    {
        if (!IsDeferredMode || _pendingUrl is null)
        {
            return Task.CompletedTask;
        }
        if (_pollingTask is not null && !_pollingTask.IsCompleted)
        {
            return _pollingTask;
        }
        // Step 10 must be the next step in line. If somebody calls this
        // out of order (defensive), bail out silently.
        if (Steps.Count + 1 != 10)
        {
            return Task.CompletedTask;
        }

        _pollingCts?.Dispose();
        _pollingCts = new CancellationTokenSource();
        var ct = _pollingCts.Token;
        _pollingTask = Task.Run(async () =>
        {
            try
            {
                await Step10PollPendingAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // User clicked Reset / changed mode while polling.
            }
            catch (Exception ex)
            {
                RecordTimeoutStep(null, null,
                    $"Background poll threw {ex.GetType().Name}: {ex.Message}");
                _aborted = true;
                IsPolling = false;
                StateChanged?.Invoke();
            }
        });
        return _pollingTask;
    }

    private void RecordDeniedStep(
        CapturedExchange last,
        string? capturedBase,
        string deniedBody)
    {
        Steps.Add(new StepRecord
        {
            Number = 10,
            Title = "Poll pending URL → 403 access_denied (user denied)",
            From = Actor.Agent,
            To = Actor.PersonServer,
            Narrative =
                "The user clicked **Deny** on the PS's interaction page. The PS marked " +
                "the pending entry as denied and the next poll receives " +
                "`403 Forbidden` with `error: \"access_denied\"`. The agent's SDK " +
                "raises `AAuthInteractionDeniedException` so callers can distinguish " +
                "denial from an unknown / expired pending id (which would be `404`). " +
                "The tour is now in a terminal state — click **Reset** to start over.",
            RequestLine = $"{last.RequestLine}  →  {_pendingUrl}",
            RequestHeaders = last.RequestHeaders,
            SignatureBase = capturedBase,
            StatusLine = last.StatusLine,
            ResponseHeaders = last.ResponseHeaders,
            ResponseBody = PrettyJson(deniedBody),
        });
    }

    private void RecordTimeoutStep(
        CapturedExchange? last,
        string? capturedBase,
        string detail)
    {
        Steps.Add(new StepRecord
        {
            Number = 10,
            Title = "Poll pending URL → timeout (user did not respond)",
            From = Actor.Agent,
            To = Actor.PersonServer,
            Narrative =
                "The polling budget expired before the user took any action at the " +
                "PS's interaction page (no Approve, no Deny). The SDK surfaces this as " +
                "`AAuthInteractionTimeoutException`. The pending entry on the PS may " +
                "still be live — but the agent has given up. The tour is now in a " +
                "terminal state — click **Reset** to start over.\n\n" +
                $"Detail: {detail}",
            RequestLine = last is null ? null : $"{last.RequestLine}  →  {_pendingUrl}",
            RequestHeaders = last?.RequestHeaders,
            SignatureBase = capturedBase,
            StatusLine = last?.StatusLine,
            ResponseHeaders = last?.ResponseHeaders,
            ResponseBody = last is null ? null : PrettyJson(last.ResponseBody),
        });
    }

    /// <summary>
    /// Simulates the user clicking <strong>Deny</strong> on the PS's
    /// consent page by POSTing the interaction code to
    /// <c>/interaction/deny</c> directly from the tour process. Used by
    /// the Guided Tour UI so the Deny path can be demoed without the
    /// user having to navigate to the PS page themselves.
    /// </summary>
    public async Task SimulateUserDenyAsync(CancellationToken ct = default)
    {
        if (!IsDeferredMode || _interactionUrl is null || _interactionCode is null)
        {
            throw new InvalidOperationException(
                "SimulateUserDenyAsync is only valid in deferred mode after step 7.");
        }
        if (Steps.Count + 1 != 9)
        {
            throw new InvalidOperationException(
                $"SimulateUserDenyAsync called at step {Steps.Count + 1}; only valid at step 9.");
        }

        // The interaction URL is `{ps}/interaction`; deny lives at
        // `{ps}/interaction/deny`. Strip any trailing slash and append.
        var denyUrl = _interactionUrl.TrimEnd('/') + "/deny";
        using var client = new HttpClient();
        using var content = new FormUrlEncodedContent(
            new Dictionary<string, string> { ["code"] = _interactionCode });
        using var resp = await client.PostAsync(denyUrl, content, ct);
        // Best-effort: even if this 404s (e.g. running against a real PS
        // without a deny endpoint), let the poller catch up and surface
        // the failure on step 10. Throwing here would leave the timeline
        // in an inconsistent state.

        _userApproved = true; // unblocks AwaitingUserApproval so step 10 runs
        Steps.Add(new StepRecord
        {
            Number = 9,
            Title = "User denies interaction at Person Server",
            From = Actor.PersonServer,
            To = Actor.PersonServer,
            Narrative =
                "The tour simulated the user clicking **Deny** on the PS's consent " +
                "page (`POST /interaction/deny` with the single-use code). The PS " +
                "marks the pending entry as denied; the next poll (step 10) will see " +
                "`403 access_denied` and the flow will terminate.",
            ResponseBody = denyUrl,
            TokenDecoded =
                $"Simulated POST /interaction/deny  (form: code={_interactionCode})\n" +
                $"Status: {(int)resp.StatusCode} {resp.ReasonPhrase}",
        });
    }

    private async Task Step11RetryWithAuthTokenAsync(CancellationToken ct)
        => await Step8RetryWithAuthTokenAsync(ct, stepNumber: 11);

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
