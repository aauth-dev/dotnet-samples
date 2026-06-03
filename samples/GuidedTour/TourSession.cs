using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth;
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
public sealed class TourSession : IAsyncDisposable
{
    private readonly TourOptions _options;
    private readonly TourAgentIdentity _selfIdentity;

    private AAuthKey? _agentKey;
    private AAuthKey? _ephemeralKey;
    private string? _agentToken;
    private string? _assignedKeyId;
    private string? _agentJwksUri;
    private string? _authToken;
    private string? _resourceToken;
    private string? _tokenEndpoint;
    private string? _pendingUrl;
    private string? _interactionUrl;
    private string? _interactionCode;
    private bool _userApproved;
    // True once the federated exchange (step 5) came back 202 — the AS (Keycloak)
    // needs an interactive login/consent, so the flow grows the consent + poll
    // steps (mirroring deferred mode). Stays false against an auto-allow stub AS.
    private bool _federatedPending;
    // True once the call-chain exchange (step 5) came back 202 — neither hop has
    // standing consent, so the flow grows TWO consent + poll cycles (hop 1:
    // Agent → Orchestrator at the PS; hop 2: the Orchestrator's CHAINED 202 for
    // Orchestrator → WhoAmI). Stays false when both hops have standing consent.
    private bool _callChainPending;
    private bool _aborted;
    private TourMode _mode;

    // Background polling state (deferred mode, poll step). Mutated from
    // the polling task; the UI listens to StateChanged and re-renders.
    private CancellationTokenSource? _pollingCts;
    private Task? _pollingTask;
    private readonly object _pollingLock = new();

    public TourSession(IOptions<TourOptions> options, TourAgentIdentity selfIdentity)
    {
        _options = options.Value;
        _selfIdentity = selfIdentity;
        _mode = _options.Mode;
    }

    /// <summary>Ordered list of step records produced so far for the active flow.</summary>
    public List<StepRecord> Steps { get; } = new();

    /// <summary>
    /// Which flow this session is running. Mutating this fully resets
    /// agent state so each flow demonstrates the complete lifecycle
    /// from key generation through enrollment.
    /// The UI re-syncs the PS's consent store afterwards via
    /// <see cref="PrepareConsentStateAsync"/>.
    /// </summary>
    public TourMode Mode
    {
        get => _mode;
        set
        {
            if (_mode == value) { return; }
            _mode = value;
            // Each flow is self-contained: fresh key + enrollment so the
            // user sees the full sequence every time.
            Reset();
        }
    }

    /// <summary>True when a Person Server URL is configured. The picker is always shown; this just controls whether the three-party options are selectable.</summary>
    public bool HasPersonServer => !string.IsNullOrWhiteSpace(_options.PersonServerUrl);

    /// <summary>
    /// Which Signature-Key scheme the agent uses for identity-based access.
    /// Only meaningful in the Identity flow (hwk or jwks_uri) — three-party
    /// flows (Autonomous/Deferred) always use jwt (requires PS) per spec.
    /// </summary>
    public SigningMode SigningMode
    {
        get => _signingMode;
        set
        {
            if (_signingMode == value) return;
            _signingMode = value;
            // Fresh enrollment per flow keeps each run isolated and
            // shows the full bootstrap→request sequence.
            Reset();
        }
    }
    private SigningMode _signingMode = SigningMode.Hwk;

    /// <summary>
    /// The effective signing mode for the current flow. Identity flow
    /// respects the user's choice; three-party flows force jwt.
    /// </summary>
    private SigningMode EffectiveSigningMode =>
        Mode is TourMode.Identity ? SigningMode : SigningMode.Jwt;

    /// <summary>Kept for backwards compatibility — always true now that the picker is always rendered.</summary>
    public bool CanSwitchMode => true;

    /// <summary>
    /// The effective WhoAmI endpoint URL for the current signing mode.
    /// Identity-based modes target dedicated paths; three-party targets /jwt.
    /// </summary>
    private string EffectiveResourceUrl => EffectiveSigningMode switch
    {
        SigningMode.Hwk => $"{_options.WhoAmIUrl.TrimEnd('/')}/hwk",
        SigningMode.JktJwt => $"{_options.WhoAmIUrl.TrimEnd('/')}/jkt-jwt",
        SigningMode.JwksUri => $"{_options.WhoAmIUrl.TrimEnd('/')}/jwks-uri",
        _ => $"{_options.WhoAmIUrl.TrimEnd('/')}/jwt",
    };

    /// <summary>
    /// True when the current flow is the identity-based path. Forced on
    /// when no PS URL is configured, regardless of <see cref="Mode"/>.
    /// </summary>
    public bool IsIdentityMode =>
        _mode == TourMode.Identity || (!HasPersonServer && _mode != TourMode.Bootstrap);

    /// <summary>True when the configured flow is the deferred / user-consent path.</summary>
    public bool IsDeferredMode =>
        HasPersonServer && _mode == TourMode.Deferred;

    /// <summary>True when the current flow is the bootstrap (keygen + AP enrolment) path.</summary>
    public bool IsBootstrapMode => _mode == TourMode.Bootstrap;

    /// <summary>True when the configured flow is autonomous (standing consent, no user interaction).</summary>
    public bool IsAutonomousMode => HasPersonServer && _mode == TourMode.Autonomous;

    /// <summary>True when the current flow is the call-chain (multi-agent) path.</summary>
    public bool IsCallChainMode => HasPersonServer && _mode == TourMode.CallChain && HasOrchestrator;

    /// <summary>True when the current flow is the four-party federated path.</summary>
    public bool IsFederatedMode => HasPersonServer && _mode == TourMode.Federated && HasAccessServer;

    /// <summary>
    /// True when the call-chain flow has entered its multi-hop consent path:
    /// the agent's exchange 202'd (no standing consent), so the flow surfaces
    /// two user approvals — hop 1 (Agent → Orchestrator) and hop 2 (the
    /// Orchestrator's chained 202 for Orchestrator → WhoAmI).
    /// </summary>
    public bool IsCallChainPending => IsCallChainMode && _callChainPending;

    /// <summary>True when an Orchestrator URL is configured.</summary>
    public bool HasOrchestrator => !string.IsNullOrWhiteSpace(_options.OrchestratorUrl);

    /// <summary>True when an Access Server URL is configured for the federated flow.</summary>
    public bool HasAccessServer => !string.IsNullOrWhiteSpace(_options.AccessServerUrl);

    /// <summary>True when an Agent Provider URL is configured for real AP enrolment.</summary>
    public bool HasAgentProvider => !string.IsNullOrWhiteSpace(_options.AgentProviderUrl);

    /// <summary>Total number of steps in the current flow.</summary>
    public int TotalSteps
    {
        get
        {
            if (IsBootstrapMode) return HasAgentProvider ? 3 : 2;
            if (IsIdentityMode) return 2;
            if (IsCallChainMode) return _callChainPending ? 13 : 7;
            if (IsFederatedMode) return _federatedPending ? 10 : 7;
            return IsDeferredMode ? 9 : 6;
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
            if (IsBootstrapMode) return HasAgentProvider ? ApBootstrapPlan : LocalBootstrapPlan;
            if (IsIdentityMode) return IdentityPlan;
            if (IsCallChainMode) return _callChainPending ? CallChainConsentPlan : CallChainPlan;
            if (IsFederatedMode) return _federatedPending ? FederatedConsentPlan : FederatedPlan;
            return IsDeferredMode ? DeferredPlan : AutonomousPlan;
        }
    }

    private static readonly TourPlanStep[] LocalBootstrapPlan =
    {
        new(1, "Generate Ed25519 keypair", "Agent mints the durable signing key.", Actor.Agent, Actor.Agent),
        new(2, "Build agent token", "Agent self-signs an aa-agent+jwt (demo mode).", Actor.Agent, Actor.Agent),
    };

    private static readonly TourPlanStep[] ApBootstrapPlan =
    {
        new(1, "Generate Ed25519 keypair", "Agent mints a fresh signing key.", Actor.Agent, Actor.Agent),
        new(2, "Discover Agent Provider", "GET /.well-known/aauth-agent.json to learn the AP's enrol endpoint.", Actor.Agent, Actor.AgentProvider),
        new(3, "Enrol with Agent Provider", "POST /enrol with {agent_id, jwk}; AP issues aa-agent+jwt.", Actor.Agent, Actor.AgentProvider),
    };

    private static readonly TourPlanStep[] IdentityPlan =
    {
        new(1, "Discover resource metadata", "Unsigned GET /.well-known/aauth-resource.json.", Actor.Agent, Actor.Resource),
        new(2, "Signed GET → 200", "Resource trusts identity alone (no PS) on the per-mode endpoint (/hwk, /jwks-uri, /jkt-jwt), returns 200 + claims directly.", Actor.Agent, Actor.Resource),
    };

    private static readonly TourPlanStep[] AutonomousPlan =
    {
        new(1, "Discover resource metadata", "Unsigned GET /.well-known/aauth-resource.json.", Actor.Agent, Actor.Resource),
        new(2, "Signed GET /jwt → 401", "Resource returns 401 with a resource_token + AAuth-Requirement.", Actor.Agent, Actor.Resource),
        new(3, "Parse the 401 challenge", "Decode the AAuth-Requirement header and resource_token claims.", Actor.Agent, Actor.Agent),
        new(4, "Discover Person Server", "Unsigned GET /.well-known/aauth-person.json for token_endpoint + jwks_uri.", Actor.Agent, Actor.PersonServer),
        new(5, "Exchange at PS → 200 auth_token", "Signed POST /token with the resource_token; PS mints an aa-auth+jwt immediately.", Actor.Agent, Actor.PersonServer),
        new(6, "Replay GET /jwt with auth_token", "Signed retry carries the auth_token in Signature-Key → 200 + claims.", Actor.Agent, Actor.Resource),
    };

    private static readonly TourPlanStep[] DeferredPlan =
    {
        new(1, "Discover resource metadata", "Unsigned GET /.well-known/aauth-resource.json.", Actor.Agent, Actor.Resource),
        new(2, "Signed GET /jwt → 401", "Resource returns 401 with a resource_token + AAuth-Requirement.", Actor.Agent, Actor.Resource),
        new(3, "Parse the 401 challenge", "Decode the AAuth-Requirement header and resource_token claims.", Actor.Agent, Actor.Agent),
        new(4, "Discover Person Server", "Unsigned GET /.well-known/aauth-person.json for token_endpoint + jwks_uri.", Actor.Agent, Actor.PersonServer),
        new(5, "Exchange → 202 Accepted", "PS lacks consent; returns 202 + Location + interaction URL + single-use code.", Actor.Agent, Actor.PersonServer),
        new(6, "Direct user to interaction URL", "Agent surfaces the {url}?code={code} link for the user to visit.", Actor.Agent, Actor.Agent),
        new(7, "User approves at the PS", "User opens the PS consent page in a new tab and clicks Approve; PS records consent.", Actor.PersonServer, Actor.PersonServer),
        new(8, "Poll pending URL → 200 auth_token", "Signed GETs to /pending/{id} until the PS mints the auth_token.", Actor.Agent, Actor.PersonServer),
        new(9, "Replay GET /jwt with auth_token", "Signed retry carries the auth_token in Signature-Key → 200 + claims.", Actor.Agent, Actor.Resource),
    };

    private static readonly TourPlanStep[] CallChainPlan =
    {
        new(1, "Discover Orchestrator metadata", "Unsigned GET /.well-known/aauth-resource.json on the Orchestrator.", Actor.Agent, Actor.Orchestrator),
        new(2, "Signed GET → 401 (agent token challenge)", "Orchestrator returns 401 with a resource_token — it requires an auth token.", Actor.Agent, Actor.Orchestrator),
        new(3, "Parse the 401 challenge", "Decode the AAuth-Requirement header and Orchestrator's resource_token.", Actor.Agent, Actor.Agent),
        new(4, "Discover Person Server", "Unsigned GET /.well-known/aauth-person.json for token_endpoint.", Actor.Agent, Actor.PersonServer),
        new(5, "Exchange at PS → auth_token", "Signed POST /token with the Orchestrator's resource_token; PS mints auth_token.", Actor.Agent, Actor.PersonServer),
        new(6, "Retry Orchestrator with auth_token", "Signed GET with auth_token → Orchestrator chains downstream.", Actor.Agent, Actor.Orchestrator),
        new(7, "Inspect multi-agent result", "Review the combined response showing the full Agent → Orchestrator → WhoAmI chain.", Actor.Agent, Actor.Agent),
    };

    // The call-chain flow when NEITHER hop has standing consent. Each hop the
    // agent can see surfaces its own user approval: hop 1 is the agent's own PS
    // exchange (202 → consent for Agent → Orchestrator); hop 2 is the
    // Orchestrator's CHAINED 202 (it has no user, so it re-emits its own 202 for
    // Orchestrator → WhoAmI, which the agent relays). The Orchestrator's internal
    // hops are shown as grouped sub-steps, not separate visible steps.
    private static readonly TourPlanStep[] CallChainConsentPlan =
    {
        new(1, "Discover Orchestrator metadata", "Unsigned GET /.well-known/aauth-resource.json on the Orchestrator.", Actor.Agent, Actor.Orchestrator),
        new(2, "Signed GET → 401 (agent token challenge)", "Orchestrator returns 401 with a resource_token — it requires an auth token.", Actor.Agent, Actor.Orchestrator),
        new(3, "Parse the 401 challenge", "Decode the AAuth-Requirement header and Orchestrator's resource_token.", Actor.Agent, Actor.Agent),
        new(4, "Discover Person Server", "Unsigned GET /.well-known/aauth-person.json for token_endpoint.", Actor.Agent, Actor.PersonServer),
        new(5, "Exchange → 202 (hop 1 consent)", "No standing consent for the Orchestrator; PS returns 202 + interaction URL + single-use code.", Actor.Agent, Actor.PersonServer),
        new(6, "Direct user to interaction URL (hop 1)", "Agent surfaces the {url}?code={code} link to approve the Agent → Orchestrator hop.", Actor.Agent, Actor.Agent),
        new(7, "User approves hop 1 at the PS", "User opens the PS consent page and approves Agent → Orchestrator; PS records consent.", Actor.PersonServer, Actor.PersonServer),
        new(8, "Poll pending URL → auth_token", "Signed GETs to /pending/{id} until the PS mints the Orchestrator-audience auth_token.", Actor.Agent, Actor.PersonServer),
        new(9, "Retry Orchestrator → 202 (hop 2 chained)", "Orchestrator calls WhoAmI; that hop needs consent too, so it re-emits its OWN 202 (interaction chaining).", Actor.Agent, Actor.Orchestrator),
        new(10, "Direct user to interaction URL (hop 2)", "Agent relays the Orchestrator's chained interaction URL to approve Orchestrator → WhoAmI.", Actor.Agent, Actor.Agent),
        new(11, "User approves hop 2 at the PS", "User approves Orchestrator → WhoAmI at the PS; PS records consent for the chained hop.", Actor.PersonServer, Actor.PersonServer),
        new(12, "Poll Orchestrator pending → 200", "Signed GETs to the Orchestrator's pending URL until it re-drives the chain and returns 200.", Actor.Agent, Actor.Orchestrator),
        new(13, "Inspect multi-agent result", "Review the combined response showing the full Agent → Orchestrator → WhoAmI chain.", Actor.Agent, Actor.Agent),
    };

    private static readonly TourPlanStep[] FederatedPlan =
    {
        new(1, "Discover resource metadata", "Unsigned GET /federated/.well-known/aauth-resource.json.", Actor.Agent, Actor.Resource),
        new(2, "Signed GET /federated → 401", "Resource returns 401 with a resource_token whose aud is the Access Server (not the PS).", Actor.Agent, Actor.Resource),
        new(3, "Parse the 401 challenge", "Decode the resource_token — its aud=Access Server URL is the four-party tell.", Actor.Agent, Actor.Agent),
        new(4, "Discover Person Server", "Unsigned GET /.well-known/aauth-person.json for token_endpoint.", Actor.Agent, Actor.PersonServer),
        new(5, "Exchange at PS → AS federation → auth_token", "Signed POST /token; the PS sees aud≠self, federates to the AS, and the AS mints the aa-auth+jwt.", Actor.Agent, Actor.PersonServer),
        new(6, "Replay GET /federated with auth_token", "Signed retry carries the AS-issued auth_token → 200 + claims.", Actor.Agent, Actor.Resource),
        new(7, "Inspect federated result", "Review the AS-minted auth token: dwk=aauth-access.json, cnf.jwk bound to the agent key.", Actor.Agent, Actor.Agent),
    };

    // The federated flow when the Access Server requires an interactive
    // login/consent. The PS relays the AS's 202 interaction back to the agent,
    // which surfaces the consent link and polls the pending URL — structurally
    // identical to deferred mode, but the consent screen is the Access
    // Server's (its own stub screen, or Keycloak) rather than the PS's. From
    // the agent's perspective the two are identical; only the interaction URL's
    // destination differs.
    private static readonly TourPlanStep[] FederatedConsentPlan =
    {
        new(1, "Discover resource metadata", "Unsigned GET /federated/.well-known/aauth-resource.json.", Actor.Agent, Actor.Resource),
        new(2, "Signed GET /federated → 401", "Resource returns 401 with a resource_token whose aud is the Access Server (not the PS).", Actor.Agent, Actor.Resource),
        new(3, "Parse the 401 challenge", "Decode the resource_token — its aud=Access Server URL is the four-party tell.", Actor.Agent, Actor.Agent),
        new(4, "Discover Person Server", "Unsigned GET /.well-known/aauth-person.json for token_endpoint.", Actor.Agent, Actor.PersonServer),
        new(5, "Exchange → 202 (AS needs consent)", "PS federates to the AS; the AS needs the user to consent, so the PS relays a 202 + interaction URL.", Actor.Agent, Actor.PersonServer),
        new(6, "Direct user to AS consent", "Agent surfaces the AS interaction link ({url}?code={code}) for the user to approve at the Access Server.", Actor.Agent, Actor.Agent),
        new(7, "User consents at the AS", "User opens the Access Server consent screen (its own stub screen, or a Keycloak login), authenticates, and approves; the AS records the verdict.", Actor.AccessServer, Actor.AccessServer),
        new(8, "Poll pending URL → 200 auth_token", "Signed GETs to the PS pending URL until the AS verdict resolves and the PS relays the aa-auth+jwt.", Actor.Agent, Actor.PersonServer),
        new(9, "Replay GET /federated with auth_token", "Signed retry carries the AS-issued auth_token → 200 + claims.", Actor.Agent, Actor.Resource),
        new(10, "Inspect federated result", "Review the AS-minted auth token: dwk=aauth-access.json, cnf.jwk bound to the agent key.", Actor.Agent, Actor.Agent),
    };

    /// <summary>True when no more steps remain in the current flow.</summary>
    public bool IsComplete => _aborted || Steps.Count >= TotalSteps;

    /// <summary>
    /// True when the deferred flow terminated abnormally (user denied or
    /// the polling budget expired). The UI uses this to lock the run
    /// buttons and surface a hint to <em>Reset</em>.
    /// </summary>
    public bool IsAborted => _aborted;

    /// <summary>The step number at which user approval occurs in deferred mode.</summary>
    public int UserApprovalStepNumber =>
        IsCallChainPending
            ? (Steps.Count <= CallChainHop1PollStep ? CallChainHop1ApprovalStep : CallChainHop2ApprovalStep)
            : 7;

    /// <summary>The step number at which polling occurs in deferred mode.</summary>
    public int PollStepNumber =>
        IsCallChainPending
            ? (Steps.Count <= CallChainHop1PollStep ? CallChainHop1PollStep : CallChainHop2PollStep)
            : 8;

    // Call-chain consent path step numbers: hop 1 (Agent → Orchestrator) and
    // hop 2 (the Orchestrator's chained 202 for Orchestrator → WhoAmI).
    private const int CallChainHop1ApprovalStep = 7;
    private const int CallChainHop1PollStep = 8;
    private const int CallChainHop2ApprovalStep = 11;
    private const int CallChainHop2PollStep = 12;

    /// <summary>
    /// The actor the current poll loop targets: the Person Server for the
    /// three-party / federated / call-chain hop-1 polls, or the Orchestrator
    /// for the call-chain hop-2 (chained) poll.
    /// </summary>
    public Actor PollLoopTarget =>
        (IsCallChainPending && PollStepNumber == CallChainHop2PollStep)
            ? Actor.Orchestrator
            : Actor.PersonServer;

    /// <summary>
    /// True when the tour is parked on the "User approves" step in deferred mode
    /// and the UI should expose the "Approve as user" action button.
    /// </summary>
    public bool AwaitingUserApproval =>
        (IsDeferredMode || (IsFederatedMode && _federatedPending) || IsCallChainPending)
        && Steps.Count + 1 == UserApprovalStepNumber && !_userApproved;

    /// <summary>The user-facing interaction URL captured during step 7 (deferred only).</summary>
    public string? UserInteractionUrl => _interactionUrl is null || _interactionCode is null
        ? null
        : new AAuth.Headers.Interaction(_interactionUrl, _interactionCode).BuildUserUrl();

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
        ResetTimeline();
        _agentKey = null;
        _ephemeralKey = null;
        _agentToken = null;
        _assignedKeyId = null;
        _agentJwksUri = null;
    }

    /// <summary>
    /// Clears the step timeline and per-flow protocol state (auth tokens,
    /// polling, pending URLs). Agent credentials are also cleared so
    /// <see cref="EnsureAgentReadyAsync"/> re-enrolls on the next run.
    /// </summary>
    private void ResetTimeline()
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
        _authToken = null;
        _resourceToken = null;
        _tokenEndpoint = null;
        _pendingUrl = null;
        _interactionUrl = null;
        _interactionCode = null;
        _apEnrolEndpoint = null;
        _callChainResponseBody = null;
        _federatedResponseBody = null;
        _userApproved = false;
        _federatedPending = false;
        _callChainPending = false;
        _aborted = false;
    }

    /// <summary>
    /// Build a signing handler for the current flow's effective signing mode.
    /// Identity flow respects the user's selected mode; three-party flows
    /// always use jwt per the AAuth spec requirement.
    /// </summary>
    private HttpMessageHandler BuildSigningHandler(
        Func<string> tokenFactory,
        HttpMessageHandler inner,
        Action<HttpRequestMessage, string>? onSignatureBase = null)
    {
        var builder = new AAuthClientBuilder(_agentKey!)
            .WithInnerHandler(inner);

        switch (EffectiveSigningMode)
        {
            case SigningMode.Hwk:
                builder.UseHwk();
                break;
            case SigningMode.JwksUri:
                // Spec: In AP-enrolled flows, _assignedKeyId is the AP's published kid (opaque).
                // In self-hosted flows (this tour), the server's own kid is used as fallback.
                builder.UseJwksUri(
                    _agentJwksUri ?? $"{_selfIdentity.Issuer.TrimEnd('/')}/.well-known/jwks.json",
                    _assignedKeyId ?? _selfIdentity.KeyId);
                break;
            case SigningMode.JktJwt:
                // jkt-jwt: ephemeral key signs the HTTP request; durable key signs the naming JWT.
                _ephemeralKey ??= AAuthKey.Generate();
                var apIssuer = _options.AgentProviderUrl!.TrimEnd('/');
                var durableThumbprint = _agentKey!.ComputeJwkThumbprint();
                builder = new AAuthClientBuilder(_ephemeralKey)
                    .WithInnerHandler(inner);
                if (onSignatureBase is not null)
                    builder.OnSignatureBase(onSignatureBase);
                builder.UseJktJwt(() => NamingJwtBuilder.Build(
                    _agentKey!, _ephemeralKey, apIssuer, durableThumbprint));
                return builder.BuildHandler();
            default:
                builder.WithTokenRefresh(async (ctx, ct) => tokenFactory());
                break;
        }

        if (onSignatureBase is not null)
            builder.OnSignatureBase(onSignatureBase);

        return builder.BuildHandler();
    }

    /// <summary>
    /// Cleanup hook for the scoped lifetime (Blazor disposes the DI scope
    /// when the user's circuit ends). Cancels and awaits any in-flight
    /// polling task so we don't leak a <see cref="CancellationTokenSource"/>
    /// or a background <see cref="Task.Run"/> past the circuit's lifetime.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        Task? toAwait;
        lock (_pollingLock)
        {
            try { _pollingCts?.Cancel(); } catch { }
            toAwait = _pollingTask;
        }
        if (toAwait is not null)
        {
            try { await toAwait.ConfigureAwait(false); }
            catch { /* swallow — already shutting down */ }
        }
        _pollingCts?.Dispose();
        _pollingCts = null;
        _pollingTask = null;
    }

    /// <summary>Run the next pending step and capture its <see cref="StepRecord"/>.</summary>
    public async Task RunNextAsync(CancellationToken ct = default)
    {
        // ── Bootstrap flow ───────────────────────────────────────────────
        if (IsBootstrapMode)
        {
            var bStep = Steps.Count + 1;
            if (bStep == 1) { BootstrapStep1GenerateKey(); return; }
            if (HasAgentProvider)
            {
                if (bStep == 2) { await BootstrapStepDiscoverApAsync(ct); return; }
                if (bStep == 3) { await BootstrapStepEnrolAsync(ct); return; }
            }
            else
            {
                if (bStep == 2) { await BootstrapStepBuildTokenAsync(); return; }
            }
            return;
        }

        // ── Protocol flows: ensure key + agent token exist silently ──────
        await EnsureAgentReadyAsync(ct);

        // ── Protocol flow ────────────────────────────────────────────────
        var nextStep = Steps.Count + 1;

        if (IsDeferredMode)
        {
            switch (nextStep)
            {
                case 1: await StepFetchResourceMetadataAsync(ct); break;
                case 2: await StepSignedGetAsync(ct); break;
                case 3: StepParseChallenge(); break;
                case 4: await StepFetchPersonMetadataAsync(ct); break;
                case 5: await StepDeferredExchangeAsync(ct); break;
                case 6: StepDirectUserToInteraction(); break;
                case 7: StepUserApprovesPlaceholder(); break;
                case 8:
                    if (_pollingTask is { } existing && !existing.IsCompleted)
                    {
                        await existing.ConfigureAwait(false);
                    }
                    else if (Steps.Count + 1 == PollStepNumber)
                    {
                        await StepPollPendingAsync(ct);
                    }
                    break;
                case 9: await StepRetryWithAuthTokenAsync(ct); break;
            }
        }
        else if (IsCallChainMode)
        {
            switch (nextStep)
            {
                case 1: await StepCallChainDiscoverOrchestratorAsync(ct); break;
                case 2: await StepCallChainSignedGetAsync(ct); break;
                case 3: StepCallChainParseChallenge(); break;
                case 4: await StepFetchPersonMetadataAsync(ct); break;
                case 5: await StepCallChainExchangeAsync(ct); break;
                // Consent (deferred) path: hop 1 (Agent → Orchestrator), then
                // hop 2 (the Orchestrator's chained 202 for Orchestrator → WhoAmI).
                case 6 when _callChainPending: StepDirectUserToInteraction(); break;
                case 7 when _callChainPending: StepUserApprovesPlaceholder(); break;
                case 8 when _callChainPending:
                    if (_pollingTask is { } ccHop1 && !ccHop1.IsCompleted)
                    {
                        await ccHop1.ConfigureAwait(false);
                    }
                    else if (Steps.Count + 1 == PollStepNumber)
                    {
                        await StepPollPendingAsync(ct);
                    }
                    break;
                case 9 when _callChainPending: await StepCallChainRetryHop2Async(ct); break;
                case 10 when _callChainPending: StepDirectUserToInteraction(); break;
                case 11 when _callChainPending: StepUserApprovesPlaceholder(); break;
                case 12 when _callChainPending:
                    if (_pollingTask is { } ccHop2 && !ccHop2.IsCompleted)
                    {
                        await ccHop2.ConfigureAwait(false);
                    }
                    else if (Steps.Count + 1 == PollStepNumber)
                    {
                        await StepCallChainPollHop2Async(ct);
                    }
                    break;
                case 13 when _callChainPending: StepCallChainInspectResult(); break;
                // Standing-consent path (exchange returned 200): original 7 steps.
                case 6: await StepCallChainRetryAsync(ct); break;
                case 7: StepCallChainInspectResult(); break;
            }
        }
        else if (IsFederatedMode)
        {
            switch (nextStep)
            {
                case 1: await StepFederatedDiscoverResourceAsync(ct); break;
                case 2: await StepFederatedSignedGetAsync(ct); break;
                case 3: StepFederatedParseChallenge(); break;
                case 4: await StepFetchPersonMetadataAsync(ct); break;
                case 5: await StepFederatedExchangeAsync(ct); break;
                // Steps 6+ branch on whether the AS asked for an interactive
                // login (202, _federatedPending) or auto-allowed (200, stub).
                case 6 when _federatedPending: StepFederatedDirectUserToInteraction(); break;
                case 7 when _federatedPending: StepUserApprovesPlaceholder(); break;
                case 8 when _federatedPending:
                    if (_pollingTask is { } fedPoll && !fedPoll.IsCompleted)
                    {
                        await fedPoll.ConfigureAwait(false);
                    }
                    else if (Steps.Count + 1 == PollStepNumber)
                    {
                        await StepPollPendingAsync(ct);
                    }
                    break;
                case 9 when _federatedPending: await StepFederatedRetryAsync(ct); break;
                case 10 when _federatedPending: StepFederatedInspectResult(); break;
                // Direct-grant (stub AS) path: no consent, 7 steps total.
                case 6: await StepFederatedRetryAsync(ct); break;
                case 7: StepFederatedInspectResult(); break;
            }
        }
        else
        {
            switch (nextStep)
            {
                case 1: await StepFetchResourceMetadataAsync(ct); break;
                case 2: await StepSignedGetAsync(ct); break;
                // Identity mode stops here (only 2 protocol steps)
                case 3: StepParseChallenge(); break;
                case 4: await StepFetchPersonMetadataAsync(ct); break;
                case 5: await StepTokenExchangeAsync(ct); break;
                case 6: await StepRetryWithAuthTokenAsync(ct); break;
            }
        }
    }

    /// <summary>
    /// Silently ensures the agent key and token are available before
    /// running protocol flow steps. Self-issues an agent token — the
    /// GuidedTour server is its own AP per §Self-Hosted Agents.
    /// Bootstrap mode is the only flow that demos external AP enrollment.
    /// </summary>
    private async Task EnsureAgentReadyAsync(CancellationToken ct)
    {
        if (_agentKey is not null && _agentToken is not null) return;

        // Use the shared singleton key so the published JWKS matches.
        _agentKey ??= _selfIdentity.Key;

        if (_agentToken is null)
        {
            // Self-issue: the tour server is a hosted service with a stable
            // URL, so it acts as its own AP (spec §Self-Hosted Agents).
            var personServer = IsIdentityMode || string.IsNullOrWhiteSpace(_options.PersonServerUrl)
                ? null
                : _options.PersonServerUrl;
            _agentToken = new AgentTokenBuilder
            {
                Issuer = _selfIdentity.Issuer,
                Subject = _options.AgentId,
                KeyId = _selfIdentity.KeyId,
                Key = _selfIdentity.Key,
                PersonServer = personServer,
            }.Build();

            // Autonomous mode simulates "standing consent" — pre-register
            // consent at the Mock Person Server so POST /token returns 200
            // immediately rather than 202 deferred.
            if (IsAutonomousMode && !string.IsNullOrWhiteSpace(_options.PersonServerUrl))
            {
                using var adminClient = new HttpClient();
                await adminClient.PostAsJsonAsync(
                    $"{_options.PersonServerUrl.TrimEnd('/')}/admin/consent",
                    new { agent = _options.AgentId, resource = _options.WhoAmIUrl.TrimEnd('/') },
                    ct);
            }
        }
    }

    /// <summary>
    /// Records the user-approval step: the user opened the PS's interaction page in a
    /// separate browser tab and (hopefully) clicked Approve. The Guided
    /// Tour itself does not make the HTTP call here — that happens
    /// out-of-band, between the user's browser and the Person Server,
    /// exactly as the spec intends. The poll step picks up the result.
    /// </summary>
    public Task RecordUserApprovalOpenedAsync(CancellationToken ct = default)
    {
        if (!(IsDeferredMode || (IsFederatedMode && _federatedPending) || IsCallChainPending)) { return Task.CompletedTask; }
        if (Steps.Count + 1 != UserApprovalStepNumber)
        {
            throw new InvalidOperationException(
                $"RecordUserApprovalOpenedAsync called at protocol step {Steps.Count + 1}; only valid at step {UserApprovalStepNumber}.");
        }

        var userUrl = UserInteractionUrl ?? "(no interaction URL captured)";
        _userApproved = true;

        if (IsFederatedMode)
        {
            Steps.Add(new StepRecord
            {
                Number = Steps.Count + 1,
                Title = "User consents at the Access Server",
                From = Actor.AccessServer,
                To = Actor.AccessServer,
                Narrative =
                    "The tour opened the Access Server's interaction URL in a new browser " +
                    "tab. The AS rendered its **own consent screen** — clearly badged " +
                    "*Access Server* so the user knows they are approving at the federated " +
                    "authority, not the Person Server. The user clicked **Approve**, and the " +
                    "AS recorded the verdict on its pending entry. (With a Keycloak-backed " +
                    "AS this same URL redirects to Keycloak's login instead — from the " +
                    "agent's perspective the two are identical; only the interaction URL's " +
                    "destination differs.) All of this happens in the user's browser → AS " +
                    "channel — neither the agent nor the Person Server is on this path. The " +
                    "agent discovers the result on its next poll of the PS pending URL.",
                ResponseBody = userUrl,
                TokenDecoded =
                    $"Interaction URL opened in new tab:\n  {userUrl}\n\n" +
                    "User performed (browser \u2192 AS):\n" +
                    $"  GET  {{as}}/interaction/login?code={_interactionCode}\n" +
                    "  \u2192 AS consent screen \u2192 click Approve\n" +
                    $"  POST {{as}}/interaction/approve (AS records verdict)",
            });
            return Task.CompletedTask;
        }

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = IsCallChainPending
                ? (Steps.Count + 1 == CallChainHop2ApprovalStep
                    ? "User approves hop 2 (Orchestrator → WhoAmI) at the PS"
                    : "User approves hop 1 (Agent → Orchestrator) at the PS")
                : "User completes interaction at Person Server",
            From = Actor.PersonServer,
            To = Actor.PersonServer,
            Narrative =
                "The tour opened the PS's interaction URL in a new browser tab. " +
                "The Person Server rendered its consent screen (the agent + resource + " +
                "scope of this request), the user clicked **Approve**, and the PS " +
                "recorded consent in its store via `POST /interaction/approve`. " +
                "All of that happens in the user's browser → PS channel — the agent " +
                "is not on this path. The agent will discover the result on its next " +
                "poll of the pending URL." +
                (IsCallChainPending && Steps.Count + 1 == CallChainHop2ApprovalStep
                    ? "\n\nThis is the **second** of two approvals: it consents to the " +
                      "Orchestrator (acting on your behalf) calling WhoAmI. The consent " +
                      "is keyed to the Orchestrator's identity, not yours — the agent " +
                      "never sees the chained credential."
                    : ""),
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
        using var client = new HttpClient();

        // Call-chain mode is a genuine multi-hop deferred demo: BOTH hops
        // (Agent → Orchestrator, and the Orchestrator's chained Orchestrator →
        // WhoAmI) must lack consent so each surfaces its own user approval.
        // Wipe the PS consent store so a replay can't skip an approval that a
        // previous run recorded (including the Orchestrator-keyed hop-2 consent).
        if (IsCallChainMode)
        {
            try { await client.PostAsync($"{_options.PersonServerUrl!.TrimEnd('/')}/admin/reset", null, ct); }
            catch { /* /admin/* only exists on MockPersonServer — swallow. */ }
            return;
        }

        var endpoint = IsDeferredMode ? "/admin/revoke" : "/admin/consent";
        var url = $"{_options.PersonServerUrl!.TrimEnd('/')}{endpoint}";
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
    // Bootstrap step implementations
    // -----------------------------------------------------------------

    private void BootstrapStep1GenerateKey()
    {
        _agentKey = AAuthKey.Generate();
        var jwk = _agentKey.ToPublicJwk().ToJsonString(new JsonSerializerOptions { WriteIndented = true });
        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Generate Ed25519 key",
            From = Actor.Agent,
            To = Actor.Agent,
            Narrative =
                "The agent mints a fresh Ed25519 keypair locally. Only the public " +
                "JWK travels — every signed request later proves possession of the " +
                "private key.",
            ResponseBody = jwk,
            TokenDecoded = $"JWK thumbprint:\n{_agentKey.ComputeJwkThumbprint()}",
            CodeSnippet = CodeSnippets.GenerateKey,
        });
    }

    private async Task BootstrapStepBuildTokenAsync()
    {
        var personServer = IsIdentityMode || string.IsNullOrWhiteSpace(_options.PersonServerUrl)
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

        await Task.CompletedTask;

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Build agent token",
            From = Actor.Agent,
            To = Actor.Agent,
            Narrative =
                "The agent self-signs an `aa-agent+jwt` containing its " +
                "public key (cnf.jwk), identifier (sub), and — for the three-party " +
                "flow — the user's Person Server URL. In production this token " +
                "would come from an Agent Provider.",
            TokenJwt = _agentToken,
            TokenHeader = DecodeJwt(_agentToken)?.Header,
            TokenPayload = DecodeJwt(_agentToken)?.Payload,
            CodeSnippet = CodeSnippets.SelfSignAgentToken,
        });
    }

    private string? _apEnrolEndpoint;

    private async Task BootstrapStepDiscoverApAsync(CancellationToken ct)
    {
        var apBase = _options.AgentProviderUrl!.TrimEnd('/');
        var metadataUrl = $"{apBase}/.well-known/aauth-agent.json";

        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        using var client = new HttpClient(capture);
        await client.GetAsync(metadataUrl, ct);
        var ex = capture.Last!;

        var meta = JsonNode.Parse(ex.ResponseBody);
        _apEnrolEndpoint = (string?)meta?["enrol_endpoint"]
            ?? $"{apBase}/enrol";

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Discover Agent Provider",
            From = Actor.Agent,
            To = Actor.AgentProvider,
            Narrative =
                "The agent fetches the Agent Provider's well-known metadata to learn " +
                "its `enrol_endpoint`, `refresh_endpoint`, and JWKS URI.",
            RequestLine = $"{ex.RequestLine}  →  {metadataUrl}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            CodeSnippet = CodeSnippets.DiscoverAp,
        });
    }

    private async Task BootstrapStepEnrolAsync(CancellationToken ct)
    {
        var enrolUrl = _apEnrolEndpoint
            ?? $"{_options.AgentProviderUrl!.TrimEnd('/')}/enrol";

        var requestBody = new JsonObject
        {
            ["agent_id"] = _options.AgentId,
            ["jwk"] = _agentKey!.ToPublicJwk(),
        };

        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        using var client = new HttpClient(capture);
        using var response = await client.PostAsJsonAsync(enrolUrl, requestBody, ct);
        var ex = capture.Last!;

        var body = JsonNode.Parse(ex.ResponseBody);
        _agentToken = (string?)body?["agent_token"];
        _assignedKeyId = (string?)body?["key_id"];
        _agentJwksUri = (string?)body?["jwks_uri"];

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Enrol with Agent Provider",
            From = Actor.Agent,
            To = Actor.AgentProvider,
            Narrative =
                "The agent registers with the AP by POSTing its `agent_id` and public " +
                "`jwk`. The AP issues a signed `aa-agent+jwt` binding the agent's " +
                "identity to its key.",
            RequestLine = $"{ex.RequestLine}  →  {enrolUrl}",
            RequestHeaders = ex.RequestHeaders,
            RequestBody = PrettyJson(ex.RequestBody),
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            TokenJwt = _agentToken,
            TokenHeader = DecodeJwt(_agentToken)?.Header,
            TokenPayload = DecodeJwt(_agentToken)?.Payload,
            CodeSnippet = CodeSnippets.EnrolWithAp,
        });
    }

    // -----------------------------------------------------------------
    // Protocol flow step implementations
    // -----------------------------------------------------------------

    private async Task StepFetchResourceMetadataAsync(CancellationToken ct)
    {
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        using var client = new HttpClient(capture);
        var url = $"{_options.WhoAmIUrl.TrimEnd('/')}/.well-known/aauth-resource.json";
        await client.GetAsync(url, ct);
        var ex = capture.Last!;
        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
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
            CodeSnippet = CodeSnippets.DiscoverResource,
        });
    }

    private async Task StepSignedGetAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        var signing = BuildSigningHandler(
            () => _agentToken!, capture, (_, b) => capturedBase = b);
        using var client = new HttpClient(signing);

        var resp = await client.GetAsync(EffectiveResourceUrl, ct);
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
            Number = Steps.Count + 1,
            Title = EffectiveSigningMode switch
            {
                SigningMode.Hwk => "Signed GET (pseudonymous — hwk)",
                SigningMode.JwksUri => "Signed GET (agent identity — jwks_uri)",
                SigningMode.JktJwt => "Signed GET (key rotation — jkt-jwt)",
                _ => "Signed GET (agent token — jwt)",
            },
            From = Actor.Agent,
            To = Actor.Resource,
            Narrative = EffectiveSigningMode switch
            {
                SigningMode.Hwk =>
                    "The agent signs the request per RFC 9421. The Signature-Key header " +
                    "carries `sig=hwk` with the key's JWK thumbprint and the full public " +
                    "key inline (base64url-encoded JWK). The resource extracts the key " +
                    "directly — no pre-registration needed. Use for: accountable " +
                    "pseudonymous access, rate-limiting by key.",
                SigningMode.JwksUri =>
                    "The agent signs the request per RFC 9421. The Signature-Key header " +
                    "carries `sig=jwks_uri` with a JWKS endpoint + kid. The resource " +
                    "fetches the agent's public key from that URI and learns the agent's " +
                    "full cryptographic identity. Use for: access control by agent identity, " +
                    "replacing API keys.",
                SigningMode.JktJwt =>
                    "The agent signs the request per RFC 9421. The Signature-Key header " +
                    "carries `sig=jkt-jwt` with a naming JWT and the durable key's JWK " +
                    "thumbprint. The naming JWT (signed by the durable key) binds the " +
                    "current ephemeral signing key via `cnf.jwk`. The resource verifies " +
                    "the HTTP signature against the ephemeral key — enabling key rotation " +
                    "without re-enrolment.",
                _ =>
                    "The agent signs the request per RFC 9421. The Signature-Key header " +
                    "carries `sig=jwt` with the full agent token inline. The resource " +
                    "learns: agent identity, PS URL, and the bound signing key via " +
                    "`cnf.jwk`. If the resource accepts the agent identity directly, " +
                    "it returns 200. Otherwise it returns 401 with an AAuth-Requirement " +
                    "header and a resource_token for the PS-asserted flow.",
            },
            RequestLine = $"{ex.RequestLine}  →  {EffectiveResourceUrl}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            SignatureBase = capturedBase,
            CodeSnippet = EffectiveSigningMode switch
            {
                SigningMode.Hwk => CodeSnippets.SignedGetHwk,
                SigningMode.JwksUri => CodeSnippets.SignedGetJwksUri,
                SigningMode.JktJwt => CodeSnippets.SignedGetJktJwt,
                _ => CodeSnippets.SignedGetJwt,
            },
        });
    }

    private void StepParseChallenge()
    {
        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Parse 401 challenge",
            From = Actor.Agent,
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
            CodeSnippet = CodeSnippets.ParseChallenge,
        });
    }

    private async Task StepFetchPersonMetadataAsync(CancellationToken ct)
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
            Number = Steps.Count + 1,
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
            CodeSnippet = CodeSnippets.DiscoverPs,
        });
    }

    private async Task StepTokenExchangeAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        // The exchange request is always signed with the AGENT token, never the
        // post-exchange auth token. The PS authenticates the agent identity.
        var signing = BuildSigningHandler(
            () => _agentToken!, capture, (_, b) => capturedBase = b);
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
            Number = Steps.Count + 1,
            Title = "Token exchange",
            From = Actor.Agent,
            To = Actor.PersonServer,
            Narrative =
                "The agent POSTs the resource_token to the PS's token_endpoint. " +
                "Per spec, the agent MUST present its agent token via the " +
                "Signature-Key header using `scheme=jwt`. The PS verifies the " +
                "signature, validates the resource_token, and (in a real PS) " +
                "checks user consent. On success it returns an `aa-auth+jwt` " +
                "whose `cnf.jwk` binds the new auth token to the same agent key.",
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
            CodeSnippet = CodeSnippets.TokenExchangeDirect,
        });
    }

    private async Task StepRetryWithAuthTokenAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        var signing = BuildSigningHandler(
            () => _authToken!, capture, (_, b) => capturedBase = b);
        using var client = new HttpClient(signing);

        await client.GetAsync(EffectiveResourceUrl, ct);
        var ex = capture.Last!;

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Replay GET with auth token",
            From = Actor.Agent,
            To = Actor.Resource,
            Narrative =
                "Same request as the initial signed GET, but now the Signature-Key " +
                "header carries the PS-issued auth_token via `sig=jwt`. Per spec, " +
                "once an auth token has been issued for a resource, the agent " +
                "presents the auth token (not the agent token) on subsequent " +
                "requests. The resource validates that the JWT is signed by its " +
                "PS, that `cnf.jwk` matches the request signer, and returns the " +
                "protected payload.",
            RequestLine = $"{ex.RequestLine}  →  {EffectiveResourceUrl}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            SignatureBase = capturedBase,
            CodeSnippet = CodeSnippets.ReplayWithAuthToken,
        });
    }

    // -----------------------------------------------------------------
    // Deferred-flow step variants
    // -----------------------------------------------------------------

    private async Task StepDeferredExchangeAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        var signing = BuildSigningHandler(
            () => _agentToken!, capture, (_, b) => capturedBase = b);
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
                        var interaction = AAuth.Headers.Interaction.FromRequirement(parsed);
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
            Number = Steps.Count + 1,
            Title = "Exchange → 202 Accepted",
            From = Actor.Agent,
            To = Actor.PersonServer,
            Narrative =
                "The agent POSTs the resource_token with its agent token via " +
                "`sig=jwt` (MUST per spec), but this PS requires user consent. " +
                "Instead of an `aa-auth+jwt`, the PS returns `202 Accepted` with a " +
                "`Location` pointing at a pending URL the agent will poll, plus an " +
                "`AAuth-Requirement: requirement=interaction` header carrying the " +
                "user-facing interaction URL and a single-use code.",
            RequestLine = $"{ex.RequestLine}  →  {_tokenEndpoint}",
            RequestHeaders = ex.RequestHeaders,
            RequestBody = PrettyJson(ex.RequestBody),
            SignatureBase = capturedBase,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            CodeSnippet = CodeSnippets.TokenExchangeDeferred,
        });
    }

    private void StepDirectUserToInteraction()
    {
        var userUrl = UserInteractionUrl
            ?? "(no interaction URL captured — is MockPersonServer running with RequireConsent=true?)";

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
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
            CodeSnippet = CodeSnippets.DirectUserToInteraction,
        });
    }

    private void StepUserApprovesPlaceholder()
    {
        // Placeholder branch: should not be reachable because the UI must
        // call ApproveAsUserAsync() at the user-approval step. Defensive fallback in
        // case "Run all" is invoked — it cannot proceed past the user-approval step on its
        // own, the user must click "Approve as user".
        if (!_userApproved)
        {
            throw new InvalidOperationException(
                "The user-approval step requires the user to click \"Approve as user\". Call ApproveAsUserAsync() instead of RunNextAsync().");
        }
    }

    private Task StepPollPendingAsync(CancellationToken ct) =>
        RunPendingPollAsync(ct, () => _agentToken!, Actor.Agent, Actor.PersonServer, (last, capturedBase) =>
        {
            // CapturingMessageHandler already buffered the final response
            // body — reuse it rather than reading via `terminal.Content`
            // again, which would force another round-trip through the
            // disposed-content guard.
            var body = JsonNode.Parse(last.ResponseBody);
            _authToken = (string?)body?["auth_token"];

            Steps.Add(new StepRecord
            {
                Number = Steps.Count + 1,
                Title = "Poll pending URL → auth_token",
                From = Actor.Agent,
                To = Actor.PersonServer,
                Narrative =
                    "While the user clicks through the PS's interaction page, the agent " +
                    "polls the pending URL with a signed `GET` (agent token via `sig=jwt`). " +
                    "Each request honors the PS's `Retry-After` cadence. Once consent is " +
                    "recorded the PS responds with `200 OK` and the long-awaited " +
                    "`aa-auth+jwt`, bound (via `cnf.jwk`) to the agent's signing key. " +
                    "If the user clicks **Deny** instead, this step records a " +
                    "`403 access_denied` and the flow aborts.",
                RequestLine = $"{last.RequestLine}  →  {_pendingUrl}",
                RequestHeaders = last.RequestHeaders,
                SignatureBase = capturedBase,
                StatusLine = last.StatusLine,
                ResponseHeaders = last.ResponseHeaders,
                ResponseBody = PrettyJson(last.ResponseBody),
                TokenJwt = _authToken,
                TokenHeader = DecodeJwt(_authToken)?.Header,
                TokenPayload = DecodeJwt(_authToken)?.Payload,
                CodeSnippet = CodeSnippets.PollPending,
            });
        });

    /// <summary>
    /// Shared pending-URL poll loop. Signs with <paramref name="tokenFactory"/>,
    /// long-polls <see cref="_pendingUrl"/>, and on terminal success invokes
    /// <paramref name="recordSuccess"/> to add the flow-specific step record.
    /// Denial (403 access_denied) and timeout are recorded uniformly and abort
    /// the flow. <paramref name="from"/>/<paramref name="to"/> drive the actors
    /// on the denied/timeout step records.
    /// </summary>
    private async Task RunPendingPollAsync(
        CancellationToken ct,
        Func<string> tokenFactory,
        Actor from,
        Actor to,
        Action<CapturedExchange, string?> recordSuccess)
    {
        if (string.IsNullOrEmpty(_pendingUrl))
        {
            throw new InvalidOperationException(
                "No pending URL captured — the prior step did not record a 202 response.");
        }

        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        string? capturedBase = null;
        var signing = BuildSigningHandler(tokenFactory, capture, (_, b) => capturedBase = b);
        // This HttpClient is constructed directly (not via AAuthClientBuilder), so it
        // keeps the default 100s timeout. That is fine here because PreferWaitSeconds (30)
        // is well under 100s. If you raise PreferWaitSeconds beyond the HttpClient.Timeout,
        // set Timeout greater than PreferWaitSeconds (or Timeout.InfiniteTimeSpan) or the
        // in-flight long-poll aborts with a TaskCanceledException.
        using var client = new HttpClient(signing);
        var pollerOptions = new DeferredPollerOptions
        {
            // Generous budget: in deferred mode the user has to flip to
            // another tab, read the consent screen, and click Approve.
            MaxTotalWait = TimeSpan.FromMinutes(2),
            DefaultPollInterval = TimeSpan.FromMilliseconds(500),
            MinPollInterval = TimeSpan.Zero,
            // Signal willingness to long-poll for up to 30s per request
            // (RFC 7240 §4.3). The PS can hold the connection open rather
            // than immediately returning 202.
            PreferWaitSeconds = 30,
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
                    RecordDeniedStep(capture.Last!, capturedBase, deniedBody, from, to);
                    _aborted = true;
                    return;
                }
            }

            recordSuccess(capture.Last!, capturedBase);
        }
        catch (TimeoutException tex)
        {
            // The user neither approved nor denied within the polling
            // budget — record a terminal timeout step and abort.
            RecordTimeoutStep(capture.Last, capturedBase, tex.Message, from, to);
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
    /// Kicks off the pending-URL poll loop as a fire-and-forget
    /// background task so the UI can keep rendering while the user is
    /// in another tab clicking Approve / Deny at the PS consent page.
    /// Subsequent calls while a poll is already in flight are no-ops.
    /// The task completes when the PS terminates (200 / 403 / 404) or
    /// the polling budget expires; the UI listens to
    /// <see cref="StateChanged"/> for per-poll updates.
    /// </summary>
    public Task StartPendingPollAsync()
    {
        if (!(IsDeferredMode || (IsFederatedMode && _federatedPending) || IsCallChainPending) || _pendingUrl is null)
        {
            return Task.CompletedTask;
        }
        // Poll step must be the next step in line. If somebody calls this
        // out of order (defensive), bail out silently.
        if (Steps.Count + 1 != PollStepNumber)
        {
            return Task.CompletedTask;
        }

        // Call-chain hop 2 polls the Orchestrator's pending URL (signed with the
        // Orchestrator-audience auth_token); every other poll hits the PS pending
        // URL with the agent token.
        var hop2 = IsCallChainPending && Steps.Count + 1 == CallChainHop2PollStep;

        // Serialize the check-then-assign so two near-simultaneous UI
        // events (e.g. "Open consent" + "Simulate deny") can't both kick
        // off a poll. Blazor Server's circuit context already serializes
        // most callbacks, but making the invariant explicit is cheap.
        lock (_pollingLock)
        {
            if (_pollingTask is not null && !_pollingTask.IsCompleted)
            {
                return _pollingTask;
            }

            _pollingCts?.Dispose();
            _pollingCts = new CancellationTokenSource();
            var ct = _pollingCts.Token;
            _pollingTask = Task.Run(async () =>
            {
                try
                {
                    await (hop2 ? StepCallChainPollHop2Async(ct) : StepPollPendingAsync(ct)).ConfigureAwait(false);
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
    }

    private void RecordDeniedStep(
        CapturedExchange last,
        string? capturedBase,
        string deniedBody,
        Actor from = Actor.Agent,
        Actor to = Actor.PersonServer)
    {
        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Poll pending URL → 403 access_denied (user denied)",
            From = from,
            To = to,
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
        string detail,
        Actor from = Actor.Agent,
        Actor to = Actor.PersonServer)
    {
        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Poll pending URL → timeout (user did not respond)",
            From = from,
            To = to,
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
                "SimulateUserDenyAsync is only valid in deferred mode after the exchange step.");
        }
        if (Steps.Count + 1 != UserApprovalStepNumber)
        {
            throw new InvalidOperationException(
                $"SimulateUserDenyAsync called at step {Steps.Count + 1}; only valid at step {UserApprovalStepNumber}.");
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
        // the failure on the poll step. Throwing here would leave the timeline
        // in an inconsistent state.

        _userApproved = true; // unblocks AwaitingUserApproval so poll step runs
        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "User denies interaction at Person Server",
            From = Actor.PersonServer,
            To = Actor.PersonServer,
            Narrative =
                "The tour simulated the user clicking **Deny** on the PS's consent " +
                "page (`POST /interaction/deny` with the single-use code). The PS " +
                "marks the pending entry as denied; the next poll iteration will see " +
                "`403 access_denied` and the flow will terminate.",
            ResponseBody = denyUrl,
            TokenDecoded =
                $"Simulated POST /interaction/deny  (form: code={_interactionCode})\n" +
                $"Status: {(int)resp.StatusCode} {resp.ReasonPhrase}",
        });
    }

    // -----------------------------------------------------------------
    // Call-chain (multi-agent) step implementations
    // -----------------------------------------------------------------

    private string? _callChainResponseBody;

    private string CallChainTargetUrl => _options.OrchestratorUrl!.TrimEnd('/');

    private async Task StepCallChainDiscoverOrchestratorAsync(CancellationToken ct)
    {
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        using var client = new HttpClient(capture);
        var url = $"{CallChainTargetUrl}/.well-known/aauth-resource.json";
        await client.GetAsync(url, ct);
        var ex = capture.Last!;
        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Discover Orchestrator metadata",
            From = Actor.Agent,
            To = Actor.Orchestrator,
            Narrative =
                "The Orchestrator is itself an AAuth-protected resource. The agent " +
                "fetches its well-known metadata just like any other resource. The " +
                "response confirms the Orchestrator's issuer and JWKS endpoint.",
            RequestLine = $"{ex.RequestLine}  →  {url}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            CodeSnippet = CodeSnippets.DiscoverResource,
        });
    }

    private async Task StepCallChainSignedGetAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        var signing = BuildSigningHandler(
            () => _agentToken!, capture, (_, b) => capturedBase = b);
        using var client = new HttpClient(signing);

        var resp = await client.GetAsync(CallChainTargetUrl, ct);
        var ex = capture.Last!;

        if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized &&
            resp.Headers.TryGetValues(AAuthRequirementHeader.Name, out var reqHeaders))
        {
            var parsed = AAuthRequirementHeader.Parse(reqHeaders.First());
            _resourceToken = parsed.ResourceToken;
        }

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Signed GET → 401 (agent token challenge)",
            From = Actor.Agent,
            To = Actor.Orchestrator,
            Narrative =
                "The agent calls the Orchestrator with its agent token (`sig=jwt`). " +
                "The Orchestrator recognises this is an agent token (not an auth " +
                "token) and returns `401` with a resource_token. This tells the " +
                "agent: \"I need a PS-issued auth_token scoped to me before I'll " +
                "forward your request downstream.\"",
            RequestLine = $"{ex.RequestLine}  →  {CallChainTargetUrl}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            SignatureBase = capturedBase,
            CodeSnippet = CodeSnippets.SignedGetJwt,
        });
    }

    private void StepCallChainParseChallenge()
    {
        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Parse Orchestrator's 401 challenge",
            From = Actor.Agent,
            To = Actor.Agent,
            Narrative =
                "The Orchestrator's 401 contains an `aa-resource+jwt` whose `aud` " +
                "points at the Person Server. The agent will exchange this " +
                "resource_token at the PS to obtain an auth_token scoped to the " +
                "Orchestrator.",
            TokenJwt = _resourceToken,
            TokenHeader = DecodeJwt(_resourceToken)?.Header,
            TokenPayload = DecodeJwt(_resourceToken)?.Payload,
            CodeSnippet = CodeSnippets.ParseChallenge,
        });
    }

    private async Task StepCallChainExchangeAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        var signing = BuildSigningHandler(
            () => _agentToken!, capture, (_, b) => capturedBase = b);
        using var client = new HttpClient(signing);

        using var resp = await client.PostAsJsonAsync(_tokenEndpoint!, new
        {
            resource_token = _resourceToken,
        }, ct);

        var ex = capture.Last!;

        // Hop 1 of the chain requires the user to consent to the agent
        // calling the Orchestrator on their behalf. With no standing
        // consent the PS returns 202 + a pending URL + an interaction
        // requirement, exactly like the single-hop deferred flow.
        if (resp.StatusCode == HttpStatusCode.Accepted)
        {
            _callChainPending = true;

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
                        var interaction = AAuth.Headers.Interaction.FromRequirement(parsed);
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

            Steps.Add(new StepRecord
            {
                Number = Steps.Count + 1,
                Title = "Exchange → 202 (hop 1 consent required)",
                From = Actor.Agent,
                To = Actor.PersonServer,
                Narrative =
                    "The agent exchanges the Orchestrator's resource_token at the PS, " +
                    "but no standing consent exists for **Agent → Orchestrator**. The PS " +
                    "returns `202 Accepted` with a `Location` (pending URL) and an " +
                    "`AAuth-Requirement: requirement=interaction` header. This is the " +
                    "**first of two** approvals: the user must consent to this agent " +
                    "calling the Orchestrator on their behalf before any chaining can " +
                    "happen.",
                RequestLine = $"{ex.RequestLine}  →  {_tokenEndpoint}",
                RequestHeaders = ex.RequestHeaders,
                RequestBody = PrettyJson(ex.RequestBody),
                StatusLine = ex.StatusLine,
                ResponseHeaders = ex.ResponseHeaders,
                ResponseBody = PrettyJson(ex.ResponseBody),
                SignatureBase = capturedBase,
                CodeSnippet = CodeSnippets.TokenExchangeDeferred,
            });
            return;
        }

        var body = JsonNode.Parse(ex.ResponseBody);
        _authToken = (string?)body?["auth_token"];

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Exchange at PS → auth_token (for Orchestrator)",
            From = Actor.Agent,
            To = Actor.PersonServer,
            Narrative =
                "The agent exchanges the Orchestrator's resource_token at the PS. " +
                "The PS mints an `aa-auth+jwt` whose `aud` is the Orchestrator " +
                "(not WhoAmI). This auth_token proves: \"this person consented to " +
                "this agent calling the Orchestrator on their behalf.\"",
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
            CodeSnippet = CodeSnippets.TokenExchangeDirect,
        });
    }

    /// <summary>
    /// Hop-2 retry: now that the agent holds an Orchestrator-audience
    /// auth_token (after hop-1 approval), it retries the Orchestrator.
    /// The Orchestrator drives its own downstream WhoAmI exchange which —
    /// lacking consent — surfaces a chained interaction. The Orchestrator
    /// re-emits that as its own 202 + pending URL, which the agent must
    /// poll after the user approves the second (Orchestrator → WhoAmI) hop.
    /// </summary>
    private async Task StepCallChainRetryHop2Async(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        var signing = BuildSigningHandler(
            () => _authToken!, capture, (_, b) => capturedBase = b);
        using var client = new HttpClient(signing);

        using var resp = await client.GetAsync(CallChainTargetUrl, ct);
        var ex = capture.Last!;

        // The Orchestrator re-emits its downstream interaction as a 202
        // pointing at its OWN pending endpoint. Capture that pending URL +
        // the (PS-issued) interaction the user must approve for hop 2.
        if (resp.StatusCode == HttpStatusCode.Accepted)
        {
            _userApproved = false; // hop-2 approval still required

            var location = resp.Headers.Location?.ToString();
            if (location is not null)
            {
                _pendingUrl = location.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? location
                    : $"{CallChainTargetUrl}{location}";
            }

            if (resp.Headers.TryGetValues(AAuthRequirementHeader.Name, out var reqVals))
            {
                foreach (var raw in reqVals)
                {
                    if (string.IsNullOrWhiteSpace(raw)) { continue; }
                    try
                    {
                        var parsed = AAuthRequirementHeader.Parse(raw);
                        var interaction = AAuth.Headers.Interaction.FromRequirement(parsed);
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
            Number = Steps.Count + 1,
            Title = "Retry Orchestrator with auth_token → 202 (hop 2 consent required)",
            From = Actor.Agent,
            To = Actor.Orchestrator,
            Narrative =
                "The agent retries the Orchestrator with its hop-1 auth_token. The " +
                "Orchestrator validates it, extracts it as `upstream_token`, and calls " +
                "WhoAmI on the user's behalf — but **there is no consent for the " +
                "Orchestrator → WhoAmI hop either**. The PS returns a chained " +
                "interaction, which the Orchestrator re-emits to us as its own " +
                "`202 Accepted` + pending URL. This is the **second** approval: the " +
                "user must consent to the Orchestrator calling WhoAmI on their behalf. " +
                "The internal Orchestrator → PS exchange is shown as grouped sub-steps.",
            RequestLine = $"{ex.RequestLine}  →  {CallChainTargetUrl}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            SignatureBase = capturedBase,
            CodeSnippet = CodeSnippets.CallChainRetry,
            SubSteps = new SubStep[]
            {
                new("GET / (agent token)", Actor.Orchestrator, Actor.Resource),
                new("401 + resource_token", Actor.Resource, Actor.Orchestrator, IsResponse: true),
                new("POST /token + upstream_token", Actor.Orchestrator, Actor.PersonServer),
                new("202 + interaction (consent needed)", Actor.PersonServer, Actor.Orchestrator, IsResponse: true),
            },
        });
    }

    /// <summary>
    /// Hop-2 poll: after the user approves the Orchestrator → WhoAmI hop,
    /// the agent polls the Orchestrator's pending URL (signed with the
    /// Orchestrator-audience auth_token). Once consent lands, the
    /// Orchestrator completes its chained WhoAmI call and returns the
    /// combined multi-agent result as `200 OK`.
    /// </summary>
    private Task StepCallChainPollHop2Async(CancellationToken ct) =>
        RunPendingPollAsync(ct, () => _authToken!, Actor.Agent, Actor.Orchestrator, (last, capturedBase) =>
        {
            _callChainResponseBody = last.ResponseBody;

            Steps.Add(new StepRecord
            {
                Number = Steps.Count + 1,
                Title = "Poll Orchestrator pending → 200 (chain resolved)",
                From = Actor.Agent,
                To = Actor.Orchestrator,
                Narrative =
                    "With the second approval recorded, the agent polls the " +
                    "Orchestrator's pending URL (signed with the Orchestrator-audience " +
                    "auth_token). The Orchestrator re-drives its downstream exchange: the " +
                    "PS now mints a **chained auth_token with a nested `act` claim** " +
                    "recording the full delegation path (you → Orchestrator → WhoAmI). " +
                    "The Orchestrator calls WhoAmI with it and returns the combined " +
                    "result as `200 OK`. The internal Orchestrator → PS → WhoAmI hops are " +
                    "shown as grouped sub-steps.",
                RequestLine = $"{last.RequestLine}  →  {_pendingUrl}",
                RequestHeaders = last.RequestHeaders,
                SignatureBase = capturedBase,
                StatusLine = last.StatusLine,
                ResponseHeaders = last.ResponseHeaders,
                ResponseBody = PrettyJson(last.ResponseBody),
                CodeSnippet = CodeSnippets.CallChainRetry,
                SubSteps = new SubStep[]
                {
                    new("POST /token + upstream_token (retry)", Actor.Orchestrator, Actor.PersonServer),
                    new("200 + chained auth_token (nested act)", Actor.PersonServer, Actor.Orchestrator, IsResponse: true),
                    new("GET / (chained auth_token)", Actor.Orchestrator, Actor.Resource),
                    new("200 + claims", Actor.Resource, Actor.Orchestrator, IsResponse: true),
                },
            });
        });

    private async Task StepCallChainRetryAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        var signing = BuildSigningHandler(
            () => _authToken!, capture, (_, b) => capturedBase = b);
        using var client = new HttpClient(signing);

        await client.GetAsync(CallChainTargetUrl, ct);
        var ex = capture.Last!;
        _callChainResponseBody = ex.ResponseBody;

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Retry Orchestrator with auth_token → 200",
            From = Actor.Agent,
            To = Actor.Orchestrator,
            Narrative =
                "The agent retries with the auth_token. The Orchestrator now:\n\n" +
                "1. **Validates** the auth_token (signature, audience, key binding)\n" +
                "2. **Extracts** the auth_token as `upstream_token`\n" +
                "3. **Calls WhoAmI** with its own agent token → gets 401 challenge\n" +
                "4. **Exchanges** at the PS with `upstream_token` → PS builds a **nested `act` claim**\n" +
                "5. **Retries WhoAmI** with the chained auth_token → 200\n" +
                "6. **Returns** the combined result to us\n\n" +
                "All of steps 2–6 happen server-side inside the Orchestrator. " +
                "From our perspective, we just see a single 200 response. " +
                "The sub-arrows in the diagram show the internal flow.",
            RequestLine = $"{ex.RequestLine}  →  {CallChainTargetUrl}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            SignatureBase = capturedBase,
            CodeSnippet = CodeSnippets.CallChainRetry,
            SubSteps = new SubStep[]
            {
                new("GET / (agent token)", Actor.Orchestrator, Actor.Resource),
                new("401 + resource_token", Actor.Resource, Actor.Orchestrator, IsResponse: true),
                new("POST /token + upstream_token", Actor.Orchestrator, Actor.PersonServer),
                new("200 + chained auth_token (nested act)", Actor.PersonServer, Actor.Orchestrator, IsResponse: true),
                new("GET / (chained auth_token)", Actor.Orchestrator, Actor.Resource),
                new("200 + claims", Actor.Resource, Actor.Orchestrator, IsResponse: true),
            },
        });
    }

    private void StepCallChainInspectResult()
    {
        var parsed = _callChainResponseBody is not null
            ? JsonNode.Parse(_callChainResponseBody) : null;

        var downstream = parsed?["downstream"];
        var downstreamAct = downstream?["act"];

        // Build a narrative explaining the nested act chain
        var actExplanation = downstreamAct is not null
            ? $"\n\nThe `act` claim in the downstream response shows the delegation " +
              $"chain: the outermost `act.sub` is the Orchestrator's identity, and " +
              $"any nested `act.act.sub` is the original calling agent (you). This " +
              $"proves end-to-end that WhoAmI was accessed on behalf of a specific " +
              $"person, delegated through a known intermediary."
            : "";

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Inspect multi-agent chain result",
            From = Actor.Agent,
            To = Actor.Agent,
            Narrative =
                "The Orchestrator's response contains three sections:\n\n" +
                "- **upstream**: how we (the calling agent) authenticated to the Orchestrator\n" +
                "- **orchestrator**: the Orchestrator's own identity and what it did\n" +
                "- **downstream**: the WhoAmI response, which includes the full " +
                "delegation chain via nested `act` claims\n\n" +
                "This demonstrates **multi-agent call chaining**: each hop in the " +
                "chain is cryptographically accountable. The Person Server built " +
                "a nested auth_token that records the full delegation path, and " +
                "the final resource (WhoAmI) can see exactly who acted on whose behalf." +
                actExplanation,
            ResponseBody = PrettyJson(_callChainResponseBody),
            TokenDecoded = FormatChainSummary(parsed),
        });
    }

    private static string FormatChainSummary(JsonNode? result)
    {
        if (result is null) return "(no response to inspect)";
        var lines = new System.Text.StringBuilder();
        lines.AppendLine("═══ Call Chain Summary ═══");
        lines.AppendLine();

        var upstream = result["upstream"];
        if (upstream is not null)
        {
            lines.AppendLine($"  Caller (you):");
            lines.AppendLine($"    scheme:     {upstream["scheme"]}");
            lines.AppendLine($"    agent:      {upstream["agent"]}");
            lines.AppendLine($"    tokenType:  {upstream["tokenType"]}");
            lines.AppendLine();
        }

        var orch = result["orchestrator"];
        if (orch is not null)
        {
            lines.AppendLine($"  Orchestrator:");
            lines.AppendLine($"    identity:   {orch["identity"]}");
            lines.AppendLine($"    action:     {orch["action"]}");
            lines.AppendLine();
        }

        var downstream = result["downstream"];
        if (downstream is not null)
        {
            lines.AppendLine($"  Downstream (WhoAmI):");
            lines.AppendLine($"    scheme:     {downstream["scheme"]}");
            lines.AppendLine($"    agent:      {downstream["agent"]}");
            var act = downstream["act"];
            if (act is not null)
            {
                lines.AppendLine($"    act.sub:    {act["sub"]}  (Orchestrator)");
                var innerAct = act["act"];
                if (innerAct is not null)
                {
                    lines.AppendLine($"    act.act.sub: {innerAct["sub"]}  (original caller = you)");
                }
            }
        }

        return lines.ToString();
    }

    // -----------------------------------------------------------------
    // Federated-flow (four-party) step implementations
    // -----------------------------------------------------------------

    private string? _federatedResponseBody;

    /// <summary>The resource's federated branch the agent targets (aud = AS).</summary>
    private string FederatedTargetUrl => $"{_options.WhoAmIUrl.TrimEnd('/')}/federated";

    private async Task StepFederatedDiscoverResourceAsync(CancellationToken ct)
    {
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        using var client = new HttpClient(capture);
        var url = $"{_options.WhoAmIUrl.TrimEnd('/')}/.well-known/aauth-resource.json";
        await client.GetAsync(url, ct);
        var ex = capture.Last!;
        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Discover resource metadata",
            From = Actor.Agent,
            To = Actor.Resource,
            Narrative =
                "The agent fetches the resource's well-known metadata, exactly as in " +
                "the three-party flow. Nothing here reveals that this resource will " +
                "delegate to an Access Server — that only shows up on the `aud` of " +
                "the resource_token in the 401 challenge.",
            RequestLine = $"{ex.RequestLine}  →  {url}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            CodeSnippet = CodeSnippets.DiscoverResource,
        });
    }

    private async Task StepFederatedSignedGetAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        var signing = BuildSigningHandler(
            () => _agentToken!, capture, (_, b) => capturedBase = b);
        using var client = new HttpClient(signing);

        var resp = await client.GetAsync(FederatedTargetUrl, ct);
        var ex = capture.Last!;

        if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized &&
            resp.Headers.TryGetValues(AAuthRequirementHeader.Name, out var reqHeaders))
        {
            var parsed = AAuthRequirementHeader.Parse(reqHeaders.First());
            _resourceToken = parsed.ResourceToken;
        }

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Signed GET /federated → 401",
            From = Actor.Agent,
            To = Actor.Resource,
            Narrative =
                "The agent signs a GET to the resource's `/federated` branch with its " +
                "agent token (`sig=jwt`). The resource returns `401` with a " +
                "resource_token — but unlike three-party, this token's `aud` is the " +
                "**Access Server** URL, not the Person Server. That single claim is " +
                "what makes this a four-party (federated) flow.",
            RequestLine = $"{ex.RequestLine}  →  {FederatedTargetUrl}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            SignatureBase = capturedBase,
            CodeSnippet = CodeSnippets.SignedGetJwt,
        });
    }

    private void StepFederatedParseChallenge()
    {
        var payload = DecodeJwt(_resourceToken)?.Payload;
        var aud = payload is not null && JsonNode.Parse(payload) is { } node
            ? (string?)node["aud"]
            : null;
        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Parse 401 challenge (aud = Access Server)",
            From = Actor.Agent,
            To = Actor.Agent,
            Narrative =
                "The agent decodes the resource_token. Its `aud` points at the " +
                $"**Access Server** (`{aud ?? "the AS URL"}`), not the Person Server. " +
                "The agent does not act on this difference — it simply forwards the " +
                "resource_token to its Person Server. The PS is the party that " +
                "notices `aud ≠ self` and federates to the AS on the agent's behalf.",
            TokenJwt = _resourceToken,
            TokenHeader = DecodeJwt(_resourceToken)?.Header,
            TokenPayload = payload,
            CodeSnippet = CodeSnippets.ParseChallenge,
        });
    }

    private async Task StepFederatedExchangeAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        // The exchange is signed with the AGENT token; the PS authenticates the
        // agent, then federates to the AS (aud ≠ self) and relays the result.
        var signing = BuildSigningHandler(
            () => _agentToken!, capture, (_, b) => capturedBase = b);
        using var client = new HttpClient(signing);

        using var resp = await client.PostAsJsonAsync(_tokenEndpoint!, new
        {
            resource_token = _resourceToken,
        }, ct);

        var ex = capture.Last!;

        // When the AS (Keycloak) requires an interactive login/consent, the PS
        // relays a 202 + Location (pending URL) + AAuth-Requirement carrying the
        // AS's user-facing interaction URL. Capture it and grow the flow into
        // the consent + poll steps (mirroring deferred mode). An auto-allow stub
        // AS resolves federation server-side and returns 200 directly.
        if (resp.StatusCode == HttpStatusCode.Accepted)
        {
            _federatedPending = true;

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
                        var interaction = AAuth.Headers.Interaction.FromRequirement(parsed);
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

            Steps.Add(new StepRecord
            {
                Number = Steps.Count + 1,
                Title = "Exchange at PS → AS federation → 202 (consent needed)",
                From = Actor.Agent,
                To = Actor.PersonServer,
                Narrative =
                    "The agent POSTs the resource_token to its Person Server. The PS " +
                    "sees the resource_token's `aud` is an **Access Server** (not " +
                    "itself) and federates: signed `POST {as}/token`. This AS's policy " +
                    "needs the user to consent, so the AS replies `202` with an " +
                    "interaction URL. The PS relays that back to the agent as its own " +
                    "`202 Accepted` with a `Location` (the PS pending URL the agent will " +
                    "poll) and an `AAuth-Requirement: requirement=interaction` header " +
                    "carrying the AS's user-facing consent URL + single-use code.",
                RequestLine = $"{ex.RequestLine}  →  {_tokenEndpoint}",
                RequestHeaders = ex.RequestHeaders,
                RequestBody = PrettyJson(ex.RequestBody),
                StatusLine = ex.StatusLine,
                ResponseHeaders = ex.ResponseHeaders,
                ResponseBody = PrettyJson(ex.ResponseBody),
                SignatureBase = capturedBase,
                CodeSnippet = CodeSnippets.TokenExchangeDeferred,
                SubSteps = new SubStep[]
                {
                    new("discover aauth-access.json", Actor.PersonServer, Actor.AccessServer),
                    new("signed POST /token (resource+agent)", Actor.PersonServer, Actor.AccessServer),
                    new("202 + interaction URL (AS consent)", Actor.AccessServer, Actor.PersonServer, IsResponse: true),
                },
                SubStepsLabel = "inside person server",
            });
            return;
        }

        var body = JsonNode.Parse(ex.ResponseBody);
        _authToken = (string?)body?["auth_token"];

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Exchange at PS → AS federation → auth_token",
            From = Actor.Agent,
            To = Actor.PersonServer,
            Narrative =
                "The agent POSTs the resource_token to its Person Server, exactly as " +
                "in three-party. The PS peeks the resource_token's `aud`, sees it is " +
                "an **Access Server** (not itself), and federates: it discovers the " +
                "AS metadata, makes a signed `POST {as}/token` (`scheme=jwks_uri`) " +
                "carrying the resource_token + agent_token, the AS evaluates policy " +
                "and mints the `aa-auth+jwt` (`dwk=aauth-access.json`, `cnf.jwk` " +
                "bound to the agent key), and the PS relays it back. All of the " +
                "AS hop happens server-side — the agent just sees a `200`.",
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
            CodeSnippet = CodeSnippets.TokenExchangeDirect,
            SubSteps = new SubStep[]
            {
                new("discover aauth-access.json", Actor.PersonServer, Actor.AccessServer),
                new("signed POST /token (resource+agent)", Actor.PersonServer, Actor.AccessServer),
                new("200 + aa-auth+jwt (dwk=aauth-access.json)", Actor.AccessServer, Actor.PersonServer, IsResponse: true),
            },
            SubStepsLabel = "inside person server",
        });
    }

    private void StepFederatedDirectUserToInteraction()
    {
        var userUrl = UserInteractionUrl
            ?? "(no interaction URL captured — is the Access Server running with RequireConsent=true or PolicyProvider=keycloak?)";

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Direct user to Access Server consent",
            From = Actor.Agent,
            To = Actor.Agent,
            Narrative =
                "The agent received the relayed interaction requirement. It constructs " +
                "the user-facing URL as `{url}?code={code}` — where `{url}` is the " +
                "**Access Server's** interaction endpoint (its own consent screen, or a " +
                "redirect to Keycloak) and `{code}` ties the upcoming browser session " +
                "back to this specific federated request. The agent surfaces this link to " +
                "its user (browser redirect, QR code, etc.). Note the user approves at the " +
                "**Access Server** here — not at the Person Server — because the AS owns the " +
                "policy decision.",
            ResponseBody = userUrl,
            TokenDecoded = $"Interaction URL:  {_interactionUrl}\nCode:             {_interactionCode}",
            CodeSnippet = CodeSnippets.DirectUserToInteraction,
        });
    }

    private async Task StepFederatedRetryAsync(CancellationToken ct)
    {
        string? capturedBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = new HttpClientHandler() };
        var signing = BuildSigningHandler(
            () => _authToken!, capture, (_, b) => capturedBase = b);
        using var client = new HttpClient(signing);

        await client.GetAsync(FederatedTargetUrl, ct);
        var ex = capture.Last!;
        _federatedResponseBody = ex.ResponseBody;

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Replay GET /federated with auth_token → 200",
            From = Actor.Agent,
            To = Actor.Resource,
            Narrative =
                "The agent retries `/federated`, now presenting the AS-issued " +
                "auth_token via `sig=jwt`. The resource verifies the JWT against the " +
                "**Access Server's** JWKS (`{iss}/.well-known/aauth-access.json`), " +
                "confirms `cnf.jwk` matches the request signer, and returns the " +
                "protected claims. The resource trusts the AS's policy verdict — it " +
                "never had to talk to the PS.",
            RequestLine = $"{ex.RequestLine}  →  {FederatedTargetUrl}",
            RequestHeaders = ex.RequestHeaders,
            StatusLine = ex.StatusLine,
            ResponseHeaders = ex.ResponseHeaders,
            ResponseBody = PrettyJson(ex.ResponseBody),
            SignatureBase = capturedBase,
            CodeSnippet = CodeSnippets.ReplayWithAuthToken,
        });
    }

    private void StepFederatedInspectResult()
    {
        var payload = DecodeJwt(_authToken)?.Payload;
        var summary = new System.Text.StringBuilder();
        summary.AppendLine("═══ Federated (four-party) Summary ═══");
        summary.AppendLine();
        if (payload is not null && JsonNode.Parse(payload) is { } node)
        {
            summary.AppendLine("  AS-minted auth token:");
            summary.AppendLine($"    iss:      {node["iss"]}   (Access Server)");
            summary.AppendLine($"    aud:      {node["aud"]}   (resource)");
            summary.AppendLine($"    agent:    {node["agent"]}");
            var cnf = node["cnf"]?["jwk"];
            if (cnf is not null)
            {
                summary.AppendLine($"    cnf.jwk:  {cnf["kty"]}/{cnf["crv"]}  (bound to the agent key)");
            }
            var act = node["act"];
            if (act is not null)
            {
                summary.AppendLine($"    act.sub:  {act["sub"]}");
            }
        }
        var header = DecodeJwt(_authToken)?.Header;
        var dwk = header is not null && JsonNode.Parse(header) is { } h ? (string?)h["dwk"] : null;

        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = "Inspect federated result",
            From = Actor.Agent,
            To = Actor.Agent,
            Narrative =
                "The auth token that authorized this request was minted by the " +
                "**Access Server**, not the Person Server. Two header/claim values " +
                $"prove the four-party shape:\n\n" +
                $"- `dwk = {dwk ?? "aauth-access.json"}` — the resource verifies it " +
                "against the AS's `/.well-known/aauth-access.json` JWKS (three-party " +
                "uses `aauth-person.json`).\n" +
                "- `cnf.jwk` — binds the token to the agent's signing key, so only " +
                "the agent that requested it can present it.\n\n" +
                "The Person Server delegated the policy decision to the AS; the " +
                "resource trusts the AS's verdict.",
            ResponseBody = PrettyJson(_federatedResponseBody),
            TokenJwt = _authToken,
            TokenHeader = header,
            TokenPayload = payload,
            TokenDecoded = summary.ToString(),
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
            return node?.ToJsonString(new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            }) ?? json;
        }
        catch (JsonException)
        {
            return json;
        }
    }
}
