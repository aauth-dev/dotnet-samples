using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Samples.Capabilities;
using AAuth.Samples.Events;
using AAuth.Server;
using AAuth.Tokens;

namespace GuidedTour;

/// <summary>
/// Capability flows (Events, Wallet Protocol, Document Release, Travel Catalog).
/// Each flow is a list of <see cref="CapStep"/> entries; every entry records one
/// <see cref="StepRecord"/> from a real wire exchange, so these flows render
/// with the same step list, sequence diagram and payload inspector as the
/// core flows. Deferred exchanges adapt the remaining plan to what the server
/// actually answered: <c>200</c> drops the consent steps, <c>202
/// requirement=interaction</c> inserts direct-user / approve / poll steps, and
/// <c>202 requirement=clarification</c> inserts an answer step first.
/// </summary>
public sealed partial class TourSession
{
    private enum CapKind { Action, DirectUser, Approval, Poll, Clarify }

    private enum CapOutcome { Done, Interaction, Clarification, Pending, Denied, Other }

    private sealed record CapStep(
        string Title, string Description, Actor From, Actor To, CapKind Kind,
        Func<CancellationToken, Task>? Run = null);

    /// <summary>
    /// Who is polled after a deferred response, with which token, and what a
    /// terminal <c>200</c> yields (an auth token by default).
    /// </summary>
    private sealed record CapCycle(
        Func<string> PollToken, Actor PollTarget, string PollTargetName,
        string SuccessTitle, Action<CapturedExchange>? OnSuccess = null);

    private const string ClarificationAnswer = "Compare the available travel budget before booking.";

    private readonly List<CapStep> _capPlan = [];
    private CapCycle? _capCycle;
    private string? _capResult;

    private WalletFlow _walletScenario = WalletFlow.Clarification;
    private string _catalogService = "destinations";
    private bool _eventsProtected = true;
    private string _eventsAccount = "personal";

    // Events flow state: the AP-enrolled key/token, subscription, and delivery.
    private string? _eventsAgent;
    private string? _eventsAsyncApiUrl;
    private string? _eventsPublicUrl;
    private string? _eventsEndpoint;
    private string? _eventsSubscriptionUrl;
    private string? _eventsSubscribeToken;
    private string? _eventsEid;
    private string? _eventsContext;
    private PendingEvent? _eventsPending;
    private string? _eventsDirectory;
    private SqliteEventStore? _eventsStore;

    // Wallet revocation: the grant that was revoked, to prove recovery mints a fresh one.
    private string? _revokedAuthJti;

    /// <summary>True when the current flow is one of the capability flows (12–15).</summary>
    public bool IsCapabilityMode => IsEventsMode || IsWalletProtocolMode || IsDocumentsMode || IsCatalogMode;

    /// <summary>True for the Bookings Events flow (AP inbox, subscription, verified delivery).</summary>
    public bool IsEventsMode => HasPersonServer && HasAgentProvider && _mode == TourMode.Events;

    /// <summary>True for the Wallet Protocol flow (clarification, AS grant chaining, revocation).</summary>
    public bool IsWalletProtocolMode => HasPersonServer && HasAccessServer && HasConcierge && _mode == TourMode.WalletProtocol;

    /// <summary>True for the Document Release flow (resource permission before PS consent).</summary>
    public bool IsDocumentsMode => HasPersonServer && _mode == TourMode.Documents;

    /// <summary>True for the Travel Catalog flow (merged OpenAPI definition, operation-bound grants).</summary>
    public bool IsCatalogMode => HasPersonServer && HasR3AccessServer && _mode == TourMode.Catalog;

    /// <summary>Wallet Protocol scenario. Changing it restarts the flow.</summary>
    public WalletFlow WalletScenario
    {
        get => _walletScenario;
        set { if (_walletScenario == value) return; _walletScenario = value; Reset(); }
    }

    /// <summary>Travel Catalog operation authorized first (<c>destinations</c> or <c>experiences</c>).</summary>
    public string CatalogService
    {
        get => _catalogService;
        set
        {
            var service = value == "experiences" ? "experiences" : "destinations";
            if (_catalogService == service) return;
            _catalogService = service;
            Reset();
        }
    }

    private string CatalogSibling => _catalogService == "destinations" ? "experiences" : "destinations";

    /// <summary>Events channel: protected reservations (account-bound) or public availability.</summary>
    public bool EventsProtected
    {
        get => _eventsProtected;
        set { if (_eventsProtected == value) return; _eventsProtected = value; Reset(); }
    }

    /// <summary>Bookings account for the protected Events channel (<c>personal</c> or <c>work</c>).</summary>
    public string EventsAccount
    {
        get => _eventsAccount;
        set
        {
            var account = value == "work" ? "work" : "personal";
            if (_eventsAccount == account) return;
            _eventsAccount = account;
            Reset();
        }
    }

    /// <summary>The verified event payload once the Events flow completes.</summary>
    public string? EventsPayload { get; private set; }

    private string DocumentsUrl => _options.DocumentsUrl.TrimEnd('/');
    private string CatalogUrl => _options.CatalogUrl.TrimEnd('/');
    private string WalletUrl => _options.WalletUrl.TrimEnd('/');
    private string BookingsUrl => _options.BookingsUrl.TrimEnd('/');
    private string PersonServerUrl => _options.PersonServerUrl!.TrimEnd('/');
    private string AgentProviderUrl => _options.AgentProviderUrl!.TrimEnd('/');

    private List<CapStep> CapPlan
    {
        get
        {
            if (_capPlan.Count == 0 && IsCapabilityMode)
            {
                _capPlan.AddRange(
                    IsEventsMode ? EventsPlan() :
                    IsWalletProtocolMode ? WalletPlan() :
                    IsDocumentsMode ? DocumentsPlan() :
                    CatalogPlan());
            }
            return _capPlan;
        }
    }

    private IReadOnlyList<TourPlanStep> CapabilityPlan =>
        CapPlan.Select((step, index) => new TourPlanStep(index + 1, step.Title, step.Description, step.From, step.To)).ToArray();

    private CapKind? NextCapKind => Steps.Count < CapPlan.Count ? CapPlan[Steps.Count].Kind : null;

    private int NextCapStepNumber(CapKind kind)
    {
        for (var index = Steps.Count; index < CapPlan.Count; index++)
        {
            if (CapPlan[index].Kind == kind) return index + 1;
        }
        if (kind == CapKind.Poll)
        {
            for (var index = Math.Min(Steps.Count, CapPlan.Count) - 1; index >= 0; index--)
            {
                if (CapPlan[index].Kind == CapKind.Poll) return index + 1;
            }
        }
        return 0;
    }

    private void ResetCapabilityState()
    {
        _capPlan.Clear();
        _capCycle = null;
        _capResult = null;
        _eventsAgent = null;
        _eventsAsyncApiUrl = null;
        _eventsPublicUrl = null;
        _eventsEndpoint = null;
        _eventsSubscriptionUrl = null;
        _eventsSubscribeToken = null;
        _eventsEid = null;
        _eventsContext = null;
        _eventsPending = null;
        _eventsStore = null;
        EventsPayload = null;
        _revokedAuthJti = null;
        if (_eventsDirectory is not null)
        {
            try { Directory.Delete(_eventsDirectory, recursive: true); } catch { /* best effort */ }
            _eventsDirectory = null;
        }
    }

    private async Task RunCapabilityStepAsync(CancellationToken ct)
    {
        if (Steps.Count >= CapPlan.Count) return;
        if (!IsEventsMode) await EnsureAgentReadyAsync(ct);
        var step = CapPlan[Steps.Count];
        switch (step.Kind)
        {
            case CapKind.Approval:
                StepUserApprovesPlaceholder();
                break;
            case CapKind.Poll:
                if (_pollingTask is { } running && !running.IsCompleted) await running.ConfigureAwait(false);
                else await CapPollAsync(ct);
                break;
            default:
                await step.Run!(ct);
                break;
        }
    }

    // -----------------------------------------------------------------
    // Plans
    // -----------------------------------------------------------------

    private static CapStep Act(string title, string description, Actor from, Actor to, Func<CancellationToken, Task> run)
        => new(title, description, from, to, CapKind.Action, run);

    private static CapStep Local(string title, string description, Action run)
        => new(title, description, Actor.Agent, Actor.Agent, CapKind.Action, _ => { run(); return Task.CompletedTask; });

    private IEnumerable<CapStep> ConsentGroup(bool clarification, string authority, Actor authorityActor, string pollTarget, Actor pollActor)
    {
        if (clarification)
        {
            yield return new("Answer the clarification", "The authority asked why; the agent answers on the pending URL, then reads the next requirement.",
                Actor.Agent, Actor.PersonServer, CapKind.Clarify, CapAnswerClarificationAsync);
        }
        yield return new("Direct user to interaction URL", "Agent surfaces {url}?code={code} so its user can decide.",
            Actor.Agent, Actor.Agent, CapKind.DirectUser, _ => { StepDirectUserToInteraction(); return Task.CompletedTask; });
        yield return new($"User decides at the {authority}", $"The user signs in at the {authority} and approves or denies in a new tab.",
            authorityActor, authorityActor, CapKind.Approval);
        yield return new($"Poll {pollTarget} pending URL", $"Signed GETs until the {pollTarget} answers 200, a new requirement, or 403 denied.",
            Actor.Agent, pollActor, CapKind.Poll);
    }

    private IEnumerable<CapStep> PsConsentGroup(bool clarification = false, string authority = "Person Server", Actor authorityActor = Actor.PersonServer)
        => ConsentGroup(clarification, authority, authorityActor, "Person Server", Actor.PersonServer);

    // A federated exchange usually needs the PS's consent and then the Access
    // Server's, both relayed through the PS pending URL.
    private IEnumerable<CapStep> FederatedConsentGroups() =>
        PsConsentGroup().Concat(AccessServerConsentGroup());

    private IEnumerable<CapStep> AccessServerConsentGroup() =>
        PsConsentGroup(authority: "Access Server", authorityActor: Actor.AccessServer);

    private IEnumerable<CapStep> PersonTokenLeg(string url, Actor actor, string name)
    {
        var path = new Uri(url).PathAndQuery;
        yield return Act($"Signed GET {path} (agent token) → 401 person-token",
            $"{name} verifies the agent token, then asks who the agent acts for: requirement=person-token, no resource token.",
            Actor.Agent, actor, ct => CapAgentTokenRequestAsync(url, actor, name, ct));
        yield return Act("Discover Person Server metadata", "Unsigned GET /.well-known/aauth-person.json for person_token_endpoint + auth_token_endpoint.",
            Actor.Agent, Actor.PersonServer, StepFetchPersonMetadataAsync);
        yield return Act($"POST /person → person token ({name})", $"Signed POST {{resource: {name}}}; the PS returns an aa-person+jwt with a directed sub and cnf = agent key.",
            Actor.Agent, Actor.PersonServer, ct => StepRequestPersonTokenAsync(url, actor, ct));
        yield return Act($"GET {path} with person token → 401 + resource token",
            $"{name} verifies the person token and challenges with requirement=auth-token and a resource_token naming it (presented_jti).",
            Actor.Agent, actor, ct => CapPresentPersonTokenAsync(url, actor, name, ct));
    }

    private IEnumerable<CapStep> DocumentsPlan()
    {
        var document = DocumentsUrl + "/document";
        yield return Act("Discover Documents metadata", "Unsigned GET /.well-known/aauth-resource.json — issuer, JWKS and documents.read.",
            Actor.Agent, Actor.Resource, ct => CapDiscoverAsync(DocumentsUrl, "Documents", Actor.Resource, ct));
        foreach (var step in PersonTokenLeg(document, Actor.Resource, "Documents")) yield return step;
        yield return Act("Verify the resource token (account + permission URL)",
            "Verify the resource token against the Documents JWKS: account=work and an interaction URL for the document owner's permission page.",
            Actor.Agent, Actor.Agent, CapVerifyDocumentTokenAsync);
        yield return Act("POST /token → 202 (resource permission first)",
            "Signed POST {resource_token, presented_token}; the PS parks the request and relays the resource's permission interaction before its own consent.",
            Actor.Agent, Actor.PersonServer, ct => CapExchangeAsync(
                "Signed `POST /token` with the `resource_token` and the presented person token. The resource token carries an " +
                "`interaction` pointing at the Documents **permission page**, so the PS parks the request (`202`) and sends the " +
                "user through the document owner's decision **before** its own consent — person consent can never override the " +
                "resource owner (§Resource Interaction).",
                DocumentWalkthrough.AuthorizeExample, false, DefaultCycle(), ct));
        foreach (var step in PsConsentGroup(authority: "Documents owner, then the Person Server", authorityActor: Actor.Resource)) yield return step;
        yield return Act("GET /document with auth token → 200 released",
            "Signed retry with the PS-issued auth token (account=work, documents.read); the resource checks the owner's release and returns the document.",
            Actor.Agent, Actor.Resource, ct => CapAuthorizedRequestAsync(document, Actor.Resource, "Documents",
                "GET /document with auth token → 200 released",
                "The agent presents the auth token (`sig=jwt`). Documents verifies it was issued by the trusted PS, that " +
                "`account` is `work` and `scope` is `documents.read`, and that the document owner released this document for " +
                "this person and key. Only then is the document returned.",
                DocumentWalkthrough.DownloadExample, ct));
    }

    private IEnumerable<CapStep> CatalogPlan()
    {
        var selected = $"{CatalogUrl}/catalog/{_catalogService}";
        var sibling = $"{CatalogUrl}/catalog/{CatalogSibling}";
        yield return Act("Discover Catalog metadata", "Unsigned GET /.well-known/aauth-resource.json — r3_vocabularies names the OpenAPI definition.",
            Actor.Agent, Actor.Resource, ct => CapDiscoverAsync(CatalogUrl, "Catalog", Actor.Resource, ct));
        yield return Act("Fetch the merged OpenAPI definition", "Unsigned GET /openapi.json — one definition, colliding list operations renamed to unique operationIds.",
            Actor.Agent, Actor.Resource, CapCatalogDefinitionAsync);
        foreach (var step in PersonTokenLeg(selected, Actor.Resource, "Catalog")) yield return step;
        yield return Local("Parse the R3 resource token", "aud is the R3 Access Server; r3_uri/r3_s256 reference the selected operation's R3 document.",
            () => CapParseResourceToken("Parse the R3 resource token (aud = R3 Access Server)",
                "The resource token's `aud` is the **R3 Access Server**, so the PS must federate. `r3_uri` and `r3_s256` " +
                "reference an R3 document naming exactly one OpenAPI operation from the merged definition " +
                $"(`{OperationId(_catalogService)}`). The grant will be bound to that operation, not to the whole Catalog."));
        yield return Act("POST /token → PS federates to the R3 AS", "Signed exchange; the PS federates (aud ≠ PS), the R3 AS fetches + hash-verifies the R3 document.",
            Actor.Agent, Actor.PersonServer, ct => CapExchangeAsync(
                "Signed `POST /token` with the operation-bound `resource_token` and the presented person token. The PS sees " +
                "`aud` = R3 Access Server and federates; the AS fetches the R3 document from `r3_uri`, checks `r3_s256`, and " +
                "mints an `aa-auth+jwt` whose `r3_granted` names only this operation.",
                CodeSnippets.TokenExchangeDeferred, false, DefaultCycle(), ct));
        foreach (var step in PsConsentGroup()) yield return step;
        yield return Act($"GET /catalog/{_catalogService} with auth token → 200",
            $"{OperationId(_catalogService)} is in r3_granted, so the Catalog serves the entries.",
            Actor.Agent, Actor.Resource, ct => CapAuthorizedRequestAsync(selected, Actor.Resource, "Catalog",
                $"GET /catalog/{_catalogService} with auth token → 200",
                "The Catalog evaluates the auth token with `R3Enforcement`: the requested operation " +
                $"(`{OperationId(_catalogService)}`) is in `r3_granted`, so the entries are served.",
                CatalogWalkthrough.Example, ct));
        yield return Act($"GET /catalog/{CatalogSibling} with the same grant → 403",
            $"{OperationId(CatalogSibling)} is not in r3_granted — the sibling operation rejects the grant.",
            Actor.Agent, Actor.Resource, ct => CapAuthorizedRequestAsync(sibling, Actor.Resource, "Catalog",
                $"GET /catalog/{CatalogSibling} with the same grant → 403",
                "Same Catalog, same auth token, different operation. `R3Enforcement` finds " +
                $"`{OperationId(CatalogSibling)}` is **not** in `r3_granted`, so the sibling rejects the grant even though " +
                "both operations were once called `list` in separate backends.",
                CatalogWalkthrough.Example, ct));
        yield return Act($"GET /catalog/{CatalogSibling} with person token → 401 + resource token",
            "The same person token earns a new resource token bound to the sibling operation.",
            Actor.Agent, Actor.Resource, ct => CapPresentPersonTokenAsync(sibling, Actor.Resource, "Catalog", ct));
        yield return Act("POST /token → sibling-operation grant", "Signed exchange for the sibling operation; the R3 AS mints a separate grant.",
            Actor.Agent, Actor.PersonServer, ct => CapExchangeAsync(
                "Signed `POST /token` for the sibling operation. The R3 AS verifies the new R3 document and mints a " +
                $"separate `aa-auth+jwt` with `{OperationId(CatalogSibling)}` in `r3_granted`. The PS already holds your " +
                "consent for the Catalog, so it usually grants at once.",
                CodeSnippets.TokenExchangeDeferred, false, DefaultCycle(), ct));
        yield return Act($"GET /catalog/{CatalogSibling} with fresh grant → 200", "The sibling operation now serves its entries.",
            Actor.Agent, Actor.Resource, ct => CapAuthorizedRequestAsync(sibling, Actor.Resource, "Catalog",
                $"GET /catalog/{CatalogSibling} with fresh grant → 200",
                "The agent retries the sibling operation with the grant minted for it; " +
                $"`{OperationId(CatalogSibling)}` is in `r3_granted`, so the Catalog recovers and serves the entries.",
                CatalogWalkthrough.Example, ct));
    }

    private IEnumerable<CapStep> WalletPlan()
    {
        switch (_walletScenario)
        {
            case WalletFlow.AsGrantChaining:
                {
                    var concierge = _options.ConciergeUrl!.TrimEnd('/') + "/wallet";
                    foreach (var step in PersonTokenLeg(concierge, Actor.Concierge, "Concierge")) yield return step;
                    yield return Local("Parse the resource token (aud = Access Server)", "The Concierge's resource token names the Access Server as audience.",
                        () => CapParseResourceToken("Parse the resource token (aud = Access Server)",
                            "The Concierge is protected by the same **Access Server** as the Wallet, so its resource token's `aud` is " +
                            "the AS. The PS must federate, and the upstream auth token the agent receives will be AS-issued."));
                    yield return Act("POST /token → upstream AS grant", "Signed exchange; the PS federates to the Access Server for the Concierge grant.",
                        Actor.Agent, Actor.PersonServer, ct => CapExchangeAsync(
                            "Signed `POST /token` for the Concierge. The PS federates to the **Access Server**, which mints the " +
                            "upstream `aa-auth+jwt` (`iss` = AS) the agent will present to the Concierge.",
                            CodeSnippets.TokenExchangeDeferred, false, DefaultCycle(), ct));
                    foreach (var step in FederatedConsentGroups()) yield return step;
                    yield return Act("GET Concierge /wallet with upstream grant → chained", "The Concierge chains to the Wallet with upstream_token at the person's PS.",
                        Actor.Agent, Actor.Concierge, ct => CapConciergeWalletAsync(concierge, first: true, ct));
                    foreach (var step in ConsentGroup(false, "Person Server", Actor.PersonServer, "Concierge", Actor.Concierge)) yield return step;
                    yield return Act("GET Wallet /wallet with upstream token → 401", "The upstream token's audience is the Concierge; the Wallet rejects it.",
                        Actor.Agent, Actor.Resource, ct => CapAuthorizedRequestAsync(WalletUrl + "/wallet", Actor.Resource, "Wallet",
                            "GET Wallet /wallet with the upstream token → 401",
                            "The agent tries to skip the Concierge and use its upstream token at the Wallet directly. The token " +
                            "was issued for the Concierge, not the Wallet, so the Wallet refuses it (`401`). Only the Concierge's " +
                            "own downstream grant works there.",
                            WalletScenarioCode.AsGrantChaining, ct));
                    yield return Act("Repeat the delegated Concierge read → 200", "The Concierge reuses its cached downstream Wallet grant.",
                        Actor.Agent, Actor.Concierge, ct => CapConciergeWalletAsync(concierge, first: false, ct));
                    break;
                }
            case WalletFlow.Revocation:
                {
                    var wallet = WalletUrl + "/wallet";
                    yield return Act("Discover Wallet metadata", "Unsigned GET /.well-known/aauth-resource.json — advertises the Wallet's revocation_endpoint.",
                        Actor.Agent, Actor.Resource, ct => CapDiscoverAsync(WalletUrl, "Wallet", Actor.Resource, ct));
                    foreach (var step in PersonTokenLeg(wallet, Actor.Resource, "Wallet")) yield return step;
                    yield return Act("POST /token → PS federates to the AS", "Signed exchange; the PS presents the person token to the Access Server.",
                        Actor.Agent, Actor.PersonServer, ct => CapExchangeAsync(
                            "Signed `POST /token`. The resource token's `aud` is the **Access Server**, so the PS federates and " +
                            "presents the person token there. The AS records that grant against the person token's `jti`.",
                            CodeSnippets.TokenExchangeDeferred, false, DefaultCycle(), ct));
                    foreach (var step in FederatedConsentGroups()) yield return step;
                    yield return Act("GET /wallet with auth token → 200", "The Wallet accepts the AS-issued grant.",
                        Actor.Agent, Actor.Resource, ct => CapAuthorizedRequestAsync(wallet, Actor.Resource, "Wallet",
                            "GET /wallet with auth token → 200",
                            "The agent presents the AS-issued auth token; the Wallet trusts the AS as issuer and returns the balance view.",
                            CodeSnippets.ReplayWithAuthToken, ct));
                    yield return Act("Agent POSTs Wallet /revoke → 403 unsupported_iss", "An agent is not a server revoker: only the issuer may revoke its token.",
                        Actor.Agent, Actor.Resource, CapAgentRevokeAsync);
                    yield return Act("PS revokes its person token at the AS", "POST PS /local/wallet/revoke; the PS revokes at the AS, which cascades to the Wallet.",
                        Actor.Agent, Actor.PersonServer, CapPsRevokeAsync);
                    yield return Act("GET /wallet with revoked grant → 401", "The Wallet recorded the cascaded revocation and refuses the old auth token.",
                        Actor.Agent, Actor.Resource, ct => CapAuthorizedRequestAsync(wallet, Actor.Resource, "Wallet",
                            "GET /wallet with revoked grant → 401",
                            "The cascade reached the Wallet: it recorded the AS auth token's `{jti, exp}` as revoked, so the same " +
                            "token now fails with `401`. A revoked grant cannot be silently reused.",
                            WalletScenarioCode.Revocation, ct));
                    yield return Act("POST /person → person token (Wallet)", "The revoked person token cannot be reused; the agent asks for a fresh one.",
                        Actor.Agent, Actor.PersonServer, ct => StepRequestPersonTokenAsync(wallet, Actor.Resource, ct));
                    yield return Act("GET /wallet with person token → 401 + resource token", "A fresh challenge for the recovery exchange.",
                        Actor.Agent, Actor.Resource, ct => CapPresentPersonTokenAsync(wallet, Actor.Resource, "Wallet", ct));
                    yield return Act("POST /token → fresh grant", "Signed exchange for a new grant; recovery must never return the revoked one.",
                        Actor.Agent, Actor.PersonServer, ct => CapExchangeAsync(
                            "Signed `POST /token` with the fresh resource token and person token. The PS federates again and the " +
                            "AS mints a **new** auth token — its `jti` differs from the revoked grant's.",
                            WalletScenarioCode.Revocation, false, DefaultCycle(), ct));
                    foreach (var step in AccessServerConsentGroup()) yield return step;
                    yield return Act("GET /wallet with fresh grant → 200 (recovered)", "Access recovers only through a new, separately approved grant.",
                        Actor.Agent, Actor.Resource, ct => CapAuthorizedRequestAsync(wallet, Actor.Resource, "Wallet",
                            "GET /wallet with fresh grant → 200 (recovered)",
                            "The Wallet accepts the newly minted grant. " +
                            (_revokedAuthJti is null ? "" : $"The revoked grant was `jti` `{_revokedAuthJti}`; this one is distinct."),
                            CodeSnippets.ReplayWithAuthToken, ct));
                    break;
                }
            default:
                {
                    var review = WalletUrl + "/wallet/review";
                    yield return Act("Discover Wallet metadata", "Unsigned GET /.well-known/aauth-resource.json — scopes include wallet.review.",
                        Actor.Agent, Actor.Resource, ct => CapDiscoverAsync(WalletUrl, "Wallet", Actor.Resource, ct));
                    foreach (var step in PersonTokenLeg(review, Actor.Resource, "Wallet")) yield return step;
                    yield return Act("POST /token (clarification capable)", "The agent declares interaction + clarification capabilities; the PS federates to the Access Server.",
                        Actor.Agent, Actor.PersonServer, ct => CapExchangeAsync(
                            "Signed `POST /token` declaring `capabilities: [\"interaction\", \"clarification\"]`. The resource token's " +
                            "`aud` is the Access Server, so the PS federates. The AS's policy wants a reason before it will grant " +
                            "`wallet.review`, and the answer is relayed back through the PS as `202`.",
                            WalletScenarioCode.Clarification, true, DefaultCycle(), ct));
                    // PS consent first; federating, the AS asks why; then both decide.
                    foreach (var step in PsConsentGroup()
                        .Concat(PsConsentGroup(clarification: true))
                        .Concat(AccessServerConsentGroup())) yield return step;
                    yield return Act("GET /wallet/review with auth token → 200", "The clarified, approved grant covers wallet.review.",
                        Actor.Agent, Actor.Resource, ct => CapAuthorizedRequestAsync(review, Actor.Resource, "Wallet",
                            "GET /wallet/review with auth token → 200",
                            "The Wallet accepts the AS-issued grant for `wallet.review` — issued only after the agent explained " +
                            "why and the user approved.",
                            CodeSnippets.ReplayWithAuthToken, ct));
                    yield return Act("GET /wallet/charge with same grant → 403", "wallet.charge is outside the grant; the Wallet rejects it.",
                        Actor.Agent, Actor.Resource, ct => CapAuthorizedRequestAsync(WalletUrl + "/wallet/charge", Actor.Resource, "Wallet",
                            "GET /wallet/charge with the same grant → 403",
                            "The same auth token is presented for a charge. It carries `wallet.review`, not `wallet.charge`, so the " +
                            "Wallet refuses (`403`). A clarified grant is exactly as wide as what was approved.",
                            CodeSnippets.ReplayWithAuthToken, ct));
                    break;
                }
        }
    }

    private IEnumerable<CapStep> EventsPlan()
    {
        yield return Act("Discover Bookings metadata", "Unsigned GET /.well-known/aauth-resource.json — r3_vocabularies advertises the AsyncAPI document.",
            Actor.Agent, Actor.Resource, CapEventsDiscoverAsync);
        yield return Act("Fetch the AsyncAPI channels", "Unsigned GET of the AsyncAPI document: publicAvailability and account-bound channels.",
            Actor.Agent, Actor.Resource, CapEventsAsyncApiAsync);
        yield return Act("Discover the Agent Provider event endpoint", "Unsigned GET /.well-known/aauth-agent.json — the AP's event_endpoint is the agent's durable inbox.",
            Actor.Agent, Actor.AgentProvider, CapEventsDiscoverApAsync);
        yield return Act("Enrol with the Agent Provider", "Signed hwk POST /enrol; the AP issues the aa-agent+jwt the inbox and subscriptions are keyed to.",
            Actor.Agent, Actor.AgentProvider, CapEventsEnrolAsync);
        if (_eventsProtected)
        {
            var search = $"{BookingsUrl}/search_availability?account={Uri.EscapeDataString(_eventsAccount)}";
            foreach (var step in PersonTokenLeg(search, Actor.Resource, "Bookings")) yield return step;
            yield return Act("POST /token → account-bound grant", "Signed exchange for the account-bound search; PS consent (and R3 AS federation).",
                Actor.Agent, Actor.PersonServer, ct => CapExchangeAsync(
                    $"Signed `POST /token` for the **{_eventsAccount}** account. The resource token carries `account`, so the " +
                    "grant — and the subscription ticket it unlocks — is bound to that account.",
                    EventDemoCode.Steps[1], false, DefaultCycle(), ct));
            foreach (var step in PsConsentGroup()) yield return step;
            yield return Act("Replay search with auth token → subscription ticket", "Bookings returns availability plus notifications.subscribe_url for this account.",
                Actor.Agent, Actor.Resource, ct => CapEventsProtectedTicketAsync(search, ct));
        }
        else
        {
            yield return Local("Select the public channel URL", "No person, no grant: the public availability channel address comes from the AsyncAPI document.",
                CapEventsSelectPublic);
        }
        yield return Act("Acquire a subscribe token from the AP", "Signed POST AP /local/events/subscribe {resource, max_uses: 1} → aa-subscribe+jwt + eid.",
            Actor.Agent, Actor.AgentProvider, CapEventsSubscribeTokenAsync);
        yield return Act("Register the subscription (aa-subscribe+jwt)", "POST the subscription URL signed with the subscribe token; Bookings records the AP inbox.",
            Actor.Agent, Actor.Resource, CapEventsRegisterAsync);
        yield return Act("Trigger a sample notification", "Bookings signs a self-jwt event and delivers it to the AP's event_endpoint.",
            Actor.Agent, Actor.Resource, CapEventsNotifyAsync);
        yield return Act("Poll the signed AP inbox", "Signed GET AP /local/events/inbox — the durable inbox holds the delivered event.",
            Actor.Agent, Actor.AgentProvider, CapEventsInboxAsync);
        yield return Act("Verify and deduplicate the event", "Verify the resource's event token against the AP delivery, then ignore a resent copy (issuer + jti).",
            Actor.Agent, Actor.Agent, CapEventsVerifyAsync);
        yield return Act("Acknowledge the event", "Signed POST AP /local/events/inbox/{receipt}/ack — the AP removes it from the inbox.",
            Actor.Agent, Actor.AgentProvider, CapEventsAckAsync);
    }

    // -----------------------------------------------------------------
    // Shared wire helpers
    // -----------------------------------------------------------------

    private async Task<(HttpResponseMessage Response, CapturedExchange Exchange, string? SignatureBase)> CapSendAsync(
        HttpMethod method, string url, Func<string>? token, CancellationToken ct,
        JsonNode? body = null, byte[]? rawBody = null, Action<HttpRequestMessage>? configure = null)
    {
        string? signatureBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = AAuthHttpTransport.CreateHandler(SampleEgress.Policy) };
        HttpMessageHandler handler = token is null ? capture : BuildSigningHandler(token, capture, (_, b) => signatureBase = b);
        using var client = new SampleHttpClient(handler);
        using var request = new HttpRequestMessage(method, url);
        if (body is not null) request.Content = JsonContent.Create(body);
        else if (rawBody is not null)
        {
            request.Content = new ByteArrayContent(rawBody);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }
        configure?.Invoke(request);
        var response = await client.SendAsync(request, ct);
        return (response, capture.Last!, signatureBase);
    }

    private void CapRecord(string title, Actor from, Actor to, string narrative, CapturedExchange? exchange, string? url,
        string? signatureBase, string? snippet, string? token = null, string? decoded = null,
        IReadOnlyList<SubStep>? subSteps = null, string? subStepsLabel = null)
    {
        var jwt = DecodeJwt(token);
        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = title,
            From = from,
            To = to,
            Narrative = narrative,
            RequestLine = exchange is null ? null : $"{exchange.RequestLine}  →  {url}",
            RequestHeaders = exchange?.RequestHeaders,
            RequestBody = exchange?.RequestBody is { Length: > 0 } requestBody ? PrettyJson(requestBody) : null,
            SignatureBase = signatureBase,
            StatusLine = exchange?.StatusLine,
            ResponseHeaders = exchange?.ResponseHeaders,
            ResponseBody = exchange is null ? null : PrettyJson(exchange.ResponseBody),
            TokenJwt = token,
            TokenHeader = jwt?.Header,
            TokenPayload = jwt?.Payload,
            TokenDecoded = decoded,
            CodeSnippet = snippet,
            SubSteps = subSteps,
            SubStepsLabel = subStepsLabel,
        });
    }

    private static int Status(CapturedExchange exchange)
    {
        var parts = exchange.StatusLine.Split(' ');
        return parts.Length > 1 && int.TryParse(parts[1], out var code) ? code : 0;
    }

    private static string OperationId(string service) => "list" + char.ToUpperInvariant(service[0]) + service[1..];

    private CapCycle DefaultCycle() => new(() => _agentToken!, Actor.PersonServer, "Person Server", "Poll Person Server pending URL → auth_token");

    /// <summary>
    /// Classify a deferred-capable response and capture its pending URL and
    /// interaction / clarification. During a poll, a <c>202</c> repeating the
    /// current interaction code is still <see cref="CapOutcome.Pending"/>.
    /// </summary>
    private async Task<CapOutcome> CapOutcomeAsync(HttpResponseMessage response, CapturedExchange exchange, string baseUrl,
        bool poll, CancellationToken ct)
    {
        if (response.StatusCode == HttpStatusCode.OK) return CapOutcome.Done;
        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            try
            {
                if ((string?)JsonNode.Parse(exchange.ResponseBody)?["error"] == "denied") return CapOutcome.Denied;
            }
            catch (JsonException) { }
            return CapOutcome.Other;
        }
        if (response.StatusCode != HttpStatusCode.Accepted) return CapOutcome.Other;

        if (response.Headers.Location is { } location)
            _pendingUrl = new Uri(new Uri(baseUrl), location).AbsoluteUri;
        if (!response.Headers.TryGetValues(AAuthRequirementHeader.Name, out var values)) return CapOutcome.Pending;
        foreach (var raw in values)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            AAuthRequirementHeader.ParsedRequirement parsed;
            try { parsed = AAuthRequirementHeader.Parse(raw); }
            catch (FormatException) { continue; }
            if (parsed.Requirement == ClarificationRequirement.RequirementType)
            {
                string? question = null;
                try { question = (string?)JsonNode.Parse(exchange.ResponseBody)?[ClarificationRequirement.ClarificationField]; }
                catch (JsonException) { }
                if (poll && question == _clarificationQuestion) return CapOutcome.Pending;
                _clarificationQuestion = question;
                return CapOutcome.Clarification;
            }
            var interaction = Interaction.FromRequirement(parsed, SampleEgress.Policy);
            if (interaction is null) continue;
            if (poll && interaction.Code == _interactionCode) return CapOutcome.Pending;
            await SampleEgress.Policy.ValidateDestinationAsync(interaction.Url, ct);
            _interactionUrl = interaction.Url;
            _interactionCode = interaction.Code;
            _userApproved = false;
            return CapOutcome.Interaction;
        }
        return CapOutcome.Pending;
    }

    /// <summary>
    /// Reconcile the deferred-step group that follows the step just recorded
    /// with the actual outcome. A predicted group that starts with the right
    /// step is kept (its next approval is re-labelled with the authority the
    /// interaction URL really opens); otherwise the group is replaced, and a
    /// terminal answer drops it.
    /// </summary>
    private void CapAdjustPlan(CapOutcome outcome)
    {
        var plan = CapPlan;
        var start = Steps.Count;
        var end = start;
        while (end < plan.Count && plan[end].Kind != CapKind.Action) end++;
        CapKind? expected = outcome switch
        {
            CapOutcome.Interaction => CapKind.DirectUser,
            CapOutcome.Clarification => CapKind.Clarify,
            _ => null,
        };
        if (expected is null)
        {
            plan.RemoveRange(start, end - start);
            if (outcome == CapOutcome.Denied) _aborted = true;
            return;
        }
        if (end == start || plan[start].Kind != expected)
        {
            var cycle = _capCycle ?? DefaultCycle();
            plan.RemoveRange(start, end - start);
            plan.InsertRange(start, ConsentGroup(outcome == CapOutcome.Clarification, "Person Server", Actor.PersonServer,
                cycle.PollTargetName, cycle.PollTarget));
        }
        if (outcome == CapOutcome.Interaction && start + 1 < plan.Count && plan[start + 1].Kind == CapKind.Approval)
        {
            var (name, actor) = CapAuthority(ApprovalAuthority(plan[start + 1]), plan[start + 1].From);
            plan[start + 1] = plan[start + 1] with
            {
                Title = $"User decides at the {name}",
                Description = $"The user signs in at the {name} and approves or denies in a new tab.",
                From = actor,
                To = actor,
            };
        }
    }

    private static string ApprovalAuthority(CapStep approval) =>
        approval.Title.Replace("User decides at the ", "", StringComparison.Ordinal);

    /// <summary>Name the authority whose page the interaction URL opens.</summary>
    private (string Name, Actor Actor) CapAuthority(string fallback, Actor fallbackActor)
    {
        var url = _interactionUrl ?? "";
        static bool Under(string url, string? baseUrl) =>
            !string.IsNullOrWhiteSpace(baseUrl) && url.StartsWith(baseUrl.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase);
        if (Under(url, _options.R3AccessServerUrl)) return ("R3 Access Server", Actor.AccessServer);
        if (Under(url, _options.AccessServerUrl)) return ("Access Server", Actor.AccessServer);
        if (Under(url, _options.PersonServerUrl))
        {
            return url.Contains("/interaction/resource", StringComparison.Ordinal)
                ? ("Documents owner, then the Person Server", Actor.Resource)
                : ("Person Server", Actor.PersonServer);
        }
        return (fallback, fallbackActor);
    }

    // -----------------------------------------------------------------
    // Generic steps
    // -----------------------------------------------------------------

    private async Task CapDiscoverAsync(string baseUrl, string name, Actor actor, CancellationToken ct)
    {
        var url = $"{baseUrl}/.well-known/aauth-resource.json";
        var (response, exchange, _) = await CapSendAsync(HttpMethod.Get, url, null, ct);
        response.Dispose();
        CapRecord($"Discover {name} metadata", Actor.Agent, actor,
            $"Before signing anything, the agent fetches {name}'s well-known metadata to learn its issuer, JWKS, " +
            "scopes and any capability-specific fields. This call is unsigned.",
            exchange, url, null, CodeSnippets.DiscoverResource);
    }

    private async Task CapAgentTokenRequestAsync(string url, Actor actor, string name, CancellationToken ct)
    {
        var (response, exchange, signatureBase) = await CapSendAsync(HttpMethod.Get, url, () => _agentToken!, ct);
        response.Dispose();
        CapRecord($"Signed GET {new Uri(url).PathAndQuery} (agent token) → {Status(exchange)} person-token", Actor.Agent, actor,
            "The agent signs the request per RFC 9421 with its agent token inline (`sig=jwt`). " +
            $"{name} learns which agent is calling and which Person Server can vouch for its person — but an agent token " +
            "says nothing about the person, so it answers `401` with `AAuth-Requirement: requirement=person-token` and no " +
            "resource token (§Person Token Required).",
            exchange, url, signatureBase, CodeSnippets.SignedGetJwt);
    }

    private async Task CapPresentPersonTokenAsync(string url, Actor actor, string name, CancellationToken ct)
    {
        await StepPresentPersonTokenAsync(url, actor, ct,
            title: $"GET {new Uri(url).PathAndQuery} with person token → 401 + resource token",
            narrative:
                "The agent repeats the request, presenting the person token in `Signature-Key` (`sig=jwt`). " +
                $"{name} verifies it against the PS's JWKS (`aud` = itself, `cnf.jwk` = the signing key), now knows **which " +
                "person** the agent acts for, and answers `401` with `requirement=auth-token` and a `resource-token` naming " +
                "that person token in `presented_jti`.");
        var record = Steps[^1];
        Steps[^1] = new StepRecord
        {
            Number = record.Number, Title = record.Title, From = record.From, To = record.To, Narrative = record.Narrative,
            RequestLine = record.RequestLine, RequestHeaders = record.RequestHeaders, SignatureBase = record.SignatureBase,
            StatusLine = record.StatusLine, ResponseHeaders = record.ResponseHeaders, ResponseBody = record.ResponseBody,
            CodeSnippet = record.CodeSnippet,
            TokenJwt = _resourceToken, TokenHeader = DecodeJwt(_resourceToken)?.Header, TokenPayload = DecodeJwt(_resourceToken)?.Payload,
        };
    }

    private void CapParseResourceToken(string title, string narrative)
    {
        CapRecord(title, Actor.Agent, Actor.Agent, narrative, null, null, null, CodeSnippets.ParseChallenge, _resourceToken,
            _resourceToken is null ? "(no resource_token in challenge)" : null);
    }

    private async Task CapAuthorizedRequestAsync(string url, Actor actor, string name, string title, string narrative, string snippet, CancellationToken ct)
    {
        var (response, exchange, signatureBase) = await CapSendAsync(HttpMethod.Get, url, () => _authToken!, ct);
        response.Dispose();
        CapRecord(title, Actor.Agent, actor, narrative, exchange, url, signatureBase, snippet);
    }

    private async Task CapExchangeAsync(string narrative, string snippet, bool clarification, CapCycle cycle, CancellationToken ct)
    {
        _capCycle = cycle;
        var endpoint = _tokenEndpoint ?? $"{PersonServerUrl}/token";
        var capabilities = new JsonArray("interaction");
        if (clarification) capabilities.Add("clarification");
        var body = new JsonObject
        {
            ["resource_token"] = _resourceToken,
            ["presented_token"] = _presentedToken,
            ["capabilities"] = capabilities,
        };
        var (response, exchange, signatureBase) = await CapSendAsync(HttpMethod.Post, endpoint, () => _agentToken!, ct, body);
        var outcome = await CapOutcomeAsync(response, exchange, endpoint, poll: false, ct);
        response.Dispose();
        string? token = null;
        if (outcome == CapOutcome.Done)
        {
            _authToken = (string?)JsonNode.Parse(exchange.ResponseBody)?["auth_token"];
            token = _authToken;
        }
        var summary = outcome switch
        {
            CapOutcome.Done => "200 auth_token",
            CapOutcome.Interaction => "202 interaction",
            CapOutcome.Clarification => "202 clarification",
            CapOutcome.Denied => "403 denied",
            _ => $"{Status(exchange)}",
        };
        var outcomeText = outcome switch
        {
            CapOutcome.Done => "\n\nThe PS (and any Access Server it federated to) granted immediately: `200` with the `aa-auth+jwt`, so no consent steps are needed.",
            CapOutcome.Interaction => "\n\nThe answer is `202 Accepted` with a `Location` (pending URL) and `AAuth-Requirement: requirement=interaction` carrying the user-facing URL and single-use code.",
            CapOutcome.Clarification => "\n\nThe answer is `202 Accepted` with `AAuth-Requirement: requirement=clarification` and a question in the body — the agent must answer before any consent screen.",
            CapOutcome.Denied => "\n\nThe request was denied (`403`). The flow ends here — click **Reset** to start over.",
            _ => "",
        };
        var federated = IsFederatedResourceToken();
        CapRecord($"POST /token → {summary}", Actor.Agent, Actor.PersonServer, narrative + outcomeText, exchange, endpoint,
            signatureBase, snippet, token,
            outcome == CapOutcome.Clarification ? $"Question relayed to the agent:\n  {_clarificationQuestion}" : null,
            federated && outcome != CapOutcome.Interaction
                ? [new SubStep("POST /token (PS → AS federation)", Actor.PersonServer, Actor.AccessServer),
                   new SubStep(outcome == CapOutcome.Done ? "200 auth_token" : "202 relayed", Actor.AccessServer, Actor.PersonServer, IsResponse: true)]
                : null,
            federated && outcome != CapOutcome.Interaction ? "inside person server" : null);
        CapAdjustPlan(outcome);
    }

    private async Task CapAnswerClarificationAsync(CancellationToken ct)
    {
        var pending = _pendingUrl ?? throw new InvalidOperationException("No pending URL for the clarification.");
        var body = new JsonObject { ["action"] = "clarification_response", ["clarification_response"] = ClarificationAnswer };
        var (response, exchange, signatureBase) = await CapSendAsync(HttpMethod.Post, pending, () => _agentToken!, ct, body);
        var outcome = await CapOutcomeAsync(response, exchange, pending, poll: false, ct);
        response.Dispose();
        var followUp = "";
        string? token = null;
        if (outcome == CapOutcome.Done) token = CapApplySuccess(exchange);
        else if (outcome is CapOutcome.Pending or CapOutcome.Other && Status(exchange) is >= 200 and < 300)
        {
            var (next, nextExchange, _) = await CapSendAsync(HttpMethod.Get, pending, () => _agentToken!, ct);
            outcome = await CapOutcomeAsync(next, nextExchange, pending, poll: false, ct);
            next.Dispose();
            followUp = $"\nThen GET {new Uri(pending).AbsolutePath} → {nextExchange.StatusLine}";
            if (outcome == CapOutcome.Done) token = CapApplySuccess(nextExchange);
        }
        var question = _clarificationQuestion;
        CapRecord($"Answer the clarification → {Status(exchange)}", Actor.Agent, Actor.PersonServer,
            "The agent answers the question with a signed `POST` to the pending URL carrying " +
            "`{ action: \"clarification_response\", clarification_response }`. The PS relays the answer to the authority " +
            "that asked, which re-evaluates its policy with the answer in the request's clarification history. The agent " +
            "then reads the pending URL again to learn the next requirement — usually a consent interaction.",
            exchange, pending, signatureBase, WalletScenarioCode.Clarification, token,
            decoded: $"Question:\n  {question}\nAnswer:\n  {ClarificationAnswer}{followUp}\nNext: {outcome}");
        CapAdjustPlan(outcome);
    }

    /// <summary>
    /// Poll the current pending URL until a terminal answer or a new requirement
    /// (another interaction or a clarification) arrives. Drives the live loop box.
    /// </summary>
    private async Task CapPollAsync(CancellationToken ct)
    {
        var cycle = _capCycle ?? DefaultCycle();
        var pending = _pendingUrl ?? throw new InvalidOperationException("No pending URL captured — the prior step did not record a 202 response.");
        IsPolling = true;
        PollCount = 0;
        PollingStartedAt = DateTimeOffset.UtcNow;
        StateChanged?.Invoke();
        CapturedExchange? last = null;
        string? lastBase = null;
        var outcome = CapOutcome.Pending;
        var deadline = DateTimeOffset.UtcNow.AddMinutes(5);
        try
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var (response, exchange, signatureBase) = await CapSendAsync(HttpMethod.Get, pending, cycle.PollToken, ct,
                    configure: request => request.Headers.TryAddWithoutValidation("Prefer", "wait=10"));
                last = exchange;
                lastBase = signatureBase;
                PollCount++;
                outcome = await CapOutcomeAsync(response, exchange, pending, poll: true, ct);
                var delay = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(1);
                response.Dispose();
                StateChanged?.Invoke();
                if (outcome != CapOutcome.Pending) break;
                if (DateTimeOffset.UtcNow > deadline)
                {
                    RecordTimeoutStep(last, lastBase, "No decision within five minutes.", Actor.Agent, cycle.PollTarget);
                    _aborted = true;
                    return;
                }
                await Task.Delay(delay < TimeSpan.FromMilliseconds(250) ? TimeSpan.FromMilliseconds(250)
                    : delay > TimeSpan.FromSeconds(5) ? TimeSpan.FromSeconds(5) : delay, ct);
            }
        }
        finally
        {
            IsPolling = false;
            StateChanged?.Invoke();
        }

        if (outcome == CapOutcome.Denied)
        {
            RecordDeniedStep(last!, lastBase, last!.ResponseBody, Actor.Agent, cycle.PollTarget);
            _aborted = true;
            StateChanged?.Invoke();
            return;
        }
        var token = outcome == CapOutcome.Done ? CapApplySuccess(last!) : null;
        var title = outcome switch
        {
            CapOutcome.Done => cycle.SuccessTitle,
            CapOutcome.Interaction => $"Poll {cycle.PollTargetName} pending URL → 202 next interaction",
            CapOutcome.Clarification => $"Poll {cycle.PollTargetName} pending URL → 202 clarification",
            _ => $"Poll {cycle.PollTargetName} pending URL → {Status(last!)}",
        };
        var narrative =
            $"While the user decides in the other tab, the agent polls the {cycle.PollTargetName}'s pending URL with signed " +
            "`GET`s, honoring `Retry-After`. " + outcome switch
            {
                CapOutcome.Done => "The request resolved: `200 OK` with the result.",
                CapOutcome.Interaction => "The first decision was recorded, but another authority now needs the user: the " +
                    "pending response carries a **new** interaction code, so the agent directs the user again.",
                CapOutcome.Clarification => "The authority now asks a clarification question, which the agent answers next.",
                _ => "The pending request ended without a grant.",
            };
        var federated = cycle.PollTarget == Actor.PersonServer && IsFederatedResourceToken();
        CapRecord(title, Actor.Agent, cycle.PollTarget, narrative, last, pending, lastBase, CodeSnippets.PollPending, token,
            outcome == CapOutcome.Interaction ? $"New interaction URL:  {_interactionUrl}\nCode:                 {_interactionCode}" : null,
            federated
                ? [new SubStep("PS → AS federated token request / poll", Actor.PersonServer, Actor.AccessServer),
                   new SubStep(outcome == CapOutcome.Done ? "200 auth_token" : "202 relayed", Actor.AccessServer, Actor.PersonServer, IsResponse: true)]
                : null,
            federated ? "inside person server" : null);
        CapAdjustPlan(outcome);
        if (outcome == CapOutcome.Other) _aborted = true;
        StateChanged?.Invoke();
    }

    // aud ≠ PS means four-party: the PS federates the request to an Access Server.
    private bool IsFederatedResourceToken()
    {
        try
        {
            var audience = (string?)JsonNode.Parse(DecodeJwt(_resourceToken)?.Payload ?? "")?["aud"];
            return audience is not null && !string.Equals(audience.TrimEnd('/'), PersonServerUrl, StringComparison.Ordinal);
        }
        catch (JsonException) { return false; }
    }

    /// <summary>Apply a terminal <c>200</c> for the current cycle; returns the auth token when one was issued.</summary>
    private string? CapApplySuccess(CapturedExchange exchange)
    {
        if (_capCycle?.OnSuccess is { } onSuccess)
        {
            onSuccess(exchange);
            return null;
        }
        try { return _authToken = (string?)JsonNode.Parse(exchange.ResponseBody)?["auth_token"]; }
        catch (JsonException) { return null; }
    }

    /// <summary>Records the user-decision step for a capability consent cycle.</summary>
    private void RecordCapabilityApproval(string userUrl)
    {
        var entry = CapPlan[Steps.Count];
        var resourceFirst = userUrl.Contains("/interaction/resource", StringComparison.Ordinal);
        var authority = ApprovalAuthority(entry);
        if (IsPersonServerConsent)
        {
            Steps.Add(new StepRecord
            {
                Number = Steps.Count + 1,
                Title = $"User decides at the {authority}",
                From = entry.From,
                To = entry.To,
                Narrative = DashboardLead + "The user signs in there and submits a session-bound, CSRF-protected " +
                    "**Approve** or **Deny**. Opening a page does not approve anything. The agent is not on this " +
                    "browser channel; it learns the decision on its next poll.",
                TokenDecoded = PersonServerDecision(userUrl),
            });
            return;
        }
        Steps.Add(new StepRecord
        {
            Number = Steps.Count + 1,
            Title = $"User decides at the {authority}",
            From = resourceFirst ? Actor.Resource : entry.From,
            To = resourceFirst ? Actor.PersonServer : entry.To,
            Narrative = resourceFirst
                ? "The tour opened the PS's resource-permission interstitial in a new tab. The PS sends the user to the " +
                  "**Documents** permission page first; the document owner releases (or declines) this document, and the " +
                  "resource redirects back to the PS callback. Only after the owner releases does the PS show its own consent " +
                  "screen. If either authority declines, the agent's next poll sees `403 denied` and no token is issued. " +
                  "The agent is not on this browser channel."
                : $"The tour opened the {authority}'s interaction page in a new tab. The user signs in there and submits a " +
                  "session-bound, CSRF-protected **Approve** or **Deny**. Opening the link does not approve anything. The " +
                  "agent is not on this browser channel; it learns the decision on its next poll.",
            TokenDecoded = $"Interaction URL opened in new tab:\n  {userUrl}\n\nUser performed (browser → {authority}):\n" +
                (resourceFirst
                    ? "  GET  {ps}/interaction/resource?code=…  → Documents /permission\n  Release or decline the document → PS callback\n  Approve or deny at the PS consent screen"
                    : "  Sign in; consume code once; open decision session\n  POST approve / deny (session + CSRF)"),
        });
    }

    // -----------------------------------------------------------------
    // Documents
    // -----------------------------------------------------------------

    private async Task CapVerifyDocumentTokenAsync(CancellationToken ct)
    {
        using var http = new SampleHttpClient();
        using var metadata = new MetadataClient(http);
        using var jwks = new JwksClient(http);
        var verified = await new TokenVerifier { EgressPolicy = SampleEgress.Policy }.VerifyResourceTokenAsync(
            _resourceToken!, PersonServerUrl, _agentKey!.ComputeJwkThumbprint(), metadata, jwks,
            expectedPersonServer: PersonServerUrl, cancellationToken: ct);
        if (verified.Issuer != DocumentsUrl || verified.Account != "work")
            throw new TokenVerificationException("Document request context mismatch.");
        var interaction = verified.Payload["interaction"]?["url"]?.ToString();
        CapRecord("Verify the resource token (account + permission URL)", Actor.Agent, Actor.Agent,
            "Before exchanging, the agent verifies the resource token itself: signature against the Documents JWKS, " +
            "`aud` = the PS, `agent_jkt` = its own key, and the request context. It carries `account` = `work` and an " +
            "`interaction` URL for the document owner's **permission page** — the resource's own decision, which the PS " +
            "must obtain before asking the person.",
            null, null, null, DocumentWalkthrough.ChallengeExample, _resourceToken,
            $"Verified issuer:   {verified.Issuer}\nAccount:           {verified.Account}\nPermission page:   {interaction}");
    }

    // -----------------------------------------------------------------
    // Catalog
    // -----------------------------------------------------------------

    private async Task CapCatalogDefinitionAsync(CancellationToken ct)
    {
        var url = $"{CatalogUrl}/openapi.json";
        var (response, exchange, _) = await CapSendAsync(HttpMethod.Get, url, null, ct);
        response.Dispose();
        CapRecord("Fetch the merged OpenAPI definition", Actor.Agent, Actor.Resource,
            "The Catalog fronts a **Destinations** and an **Experiences** backend that both expose `list`. R3 draft-11 " +
            "removed the gateway vocabulary, so the Catalog publishes **one** merged OpenAPI definition and renames the " +
            "colliding operations to unique `operationId`s — `listDestinations` and `listExperiences`. Grants are bound " +
            "to these operation ids.",
            exchange, url, null, CodeSnippets.DiscoverResource);
    }

    // -----------------------------------------------------------------
    // Wallet
    // -----------------------------------------------------------------

    private async Task CapConciergeWalletAsync(string url, bool first, CancellationToken ct)
    {
        var upstream = _authToken!;
        if (first)
        {
            _capCycle = new(() => upstream, Actor.Concierge, "Concierge", "Poll Concierge pending URL → chained Wallet result",
                exchange => _capResult = exchange.ResponseBody);
        }
        else
        {
            await Task.Delay(TimeSpan.FromSeconds(1), ct);
        }
        var (response, exchange, signatureBase) = await CapSendAsync(HttpMethod.Get, url, () => upstream, ct);
        var outcome = first ? await CapOutcomeAsync(response, exchange, url, poll: false, ct) : CapOutcome.Done;
        response.Dispose();
        if (response.StatusCode == HttpStatusCode.OK) _capResult = exchange.ResponseBody;
        var subSteps = new SubStep[]
        {
            new("POST /person {upstream_token} → Wallet person token", Actor.Concierge, Actor.PersonServer),
            new("GET /wallet → 401 resource token (aud = AS)", Actor.Concierge, Actor.Resource),
            new("POST /token {upstream_token} → PS federates to AS", Actor.Concierge, Actor.PersonServer),
            new("GET /wallet with downstream grant", Actor.Concierge, Actor.Resource),
        };
        CapRecord(first
                ? $"GET Concierge /wallet with upstream grant → {Status(exchange)}{(outcome == CapOutcome.Interaction ? " chained interaction" : "")}"
                : $"Repeat the delegated Concierge read → {Status(exchange)}",
            Actor.Agent, Actor.Concierge,
            first
                ? "The agent presents its AS-issued upstream grant to the Concierge. The Concierge is itself an agent: it asks " +
                  "the **person's** PS for a Wallet person token with `upstream_token`, meets the Wallet's challenge, and " +
                  "exchanges with `upstream_token` so the PS can federate to the Wallet's Access Server. When that downstream " +
                  "grant needs the user, the Concierge chains the interaction back as its own `202` (§Interaction Chaining); " +
                  "the agent then polls the **Concierge's** pending URL."
                : "A second delegated read. The Concierge reuses the downstream Wallet grant it already holds for this person, " +
                  "so no new consent is needed and the Wallet answers `200` through the Concierge.",
            exchange, url, signatureBase, WalletScenarioCode.AsGrantChaining,
            subSteps: first ? subSteps : null, subStepsLabel: first ? "inside concierge" : null);
        if (first) CapAdjustPlan(outcome);
    }

    private async Task CapAgentRevokeAsync(CancellationToken ct)
    {
        string? signatureBase = null;
        var capture = new CapturingMessageHandler { InnerHandler = AAuthHttpTransport.CreateHandler(SampleEgress.Policy) };
        using var signed = new SampleHttpClient(BuildSigningHandler(() => _agentToken!, capture, (_, b) => signatureBase = b));
        var claims = JsonNode.Parse(DecodeJwt(_authToken)!.Value.Payload)!;
        var endpoint = WalletUrl + "/revoke";
        var result = await new RevocationClient(signed).RevokeAsync(new Uri(endpoint), (string)claims["jti"]!,
            DateTimeOffset.FromUnixTimeSeconds((long)claims["exp"]!), ct);
        CapRecord($"Agent POSTs Wallet /revoke → {(int)result.StatusCode} unsupported_iss", Actor.Agent, Actor.Resource,
            "The agent tries to revoke its own grant at the Wallet's `revocation_endpoint`, signing with its agent token. " +
            "Revocation is keyed by **issuer**: only the Access Server that issued the auth token (or the PS for its own " +
            "person tokens) may revoke it. The Wallet answers `403` with `unsupported_iss` (§Token Revocation).",
            capture.Last, endpoint, signatureBase, WalletScenarioCode.Revocation);
    }

    private async Task CapPsRevokeAsync(CancellationToken ct)
    {
        _revokedAuthJti = (string?)JsonNode.Parse(DecodeJwt(_authToken)!.Value.Payload)?["jti"];
        var endpoint = $"{PersonServerUrl}/local/wallet/revoke";
        CapturedExchange? first = null;
        CapturedExchange? last = null;
        string? signatureBase = null;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            if (attempt > 0) await Task.Delay(TimeSpan.FromSeconds(1), ct);
            var (response, exchange, sig) = await CapSendAsync(HttpMethod.Post, endpoint, () => _agentToken!, ct,
                new JsonObject { ["person_token"] = _presentedToken });
            response.Dispose();
            first ??= exchange;
            last = exchange;
            signatureBase = sig;
        }
        CapRecord($"PS revokes its person token at the AS → {Status(last!)}", Actor.Agent, Actor.PersonServer,
            "The agent asks its PS (a local demo route) to end the federated access. Per §Revocation Cascade the PS " +
            "revokes, at the Access Server, the **person token it presented** there (`{jti, exp}`, signed by the PS). The " +
            "AS then revokes every auth token it issued against that person token at the Wallet and reports each " +
            "downstream recipient. The call is repeated once to show the cascade is idempotent.",
            last, endpoint, signatureBase, WalletScenarioCode.Revocation,
            decoded: $"First call:  {first!.StatusLine}\nSecond call: {last!.StatusLine}",
            subSteps:
            [
                new("POST AS /revoke {jti, exp} (person token)", Actor.PersonServer, Actor.AccessServer),
                new("POST Wallet /revoke {jti, exp} (AS auth token)", Actor.AccessServer, Actor.Resource),
            ],
            subStepsLabel: "revocation cascade");
    }

    // -----------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------

    private SqliteEventStore EventsStore
    {
        get
        {
            if (_eventsStore is not null) return _eventsStore;
            _eventsDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".aauth", "event-tour", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_eventsDirectory);
            return _eventsStore = new SqliteEventStore(Path.Combine(_eventsDirectory, "agent.db"));
        }
    }

    private async Task CapEventsDiscoverAsync(CancellationToken ct)
    {
        var url = $"{BookingsUrl}/.well-known/aauth-resource.json";
        var (response, exchange, _) = await CapSendAsync(HttpMethod.Get, url, null, ct);
        response.Dispose();
        var metadata = JsonNode.Parse(exchange.ResponseBody);
        var document = (string?)metadata?["r3_vocabularies"]?["urn:aauth:vocabulary:asyncapi"]
            ?? throw new InvalidOperationException("Bookings did not advertise an AsyncAPI document.");
        _eventsAsyncApiUrl = new Uri(new Uri(BookingsUrl), document).AbsoluteUri;
        CapRecord("Discover Bookings metadata", Actor.Agent, Actor.Resource,
            "A reservation Aria wanted was unavailable, so Aria asks **Bookings** to notify it when a place opens. The " +
            "unsigned metadata advertises an **AsyncAPI** document under `r3_vocabularies` — the machine-readable list " +
            "of event channels Bookings can deliver.",
            exchange, url, null, EventDemoCode.Steps[0]);
    }

    private async Task CapEventsAsyncApiAsync(CancellationToken ct)
    {
        var url = _eventsAsyncApiUrl!;
        var (response, exchange, _) = await CapSendAsync(HttpMethod.Get, url, null, ct);
        response.Dispose();
        var address = (string?)JsonNode.Parse(exchange.ResponseBody)?["channels"]?["publicAvailability"]?["address"]
            ?? throw new InvalidOperationException("Public channel address is missing.");
        _eventsPublicUrl = new Uri(new Uri(BookingsUrl), address).AbsoluteUri;
        CapRecord("Fetch the AsyncAPI channels", Actor.Agent, Actor.Resource,
            "The AsyncAPI document lists the channels: `publicAvailability` anyone may subscribe to, and account-bound " +
            "reservation channels whose subscription URL is only handed out after an authorized request.",
            exchange, url, null, EventDemoCode.Steps[0]);
    }

    private async Task CapEventsDiscoverApAsync(CancellationToken ct)
    {
        var url = $"{AgentProviderUrl}/.well-known/aauth-agent.json";
        var (response, exchange, _) = await CapSendAsync(HttpMethod.Get, url, null, ct);
        response.Dispose();
        _eventsEndpoint = (string?)JsonNode.Parse(exchange.ResponseBody)?["event_endpoint"]
            ?? throw new InvalidOperationException("The Agent Provider did not advertise an event_endpoint.");
        CapRecord("Discover the Agent Provider event endpoint", Actor.Agent, Actor.AgentProvider,
            "An agent cannot receive a public webhook, so its **Agent Provider** acts as a durable inbox. The AP's " +
            "metadata names the `event_endpoint` resources deliver signed events to on the agent's behalf.",
            exchange, url, null, CodeSnippets.DiscoverAp);
    }

    private async Task CapEventsEnrolAsync(CancellationToken ct)
    {
        _agentKey = AAuthKey.Generate();
        var capture = new CapturingMessageHandler { InnerHandler = AAuthHttpTransport.CreateHandler(SampleEgress.Policy) };
        using var http = new SampleHttpClient(capture);
        var enrolled = await new AgentProviderClient(http, new InMemoryKeyStore()).EnrolWithKeyAsync(
            AgentProviderUrl, null, AgentProviderUrl + "/enrol", _agentKey, PersonServerUrl, ct);
        _agentToken = enrolled.AgentToken;
        _eventsAgent = enrolled.AgentId ?? throw new InvalidOperationException("AP did not return its assigned identity.");
        CapRecord("Enrol with the Agent Provider", Actor.Agent, Actor.AgentProvider,
            "The agent generates a key and enrols with a body-bound `hwk` signature. The AP assigns an identity and " +
            "issues an `aa-agent+jwt`; the AP's inbox, its subscribe tokens and every delivered event are keyed to this agent.",
            capture.Last, AgentProviderUrl + "/enrol", null, CodeSnippets.EnrolWithAp, _agentToken,
            $"Assigned agent: {_eventsAgent}");
    }

    private async Task CapEventsProtectedTicketAsync(string search, CancellationToken ct)
    {
        var (response, exchange, signatureBase) = await CapSendAsync(HttpMethod.Get, search, () => _authToken!, ct);
        response.Dispose();
        var json = JsonNode.Parse(exchange.ResponseBody);
        _eventsSubscriptionUrl = (string?)json?["notifications"]?["subscribe_url"]
            ?? throw new InvalidOperationException($"Bookings returned no subscription ticket (HTTP {Status(exchange)}).");
        if ((string?)json?["account"] != _eventsAccount) throw new InvalidOperationException("Authorized account mismatch.");
        CapRecord("Replay search with auth token → subscription ticket", Actor.Agent, Actor.Resource,
            $"The account-bound grant is accepted. Alongside availability, Bookings returns `notifications.subscribe_url` — a " +
            $"**protected subscription ticket** for the {_eventsAccount} reservations channel, bound to the agent key's " +
            "thumbprint (Events §Protected Subscriptions).",
            exchange, search, signatureBase, EventDemoCode.Steps[1]);
    }

    private void CapEventsSelectPublic()
    {
        _eventsSubscriptionUrl = _eventsPublicUrl;
        CapRecord("Select the public channel URL", Actor.Agent, Actor.Agent,
            "The public availability channel needs no person and no grant: its subscription address comes straight from " +
            "the AsyncAPI document. Anyone may subscribe; only the subscribe token binds the subscription to this agent's inbox.",
            null, null, null, EventDemoCode.Steps[1], decoded: $"Subscription URL: {_eventsSubscriptionUrl}");
    }

    private async Task<(CapturedExchange Exchange, string? SignatureBase, JsonNode? Json)> CapEventsSendAsync(
        HttpMethod method, string url, string token, byte[]? body, CancellationToken ct)
    {
        var (response, exchange, signatureBase) = await CapSendAsync(method, url, () => token, ct, rawBody: body ?? [],
            configure: request => request.Options.Set(AAuthSigningHandler.AdditionalComponentsKey, ["content-type", "content-digest"]));
        response.Dispose();
        if (Status(exchange) is < 200 or >= 300)
            throw new InvalidOperationException($"HTTP {Status(exchange)}: {exchange.ResponseBody}");
        JsonNode? json = null;
        try { json = exchange.ResponseBody.Length == 0 ? null : JsonNode.Parse(exchange.ResponseBody); } catch (JsonException) { }
        return (exchange, signatureBase, json);
    }

    private async Task CapEventsSubscribeTokenAsync(CancellationToken ct)
    {
        var url = $"{AgentProviderUrl}/local/events/subscribe";
        var body = Encoding.UTF8.GetBytes(new JsonObject { ["resource"] = BookingsUrl, ["max_uses"] = 1 }.ToJsonString());
        var (exchange, signatureBase, json) = await CapEventsSendAsync(HttpMethod.Post, url, _agentToken!, body, ct);
        _eventsSubscribeToken = (string?)json?["subscribe_token"];
        _eventsEid = (string?)json?["eid"];
        _eventsContext = _eventsProtected ? _eventsAccount + " reservations" : "public availability";
        EventsStore.Remember(new(_eventsEid!, BookingsUrl, _eventsAgent!, _eventsContext));
        CapRecord("Acquire a subscribe token from the AP", Actor.Agent, Actor.AgentProvider,
            "The agent asks its AP for a single-use (`max_uses: 1`) **subscribe token** for Bookings. The AP mints an " +
            "`aa-subscribe+jwt` naming its own `event_endpoint` and an event id (`eid`). The agent remembers the `eid`, " +
            "issuer and account context durably so it can recognize the event later.",
            exchange, url, signatureBase, EventDemoCode.Steps[2], _eventsSubscribeToken,
            $"eid:     {_eventsEid}\ncontext: {_eventsContext}");
    }

    private async Task CapEventsRegisterAsync(CancellationToken ct)
    {
        var url = _eventsSubscriptionUrl!;
        var (exchange, signatureBase, _) = await CapEventsSendAsync(HttpMethod.Post, url, _eventsSubscribeToken!,
            "{\"event_types\":[\"reservation.available\"]}"u8.ToArray(), ct);
        CapRecord($"Register the subscription → {Status(exchange)}", Actor.Agent, Actor.Resource,
            "The agent POSTs to the subscription URL signed with the **subscribe token** (`sig=jwt`, covering " +
            "`content-type` and `content-digest`). Bookings verifies it was issued by the agent's AP, and — for the " +
            "protected channel — that the ticket is bound to this signing key. It records the AP's `event_endpoint` as the " +
            "delivery target for `reservation.available`.",
            exchange, url, signatureBase, EventDemoCode.Steps[3]);
    }

    private async Task CapEventsNotifyAsync(CancellationToken ct)
    {
        var url = $"{BookingsUrl}/local/events/{_eventsEid}/notify" +
            (_eventsProtected ? "?account=" + Uri.EscapeDataString(_eventsAccount) : "");
        var (exchange, signatureBase, _) = await CapEventsSendAsync(HttpMethod.Post, url, _agentToken!, null, ct);
        CapRecord($"Trigger a sample notification → {Status(exchange)}", Actor.Agent, Actor.Resource,
            "A local demo route makes Bookings emit `reservation.available`. Bookings signs the event as a **self-jwt** " +
            $"(its own key) and POSTs it to the AP's `event_endpoint` ({_eventsEndpoint}). The AP verifies it and stores it " +
            "in the agent's durable inbox; no public webhook on the agent is needed.",
            exchange, url, signatureBase, EventDemoCode.Steps[4],
            subSteps: [new($"POST {new Uri(_eventsEndpoint!).AbsolutePath} (self-jwt event)", Actor.Resource, Actor.AgentProvider)],
            subStepsLabel: "resource → agent provider");
    }

    private async Task CapEventsInboxAsync(CancellationToken ct)
    {
        string? after = null;
        CapturedExchange? last = null;
        string? signatureBase = null;
        var url = $"{AgentProviderUrl}/local/events/inbox";
        for (var attempt = 0; attempt < 20 && _eventsPending is null; attempt++)
        {
            var target = url + (after is null ? "" : "?after=" + Uri.EscapeDataString(after));
            var (exchange, sig, _) = await CapEventsSendAsync(HttpMethod.Get, target, _agentToken!, null, ct);
            last = exchange;
            signatureBase = sig;
            var pending = JsonSerializer.Deserialize<PendingEvent[]>(exchange.ResponseBody, JsonSerializerOptions.Web) ?? [];
            _eventsPending = pending.SingleOrDefault(delivery => delivery.Event.Eid == _eventsEid);
            if (_eventsPending is not null) break;
            if (pending.Length == 0) await Task.Delay(TimeSpan.FromMilliseconds(500), ct);
            else after = pending[^1].Receipt;
        }
        if (_eventsPending is null) throw new InvalidOperationException("The event did not reach the inbox.");
        CapRecord("Poll the signed AP inbox → 200", Actor.Agent, Actor.AgentProvider,
            "The agent polls its AP inbox with a signed `GET`. The pending delivery carries the resource's event token and " +
            "the exact body Bookings signed, plus an AP receipt the agent acknowledges once it has processed the event.",
            last, url, signatureBase, EventDemoCode.Steps[5], _eventsPending.Event.Token,
            $"Receipt: {_eventsPending.Receipt}\neid:     {_eventsPending.Event.Eid}");
    }

    private async Task CapEventsVerifyAsync(CancellationToken ct)
    {
        using var http = new SampleHttpClient();
        var protocol = new EventsProtocol(http, [new EventsSignatureTokenVerifier(true), new EventsSignatureTokenVerifier(false)]);
        var receiver = new EventReceiver(protocol, EventsStore, _eventsAgent!);
        var processed = await receiver.ReceiveAsync(_eventsPending!.Event.Token, _eventsPending.Event.Body, ct);
        var duplicate = await receiver.ReceiveAsync(_eventsPending.Event.Token, _eventsPending.Event.Body, ct);
        EventsPayload = Encoding.UTF8.GetString(_eventsPending.Event.Body);
        CapRecord("Verify and deduplicate the event", Actor.Agent, Actor.Agent,
            "The agent verifies the event token: issued by Bookings (self-jwt, key from its JWKS), addressed to this agent, " +
            "with a `content-digest` matching the delivered body, and an `eid` it remembered. It records a durable receipt " +
            "keyed by issuer + `jti`; processing the **same** delivery again is recognized and ignored.",
            null, null, null, EventDemoCode.Steps[5], _eventsPending.Event.Token,
            new JsonObject
            {
                ["processed"] = processed, ["duplicate_ignored"] = !duplicate, ["eid"] = _eventsEid,
                ["context"] = _eventsContext, ["payload"] = JsonNode.Parse(EventsPayload),
            }.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    private async Task CapEventsAckAsync(CancellationToken ct)
    {
        var url = $"{AgentProviderUrl}/local/events/inbox/{_eventsPending!.Receipt}/ack";
        var (exchange, signatureBase, _) = await CapEventsSendAsync(HttpMethod.Post, url, _agentToken!, null, ct);
        CapRecord($"Acknowledge the event → {Status(exchange)}", Actor.Agent, Actor.AgentProvider,
            "With the event durably processed, the agent acknowledges the AP receipt. The AP removes the delivery from the " +
            "inbox. The subscription was single-use (`max_uses: 1`), so this completes the notification.",
            exchange, url, signatureBase, EventDemoCode.Steps[5],
            decoded: $"Verified payload:\n{EventsPayload}");
    }
}
