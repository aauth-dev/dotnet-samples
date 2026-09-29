# SDK API Surface Consistency — Research

Follow-up to
[2026-06-27-server-api-surface](../2026-06-27-server-api-surface/implementation-plan.md)
and [2026-05-23-convenience-apis](../2026-05-23-convenience-apis/implementation-plan.md).
Baseline: `wip/aauth-draft-11` at `e2154a1` (draft-11 migration closed at
`ecc71e7`). Spec: [aauth-spec/v11](../../../aauth-spec/v11/).

## Trigger and scope

The owner asked whether the draft-11 migration drifted from the spirit of the
server-api-surface plan, then asked for a follow-up covering **both
server-facing and client-facing SDK APIs**, specifically:

- how clients are constructed;
- how configuration and callbacks are passed in (`IOptions<T>` etc.);
- fluent builders, DI registration, and convenience methods on both sides.

**No backward compatibility is required.** Every change here is a single
cutover with no shims (see the plan's guiding principles).

This is an API-shape initiative. Wire behaviour stays at draft-11. Spec
sections are cited only where an API must express a spec concept: termination
reasons, the revocation cascade, and error codes.

## Method

1. Two read-only Explore subagents, one per side:
   - client construction: builder, DI, typed clients, options, callbacks;
   - server surface: `Add*`/`Use*`/`Map*`, options, seams, samples.
2. Direct re-verification of every finding recorded below, using greps and
   file reads against `e2154a1`. Each finding carries a **V** (re-verified
   by me) or **R** (reported by a subagent, not re-verified) marker.
3. Subagent claims found **wrong** on re-verification and discarded:
   - "`AgentProviderTokenRefresher` is internal/opaque". It is `public sealed`
     ([AgentProviderTokenRefresher.cs](../../../src/AAuth/Agent/AgentProviderTokenRefresher.cs#L40)).
   - "`AgentPersonBinding` not found". It exists.
   - "`AAuthResourceManagedOptions` not found". Not relevant here; dropped.
   - The dead `AddHttpClient()` in Concierge is at L43, not L47.

## Baseline principles (carried forward)

From the server-api-surface plan, which this initiative extends to the client
side:

- **P1 Layered 80/20.** Primitives → options-driven middleware or handlers →
  one-call DI plus `Map*`. Every high-level call is expressible via
  primitives. Every default is replaceable via DI.
- **P2 Opt-in, not embedded.** Features are added by registration, never
  hard-wired.
- **P3 Configurability ceiling.** No god-object. Per-route axes are a closed
  set.
- **P4 No string indirection.** Protocol values are typed constants.
- **P5 No consumer HTTP plumbing.** Consumers register zero
  `HttpClient`/`IHttpClientFactory` plumbing.
- **P6 SDK owns mechanics, consumers own policy.**

That plan's Out-of-scope table deferred "Agent-side convenience APIs"
to the convenience-apis plan. That plan's Phase 7 ("Update Samples to Use
Convenience APIs") still has an unticked `make demo` box. As F-C2 shows, no
sample uses its `AddAAuthAgent`.

## Spec touchpoints (verified against `aauth-spec/v11`)

| Concept | Location |
|---|---|
| Termination reasons `completed`/`revoked`/`expired`/`superseded`/`administrative` | (#mission-management, L1509), table L1522-L1526 |
| `mission_terminated` + OPTIONAL `termination_reason`, open set | (#mission-status-errors, L1548), L1567 |
| PS revokes a person token: call resource `aud` **and every AS it presented to** | (#revocation-cascade, L2747), L2752 |
| PS revokes a mission: SHOULD revoke outstanding auth tokens | L2754 |
| AP revokes an agent token: PS cascade by agent `sub` | L2755 |
| `invalid_agent_token`/`expired_agent_token` kept under interim AAuth #199 ruling | [v11 migration log](../2026-09-11-aauth-v11-spec-migration/implementation-log.md) L258-L260 |

## Inventory

### Server-side public entry points (V)

| Kind | Members |
|---|---|
| `Add*` | `AddAAuthResource`, `AddAAuthResourceManaged`, `AddAAuthDiscovery`, `AddAAuthGovernance`, `AddAAuthInteractionRelay`, `AddAAuthDeferredConsent`, `AddAAuthFederation`, `AddAAuthEvents`, `AddAAuthAuthentication`, `AddAAuthAuthorization`, `AddAAuthScopePolicy`, `AddAAuthRolePolicy` |
| `Use*` | `UseAAuth`, `UseAAuthVerification`, `UseAAuthChallenge`, `UseAAuthIntermediary` |
| `Map*` | `MapAAuthResource`, `MapAAuthWellKnown`, `MapAAuthResourceWellKnown`, `MapAAuthPersonServerWellKnown`, `MapAAuthAccessServerWellKnown`, `MapAAuthAgentWellKnown`, `MapAAuthPersonServer`, `MapAAuthAccessServer`, `MapAAuthGovernance`, `MapAAuthInteractionPoll`, `MapAAuthAuthorizationEndpoint`, `MapAAuthRevocationEndpoint` (×2), `MapAAuthIssuerRevocation`, `MapAAuthHeldInvocations`, `MapAAuthEventEndpoint`, `MapAAuthSubscriptionEndpoint`, `MapR3Document` (×2), `MapR3AccessTokenEndpoint` |

### Client-side construction (V)

| Path | Shape |
|---|---|
| Builder | `new AAuthClientBuilder(key)`, `.Bootstrap(...)`, `.From(EnrollResult)`, `.SelfIssuing(key)`, `.Enrolled(key)`. Signing modes, `WithChallengeHandling`, `WithInteractionHandling`, `WithCallChaining`, `WithMission`, `WithTokenRefresh`, `WithResourceManagedAccess`, `WithInnerHandler`, then `Build()` / `BuildHandler()` / `BuildGovernance()` |
| DI agent | `AddAAuthAgent(name, Action<AAuthAgentOptions>)` registers a named `HttpClient` ([AAuthAgentServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthAgentServiceCollectionExtensions.cs#L23)) |
| DI generic signing | `AddAAuthClient(name, Action<AAuthClientOptions>)` returns `IHttpClientBuilder` ([AAuthHttpClientExtensions.cs](../../../src/AAuth/HttpSig/AAuthHttpClientExtensions.cs#L46)) |
| DI governance | `AddAAuthGovernanceClient(Func<IServiceProvider, AAuthClientBuilder>, GovernanceOptions?)` and `(Func<IServiceProvider, AAuthGovernanceClient>)` |
| Typed clients | `TokenExchangeClient(HttpClient, MetadataClient)`, `MissionClient`/`PermissionClient`/`AuditClient`/`InteractionClient(HttpClient, MetadataClient, string personServer)`, `AgentProviderClient(HttpClient, IKeyStore, IPlatformAttestor?)`, `RevocationClient(HttpClient)`, `AccessServerClient(...)`. None are DI-registered except `AccessServerClient` (via `AddAAuthFederation`) and the governance client |

## Findings

### Cross-cutting

**F-X1 No `IOptions<T>` anywhere (V).** Every SDK options type is a POCO
configured by an eager lambda or passed as an instance. The only `IOptions`
references in `src` are:

- `AAuthAuthenticationHandler.cs` L68, the ASP.NET authentication scheme
  (framework-mandated);
- `AAuthFederationServiceCollectionExtensions.cs` L56, which reads
  `IOptions<AAuthFederationOptions>` for a transport contract.

Consequences:

- Nothing binds from `IConfiguration`.
- Nothing is validated at start.
- Nothing can be post-configured or overridden by a later registration.
- Nothing is resolved lazily from `IServiceProvider`.

Samples read configuration keys by hand. The most common are
`Configuration["AAuth:Issuer"]` (12 reads), `AAuth:PersonServer` (8),
`AAuth:Wallet`/`AgentProvider`/`AccessServer` (4 each), and 17 other keys.

**F-X2 Two clock abstractions (V).**

- `TimeProvider` is used in 17 source files, e.g.
  `PersonTokenBuilder.TimeProvider` L56, `AuthTokenBuilder` L58,
  `InMemoryJtiStore`, `AAuthSingleUseGrants`, R3's pending store, and the
  PS/AS options.
- `Func<DateTimeOffset> Clock` is used in 5 places:
  - `TokenVerifier` L25
  - `AAuthVerifier` L36
  - `AAuthVerificationOptions` L108
  - `AAuthResourceOptions` L35
  - `R3Challenge` L22

**F-X3 Options mutability is inconsistent (V).**

- `init` is used by `GovernanceOptions`, `TokenVerifier`, and the PS/AS
  options.
- `set` is used by `ChallengeHandlingOptions`, `InteractionHandlingOptions`,
  `AAuthAgentOptions`, and `AAuthResourceOptions`.

`IOptions<T>` configuration requires settable properties.

**F-X4 Trust configuration is triplicated (V).** The same three pairs appear
on three types:

- `TrustedAuthTokenIssuers` / `IsTrustedAuthTokenIssuer`
- `TrustedPersonServers` / `IsTrustedPersonServer`
- `TrustedAgentProviderIssuers` / `IsTrustedAgentProviderIssuer`

The three types:

- `AAuthServerOptions` ([AAuthEndpointRequirement.cs](../../../src/AAuth/Server/Endpoints/AAuthEndpointRequirement.cs#L34))
- `AAuthVerificationOptions` ([AAuthVerificationOptions.cs](../../../src/AAuth/Server/Verification/AAuthVerificationOptions.cs))
- `AAuthResourcePipelineOptions` ([AAuthResourcePipelineOptions.cs](../../../src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs))

PS and AS options add further `TrustedAccessServers`/`TrustedPersonServers`
pairs.

### Server side

**F-S1 PS and AS have no `Add*` role registration (V).**

- `MapAAuthPersonServer(AAuthPersonServerOptions)`
  ([AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L152))
  and `MapAAuthAccessServer(AAuthAccessServerOptions)`
  ([AAuthAccessServerEndpoints.cs](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs#L107))
  take an options instance.
- The PS mapper then calls `GetRequiredService` for `TokenVerifier`,
  `IIdentityClaimsAsserter`, `IPersonPendingStore`, and `ILoggerFactory`
  (L257-L262). Later it also resolves `IMissionStore`, `IMissionLog`,
  `IMissionTokenConsent`, and `AccessServerClient`.
- No SDK method registers `TokenVerifier`, `IIdentityClaimsAsserter`,
  `IPersonPendingStore`, `IAccessPendingStore`, or `IAccessPolicy`. Only
  `AddAAuthGovernance` `TryAdd`s the mission stores.
- In-memory defaults exist but are not auto-registered:
  - `InMemoryPersonPendingStore` (IPersonPendingStore.cs L245)
  - `DefaultIdentityClaimsAsserter` (IIdentityClaimsAsserter.cs L208)
  - `InMemoryAccessPendingStore` (IAccessPendingStore.cs L139)
- The result is a hidden DI contract: it fails at map time, and P1's
  "every default replaceable via DI" only half holds.
- `MockPersonServer` registers the seams by hand:
  - `TokenVerifier` at L84
  - `IIdentityClaimsAsserter` at L95
  - `IPersonPendingStore` at L98
  - `IMissionTokenConsent` at L111
- The Federated AS registers `IAccessPolicy` at L87/L95 and
  `IAccessPendingStore` at L107.

**F-S2 Server identity is restated per call (V).** In
[MockPersonServer/Program.cs](../../../samples/MockPersonServer/Program.cs),
`psKey`/`psIssuer`/`PsKid` are passed to:

- `AddAAuthFederation(psKey, psIssuer, PsKid)` at L125;
- the PS options at L138-L140;
- the metadata options at L161-L171, which hand-build four endpoint URLs from
  `psIssuer`;
- a per-request signed client at L201;
- `TokenKey(psIssuer, ...)` at L205;
- `IssueMissionPersonTokensAsync(psIssuer, ...)` at L324/L374;
- `StoredMission(s256, psIssuer, ...)` at L321/L372;
- `Interaction.Format($"{psIssuer}/interaction", ...)` at L312, L357, L444,
  and L613.

`MapAAuthIssuerRevocation(app, issuer, dwk, signingKey, signingKid, path,
egressPolicy, clock, configure, ...)`
([RevocationEndpoint.cs](../../../src/AAuth/Server/RevocationEndpoint.cs#L28))
takes identity positionally as well. The resource role, by contrast, holds
identity once in `AddAAuthResource`.

**F-S3 Instance-parameter `Map*`/`Use*` (V).**

| Method | Parameters |
|---|---|
| `MapAAuthRevocationEndpoint` | `IJtiStore` (RevocationEndpoint.cs L102) |
| `MapAAuthHeldInvocations` | `AAuthHeldInvocations` (HeldInvocations.cs L235) |
| `MapAAuthEventEndpoint` | `(path, EventsProtocol, IAgentProviderEventStore)` (EventsEndpoints.cs L12) |
| `MapAAuthSubscriptionEndpoint` | `(path, resource, operation, protectedChannel, protocol, store, validateParameters)` (L33) |
| `MapR3Document` | `(pattern, getBytes, R3DocumentReaderPolicy)` (R3DocumentEndpoint.cs L16) |
| `MapR3AccessTokenEndpoint` | `R3AccessTokenEndpointOptions` (R3AccessTokenEndpoint.cs L22) |
| `UseAAuthChallenge` | `ChallengeOptions` (AAuthApplicationBuilderExtensions.cs L86) |
| `UseAAuthVerification` | `AAuthVerificationOptions?` (L35) |

Instance parameters bypass DI replacement, and some of these are
positional-heavy (P3).

**F-S4 Held invocations and single-use grants are concrete in-memory classes
(V).**

- `AAuthSingleUseGrants(TimeProvider?)` is at HeldInvocations.cs L41.
  `AAuthHeldInvocations(pathPrefix, pendingLifetime, timeProvider)` is at L111.
- Both are `public sealed`, with no interface and no DI registration.
- Bookings news them up (`var perCallGrants = new AAuthSingleUseGrants();` at
  [Bookings/Program.cs](../../../samples/MockResourceServers/Bookings/Program.cs#L99)).
- Both were introduced in the draft-11 migration (`a864f7d`).

**F-S5 R3 entitlement is manual (V).** Consumers must call
`R3ProposalStore.Entitle(s256, personServer)` (R3ProposalStore.cs L18)
themselves. Bookings does so at L304 and L560, and wires
`IsEntitledPersonServer` at L54-L55. Missing a call silently denies R3 access
(P6: mechanics should be SDK-owned).

**F-S6 Revocation initiation has no DI surface (V).**

- `RevocationClient(HttpClient signedHttp)` (RevocationClient.cs L24) is
  constructed per call with a hand-built PS-signed client in four places:
  - `MockPersonServer/Program.cs` L213 (client built at L201)
  - `GuidedTour/TourSession.Capabilities.cs` L1052
  - `CapabilitySupport/WalletDemoSession.cs` L78
  - `CapabilitySupport/WalletScenarioCode.cs` L53
- The spec's PS person-token fan-out (L2752) is hand-coded in the PS sample:
  it looks up `tokenInventory.GetGrantsAsync` and then revokes at each AS.
  The AP→PS cascade (L2755) and the mission cascade (L2754) have no SDK entry
  point.
- `MapAAuthIssuerRevocation` builds a signed client internally, but its
  `RevokeAtAsync` is private.

**F-S7 Termination reason is string-typed (V).**

- `GovernanceEndpoints.MissionTerminated(string? terminationReason = null)` is
  at GovernanceEndpoints.cs L178. Call sites pass the literal `"expired"` (L45).
- The client-side `AAuthMissionTerminatedException.TerminationReason` is
  `string?` (L30).
- The spec set is open (L1567), so an extensible typed constant (a
  `readonly record struct` or a constants class) fits better than an enum
  (P4).

**F-S8 Stale "removed" labels on agent-token codes (V).**

- `TokenErrorCode.InvalidAgentToken`/`ExpiredAgentToken` comments say the
  exchange cutover "removes this code" (TokenError.cs L15, L19).
- [docs/advanced/error-handling.md](../../../docs/advanced/error-handling.md)
  L111-L112 says "removed at the draft-11 exchange cutover".
- In fact they are **kept** under the #199 interim ruling, and the AS still
  emits them.

**F-S9 Minor server-sample drift (V).**

- Bookings registers `new TokenVerifier { EgressPolicy = SampleEgress.Policy }`
  by hand (L86) because `AddAAuthResource` does not register a
  `TokenVerifier`.
- Dead `builder.Services.AddHttpClient();` in `Concierge/Program.cs` L43 and
  `SampleApp/Program.cs` L20 (P5).
- `MockPersonServer` maps metadata with `MapAAuthResourceWellKnown` at
  L135, although `MapAAuthPersonServerWellKnown` exists
  (WellKnownEndpoints.cs L68). The PS may be deliberately publishing
  resource metadata for its own protected endpoints. Confirm the intent
  before changing it.

**F-S10 Agent Provider server role has no SDK endpoints (V).**
`MockAgentProvider` maps its 5 routes by hand. No `MapAAuth*` exists for AP
refresh or enrolment.

### Client side

**F-C1 `AddAAuthAgent` is an eager, reduced subset of the builder (V).**

- It runs `configure` immediately at registration (L34-L35). It cannot
  resolve anything from `IServiceProvider`, so keys, refreshers, callbacks,
  and stores must exist before `Build()`.
- `AAuthAgentOptions` exposes only these properties: `EgressPolicy`, `Key`,
  `AgentToken`, `SignatureKeyProvider`, `PersonServer`,
  `OnInteractionRequired`, `OnResourceInteraction`, `OnApprovalPending`,
  `TokenRefresher`, `PollingTimeout`, `EnableResourceManagedAccess`,
  `AAuthAccessStore`.
- Missing compared with the builder:
  - identity sources (`SelfIssuing`, `Enrolled`, `UseJwksUri`, `UseJktJwt`);
  - `OnClarificationRequired` and `MaxClarificationRounds`;
  - `Capabilities` and `Prompt`;
  - `WithMission` and `WithCallChaining`;
  - poll tuning (`DefaultPollInterval`, `PreferWaitSeconds`, `OnPoll`);
  - development loopback and inner handler.
- The docs describe the DI path as the host-app route, e.g.
  [docs/reference/dependency-injection.md](../../../docs/reference/dependency-injection.md)
  and five workflow pages. Yet no draft-11 feature (missions, clarification,
  call chaining) is reachable through it.

**F-C2 No sample uses the DI client path (V).** `AddAAuthAgent`,
`AddAAuthClient`, and `AddAAuthGovernanceClient` appear only in docs. All
samples construct clients through `AAuthClientBuilder`, which appears 80+
times across 28 files, including all SampleApp pages, Concierge, MissionAgent,
AgentConsole, and CapabilitySupport.

**F-C3 Per-request `Build()` discards token caches (V).**

- Each built pipeline allocates its own `AAuthTokenHolder` instances
  (AAuthClientBuilder.cs L676-L678 and L815). These hold the agent token and
  the carrier cache for person and auth tokens.
- The holders are not injectable or shareable.
- Samples build per request or per click and dispose with `using var`.
  Examples:
  - Concierge L151-L166 (per inbound request);
  - SampleApp pages such as Jwt.razor L151-L156;
  - MockPersonServer L201.
- The effect is that every call repeats the full challenge → token exchange.
  Nothing in the docs states the intended client lifetime.
- `AddAAuthAgent` sets `SetHandlerLifetime(Timeout.InfiniteTimeSpan)` (L81),
  so the DI path does keep caches. Only the builder path loses them.

**F-C4 Callbacks are lambdas with divergent shapes (V).**

- PS interaction: `ChallengeHandlingOptions.OnInteractionRequired` is
  `Func<Interaction, CancellationToken, Task>` (L19).
- Resource interaction: `InteractionHandlingOptions.OnInteractionRequired` is
  `Func<string, string, CancellationToken, Task>` (url, code; L18).
- Clarification: `Func<ClarificationRequirement, CancellationToken,
  Task<ClarificationResponse>>`, duplicated on both `ChallengeHandlingOptions`
  (L29) and `GovernanceOptions` (L30).
- Also lambdas: `OnApprovalPending`, `OnPoll` (`Action<HttpResponseMessage>`),
  and `OnSignatureBase`.
- `ITokenRefresher` is the only agent-side callback interface. The server side
  offers an interface seam (`IInteractionRelay` via
  `AddAAuthInteractionRelay`) for the equivalent concern.

**F-C5 Typed clients are hand-assembled (V).**

- Every typed client takes a signed `HttpClient` plus `MetadataClient`, and
  the governance clients also take a `personServer` string.
- None has a DI registration tied to a named agent. Consumers must resolve
  `MetadataClient` and build or sign the `HttpClient` themselves.
- Walkthroughs call `TokenExchangeClient.RequestPersonTokenAsync`/
  `ExchangeAsync` directly:
  - `DocumentDemoSession.cs` L47
  - `WalletScenarioCode.cs` L18

**F-C6 Key and refresher provisioning is imperative (V).**

- `AAuthAgentOptions.Key` must be a loaded `IAAuthKey` at registration time.
  The documented startup is `keyStore.LoadAsync → AddAAuthAgent`
  (dependency-injection.md L22).
- `AgentProviderTokenRefresher` is public. Its constructor takes
  `(HttpClient http, IKeyStore keyStore, string refreshEndpoint, string
  localKeyHandle, ...)` (L42 onward), and there is no DI helper to
  provision it.
- `AgentProviderClient(HttpClient, IKeyStore, IPlatformAttestor?)` has no DI
  helper either.

**F-C7 Timeouts are two-layered and undocumented (R).**

- `PollingTimeout` defaults to 5 minutes on the handler options, while
  `HttpClient.Timeout` defaults to 100 s.
- The SDK transport also applies a per-request
  `AAuthEgressPolicy.RequestTimeout` deadline (AAuthHttpTransport.cs L77,
  L141).
- A long-poll exchange behind a default `HttpClient` may hit an outer
  timeout first.
- This was not reproduced. Phase 8 must confirm or refute it with a test.

## Relationship to in-flight work

- [2026-09-28-ps-consent-dashboard](../2026-09-28-ps-consent-dashboard/implementation-plan.md)
  has 22 of 23 DoD boxes open. It edits MockPersonServer, SampleApp, and the
  walkthroughs, all of which this initiative also rewrites. The work must be
  sequenced; see Q16.

## Gaps and open questions

Each question has a proposed default. Rulings are recorded in
[implementation-log.md](implementation-log.md).

| # | Question | Proposed default |
|---|---|---|
| Q1 | Options model | `IOptions<T>` everywhere. Named options keyed by client name on the agent side. `Add*` returns a builder type for chaining. `ValidateOnStart` via `IValidateOptions<T>` |
| Q2 | Configuration binding and section names | `Add*(IConfiguration)` overloads bind scalars only. Sections: `AAuth:Resource`, `AAuth:PersonServer`, `AAuth:AccessServer`, `AAuth:Agents:<name>`. Use the configuration-binding source generator |
| Q3 | Non-bindable members (keys, seams) | Remove key and seam instances from options. Keys come from DI (keyed `IAAuthKey` or a key-source seam) by role or client name; seams are DI services |
| Q4 | Callbacks | DI interfaces are primary: `IAAuthInteractionHandler`, `IAAuthClarificationHandler`, `IAAuthApprovalObserver`. Builder lambda overloads adapt to the same interfaces; there is one internal representation |
| Q5 | Interaction callback shape | One `Interaction` type for PS- and resource-initiated interaction, with a source discriminator. The `(url, code)` lambda shape is deleted |
| Q6 | Builder vs DI | The builder stays the primitive layer. `AddAAuthAgent` composes it and reaches **full parity** (identity sources, mission, call chaining, clarification, capabilities, poll tuning). `AddAAuthClient` stays as the generic-signature primitive under the same options conventions |
| Q7 | Token cache lifetime | New `IAAuthTokenCache` seam (in-memory default, singleton per agent name) that the builder can accept. Document the client lifetime: build once and reuse |
| Q8 | Typed clients | Registered as keyed services by agent name (`[FromKeyedServices("x")] TokenExchangeClient`), sharing the agent's signed pipeline and the DI `MetadataClient` |
| Q9 | PS/AS role registration | `AddAAuthPersonServer`/`AddAAuthAccessServer` hold identity once and `TryAdd` every seam default. Parameterless `MapAAuthPersonServer()`/`MapAAuthAccessServer()`. `AddAAuthFederation` folds into the PS registration |
| Q10 | Held-invocation and single-use stores | `IAAuthHeldInvocationStore` + `IAAuthSingleUseGrantStore` with in-memory defaults, registered by `AddAAuthHeldInvocations()`. The execute delegate stays an in-process registry. Persistent implementations are out of scope |
| Q11 | Revocation initiation | `IAAuthRevocationService` resolved from DI and signed with the role identity. Adds `RevokeAtAsync`, plus PS cascades for person tokens (L2752), missions (L2754), and agent tokens (L2755) over the token inventory. `MapAAuthIssuerRevocation` collapses into role registration |
| Q12 | R3 entitlement | The SDK entitles on approval inside the R3 decision path. `Entitle` becomes internal |
| Q13 | Clock | `TimeProvider` everywhere. Delete `Func<DateTimeOffset> Clock` |
| Q14 | Trust configuration | One `AAuthTrustOptions` (sets and predicates) configured once per role and consumed by verification, pipeline, and endpoint requirements |
| Q15 | Samples policy | Host apps (SampleApp, Concierge, MissionAgent, AgentConsole, mock servers) move to the DI/high-level path. Teaching panes keep the builder only where the lesson is the primitive (e.g. signing-mode pages) |
| Q16 | Sequencing with the PS consent dashboard | The dashboard lands first; this initiative rebases on it |
| Q17 | AP server endpoints (F-S10) | Out of scope. Tracked in the Out-of-scope table |
| Q18 | Termination reason type | Extensible `readonly record struct MissionTerminationReason` with the five spec values as static members, used on both server and client |
