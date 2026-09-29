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

> **Update (2026-09):** there is **no** cross-context leak, contrary to a
> subagent claim.
>
> - The holder is single-valued, but `SelectForRequest`
>   (AAuthTokenHolder.cs L50-L73) reuses the carrier only when all of these
>   match: agent token, upstream, mission `s256`, audience, account, `exp`,
>   and cnf thumbprint. On any mismatch it falls back to the agent token.
> - The field is `volatile` over an immutable record, which makes the class
>   remark "Not thread-safe by design" stale.
> - The real defects:
>   - alternating resources **thrash**: each switch forces a re-exchange;
>   - concurrent first requests may each exchange;
>   - per-`Build()` clients lose the cache.
> - That guard tuple is the correct cache key for Q7.

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
- This was not reproduced. Phase 9 must confirm or refute it with a test.

### Added by the adversarial review

**F-X5 Keys must be exportable and sign synchronously (V).**

- `IAAuthKey` (src/AAuth/Crypto/IAAuthKey.cs L10) exposes sync
  `byte[] Sign(byte[])` (L19) and `ToPrivateJwk()` (L28).
- `ToPrivateJwk` is used only by `FileKeyStore` (L62).
- Five sync signing sites:
  - `JwtWriter.cs` L25
  - `AgentTokenBuilder.cs` L211
  - `AAuthSigningHandler.cs` L258 (already inside an async `SignAsync`,
    L124)
  - `R3Challenge.cs` L137
  - `EventsTokens.cs` L24
- Token builders expose sync `Build()`, e.g. `AuthTokenBuilder` L115,
  `PersonTokenBuilder` L59, `ResourceTokenBuilder` L79.
- Consequences:
  - A KMS/HSM key can't be expressed without sync-over-async.
  - A non-exportable key must throw from `ToPrivateJwk`.
  - Roles take `SigningKeys` dictionaries with no "active kid" for rotation.

**F-X6 Trust semantics today (V).**

- Set and predicate are AND-composed by `IssuerTrust.IsTrusted`
  (IssuerTrust.cs L31).
- `null` means no constraint (open). `TrustConfigDiagnostics` logs a startup
  warning, and `AAuthTrust.Any` (AAuthTrust.cs L30) declares intentional open
  trust.
- Predicates are sync and receive only the issuer string.
- HttpContext-aware hooks exist separately:
  - `ExpectedAccount` / `AccountSelector` (`Func<HttpContext, string?>`);
  - `R3DocumentReaderPolicy.IsEntitledPersonServer`
    (`Func<HttpContext, string, bool>`).
- Async, context-rich policy interfaces already exist elsewhere:
  `IAccessPolicy`, `IIdentityClaimsAsserter`, `IPermissionDecider`.

**F-S5 correction (V).** Entitlement is **not** tied to approval.

- The R3 spec (draft-hardt-aauth-r3.md, #r3-document-access-restriction,
  L723; entitled parties L725-L730) makes two parties entitled readers of an
  `r3_uri`: the AS in `aud` and the PS in `ps` of a resource token carrying
  it.
- Bookings calls `Entitle` right after minting such tokens (L304, L560).
  `R3Challenge` mints them in the SDK (R3Challenge.cs ~L70).

**F-S6 refinement (V).**

- The cascade engine already exists, privately:
  `RevocationEndpoint.cs` `CascadeAsync` (~L228), used by inbound
  revocation endpoints.
- What is missing is a public, app-callable entry point.
- The spec Records paragraph (protocol L2758) requires:
  - agent `(iss, jti)` + `sub`;
  - person-token upstream `(iss, jti)`;
  - AS `presented_jti`.
- `TokenGrant` is `(TokenKey, Resource, ExpiresAt)` (TokenGrant.cs L5).
  Whether the inventory already covers the `sub` index was not established.
  Phase 6 checks it first.

**Open-set convention (V).**

- Open-set protocol values are `const string` classes in `AAuthConstants`
  (e.g. `AccessModes`, L59).
- Closed sets are enums (`TokenErrorCode`, `PollingErrorCode`).
- `readonly struct` is used only for identifiers (`AgentId`, `ServerId`).

## Adversarial review (2026-09-29)

The owner's constraint: "The usage we have now is not the only way the SDK
will be used. Our builder methods and DI need to support the various trust
lambdas etc."

**Method.**

1. Six read-only adversarial subagents, one per cluster:
   - options/config (Q1, Q2, Q3, Q13);
   - trust (Q14);
   - client construction (Q6, Q7, Q8, Q15);
   - callbacks (Q4, Q5);
   - server roles and revocation (Q9, Q11);
   - server feature seams (Q10, Q12, Q18, Events).

   Each attacked the proposed default against these scenarios:
   - multi-tenant hosts;
   - dynamic and async trust;
   - KMS/HSM keys and rotation;
   - scale-out;
   - background jobs;
   - console apps without DI;
   - runtime-created agents and per-request intermediaries;
   - tests and AOT.

   Each then steelmanned alternatives and recommended a shape.
2. Lead verification of every load-bearing claim against source (the facts
   above).
3. A red-team synthesis subagent attacked the combined draft rulings for
   cross-question consistency.

**Subagent claims rejected on verification.**

| Claim | Reality |
|---|---|
| Shared token holder leaks tokens across upstream contexts (a "security bug") | `SelectForRequest` guards every context field (see F-C3 update) |
| `TimeProvider` can't model a remote/NTP clock | `TimeProvider` is abstract with a virtual `GetUtcNow`; subclass it |
| Keyed DI falls back to unkeyed registrations | It does not; the SDK must implement the fallback (R0) |
| The signing handler is sync, so async signing is impossible | `AAuthSigningHandler.SignAsync` is already async (L124); the sync sites are the token writers |
| Null set plus predicate is "not fail-closed" and ambiguous | The semantics are documented AND composition with an explicit open-trust warning (F-X6) |

**Rulings changed by the review.**

- **Q3.** The "no delegates or instances in options" rule is withdrawn. It
  would have removed trust lambdas, call-chaining sources, and console-friendly
  callbacks. It is replaced by the extensibility ladder, R0.
- **Q4.** Delegates stay alongside the interfaces, plus a per-request
  override. Capability inference keeps today's rule.
- **Q12.** Entitlement moves from "on approval" to "at resource-token
  minting". The seam stays public for host-minted tokens.
- **Q14.** Sync set-and-predicate only becomes an async context-rich
  `IAAuthTrustPolicy`, with today's semantics as the default.
- **Q18.** The `readonly record struct` becomes `const string` constants,
  matching the open-set convention.
- **Q19 (new).** Signing abstraction, from F-X5.

**R0: the extensibility ladder (cross-cutting).**

- Every decision point accepts three forms: data, a delegate, or a DI
  service. They normalize into one internal seam.
- Precedence:
  1. per-request or per-endpoint override;
  2. an explicit instance or delegate;
  3. a DI service, keyed by instance name and then unkeyed, with an
     SDK-implemented fallback;
  4. the default from data.
- Seam contexts carry an `IServiceProvider`, so scoped dependencies work
  with or without `HttpContext`.
- .NET precedent: `JwtBearerOptions` (delegate slots + `Events` +
  `EventsType`), `TokenValidationParameters.IssuerValidator`, and
  `AuthenticationBuilder`.

**Target shapes (illustrative).**

```csharp
// Trust: data, delegate, DI service, per-endpoint override
builder.Services.AddAAuthResource(config.GetSection("AAuth:Resource"))
    .WithTrust(t =>
    {
        t.PersonServers.Add("https://ps.example");                       // data
        t.IsTrustedAuthTokenIssuerAsync = (ctx, ct) =>                   // async delegate
            ctx.Services.GetRequiredService<ITenantTrust>().AllowsAsync(ctx.Issuer, ctx.HttpContext, ct);
    });
builder.Services.AddScoped<IAAuthTrustPolicy, DbTrustPolicy>();          // or a DI service
app.MapGet("/partner", ...).RequireAAuth(scope: "read", trust: t => t.PersonServers.Add("https://partner-ps"));

// Keys: KMS signer, rotation
builder.Services.AddAAuthPersonServer("tenant-a", config.GetSection("AAuth:PersonServers:tenant-a"))
    .WithSigningKeys(new AAuthSigningKeySet(active: "k2")
        .Add("k1", previousSigner).Add("k2", new KmsSigner(kms, "arn:...")));

// Agents: static from config, runtime per tenant, per-request callback routing
builder.Services.AddAAuthAgent("calendar", config.GetSection("AAuth:Agents:calendar"))
    .OnInteraction((i, ct) => Console.Out.WriteLineAsync(i.Url));        // delegate form
var tenantAgent = agents.Create(new AAuthAgentDescriptor(tenantId) { Signer = kmsSigner, PersonServer = ps });
using var req = new HttpRequestMessage(HttpMethod.Get, url);
req.Options.Set(AAuthRequestOptions.InteractionHandler, new SignalRInteractionHandler(hub, userId));
```

## Relationship to in-flight work

- [2026-09-28-ps-consent-dashboard](../2026-09-28-ps-consent-dashboard/implementation-plan.md)
  has 22 of 23 DoD boxes open. It edits MockPersonServer, SampleApp, and the
  walkthroughs, all of which this initiative also rewrites. The work must be
  sequenced; see Q16.

## Gaps and open questions

Each question has a proposed default. Rulings are recorded in
[implementation-log.md](implementation-log.md).

> **Update (2026-09):** the adversarial review revised the defaults. The
> "Revised ruling" column supersedes "Proposed default" where it is filled.

| # | Question | Proposed default | Revised ruling (2026-09-29) |
|---|---|---|---|
| Q1 | Options model | `IOptions<T>` everywhere. Named options keyed by client name on the agent side. `Add*` returns a builder type for chaining. `ValidateOnStart` via `IValidateOptions<T>` | Kept. Typed builders expose `Services` + `Name` (the `AuthenticationBuilder` pattern). Validation is sync and shape-only; async key loading fails at first use. Identity options are read once; no hot reload |
| Q2 | Configuration binding and section names | `Add*(IConfiguration)` overloads bind scalars only. Sections: `AAuth:Resource`, `AAuth:PersonServer`, `AAuth:AccessServer`, `AAuth:Agents:<name>`. Use the configuration-binding source generator | Kept. `KeyHandle` binds and resolves through the registered `IKeyStore` |
| Q3 | Non-bindable members (keys, seams) | Remove key and seam instances from options. Keys come from DI (keyed `IAAuthKey` or a key-source seam) by role or client name; seams are DI services | **Reversed.** Options MAY hold delegates and instances (binding ignores them). All three forms normalize into one seam via R0 |
| Q4 | Callbacks | DI interfaces are primary: `IAAuthInteractionHandler`, `IAAuthClarificationHandler`, `IAAuthApprovalObserver`. Builder lambda overloads adapt to the same interfaces; there is one internal representation | **Revised.** Interfaces plus delegate properties plus a per-request `HttpRequestOptionsKey<T>` override. Precedence per R0. Capabilities keep today's rule: inferred, with an explicit list (possibly empty) as override |
| Q5 | Interaction callback shape | One `Interaction` type for PS- and resource-initiated interaction, with a source discriminator. The `(url, code)` lambda shape is deleted | Kept. `Interaction(Url, Code)` gains `Source` |
| Q6 | Builder vs DI | The builder stays the primitive layer. `AddAAuthAgent` composes it and reaches **full parity** (identity sources, mission, call chaining, clarification, capabilities, poll tuning). `AddAAuthClient` stays as the generic-signature primitive under the same options conventions | Kept, **plus `IAAuthAgentFactory`** for runtime-created agents (per tenant, per user, per-request intermediary). The parity test has an explicit exclusion list |
| Q7 | Token cache lifetime | New `IAAuthTokenCache` seam (in-memory default, singleton per agent name) that the builder can accept. Document the client lifetime: build once and reuse | Kept. Multi-entry, keyed by the `SelectForRequest` guard tuple, thread-safe, single-flight per key |
| Q8 | Typed clients | Registered as keyed services by agent name (`[FromKeyedServices("x")] TokenExchangeClient`), sharing the agent's signed pipeline and the DI `MetadataClient` | Kept. Factory-created agents expose the same clients on `AAuthAgent` |
| Q9 | PS/AS role registration | `AddAAuthPersonServer`/`AddAAuthAccessServer` hold identity once and `TryAdd` every seam default. Parameterless `MapAAuthPersonServer()`/`MapAAuthAccessServer()`. `AddAAuthFederation` folds into the PS registration | Kept, with **named instances** (multi-tenant, co-hosted roles), `.Use*<T>()` helpers, and a startup warning for in-memory defaults outside Development. Identity signs via `IAAuthSigner`. A per-request issuer resolver is out of scope |
| Q10 | Held-invocation and single-use stores | `IAAuthHeldInvocationStore` + `IAAuthSingleUseGrantStore` with in-memory defaults, registered by `AddAAuthHeldInvocations()`. The execute delegate stays an in-process registry. Persistent implementations are out of scope | **Revised.** `IAAuthSingleUseGate` (claim/complete/result by `jti`) plus `IAAuthHeldInvocationStore`, both serializable. Per-route lifetime via endpoint metadata |
| Q11 | Revocation initiation | `IAAuthRevocationService` resolved from DI and signed with the role identity. Adds `RevokeAtAsync`, plus PS cascades for person tokens (L2752), missions (L2754), and agent tokens (L2755) over the token inventory. `MapAAuthIssuerRevocation` collapses into role registration | **Refined.** Extract the existing private cascade engine, so inbound endpoints and app code (background jobs) share it. Structured per-recipient results. Check the Records (L2758) gap first |
| Q12 | R3 entitlement | The SDK entitles on approval inside the R3 decision path. `Entitle` becomes internal | **Corrected.** Entitle the `aud` AS and the `ps` PS whenever the SDK mints a resource token carrying `r3_uri` (r3 L725-L730), via `IR3DocumentEntitlements`. `EntitleAsync` stays public for host-minted tokens |
| Q13 | Clock | `TimeProvider` everywhere. Delete `Func<DateTimeOffset> Clock` | Kept. Custom clocks subclass `TimeProvider` |
| Q14 | Trust configuration | One `AAuthTrustOptions` (sets and predicates) configured once per role and consumed by verification, pipeline, and endpoint requirements | **Revised.** Async `IAAuthTrustPolicy(AAuthTrustContext)` carrying issuer, party, token type, `HttpContext?`, and `IServiceProvider`. The default is built from `AAuthTrustOptions` (sets plus sync or async predicates) and preserves today's semantics. Per-endpoint override via `.RequireAAuth(trust:)` |
| Q15 | Samples policy | Host apps (SampleApp, Concierge, MissionAgent, AgentConsole, mock servers) move to the DI/high-level path. Teaching panes keep the builder only where the lesson is the primitive (e.g. signing-mode pages) | Kept |
| Q16 | Sequencing with the PS consent dashboard | The dashboard lands first; this initiative rebases on it | Unchanged; owner input |
| Q17 | AP server endpoints (F-S10) | Out of scope. Tracked in the Out-of-scope table | Unchanged |
| Q18 | Termination reason type | Extensible `readonly record struct MissionTerminationReason` with the five spec values as static members, used on both server and client | **Reversed.** `AAuthConstants.MissionTerminationReasons` `const string` values. `TerminationReason` stays `string?`, matching the open-set convention |
| Q19 | Signing abstraction (F-X5) | — | **New.** Split `IAAuthKey` into public identity plus async `IAAuthSigner`. `ToPrivateJwk` moves to an exportable subtype. Token builders get `BuildAsync`. `AAuthSigningKeySet` (kid → signer, active kid) handles rotation |
