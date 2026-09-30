# SDK API Surface Consistency — Implementation Log

Append-only. Entries: `[YYYY-MM-DD] [Phase N] <title>` with a status of
`PROCEEDED (default X)`, `BLOCKED`, or `RESOLVED`.

## Decisions taken

### [2026-09-29] [Phase 0] Q0 — Backward compatibility

RESOLVED (owner). "No backward compatibility required."
- Every API change is a single cutover.
- Deleted or reshaped members get no `[Obsolete]` bridges or retained
  overloads.

### [2026-09-29] [Phase 0] Q1–Q18 — Proposed defaults seeded

PROCEEDED (defaults as listed in
[research.md](research.md#gaps-and-open-questions)).
- Each default stands unless the owner overrides it before Phase 1 starts.
- An override gets its own dated `RESOLVED` entry that supersedes the
  default.
- The defaults most in need of owner review are:
  - **Q3**: keys and seams leave the options types and resolve from DI.
  - **Q4**: callbacks become DI interfaces, and builder lambdas adapt to them.
  - **Q8**: typed clients become keyed services by agent name.
  - **Q9**: new `AddAAuthPersonServer`/`AddAAuthAccessServer`, with
    `AddAAuthFederation` folded in.
  - **Q16**: the PS consent dashboard lands first.

  > Partly superseded by the 2026-09-29 adversarial-review entries below.

### [2026-09-29] [Phase 0] Adversarial review round — method

RESOLVED. This responds to the owner's constraint that current usage is not
the only usage, and that builders and DI must support trust lambdas and
similar hooks.
- Six adversarial subagents ran, one per question cluster.
- The lead verified every load-bearing claim against source.
- A red-team synthesis pass followed.
- Five subagent claims were rejected as factually wrong; see research.md
  §Adversarial review.
- Outcome: the cross-cutting rule R0 (extensibility ladder) plus the revised
  rulings below. They supersede the matching Q1–Q18 defaults.

### [2026-09-29] [Phase 0] R0 — Extensibility ladder

PROCEEDED (default: adopt).
- Every decision point accepts data, a delegate, or a DI service,
  normalized into one internal seam.
- Precedence:
  1. per-request or per-endpoint override;
  2. an explicit instance or delegate;
  3. DI keyed by instance name, then unkeyed. The fallback is implemented by
     the SDK, because keyed DI does not fall back.
  4. the default from data.
- Seam contexts carry `IServiceProvider`.
- Precedent: `JwtBearerOptions` delegate slots + `Events`/`EventsType`,
  `TokenValidationParameters.IssuerValidator`, `AuthenticationBuilder`.

### [2026-09-29] [Phase 0] Q3 — Options may hold delegates and instances (supersedes default)

PROCEEDED (default: reversed). The "bindable scalars only / no `Func`
 properties" DoDs are withdrawn.
- Why: they would remove trust lambdas, call-chaining sources, and
  console-friendly callbacks, which the owner explicitly requires.
- Configuration binding ignores non-bindable members.

### [2026-09-29] [Phase 0] Q4 — Callbacks: interfaces + delegates + per-request override (supersedes default)

PROCEEDED (default: revised).
- A singleton handler cannot reach the current end user in a web app. The
  typed per-request key on `HttpRequestMessage.Options` solves that.
- Capability inference keeps the current rule (ChallengeHandlingOptions.cs
  L70-L76): inferred when `null`; an explicit list overrides, and an empty
  list suppresses.

### [2026-09-29] [Phase 0] Q6 — Add `IAAuthAgentFactory`

PROCEEDED (default: add).
- Named options and keyed services only cover agents known at startup.
- Runtime agents (per tenant, per user, per-request intermediary) need a
  factory, like `IHttpClientFactory` and `IAzureClientFactory<T>`.

### [2026-09-29] [Phase 0] Q7 — Cache key is the existing guard tuple

PROCEEDED (default: adopt).
- `SelectForRequest` already guards on agent token, upstream, mission,
  audience, account, `exp`, and cnf thumbprint. It is **not** leaking
  (a subagent claim, rejected).
- The multi-entry cache uses that tuple and is single-flight per key.

### [2026-09-29] [Phase 0] Q9 — Named role instances + in-memory warning

PROCEEDED (default: revised).
- Named instances cover multi-tenant and co-hosted roles.
- A per-request issuer resolver is out of scope (Out-of-scope table).
- Any `TryAdd`ed in-memory default logs a warning outside Development.

### [2026-09-29] [Phase 0] Q10 — Split single-use gate from held-invocation store

PROCEEDED (default: revised).
- The execute delegate is not serializable. The seams are therefore
  claim/complete/result by `jti` and pending entries, both serializable.
  This makes scale-out stores possible.

### [2026-09-29] [Phase 0] Q11 — Extract the existing cascade engine

PROCEEDED (default: refined).
- `RevocationEndpoint.cs` already cascades privately (`CascadeAsync`, ~L228).
- Make it a public service, shared by inbound endpoints and app code.
- Check the Records (L2758) inventory gap before building on it.

### [2026-09-29] [Phase 0] Q12 — Entitle at resource-token minting (supersedes default)

PROCEEDED (default: corrected).
- The R3 spec L725-L730 entitles the `aud` AS and the `ps` PS of a resource
  token carrying the `r3_uri`. Entitlement is not "on approval".
- `EntitleAsync` stays public for host-minted tokens.

### [2026-09-29] [Phase 0] Q14 — Async context-rich trust policy (supersedes default)

PROCEEDED (default: revised).
- `IAAuthTrustPolicy.IsTrustedAsync(AAuthTrustContext)`.
- Its default comes from `AAuthTrustOptions`, preserving AND composition,
  `null` = open with a warning, and `AAuthTrust.Any`.
- Per-endpoint override via `.RequireAAuth(trust:)`.

### [2026-09-29] [Phase 0] Q18 — Constants, not a struct (supersedes default)

PROCEEDED (default: reversed).
- The SDK's open-set convention is `const string` classes in
  `AAuthConstants` (`AccessModes`, L59). The `readonly struct` pattern is
  for identifiers only.

### [2026-09-29] [Phase 0] Plan restructured

RESOLVED.
- New Phase 3 (signing abstraction).
- Former Phases 3–11 renumbered to 4–12.

### [2026-09-29] [Phase 0] Q19 — Async signing

RESOLVED (owner): "yes make it async".
- Phase 3 proceeds as planned: `IAAuthSigner.SignAsync`, token builders get
  `BuildAsync`, and `AAuthSigningKeySet` handles rotation.
- Supersedes the open-question entry below.

### [2026-09-29] [Phase 0] Q16 — PS consent dashboard goes first

RESOLVED (owner): "We will do it next."
- [2026-09-28-ps-consent-dashboard](../2026-09-28-ps-consent-dashboard/implementation-plan.md)
  lands before this initiative.
- That plan was updated with forward-compatibility rules (Q16 there), so
  that Phases 4, 9, and 10 here can absorb its wiring.
- Before Phase 1: rebase onto the dashboard work, re-derive every
  MockPersonServer, SampleApp, and GuidedTour line citation in research.md,
  and add the dashboard's new services (`PersonConsentDecisions`,
  `ConsentRegistry`, the `ConsentSupport` prompt) to the Phase 4 and Phase 10
  migration inventories.
- Supersedes the open-question entry below.

### [2026-09-29] [Phase 0] Baseline after the dashboard landed

PROCEEDED.
- **No rebase needed.** The dashboard landed on this branch
  (`wip/aauth-draft-11`, `4692e8b`..`0ba8f78`). The baseline commit is
  **`0ba8f78`**.
- **Citations re-derived in research.md** (grep for the cited code, then
  `sed -n` on the line):
  - `MockPersonServer/Program.cs`: RevocationClient L213 → **L219**; signed
    client L201 → **L207**.
  - `GuidedTour/TourSession.Capabilities.cs` L1052 → **L1067**.
  - `CapabilitySupport/WalletDemoSession.cs` L78 → **L79**.
  - Unchanged:
    - `CapabilitySupport/WalletScenarioCode.cs` L53;
    - `SampleApp/Program.cs` L20;
    - `Concierge/Program.cs` L43;
    - `SampleApp/.../Jwt.razor` L151.
  - `src/` changed only in `BrowserConsentSessions.cs` (`Consume()`), so the
    SDK citations stand.
- **Inventories.** The dashboard seams were added to Phase 4 (registry,
  decisions, sessions, `Consume()`, the four-party `Pending202` re-advertise
  finding) and Phase 10 (restated PS identity in ConsentSupport, the CLIs and
  GuidedTour).
- **Baseline gates at `0ba8f78`.**
  - Build clean.
  - Test projects: AAuth.Tests 1691 (includes the snippet and doc-link
    tests), AAuth.Conformance 1254, AAuth.R3.Tests 327, AAuth.Events.Tests
    80.
  - e2e typecheck clean.
  - Full Playwright suite: 78 passed, 1 skipped (Keycloak).
- **ApiSurface snapshot.** The starting snapshot is the committed map at the
  baseline:
  `git show 0ba8f78:.agent/plans/2026-09-11-aauth-v11-spec-migration/api-surface-map.md`
  (160 files, +420/-154 declarations against `v0.10.0-alpha.1`).

### [2026-09-29] [Phase 1] Constants, labels, dead code

PROCEEDED.
- **Termination reasons.** `AAuthConstants.MissionTerminationReasons` defines
  `Completed`, `Revoked`, `Expired`, `Superseded` and `Administrative`
  (v11 #mission-management L1522-L1526, verified with `sed -n`). The type
  follows the `AccessModes` const convention, and `TerminationReason` stays
  `string?`.
  - The three SDK termination sites now use `Expired`:
    - `GovernanceEndpoints`: the expired-mission check;
    - `AAuthPersonServerEndpoints`: `MissionExpired`;
    - `AAuthPersonServerEndpoints`: the stored-mission expiry throw.
  - Grep evidence: `MissionTerminated("` and `"mission_terminated", "`
    match only two doc comments in `src`. Samples never pass a reason;
    MockPersonServer terminates without one.
  - The other `"expired"`/`"revoked"` literals in `src` are error codes
    (`AAuthProblemDetails`, `PollingError`, `DeferredState`), not
    termination reasons.
- **Tests.** `MissionTerminatedTests` gained:
  - `TerminationReasons_MatchSpecTable`;
  - `UnknownTerminationReason_RoundTrips` (`budget_exhausted` surfaces
    unchanged on `AAuthMissionTerminatedException`).
- **#199 labels.** `TokenError.cs` and `docs/advanced/error-handling.md` now
  say the agent-token codes are kept for the AS/R3 `agent_token` parameter
  pending the AAuth #199 interim ruling.
- **Dead code.** The `AddHttpClient()` calls in `SampleApp/Program.cs` and
  `Concierge/Program.cs` are deleted. Neither host nor any SDK registration
  it uses resolves `IHttpClientFactory`.
- **PS well-known ruling: unintended, removed.** MockPersonServer mapped
  `MapAAuthResourceWellKnown` with calendar scope descriptions, but nothing
  consumes `{ps}/.well-known/aauth-resource.json`. Test grep found only stub
  resources (Wallet, Calendar) serving that path. `MapAAuthPersonServer`
  already publishes `aauth-person.json` and the shared JWKS. The call and the
  now-unused `PsAdminScope` constant are removed.
- **Gates.**
  - Build clean.
  - Test projects: AAuth.Tests 1691, AAuth.Conformance 1256 (+2),
    AAuth.R3.Tests 327, AAuth.Events.Tests 80.
  - ApiSurface: +6 declarations.
  - Docs inventory refreshed; e2e typecheck clean.
  - Full Playwright: 78 passed, 1 skipped (Keycloak), `--retries=0`.

### [2026-09-29] [Phase 2] Shared options foundations

PROCEEDED.
- **2a TimeProvider (`b59f110`).** Every `Func<DateTimeOffset>` clock is now a
  `TimeProvider`: `TokenVerifier`, `AAuthVerifier`, `AAuthVerificationOptions`,
  `AAuthResourceOptions`, `R3Challenge`, `JwksClient`, `MetadataClient`,
  `DiscoveryCache`, `AAuthSigningHandler` and `EventsProtocol`. Tests use
  `FakeTimeProvider`. `R3ChallengeTimeTests` closes the last clock-injection
  gap.
- **2b trust seam.** `AAuthTrustOptions` (rules `AuthTokenIssuers`,
  `PersonServers`, `AgentProviders`, `AccessServers`, plus an optional
  `Policy`) and `IAAuthTrustPolicy` replace every `Trusted*` member on the
  server, verification, resource pipeline, PS, AS and R3 options.
  - An `AAuthTrustRule` ANDs an allow-list, a sync predicate and an async
    predicate. An unset rule stays open and still triggers the startup
    warning. An empty set denies. `PersonServers` falls back to
    `AuthTokenIssuers` until configured.
  - Policy resolution: explicit `Policy`, then a DI-registered
    `IAAuthTrustPolicy`, then the rules. `RequireAAuth(..., trust:)` overrides
    per endpoint (`EndpointTrustOverride_BeatsResourceTrust`).
  - `IssuerTrust` and its tests are deleted. `AgentIssuanceContext.VerifyAsync`
    and `UpstreamTokenValidator.ValidateAsync` take an async issuer predicate.
  - **Semantic change.** The PS upstream auth-token issuer check was "own
    issuer OR in set OR predicate". It is now "own issuer OR (AccessServers
    rule configured AND trusted)", so the parts AND-compose like every other
    rule.
  - Sample configuration keys (for example
    `MockPersonServer:TrustedAccessServers`) are unchanged; only the code that
    binds them moved to `Trust`.
- **2c seam resolver.** Internal `AAuthSeams.Resolve<T>`: explicit, then
  keyed (instance name), then unkeyed, then the default. `SeamResolverTests`
  covers each step.
- **2d settable options.** 143 `init` accessors on public `*Options` types are
  now `set`. The internal `DeferredExchangeOptions` keeps `init`; `init`
  remains only on non-options types (grep evidence).
- **2e validators.** Internal `AAuthOptionsValidator<T>` and
  `AddValidatedAAuthOptions<TOptions, TValidator>` (TryAddEnumerable plus
  `ValidateOnStart`). Later phases adopt it per role.
- **Finding for Phase 11.** `R3Challenge.BuildResourceToken(presented,
  agentJkt, r3Uri, r3S256)` silently binds positionally to the auth-token
  overload `(verifiedAuthToken, r3Uri, r3S256, scope)`, which then fails on
  `cnf.jwk`. The test uses named arguments.
- **Gates.**
  - Build clean.
  - Test projects: AAuth.Tests 1701, AAuth.Conformance 1257, AAuth.R3.Tests
    328, AAuth.Events.Tests 80.
  - ApiSurface: +597/-314 declarations cumulative against the baseline.
  - Docs inventory refreshed; e2e typecheck clean.
  - Full Playwright: 78 passed, 1 skipped (Keycloak), `--retries=0`.

### [2026-09-29] [Phase 3] Signing abstraction

PROCEEDED.
- **Key types.** `IAAuthKey` is the public identity (algorithm, public JWK,
  thumbprint, `Verify`, `HasPrivateKey`). `IAAuthSigner : IAAuthKey` adds
  `ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte>, CancellationToken)`.
  `IAAuthExportableKey : IAAuthSigner` adds `ToPrivateJwk`. `AAuthKey` and
  `EcdsaAAuthKey` are exportable, keep a sync `Sign`, and complete
  `SignAsync` synchronously. `KeyFactory.FromJwk` returns
  `IAAuthExportableKey`; `IKeyStore` loads and stores `IAAuthSigner`.
- **Async signing sites.** `JwtWriter.SignCompactAsync`, the five token
  builders plus `SubscribeTokenBuilder`/`EventTokenBuilder` (`BuildAsync`),
  `NamingJwtBuilder.BuildAsync`, `EventsTokens.CreateAsync`,
  `R3Challenge.BuildResourceTokenAsync`/`ChallengeAsync`,
  `R3EnforcementDecision.ToResultAsync`,
  `AAuthChallengeMiddleware.BuildResourceTokenAsync`, and
  `AAuthSigningHandler` (public sync `Sign` replaced by
  `SignHeadersAsync`). `AuthTokenResponse` mint delegates are
  `Func<CancellationToken, ValueTask<string>>`; `Create(Func<string>)`
  became `CreateAsync`. Signing members that need a private key now take
  `IAAuthSigner`.
- **`AAuthSigningKeySet`.** Replaces every `SigningKeys` dictionary (PS,
  AS, R3 AS, resource, and the four metadata options) and the
  `ResourceSigningKey`/`ResourceKeyId` pairs on `ChallengeOptions` and
  `AAuthServerOptions` (now `ResourceSigningKeys`). Snapshot-swapped under a
  lock; the first key added is active until `Activate`; the active key
  cannot be removed. PS, AS, R3 AS and the resource challenge read `Active`
  atomically per mint. The JWKS endpoint rebuilds from the live sets per
  request. `MapAAuthIssuerRevocation` takes the set and signs each
  downstream revocation with the active key at send time.
  `TokenVerifier.WithLocalIssuer` takes the set, so self-verification
  follows rotation.
- **Evidence.** `grep -rn '\.Sign(' src` returns nothing (the local-key
  `Sign` definitions are the only sync signing code).
  `RemoteSignerTests` (7) and `SigningKeySetTests` (7).
- **Migration.** A subagent migrated tests, samples, Razor snippets and
  docs (new key-interface and rotation sections in
  `docs/advanced/key-management.md` and `docs/reference/configuration.md`).
  Verified independently: build clean, counts unchanged before the new
  tests. `.GetAwaiter().GetResult()` appears only in test static
  initializers/getters, one per-request test token factory, and the
  GuidedTour jkt-jwt naming-JWT factory (local key, commented).
- **Deferred, with owner visibility.**
  - KeyHandle resolution through `IKeyStore` (Q2) needs the config-bound
    role registration: Phase 4.
  - `AddAAuthFederation` still takes one signer and kid; it folds into
    `AddAAuthPersonServer` in Phase 4, which should pass the PS key set.
  - Agent-side token factories are sync (`UseJwt`/`UseJktJwt`/`UseSelfJwt`
    `Func<string>`, `ISignatureKeyProvider.GetSignatureKeyHeader`). A KMS
    durable key minting a jkt-jwt naming JWT per request would need
    sync-over-async. Proposed for Phase 7: async signature-key providers.
- **Gates.**
  - Build clean.
  - Test projects: AAuth.Tests 1715 (+14), AAuth.Conformance 1257,
    AAuth.R3.Tests 328, AAuth.Events.Tests 80.
  - ApiSurface: +666/-368 cumulative. Docs inventory refreshed (666
    blocks); e2e typecheck clean.
  - Full Playwright: 78 passed, 1 skipped, `--retries=0`.
  - Keycloak profile (`KEYCLOAK_E2E=1`, live Keycloak 26.0 container):
    `federated-deferred` 1 passed; container removed.

### [2026-09-29] [Phase 4] Server role registration

PROCEEDED.
- **PS and AS roles.** `AddAAuthPersonServer(name?, configure?)` and
  `AddAAuthAccessServer(name?, configure?)`, plus `(IConfiguration, ...)`
  overloads for `AAuth:PersonServer` / `AAuth:AccessServer`, return builders
  exposing `Services` and `Name`. Default instance names are
  `"PersonServer"` and `"AccessServer"` (distinct so both roles co-host
  without naming). Options are named `IOptions` validated at start: issuer,
  a key (`SigningKeys` or `KeyHandle`), path shape, trusted URLs, and (AS) an
  `IAccessPolicy`. `MapAAuthPersonServer(name?)` / `MapAAuthAccessServer(name?)`
  read them; the options overloads are gone.
- **Seams.** Keyed singletons per instance name, resolved builder `Use*` →
  unkeyed DI → SDK default. The defaults are keyed factories that forward to
  an unkeyed registration first, so samples and tests that register seams
  unkeyed keep working and everything is resolvable by key. PS: pending
  store, claims asserter, `TokenVerifier`, token inventory (`IJtiStore`,
  replacing `AAuthPersonServerOptions.TokenInventory`). AS: policy (no
  default; the keyed default throws), pending store, `TokenVerifier`,
  inventory. Builders also take factory overloads. `IMissionStore` /
  `IMissionLog` defaults and `AAuthVerifier` are `TryAdd`ed.
- **Identity.** `IAAuthServerIdentity` (keyed): issuer, dwk, key set, egress
  policy, `Url(path)`, `CreateSignedClient()` (jwks_uri, active key, via the
  shared internal `AAuthSigningKeySetHandler`). MockPersonServer and the
  Federated AS use it; `psIssuer`/`asIssuer` remain only at the config read.
- **Federation.** `AddAAuthFederation` deleted; `.WithFederation()` registers
  a keyed `AccessServerClient` signing through the identity. It now uses the
  PS's own egress policy rather than `MetadataClient.Policy`
  (`EgressTransportTests` sets both). The `FederationHttpClientName` constant
  moved to `AAuthPersonServerBuilder`. `.WithGovernance()` calls
  `AddAAuthGovernance`.
- **Metadata URLs.** `MissionEndpoint`/`PermissionEndpoint`/`AuditEndpoint`/
  `InteractionEndpoint` URLs became `MissionPath`/`PermissionPath`/`AuditPath`/
  `InteractionEndpointPath`; the mapper derives URLs from the issuer.
- **Co-hosting.** Server identifiers are origins (no path), so instances
  sharing a process are distinguished by host. `MatchIssuerHost` confines an
  instance's endpoints (`RequireHost` route group), its verification
  middleware, its revocation middleware and its JWKS to the issuer authority.
  Without it the behaviour is unchanged. `MapAAuthIssuerRevocation` keeps its
  public shape over an internal host-scopable core.
- **Resource.** `AddAAuthResource(IConfiguration, configure?)` for
  `AAuth:Resource`; registers `TokenVerifier` (role policy and clock) and
  `IOptions<AAuthResourceOptions>`; `KeyHandle`/`KeyId` load lazily with the
  metadata options. Bookings and Concierge drop their hand-made verifiers.
- **In-memory warning.** Mapping a PS or AS logs a warning per in-memory
  default (pending store, inventory, mission store/log) outside Development.
- **Tests.** `ServerRoleRegistrationTests.cs`: `PersonServerRegistrationTests`
  (defaults, builder and DI replacement, validation, key handle, binding,
  warning, derived metadata URLs, unregistered map), `AccessServerRegistrationTests`,
  `ResourceRegistrationTests`, `CoHostedRolesTests` (two named PS + AS +
  resource in one host: per-host metadata, JWKS, seams, token endpoints).
  A subagent migrated tests, samples, Razor snippets and docs; verified
  independently.
- **Deferred to Phase 5 (server feature seams):** the consent-dashboard items
  in this phase's body. `ConsentRegistry`/`PersonConsentDecisions`/
  `ConsentDashboardSessions` remain sample registrations; the pending-store
  observer, the SDK out-of-band decision API owning
  `BrowserInteraction.Consume()`, and the four-party `Pending202`
  re-advertisement ruling need their own design and tests.
- **Gates.**
  - Build clean.
  - Test projects: AAuth.Tests 1734 (+19), AAuth.Conformance 1257,
    AAuth.R3.Tests 328, AAuth.Events.Tests 80.
  - ApiSurface: +725/-372 cumulative. Docs inventory refreshed; e2e
    typecheck clean.
  - Full Playwright: 78 passed, 1 skipped, `--retries=0`.
  - Keycloak profile: `federated-deferred` 1 passed; container removed.

### [2026-09-29] [Phase 5] Server feature seams

PROCEEDED.
- **Held invocations (Q10).** `AAuthSingleUseGrants` and the concrete
  `AAuthHeldInvocations` class are replaced by serializable seams:
  - `IAAuthSingleUseGate` (`TryClaimAsync`/`CompleteAsync`/`GetResultAsync`,
    plus `ReleaseAsync` so a failed execution can retry) with
    `InMemorySingleUseGate`; `ExecuteOnceAsync` is an extension that waits
    on another instance's in-progress claim by polling.
  - `IAAuthHeldInvocationStore` (`HeldInvocation` record with operation name
    and `JsonObject` state; strict `TryConsumeAsync`) with
    `InMemoryHeldInvocationStore`.
  - The execute delegate is endpoint metadata
    (`.WithHeldInvocation(operation, execute, pendingLifetime?)`), found by
    operation name through `EndpointDataSource`, never stored. The handler
    calls `IAAuthHeldInvocations.HoldAsync(context, token, scopes, state)`.
  - `AddAAuthHeldInvocations(o => ...)`; `MapAAuthHeldInvocations()` is
    parameterless and warns on in-memory defaults outside Development.
  - A poll claims the gate first, then consumes the entry once, so a lapsed
    retention can never re-run the invocation (the migration exposed this;
    `RepeatedAuthToken_ReturnsRetainedResult` covers it). A failure after
    consumption now leaves the invocation consumed.
- **R3 (Q12).** `IR3DocumentEntitlements` + `InMemoryR3DocumentEntitlements`.
  `R3Challenge` entitles `aud` and `ps` on every mint (its `Entitlements`
  property, else the DI store for `ChallengeAsync` and per-call
  `ToResultAsync`). `R3ProposalStore.Entitle`/`IsEntitled` removed.
  `AddAAuthR3Documents(readerPolicy)`; `MapR3Document(pattern, getBytes)`
  resolves policy and entitlements from DI and checks PS readers against the
  SHA-256 of the served bytes (or `IsEntitledPersonServer`). The AS reader
  stays governed by the designated-AS policy.
  `AddR3AccessTokenEndpoint(o => ...)` + `MapR3AccessTokenEndpoint()`.
- **Events.** `AddAAuthEvents(o => ...)` registers a shared `EventsProtocol`;
  `MapAAuthEventEndpoint(path)` and
  `MapAAuthSubscriptionEndpoint(path, o => ...)` resolve protocol and stores
  from DI per request.
- **Revocation.** `MapAAuthRevocationEndpoint(path, configure?)` resolves
  `IJtiStore` from DI. The positional issuer overload is internal (R3 via
  `InternalsVisibleTo`); resources get a public DI form,
  `app.MapAAuthIssuerRevocation(path, configure?)`, reading identity and keys
  from `AddAAuthResource` (Bookings uses it).
- **Middleware options from DI.** `UseAAuthVerification(configure?)`,
  `UseAAuthChallenge(configure?)`, `UseAAuthIntermediary(configureVerification?,
  configureChallenge?)` start from DI configuration (internal
  `AAuthOptionsResolver`); SDK role mappers use internal instance cores.
- **Well-known.** Resource/PS/AS well-known mappers are internal (use
  `MapAAuthWellKnown()` and the role mappers); `MapAAuthAgentWellKnown(o => ...)`.
  `AAuthResourceOptions` gained `LogoUri`, `LogoDarkUri`, `DocumentationUri`,
  `TosUri`, `PolicyUri` so resource metadata stays fully expressible.
- **Tests.** `SingleUseGateTests` (5), `R3AutoEntitlementTests` (2),
  `EventsDependencyInjectionTests` (3), `RevocationEndpointDependencyInjectionTests`
  (2). A subagent migrated tests, samples and docs; verified independently.
  Two revocation conformance hosts use the internal endpoint core because a
  DI `IJtiStore` also enables replay detection against their fixed clocks.
- **Consent-dashboard seams: moved to Phase 10.** The pending-store observer
  and out-of-band decision API are shaped by the sample consent surface;
  design them with the sample migration. `Pending202` ruling stays open.
- **Gates.**
  - Build clean.
  - Test projects: AAuth.Tests 1741, AAuth.Conformance 1257,
    AAuth.R3.Tests 330, AAuth.Events.Tests 83.
  - ApiSurface: +784/-386 cumulative (from +725/-372 at Phase 4).
    Docs inventory refreshed; e2e typecheck clean.
  - Full Playwright: 78 passed, 1 skipped, `--retries=0`.

### [2026-09-30] [Phase 6] Revocation service

PROCEEDED.
- **Records gap (L2758), checked first.** The token inventory already held
  issued grants with their resource and `exp`, the presented person token as
  a source of AS-issued grants, and the upstream `(iss, jti)` as a source of
  chained tokens. Missing: the agent token's `sub`, a lookup of a token's own
  grant (to revoke by `jti` alone), and any mission index. Added
  `IJtiStore.RecordSubjectAsync`/`GetSubjectAsync` and `GetGrantAsync`. The PS
  registers two index keys as sources of everything it issues to an agent: the
  agent identity `(agent iss, sub)` and, under a mission, the mission `s256`.
  The agent index is walked, never revoked, so the binding and later agent
  tokens are unaffected.
- **`IAAuthRevocationService`** (keyed per PS/AS instance; unkeyed for a
  resource): `RevokeAtAsync`, `RevokeTokenAsync(jti)`, `CascadeAsync(token,
  exp)`, `RevokeMissionAsync(s256)` (marks the mission terminated, revokes the
  mission index), `RevokeAgentAsync(iss, sub)`. Results are
  `RevocationCascadeResult` with per-recipient `RevocationDownstreamResult`
  entries, which now nest the recipient's own `Downstream`. Delivery failures
  are reported, never thrown. The cascade engine moved out of
  `RevocationEndpoint`; the endpoint and app code share it. An AP revocation of
  an agent token now cascades by `sub` across the agent's agent tokens.
- **Signing.** The service signs through `IAAuthServerIdentity`; a
  `RevocationClient` keyed by instance name, else unkeyed, overrides the
  transport (tests route in process this way).
- **Endpoint.** `MapAAuthIssuerRevocation` deleted. PS/AS role mappers map the
  endpoint over their service; the R3 AS builds an internal one. Resources:
  `AAuthResourceOptions.ConfigureRevocation` + parameterless
  `app.MapAAuthResourceRevocation()` at the path of `RevocationEndpoint`.
  `AAuthRevocationOptions.RevokeGrantAsync` applies to the generic
  `MapAAuthRevocationEndpoint` only; a role endpoint rejects it.
- **Samples.** MockPersonServer `/local/wallet/revoke` calls
  `RevokeTokenAsync`, so the PS now revokes at the Wallet (`aud`) as well as
  the AS; tour and CapabilitySupport step titles say so. The agent-signed
  `unsupported_iss` demos post `{jti, exp}` directly. Bookings uses
  `MapAAuthResourceRevocation`. Grep: no `new RevocationClient(` outside the
  SDK.
- **Tests.** `PersonTokenRevocationCascadeTests` (3),
  `AgentTokenRevocationCascadeTests` (3), `MissionRevocationCascadeTests` (1),
  `BackgroundRevocationTests` (2, one over real loopback HTTP asserting the
  `Signature-Key` names the PS identity and key). They reuse the
  `RevocationLifecycleTests.Graph` harness, now internal. Mutation check:
  disabling the `sub` start fails 2 of 3 agent tests. Ledger rows added to the
  draft-11 conformance ledger.
- **Gates.**
  - Build clean.
  - Test projects: AAuth.Tests 1741, AAuth.Conformance 1266 (+9),
    AAuth.R3.Tests 330, AAuth.Events.Tests 83.
  - ApiSurface: +800/-386 cumulative. Docs inventory refreshed; e2e typecheck
    clean.
  - First full Playwright run: 2 failures, both expectations of the old
    wording (tour step title, wallet snippet `RevokeAsync`); updated. The
    guided-tour "AS clarification" test fails when run alone on HEAD too
    (order-dependent, pre-existing); it passes in the full suite.
  - Full Playwright rerun: 78 passed, 1 skipped, `--retries=0`.
  - Keycloak `federated-deferred`: 1 passed.

### [2026-09-30] [Phase 7] Client registration, factory, configuration

PROCEEDED.
- **`AddAAuthAgent(name, configure?)`** and **`AddAAuthAgent(name, IConfiguration, configure?)`**
  return `AAuthAgentBuilder` (`Services`, `Name`, `HttpClientBuilder`, `Configure`,
  `WithAgentProvider`, `WithGovernance`). Named `IOptions<AAuthAgentOptions>`
  validated on start; the pipeline is composed from the `IServiceProvider` at first
  resolve by an internal composer over `AAuthClientBuilder` (the primitive).
- **`AAuthAgentOptions`** (unsealed): `KeyHandle` (through `IKeyStore`) or `Signer`;
  identity sources `AgentToken`/`AgentTokenFactory`/`TokenRefresher`, `SelfIssued`,
  `AgentProvider`, `JwksUri`, `SignatureKeyProvider`; `PersonServer`,
  `HandleChallenges` + `Challenge` (`ChallengeHandlingOptions`), `HandleInteractions`
  + `Interaction` (`InteractionHandlingOptions`), `Capabilities`, `Mission`,
  `UpstreamTokenProvider`/`ChainFromHttpContext`, resource-managed access,
  `DevelopmentLoopbackOrigins`/`EgressPolicy`, `InnerHandler`, `OnSignatureBase`.
  Delegates and instances are code-only (documented).
- **`IAAuthAgentFactory`**: `Get(name)` (factory-owned, cached, disposed with the
  container), `Create(AAuthAgentDescriptor)` and `Create(name, signer, builder => …)`
  (caller-owned). `AAuthAgent` exposes `Name` and `HttpClient`; typed clients land
  in Phase 9. `AddAAuthAgentFactory()` registers the factory alone.
- **`AddAAuthClient`** uses named, validated `AAuthClientOptions`
  (`KeyHandle`/`Signer`, `SignatureKeyProvider`, `Capabilities`), composed lazily.
- **`AddAAuthGovernanceClient` deleted**; `.WithGovernance()` registers a keyed
  `AAuthGovernanceClient`.
- **Tests.** `AgentBuilderParityTests` (reflection over `AAuthClientBuilder`,
  `SelfIssuingBuilder`, `EnrolledBuilder` with a justified exclusion list; plus the
  console builder-only test); `AAuthAgentDITests` (lazy composition, `KeyHandle`,
  every scalar bound from `AAuth:Agents:<name>` by reflection, `ValidateOnStart` on
  missing/conflicting sources, `WithGovernance`, `WithAgentProvider`);
  `AgentDependencyInjectionFlowTests` (mission, clarification, call chaining against
  a loopback PS/resource); `AgentFactoryTests` (tenant isolation across two PSs,
  per-request intermediary, ownership). A subagent migrated the docs; verified.
- **Gates.**
  - Build clean.
  - Test projects: AAuth.Tests 1743, AAuth.Conformance 1272, AAuth.R3.Tests 330,
    AAuth.Events.Tests 83.
  - ApiSurface: +856/-399 cumulative. Docs inventory refreshed; e2e typecheck clean.
  - Full Playwright: 78 passed, 1 skipped, `--retries=0`.

### [2026-09-30] [Phase 8] Client callbacks

PROCEEDED.
- **Interfaces** (`src/AAuth/Agent/AAuthCallbackHandlers.cs`):
  `IAAuthInteractionHandler`, `IAAuthClarificationHandler`,
  `IAAuthDeferredObserver` (approval pending, poll; default no-op members).
  Delegates adapt to them internally.
- **`Interaction.Source`** (`InteractionSource.PersonServer | Resource`). The
  resource path passes the `Interaction` (with `Source = Resource`); the
  `(url, code)` callback shape is deleted, so `InteractionHandlingOptions`,
  `ChallengeHandlingOptions` and `GovernanceOptions` share one callback shape.
- **Per-request override:** `AAuthRequestOptions.InteractionHandler`,
  `ClarificationHandler`, `DeferredObserver`, honoured by `InteractionHandler`
  and `ChallengeHandler`. The DI composer resolves options delegate, then the
  handler keyed by agent name, then unkeyed (R0), and turns interaction
  handling on when a handler or observer resolves.
- **Capabilities:** the builder no longer declares `interaction` statically.
  `InteractionHandler` declares it per request when a handler resolves (new
  internal `AAuthSigningHandler.RequestCapabilitiesKey`). The PS exchange
  keeps inferring from the resolved callbacks; an explicit list overrides.
- **Concierge:** a registered `ChainInteractionHandler` throws
  `AAuthInteractionChainedException`; the chain uses it with
  `Capabilities = []`.
- **Tests.** `InteractionHandlerResolutionTests` (4 precedence cases, capability
  inference, concurrent per-user routing); in `ChallengeClarificationSeamTests`,
  a per-request clarification handler beating the configured one up to the
  round limit, and PS- and resource-initiated interactions reaching one handler
  with their `Source`. A subagent migrated samples, tests and docs (two tests now
  configure a callback to keep asserting `interaction`; one new test asserts its
  absence). Fixed a pre-existing flake in
  `PersonTokenEndpoint_LifetimeIsCappedByEveryBound("agent")`: the agent token is
  minted after the test's `now`.
- **Gates.**
  - Build clean.
  - Test projects: AAuth.Tests 1750, AAuth.Conformance 1274, AAuth.R3.Tests 330,
    AAuth.Events.Tests 83.
  - ApiSurface: +873/-401 cumulative. Docs inventory refreshed; e2e typecheck clean.
  - Full Playwright: 78 passed, 1 skipped, `--retries=0`.

### [2026-09-30] [Phase 9] Typed clients, token cache, lifetime

PROCEEDED.
- **Token cache** (`src/AAuth/Agent/AAuthTokenCache.cs`): `AAuthTokenCacheKey`
  (agent token, upstream, mission, audience, account, key thumbprint),
  `IAAuthTokenCache` (`Get`, `Set`, single-flight `AcquireAsync`) and
  `InMemoryAAuthTokenCache`. `AAuthTokenHolder` reads the cache first; the
  challenge handler obtains both person tokens and auth tokens through it.
  `AAuthClientBuilder.WithTokenCache(cache)` shares one cache between builds.
- **DI:** each agent gets a keyed in-memory cache; `AAuthAgentOptions.TokenCache`
  overrides it. Keyed `TokenExchangeClient`, `AAuthGovernanceClient`,
  `MissionClient`, `PermissionClient`, `AuditClient`, `InteractionClient` and
  `RevocationClient` share one internal agent channel (agent-signed client plus the
  DI `MetadataClient`, else an owned one). `AAuthAgent` exposes `TokenExchange`,
  `Governance` and `Revocation`; created agents own and dispose their channel.
  `WithGovernance(options)` now only sets the governance defaults.
- **Timeouts (F-C7 confirmed):** an agent pipeline behind a 500 ms
  `HttpClient.Timeout` is cancelled mid-consent. Agent `HttpClient`s (DI and
  `Build()`) use `Timeout.InfiniteTimeSpan`; `RequestTimeout` bounds each call and
  `PollingTimeout` the consent wait. Documented with client lifetime and cache
  sharing in `docs/reference/dependency-injection.md`.
- **Defect found:** `AgentTokenSourceHandler` held its semaphore across
  `SendAsync`, so every `UseJwt` client ran one request at a time. It now locks
  only the token update (see deviations).
- **Samples:** `DocumentDemoSession` and `WalletDemoSession` create an agent through
  `IAAuthAgentFactory` (registered in SampleApp) and use `agent.TokenExchange`;
  the Document and Wallet code snippets take an `AAuthAgent`.
- **Tests.** `TokenCacheSharingTests` (shared cache, alternating resources,
  single-flight under a held PS, upstream and mission isolation) and
  `AgentTypedClientTests` (DI cache reuse, configured shared cache, keyed clients,
  missing-PS error, created agent's clients, F-C7 reproduction and fix).
  `AgentFlowHost` gained a second resource origin, a PS POST counter and a hold
  gate. Single-flight was mutation-checked: disabling it fails the concurrency test.
- **Gates.**
  - Build clean.
  - Test projects: AAuth.Tests 1750, AAuth.Conformance 1285, AAuth.R3.Tests 330,
    AAuth.Events.Tests 83.
  - ApiSurface: +891/-403 cumulative. Docs inventory refreshed; e2e typecheck clean.
  - Full Playwright: 76 passed, 1 skipped, 2 failed, `--retries=0`. Both failures
    were the Documents helper expecting `TokenExchangeClient` in the step 3
    snippet. Now it expects `agent.TokenExchange`. The documents and wallet specs
    then passed 12/12, which drives both migrated sessions end to end.

### [2026-09-30] [Phase 10a] SampleApp on the registered agent

PROCEEDED (Phase 10 part 1 of 4: SampleApp; then Concierge/MissionAgent/
AgentConsole/EventSupport, the consent-dashboard seams, and teaching panes).
- **Registration:** `AddAAuthAgent("aria", AAuth:Agents:aria)` (Person Server,
  self-issued identity, polling budgets; key generated at startup).
  `AAuth:PersonServer`, `AAuth:SelfIssuer` and `AAuth:SelfAgentId` are gone from
  SampleApp. `SampleAgents` exposes Aria's client, Person Server, a poller budget
  for per-call governance options, and `StartOver()`.
- **Pages** (Deferred by hand, the rest by a subagent, verified): Deferred,
  Federated, Bookings, CallChain, MissionCallChain and Inbox send through a
  registered agent with a per-request `IAAuthInteractionHandler` (the page), and
  CallChain branches on `Interaction.Source`. Mission and MissionCallChain use
  Aria's keyed `AAuthGovernanceClient`/`TokenExchangeClient`. Inbox uses one
  enrolled agent that `EnrollmentService` creates through `IAAuthAgentFactory`
  after enrolment. The CapabilitySupport and EventSupport walkthroughs take a
  `PersonServer` parameter from the host page.
- **Builder kept, with a comment:** the signing-mode lessons Hwk, Jwt, JwksUri
  and JktJwt; Bookings `CheckPreviousGrant` and Mission gates 2-3, which present
  one specific held token (the lesson); the CallChain Concierge server pane.
- **SDK:** `IAAuthTokenCache.Clear()` (sign-out). `SelectForRequest` now reads
  only the cache: it fell back to the holder's latest carrier, so a cleared cache
  still presented the old auth token (found by the Deferred e2e). The keyed
  `AAuthGovernanceClient` now defaults to the agent's challenge callbacks
  (options, keyed handler, unkeyed handler) and polling budget when
  `WithGovernance` sets none.
- **Tests.** `Clear_ForcesAFreshExchange`; `AccountBindingTests` rewritten for
  cache keys (a person token is keyed by the requested account). Snippet context
  gained `clients`, `consent`, `calendar`, `clarify`, `factory`, `Agents`.
- **Gates.** Build clean. AAuth.Tests 1750, AAuth.Conformance 1286, R3 330,
  Events 83. ApiSurface +904/-405. Docs inventory refreshed. Playwright
  `sample-app` project: 35 passed, 1 skipped, `--retries=0`.

### [2026-09-30] [Phase 10b] Concierge, consoles and events on DI agents

PROCEEDED (Phase 10 part 2 of 4).
- **Concierge:** one `AddAAuthAgent("downstream")` (self-issued, `ChainFromHttpContext`,
  `HandleInteractions = false`, `Challenge.Capabilities = []`, the registered
  `ChainInteractionHandler`). `ChainCaptureHandler` is the agent's inner handler
  and records into a per-inbound-request `AsyncLocal` capture.
  `RunChainAsync` lost its upstream parameter (the pending routes re-verify the
  same token).
- **MissionAgent:** generic host; the enrolled agent is registered with
  `KeyHandle` + `AgentProvider.RefreshEndpoint`; governance runs on the keyed
  client with defaults from `Challenge`, so the per-call `GovernanceFor(...)` is
  gone. Resource calls set `AAuthRequestOptions.MissionS256`.
- **AgentConsole:** generic host; jwt mode is a registered agent (challenges,
  chaining, resource-managed access from options); hwk/jwks/jkt-jwt are the
  signing-mode lessons and are created through `IAAuthAgentFactory` from the
  builder.
- **EventSupport:** `EventDemoSession` takes `IAAuthAgentFactory` and creates
  its agent once after enrolment; the Events code pane matches.
- **SDK fix (found by the tour e2e):** identical requests with a cached token in
  one second produced byte-identical signatures, which the resource replay
  cache (§Freshness and Replay) rejected as `invalid_jwt`. `AAuthSigningHandler`
  now gives each (key, method, authority, path) a unique `created`, taking the
  next second on collision. The jkt-jwt replay test now replays the same signed
  request.
- **Manual runs:** `make demo-mission` + `MissionAgent --auto` completed all ten
  steps; `AgentConsole <trips> --ps` (jwt) returned 200.
- **Tests.** New `SendAsync_IdenticalRequestsInOneSecond_TakeDistinctCreated`.
  The wallet-protocol e2e now expects the repeated delegated read to reuse the
  Concierge's cached grant (`[200]`).
- **Gates.** Build clean. AAuth.Tests 1751, AAuth.Conformance 1286, R3 330,
  Events 83. ApiSurface +907/-408. Docs inventory refreshed. Full Playwright:
  78 passed, 1 skipped, `--retries=0`.

### [2026-09-30] [Phase 10c] Consent-dashboard seams

PROCEEDED (Phase 10 part 3 of 4; the seams moved here from Phases 4 and 5).
- **Pending observer:** `IPersonPendingObserver.OnParked(entry)`, resolved keyed
  by Person Server name plus unkeyed. `MapAAuthPersonServer` wraps the pending
  store (internal `ObservedPersonPendingStore`) when any are registered.
  MockPersonServer's `ConsentRegistry` is now an observer; the bridge store no
  longer registers entries itself.
- **Out-of-band decision:** `BrowserInteraction.CompleteOutOfBandAsync(lifecycle,
  apply)` runs the host's decision under the request's gate and consumes the
  code when it applies (#user-interaction). `Consume()` is internal.
  `PersonConsentDecisions.DecideAsync` uses it.
- **Pending202 ruling:** a four-party entry waiting only on the AS (no PS consent
  pending, no relayed AS interaction) now polls as a bare `202` with no
  `AAuth-Requirement` (\u00a7Deferred Responses: the header is present only when the
  person must act). The guided tour's clarification step keeps polling through
  bare `202`s until the next requirement arrives.
- **Docs:** `docs/server/token-issuance.md` covers both seams with a compiled
  snippet.
- **Tests.** `PendingConsentSeamTests` (observer, applied/unapplied/withdrawn
  out-of-band decisions) and
  `DeferredFederationTests.WaitingOnAccessServer_PendingCarriesNoRequirement`
  (new `hold` policy outcome).
- **Gates.** Build clean. AAuth.Tests 1755, AAuth.Conformance 1287, R3 330,
  Events 83. ApiSurface +910/-408. Docs inventory refreshed. Full Playwright:
  78 passed, 1 skipped, `--retries=0` (an earlier run on a loaded machine timed
  out in page setup; the rerun and the per-project runs were clean).

### [2026-09-30] [Phase 10] Wrap-up and Definition of Done

PROCEEDED.
- **`AAuthClientBuilder` left in SampleApp pages** (each commented in place):
  - signing-mode lessons: `Hwk.razor`, `Jwt.razor`, `JwksUri.razor`,
    `JktJwt.razor` (panes and handlers);
  - held-token lessons: `Bookings.razor` `CheckPreviousGrant` (presents the
    previous account's grant) and the `Mission.razor` gate 2/3 panes (walk
    challenge, exchange and retry with a held person token and auth token);
  - `CallChain.razor` pane showing the Concierge's own code (another app).
- **`.Build()` outside startup:** no request or page handler builds an agent
  client. What remains builds a client around one specific held token for a
  hand-walked protocol step: `DocumentDemoSession`, `WalletDemoSession`,
  `CatalogDemoSession`, `FederatedWorkerScenario`, `TourSession` (sub-agent
  step), the lesson pages above, and `LiveWhoAmITest` (a console smoke test).
  The GuidedTour `CodeSnippets.cs` and walkthrough strings are display text,
  swept in Phase 11.
- **Configuration reads:** SampleApp reads no `AAuth:PersonServer`,
  `AAuth:SelfIssuer` or `AAuth:SelfAgentId`; Aria's registration is the only
  source. The walkthrough components keep `Configuration["AAuth:PersonServer"]`
  only as a fallback when their host passes no `PersonServer`. The Concierge
  binds no agent section, so its `AAuth:*` keys are not duplicates.
- **`make demo`:** every service answered, and the `sample-app` Playwright
  project ran against the live stack (reusing its servers): 35 passed,
  1 skipped.
- **Keycloak profile:** `federated-deferred` passed (1 passed). The first
  attempt timed out opening a browser page while swap was full; shutting down
  idle build servers fixed it.
- **Full Playwright:** 78 passed, 1 skipped (Phase 10c run).

### [2026-09-30] [Phase 11] Samples, snippets and docs sweep

PROCEEDED.
- **Deleted/renamed symbol sweep.** The stale names came from diffing public
  declarations since `9d5a182^` against `src`:
  `AAuthFederationServiceCollectionExtensions`,
  `AAuthGovernanceClientServiceCollectionExtensions`, `AAuthSingleUseGrants`,
  `AddAAuthFederation`, `AddAAuthGovernanceClient`, `BuildResourceToken`,
  `Entitle`, `IsEntitled`, `IsTrusted`, `IsTrustedAccessServer`,
  `IsTrustedAgentProviderIssuer`, `IsTrustedPersonServer`, `IssuerTrust`,
  `MapAAuthIssuerRevocation`, `OnResourceInteraction`, `ResourceKeyId`,
  `ResourceSigningKey`, `SigningMode`, `TrustedAccessServers`,
  `TrustedAgentProviderIssuers`, `TrustedAuthTokenIssuers`,
  `TrustedPersonServers`, `UpdateFromExchange`, `SelfIssuer`, `SelfAgentId`.
  Each was grepped case-insensitively with separators stripped over `docs/**`,
  READMEs, samples and tests, and re-run until the counts were stable:

  | Name | Hits | Verdict |
  |------|-----:|---------|
  | `TrustedAccessServers` | 6 | prose / sample config keys |
  | `TrustedPersonServers` | 11 | the samples' `AAuth:TrustedPersonServers` key and locals |
  | `IssuerTrust` | 7 | prose (`AAuthTrustOptions` wording) |
  | `ResourceSigningKey` | 8 | the current `ResourceSigningKeys` |
  | `SigningMode` | 75 | the `docs/signing-modes/` folder and prose |
  | `BuildResourceToken` | 4 | sample-local helpers |
  | `Entitle` | 18 | prose (`entitlement`) |
  | `IsEntitled` | 3 | sample-local method |
  | `AAuth:PersonServer` | 10 | the SDK section and the Concierge sample key |
  | every other name | 0 | — |

- **Configuration reference.** `ConfigurationReferenceTests` reflects every
  public settable (and nested-options) property of `AAuthAgentOptions` and its
  identity objects, `AAuthResourceOptions`, `AAuthPersonServerOptions`,
  `AAuthAccessServerOptions`, `AAuthTrustOptions`, `AAuthDiscoveryOptions`,
  `ChallengeHandlingOptions` and `InteractionHandlingOptions`. It asserts a row
  in that type's section; the existing `ReferenceTablesMatchSource` checks each
  row's type. The first run found 44 undocumented members (for example
  `MaxSignatureAge`, `AccessMode`, `RevocationPath`, `DeriveAgentClaims`,
  `OnClarificationRequired`, `MaxCacheAge`, and the `SelfIssued:*`,
  `AgentProvider:*` and `JwksUri:*` keys). All are now documented. The
  duplicate `AAuthResourceOptions`, `ChallengeHandlingOptions` and
  `InteractionHandlingOptions` tables were folded into one each.
- **Extensibility patterns.** A new `configuration.md` section covers the
  precedence ladder, a seam × form table, all four trust forms, a multi-tenant
  example (per-host trust plus a caller-owned per-tenant agent) and a KMS
  signer (`IAAuthSigner` over a KMS client, set through
  `AddOptions<AAuthAgentOptions>(name).Configure<IKmsClient>`). All three fences
  compile in `Documentation_CompilationProbe`.
- **Teaching panes.** GuidedTour `FullAutomatic` and `CallChainConvenience`
  (the application-level snippets) now show `AddAAuthAgent` plus
  `IHttpClientFactory` and `ChainFromHttpContext`. The remaining tour and
  CapabilitySupport panes keep the builder because the builder is the lesson:
  each teaches one signing mode or one held carrier token
  (`SignedGet*`, person-token/auth-token presentation, `WithCallChaining` with
  an explicit upstream token). `CatalogWalkthrough.Example` is resource-side
  enforcement with no agent composition. The e2e suite asserts displayed code
  only in `resource-managed.spec.ts` (`AAuthClientBuilder.SelfIssuing`, a
  signing lesson that is unchanged).
- **ApiSurface review against Phase 0.** `--baseline 9d5a182^` gives
  +533/-297. Of the 297 removed lines, 208 are replaced by a declaration with
  the same name. The other 89 are true removals, and all are intentional:

  | Removed | Phase | Replacement |
  |---------|-------|-------------|
  | `Clock` on `AAuthVerifier`, `TokenVerifier`, `AAuthVerificationOptions`, `AAuthResourceOptions`, `R3Challenge` | 2a | `TimeProvider` |
  | `Trusted*`/`IsTrusted*` on `AAuthServerOptions`, `AAuthVerificationOptions`, `AAuthResourcePipelineOptions`, PS/AS options, `R3AccessTokenEndpointOptions`; `IssuerTrust` | 2b–e | `AAuthTrustOptions` / `IAAuthTrustPolicy` |
  | `ResourceKeyId`, `ResourceSigningKey` on `AAuthServerOptions` and `ChallengeOptions` | 2b–e / 3 | `ResourceSigningKeys` |
  | `IAAuthKey.Sign`, `IAAuthKey.ToPrivateJwk` | 3 | `IAAuthSigner.SignAsync`, `IAAuthExportableKey.ToPrivateJwk` |
  | Sync `Build` on token, naming-JWT and event builders; `AAuthSigningHandler.Sign`; `AuthTokenResponse.Create`; `EventsTokens.Create` | 3 | `BuildAsync` / `CreateAsync` |
  | `AAuthAgentOptions.Key`, `AAuthClientOptions.Key` | 3 | `Signer` |
  | PS `MissionEndpoint`/`PermissionEndpoint`/`AuditEndpoint`/`InteractionEndpoint`, `TokenInventory` | 4 | `*Path`; the keyed `IJtiStore` seam |
  | `AAuthHeldInvocations`, `AAuthSingleUseGrants` | 5 | `IAAuthHeldInvocations`, `IAAuthSingleUseGate`, `IAAuthHeldInvocationStore` |
  | `R3Challenge.Challenge`/`BuildResourceToken`, `AAuthChallengeMiddleware.BuildResourceToken`, `R3EnforcementDecision.ToResult` | 3 / 5 | `ChallengeAsync`, `BuildResourceTokenAsync`, `ToResultAsync` |
  | `R3ProposalStore.Entitle`/`IsEntitled` | 5 | `IR3DocumentEntitlements` |
  | Public `Map{Resource,PersonServer,AccessServer}WellKnown` | 5 | internal; the role mappers publish metadata |
  | `MapAAuthIssuerRevocation` | 6 | `MapAAuthResourceRevocation` and the role mappers |
  | `AddAAuthFederation`, `AddAAuthGovernanceClient` (and their classes) | 7 | `AddAAuthAgent` typed clients |
  | `AAuthClientOptions.SigningMode`; `AAuthAgentOptions.OnInteractionRequired`/`OnApprovalPending`/`OnResourceInteraction`/`PollingTimeout` | 7 | identity-source options; `Interaction.*` / `Challenge.*` |
  | `BrowserInteraction.Consume` | 10c | internal; `CompleteOutOfBandAsync` |
  | Sample members: `FederatedWorkerScenario.IssueParent`/`IssueWorker`, `SqliteEventStore.PrepareDelivery`, `ChainCaptureHandler.Exchanges` | 3 / 10b | `*Async` variants; AsyncLocal capture |

  The repo map (`--write`, baseline v0.10.0-alpha.1) is +910/-408 with
  0 unmapped files.
- **Gates:** build clean; AAuth.Tests 1766, Conformance 1287, R3 330,
  Events 83 (snippet, link and docs-inventory tests included); e2e typecheck
  clean; full Playwright 78 passed, 1 skipped.

## Deviations from plan

### [2026-09-30] [Phase 10] Teaching panes and dashboard URLs move to Phase 11

PROCEEDED. "GuidedTour and CapabilitySupport code panes show the DI path by
default" is the same work as Phase 11's `CodeSnippets.cs` and walkthrough-pane
sweep, so it moves there. The dashboard URL call sites were left as they are:
MissionAgent and AgentConsole build `{ps}/dashboard` from the same variable
they register the agent with, `PersonServerConsent.DashboardUrl` takes the PS
from its host page (SampleApp passes Aria's), and `TourSession.PersonServer`
is the tour's configured PS, not an agent registration.

### [2026-09-30] [Phase 10c] Observers are multi-registration, not a builder seam

PROCEEDED. The dashboard seams are additive: every registered
`IPersonPendingObserver` (keyed by Person Server name, then unkeyed) sees every
parked request, so there is no `Use...` builder method and no R0 precedence.
The sample's own `MissionPendingStore` still registers its entries directly,
because mission governance parking is sample code, not the SDK store.

### [2026-09-30] [Phase 10b] Signatures take a unique created per target

PROCEEDED. Not in the plan; required by Phase 9 caching. The profile has no
nonce, so two requests with the same key, token, method, authority and path in
one second were indistinguishable to a replay cache. The signer now bumps
`created` to the next free second for that target (shared across handlers using
one key), staying well inside the verifier's 60-second window.

### [2026-09-30] [Phase 10b] MissionAgent clears its cache per showcase step

PROCEEDED. Each step must reach the PS to print its gate decision, and the
elevated step would otherwise meet the 403 scope gap logged in 10a. A real agent
would keep its tokens.

### [2026-09-30] [Phase 10a] Demo pages clear the token cache per run

PROCEEDED. The pages used to build a client per click, so every run started
without tokens and asked for consent; the e2e specs rely on that. A shared agent
keeps its tokens, so each consent demo calls `SampleAgents.StartOver()`
(`IAAuthTokenCache.Clear()`) first. Real agents should not.

### [2026-09-30] [Phase 10a] Open: scope step-up answers 403

PROCEEDED, open for Phase 12. `RequireAAuth(scope:)` answers a valid auth token
that lacks the scope with 403, not a 401 with a fresh resource token, so a cached
narrower token cannot step up. Mission gate 3 therefore keeps its hand-walked
flow.

### [2026-09-30] [Phase 10a] Person tokens are cached per requested account

PROCEEDED. The old single-slot carrier reused a person token for any account.
The cache key includes the requested account, so another account obtains its own
person token (one extra round trip, never a wrong binding).

### [2026-09-30] [Phase 9] Agent-token source no longer serializes requests

PROCEEDED. Not in the plan. `AgentTokenSourceHandler` (every `UseJwt` client) held
a semaphore across `SendAsync`, so an agent ran one request at a time, including
whole consent waits. That also made single-flight untestable. The lock now covers
only the token update, and a cancelled request still returns before reading the
token source.

### [2026-09-30] [Phase 9] The cache keeps a latest-carrier slot

PROCEEDED. The plan says the cache replaces the single-value holder. Pipelines
that are composed by hand sign with `AAuthTokenHolder.Current`, so the holder
still records the latest carrier after each acquisition. Builder and DI clients
select from the cache first. Person tokens and auth tokens share one entry per
key; an auth token for a resource replaces the person token that earned it.

### [2026-09-30] [Phase 9] Typed clients use the agent channel, not the pipeline

PROCEEDED. The plan says typed clients share "the agent's signed pipeline" and the
DI `MetadataClient`/`JwksClient`. They share an agent-signed channel instead,
because the challenge pipeline would present carrier tokens to the Person Server.
None of them verifies JWKS, so no `JwksClient` is involved. The F-C7 test uses a
1.5-second consent against a 500 ms `HttpClient.Timeout` instead of a 3-minute
poll.

### [2026-09-30] [Phase 9] Wallet walkthrough migrated too

PROCEEDED. Beyond `DocumentDemoSession` and `WalletScenarioCode`, the Wallet
session and both walkthrough snippet sets moved to `IAAuthAgentFactory` so each
snippet matches the code it describes. SampleApp registers the factory.

### [2026-09-30] [Phase 8] One callback shape, not one shared callback type

PROCEEDED. The plan says the three option types share "one callback set". They
now share one shape per callback (`Func<Interaction, …>`, the clarification
`Func`, `OnApprovalPending`, `OnPoll`) and one interface per concern, but each
keeps its own members: `InteractionHandlingOptions` has no clarification and the
governance options have no approval/poll hooks, so a common base type would
carry members that do nothing there.

### [2026-09-30] [Phase 7] Async signature-key providers not taken

PROCEEDED, open for Phase 12. The Phase 3 entry proposed async agent-side token
factories for Phase 7. Phase 7's scope (registration, factory, configuration) does
not need them: DI agents resolve keys once through `IKeyStore` and sign through
`IAAuthSigner.SignAsync`. Only a per-request naming JWT minted by a remote durable
key is still sync-over-async (`Func<string>`, `ISignatureKeyProvider`). The Phase 12
review decides whether that justifies an async provider contract.

### [2026-09-30] [Phase 7] DI-path flow tests use a loopback Kestrel host

PROCEEDED. The builder's token-exchange channel and metadata client use the
real SDK transport, not `InnerHandler`, so the in-process `WebApplicationFactory`
mocks cannot serve the exchange. The tests host a PS/agent provider/resource on a
loopback port, as `ReusableChainingTests` does.

### [2026-09-30] [Phase 7] Challenge handling defaults on only with a Person Server or chaining

PROCEEDED. A token source without an explicit Person Server cannot resolve one
until the first token arrives, so `HandleChallenges` defaults on when
`PersonServer` or call chaining is set (the previous DI rule), and is otherwise
opt-in.

### [2026-09-30] [Phase 6] `RevokeTokenAsync` instead of `RevokePersonTokenAsync`

PROCEEDED. One cascade covers PS person tokens, PS auth tokens and AS auth
tokens: revoke at the token's recipient, then walk what was issued against it.
A person-token-only name would leave AS and three-party revocations without an
entry. `CascadeAsync` is public so hosts can record a revocation learned out of
band.

### [2026-09-30] [Phase 6] Resource endpoint mapped by `MapAAuthResourceRevocation()`

PROCEEDED. The resource role has no single role mapper that every resource
uses (Bookings composes `MapAAuthWellKnown` and its own pipeline), so the
endpoint keeps a parameterless mapper that reads path, identity and acceptance
from `AddAAuthResource`. The five resources on the generic
`MapAAuthRevocationEndpoint` stay on it: they cascade nothing.

### [2026-09-29] [Phase 5] Consent-dashboard seams moved to Phase 10

PROCEEDED. See the Phase 5 entry.

### [2026-09-29] [Phase 4] Seam defaults are keyed forwarding factories

PROCEEDED. The plan says the builder `TryAdd`s defaults. A plain keyed
default would shadow a user's unkeyed DI registration, breaking "replaceable
through DI". Each default is instead a keyed factory returning the unkeyed
registration when present, else the SDK default.

### [2026-09-29] [Phase 4] Resource role stays single-instance

PROCEEDED. `AddAAuthResource` keeps its eager single options instance (exposed
as `IOptions<AAuthResourceOptions>`) instead of named options: its conditional
registrations (replay store, opaque-token store, key resolver) depend on option
values at registration time. Named resource instances are not needed by any
DoD item; revisit with Phase 5.

### [2026-09-29] [Phase 4] Consent-dashboard seams moved to Phase 5

PROCEEDED. See the Phase 4 entry.

## Open questions

### [2026-09-29] [Phase 0] Q16 — Sequencing with PS consent dashboard

BLOCKED (owner input). 2026-09-28-ps-consent-dashboard is open (1 of 23 DoD
boxes ticked). It edits MockPersonServer, SampleApp, and the walkthroughs,
which Phases 3, 8, and 9 rewrite.

The default is for the dashboard to land first. Confirm, or rule that this
initiative goes first and the dashboard rebases.

> After the 2026-09-29 renumbering, the overlapping phases are 4, 9, and 10.

### [2026-09-29] [Phase 0] Q19 — Async signing abstraction (new)

PROCEEDED (default: include as Phase 3). Owner review requested.
- KMS/HSM keys need async, non-exportable signing. Today `IAAuthKey`
  requires sync `Sign` and `ToPrivateJwk` (IAAuthKey.cs L19, L28).
- Blast radius:
  - five signing sites;
  - every token builder's `Build()` becomes `BuildAsync()`;
  - the `SigningKeys` dictionaries become `AAuthSigningKeySet`.
- Alternative: keep sync signing and document that remote keys must be
  loaded into memory. That does not support non-exportable keys.
