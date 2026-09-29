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

## Deviations from plan

None yet.

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
