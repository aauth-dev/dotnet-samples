---
description: Proposed draft-11 migration scenarios and validation in both primary apps.
---

# Capability scenarios - draft-11 WIP

Planning baseline: 2026-09-11. No scenarios below are claimed implemented or
executed. Findings reference [research.md](research.md), which supplies pinned
spec lines and current implementation evidence. Both
[SampleApp](../../../samples/SampleApp/) and
[GuidedTour](../../../samples/GuidedTour/) are deliverables, not interchangeable
substitutes. Reuse [CapabilitySupport](../../../samples/CapabilitySupport/),
[EventSupport](../../../samples/EventSupport/), and existing resource projects.

## Required scenarios

| ID | Scenario and resource | Proposed visible protocol sequence in both apps | Required negative/runtime evidence |
|---|---|---|---|
| S01 | Person identity, focused Profile endpoint | Enroll or self-issue; agent-only call yields person challenge; obtain person token with consent; serve person preferences; step up on a scope-protected endpoint. Preserve separate generic Profile routes. F02/F03/F06 | Person token rejected as auth token; wrong audience/key; issuer-colliding `sub`; absence of agent/act at person-resource surface |
| S02 | Calendar three-party authorization | Person acquisition; person-signed resource request; resource token plus exact presented token to PS; auth token; protected read and scope denial. F01-F05 | Scope-only auth invalid; stale/different presented `jti`; mission/tenant stripping; correct account and subject |
| S03 | Wallet four-party authorization | Person token; resource challenge; PS consent and AS policy; forwarded presented token; delivered auth token verified by PS; protected access. Run stub and Keycloak modes. F04/F06/F16 | PS and AS independently reject substitution; claims cannot replace person identity; terminal AS denial relayed versus 502 unavailable |
| S04 | Inbox resource-managed session | Existing resource login/interaction; AAuth-Access opaque session; Authorization: AAuth reuse and rolling replacement. New label is session-token, not a new PS flow. F05/F23 | Token68/multiple values, signature coverage, wrong key/account/origin, revocation/reset behavior remain protected |
| S05 | Mission approval, update and completion | Propose tools/resources; decode envelope and verify blob digest; use returned person token; local permission/audit; accept an update without changing mission hash; propose completion at mission URL; follow-up then person acceptance. F07-F10 | Envelope whitespace independent of hash; blob tampering; update affects cached consent; mission expires during consent; non-owner/missing equivalence; no reactivation |
| S06 | Concierge downstream chaining | Receive upstream authorization; route via its PS, not intermediary PS or AS issuer; obtain downstream person token; downstream resource/exchange; return result and PS-side attribution. F11 | Distinct caller/intermediary keys; correct upstream audience; two people and resources; downstream sub not copied; Q3/Q4 must be resolved |
| S07 | Parent/worker authorization | Parent obtains worker-key person token; passes it to worker; worker obtains resource token; parent exchanges resource/presented/worker tokens; worker presents auth token. Reuse [FederatedWorkerScenario](../../../samples/FederatedWorkerScenario.cs). F11 | Parent cannot present worker token with parent key; worker cannot call PS directly; unrelated parent fails; no resource actor chain |
| S08 | Wallet revocation cascade | PS revokes person token at AS; AS revokes issued auth tokens at resource; subsequent access rejected with appropriate error; fresh-person authorization succeeds only if policy permits. F14-F16 | Same jti/different issuer isolation; unseen-token revocation acknowledged; pending grant withdrawal; resource source expiry does not truncate valid auth grant |
| S09 | Bookings per-call approval | Discover operation/account; proposal with concrete parameters; approval; single execution; lost-response retry returns retained result. Show held-invocation 202 path and test 401 retry separately. F17-F19 | Concurrent fresh signatures under same grant execute once; changed parameters/account/key fail; same proposal hash with two grants remains distinct |
| S10 | Catalog standard OpenAPI aggregation | Replace OpenAPI Gateway service maps with one valid definition containing unique operation IDs, or separately identified resources after Q6. Discover, authorize, execute and reject an ungranted operation. F18 | Collision detection, no obsolete standard vocabulary/qualifier emitted, seven vocabulary tests preserved |
| S11 | Documents resource-first permission | Retain resource-owned interaction before PS consent, but start the authorization leg with person identity and exact presented-token exchange. F03/F04/F10 | Resource refusal prevents downstream consent/grant; PS relay is not authoritative resource completion; new token and step indices correct |
| S12 | Public and protected Events | Preserve AP subscribe/event flows and public subscriptions. Protected Bookings ticket uses the Q5-agreed trusted binding after migrated auth; deliver resource self-JWT event and persist delivery state. F20 | Wrong key/agent/account/operation ticket redemption; replay; restart; no false use of person sub as agent ID; Q5 unresolved means not closed |
| S13 | Refresh and recoverable errors | Fake-clock SDK scenarios plus representative browser token renewal; refresh agent then person then auth; surface clock skew; distinguish revoked credential, AS denial and unavailable AS. F12/F16 | No refresh loop for future iat; no replay of unsafe original request; cancellation doesn't publish renewed state; original expiry retained in fixtures |

## Optional decisions

| ID | Capability | Proposed default |
|---|---|---|
| S14 | Operation access annotations | Include a small OpenAPI/AsyncAPI/MCP metadata demonstration when its actual flow exists. Runtime requirements remain authoritative; no operation session-token, and no budget marker claiming unimplemented accounting. F19 |
| S15 | Resource-link discovery and algorithm advertisement | Include validated metadata support and a focused discovery scenario if selected in Q6; malformed links fail before fetch. Preserve verifier key-discovery isolation. F05 |
| S16 | R3 approve release instead of execute | Default no execution feature; represent or reject result-bearing proposals explicitly. If selected, add a side-effect-free Documents query scenario to both apps with truthful already-executed display and retained result; not the existing permission flow renamed. F21 |
| S17 | Full Budgets | Separate initiative by default, with its own metering, usage, settlement, race and persistence gates. A metadata hint or example JSON is insufficient. F22 |
| S18 | Hosted worker enrollment/delayed artifacts | Preserve existing self-issued worker and live-signature paths. Hosted AP endpoint design and delayed verifier remain separately selected capabilities. F23 |

## Walkthrough synchronization

[TourSession](../../../samples/GuidedTour/TourSession.cs#L300) and
[e2e tour helper](../../../tests/e2e/helpers/tour.ts#L48) have independent step
counts. Plan arrays, dispatchers, polling/approval indices, actor lanes, nested
protocol sequences, captured headers/bodies, snippets, payload selectors, and
completion counts must all change in the same owning phase.

SampleApp legacy pages use buttons and response panels rather than the entire
GuidedTour timeline. Shared Wallet/Catalog/Documents/Events components have
their own sequence models. Preserve each app's interaction conventions while
using common protocol services and exact code templates where they already exist.
Update numeric selections and removed `act.agent` assertions in
[Wallet browser helpers](../../../tests/e2e/helpers/wallet-protocol.ts) and
all step-dependent tests, not just displayed labels.

Every selected new user-facing capability must be exercised in both apps. SDK
tests, a console demonstration, or a static prose section cannot substitute for
one missing host. Avoid one new server per test variation; add a resource only
when reuse would obscure an existing single-purpose example.

## Browser and environment evidence

- Reuse the two projects in [e2e configuration](../../../tests/e2e/playwright.config.ts)
  and existing consent helpers; require fresh services and zero retries for
  migration evidence. Run both stub and live-Keycloak modes separately.
- Capture actual wire values for identity/key/account/mission expectations;
  inspect the payload of the selected step, not any matching text on the page.
- Retain desktop/mobile layout, reset/re-enrollment, concurrent sessions,
  deferred approval/cancel/deny, authenticated consent and CSRF checks.
- .NET 10, Node 20+, locked npm dependencies, Chromium, available local ports,
  and isolated state are prerequisites. Live Keycloak requires its configured
  realm/container and human or automated test-user consent, as applicable.
- External whoami and external sub-agent/mission interoperability remain separate
  gates requiring reachable HTTPS metadata/JWKS and compatible deployed drafts.
  A local pass, unavailable external service, or old draft-10 evidence is not
  draft-11 external success. No external state was changed in this research.