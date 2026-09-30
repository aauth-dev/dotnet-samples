# S09 — Guided Tour session part 3 and capabilities partial

Spec slice: `aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md` L930-L951, L1888-L1939, L2456-L2477, L2478-L2631; `aauth-spec/v11/draft-hardt-aauth-r3.md` L560-L720; `aauth-spec/v11/draft-hardt-aauth-events.md` L180-L210, L224-L240, L389-L437. Files read: `samples/GuidedTour/TourSession.cs` L3501-L5208; `samples/GuidedTour/TourSession.Capabilities.cs` L1-L1330.

## Findings

| ID | Sev | Spec (anchor, line) | Code (file:line) | Requirement | Observed | Adversarial scenario | Conf |
|---|---|---|---|---|---|---|---|
| S09-01 | HIGH | `#deferred-responses`, L2531; `#polling-error-codes`, L2626 | `samples/GuidedTour/TourSession.Capabilities.cs:579`, `:589`, `:861`, `:871`, `:872`; `:810`-`:818` | Agents MUST respect `Retry-After`; on `429 slow_down` they MUST increase the polling interval by 5 seconds. | Capability polling treats any non-`200`/`202`/`403` response, including `429`, as `Other`/terminal, and clamps any `Retry-After` over 5 seconds down to 5 seconds. The clarification follow-up loop polls every 500 ms and ignores `Retry-After` entirely. | A conforming PS/AS returns `Retry-After: 30` or `429 slow_down` while a user is deciding. The tour keeps polling early or aborts instead of backing off, contradicting the protocol and the UI text that it is "honoring `Retry-After`." | 9 |
| S09-02 | MEDIUM | `#aauth-capabilities`, L2474 | `samples/GuidedTour/TourSession.Capabilities.cs:512`-`:529`, `:701`-`:710`, `:739`-`:744`, `:750`-`:756` | Agents SHOULD include `AAuth-Capabilities` on signed requests to resources; PS endpoints use the body `capabilities` parameter instead. | Capability flows only put `capabilities` in the PS `/token` JSON body. The shared signed-request helper and resource callers do not set `AAuth-Capabilities` on signed resource requests, even though these flows support `interaction`/`clarification`. | A resource that chooses between `interaction`, `clarification`, `payment`, or a plain denial based on the request header receives no advertised capabilities and MUST NOT assume any, so it may avoid raising a capability the tour can actually handle. | 8 |

## Verified compliant

- Capability values advertised to the PS are registry values only: `interaction`, plus `clarification` when the flow expects a clarification; no unregistered or `payment` value is advertised by this file — `samples/GuidedTour/TourSession.Capabilities.cs:750`-`:756` vs `#aauth-capabilities`, L2464-L2470.
- R3 per-call proposal retry resends the same reservation parameters and describes structural/digest binding before execution — `samples/GuidedTour/TourSession.cs:4099`, `:4124`-`:4132`, `:4284`-`:4307` vs `#per-call-flow`, L671-L676.
- R3 auth-token explanatory text uses draft-11 extension claims `r3_uri`, `r3_s256`, `r3_granted`, and `r3_per_call`, not scopes or removed gateway vocabulary — `samples/GuidedTour/TourSession.cs:3879`-`:3887`, `:4017`-`:4031` vs `#auth-token-extensions`, L566-L617.
- Events flow uses the Events draft concepts: AP `event_endpoint`, subscribe token with `max_uses: 1`, self-jwt event delivery, and agent-side `(iss, jti)` deduplication — `samples/GuidedTour/TourSession.Capabilities.cs:1164`-`:1190`, `:1230`-`:1244`, `:1260`-`:1317` vs Events `#ap-metadata`, L198-L208 and `#event-delivery`, L389-L424.
- Wallet call-chain explanation correctly says the intermediary chains its own `202` and pending URL back to the caller instead of leaking the downstream pending URL — `samples/GuidedTour/TourSession.Capabilities.cs:1030`-`:1067` vs `#interaction-chaining`, L1884-L1886.
- No private key material was found in the read slice; token views decode JWT headers/payloads and public `cnf.jwk`, while generated keys remain in `_agentKey` and are only used for signing/enrolment — `samples/GuidedTour/TourSession.Capabilities.cs:1177`-`:1190`, `samples/GuidedTour/TourSession.cs:3733`-`:3744`.

## Not assessed / out of slice

- SDK-03 single-use enforcement at the Bookings resource — the assigned files drive the client retry once, but the resource-side `IAAuthSingleUseGate`/proposal-consumption implementation is outside this slice.
- Sub-agent flow implementation — relevant spec was checked, but the assigned `TourSession.cs` range begins after the sub-agent steps; earlier lines are owned by another slice.
- Existing SDK findings inherited by lower layers (for example SDK-11 in `ChallengeHandler`) unless this slice reimplemented the behavior; S09-01 is reported because `TourSession.Capabilities.cs` has its own polling loop.
