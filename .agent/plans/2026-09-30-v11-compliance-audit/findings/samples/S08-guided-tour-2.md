# S08 — Guided Tour session, part 2

Spec slice: `aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md` L924–L1126, L1307–L1765, L1846–L1887, L2365–L2416, L2478–L2640, L2666–L2768. Files read: `samples/GuidedTour/TourSession.cs` L1751–L3500.

## Findings

| ID | Sev | Spec (anchor, line) | Code (file:line) | Requirement | Observed | Adversarial scenario | Conf |
|---|---|---|---|---|---|---|---|
| S08-01 | HIGH | `#deferred-responses`, L2516 | `samples/GuidedTour/TourSession.cs:2312`, `:2493`, `:3093`, `:3203`; signed polls at `:2399`, `:2548`, `:3275` | A deferred `Location` is required to be on the same origin as the responding server; agents should not continue the protocol at a different origin with the same proof material. | The tour accepts any absolute `Location` (`StartsWith("http")`) for PS, Inbox, and Concierge pending URLs, then `RunPendingPollAsync` signs GETs to that URL with the agent token or auth token. Only the interaction URL is egress-validated. | A malicious or compromised PS/resource returns `202 Location: https://evil.example/pending`; the tour follows it and sends a signed request carrying the token in `Signature-Key`, leaking a usable proof-of-possession credential transcript to a forbidden origin. | 9 |
| S08-02 | MEDIUM | `#deferred-responses`, L2531 | `samples/GuidedTour/TourSession.cs:2691-2692` | If `Retry-After` is absent, the agent's default polling interval is 5 seconds; `429` requires increasing the interval by 5 seconds. | The tour configures `DeferredPollerOptions.DefaultPollInterval = 500ms` and `MinPollInterval = 0`, so its fallback cadence is ten times faster than draft-11's default. | A pending endpoint has `Retry-After` stripped or omitted; the educational tour demonstrates sub-second polling rather than the mandated 5-second default/backoff behavior. | 8 |
| S08-03 | MEDIUM | `#polling-error-codes`, L2623-L2625 | `samples/GuidedTour/TourSession.cs:2782`, `:2887` | Pending expiration is `expired` with status 408, and an unrecognized/already-consumed interaction code is `invalid_code` with status 410. | The tour comments/text teach that the poll task terminates on `404` and that an unknown or expired pending id “would be `404`.” | Implementers copying the tour handle pending expiry as 404 instead of the draft-11 terminal polling errors, breaking interop with conforming PS/resource pending endpoints. | 10 |
| S08-04 | INFO | `#interaction-chaining`, L1886 | `samples/GuidedTour/TourSession.cs:3193-3195`, `:3241-3243` | When propagating a downstream interaction, the intermediary resource must return its own `202`, own pending `Location`, and own interaction code. | Inherits SDK MEDIUM A18-003: the Guided Tour describes the Concierge re-emitting the downstream/PS-issued interaction, not minting and exposing the Concierge's own interaction code. | A caller is directed to the downstream PS/AS interaction rather than an intermediary-owned interaction, contrary to the interaction-chaining shape. | 8 |
| S08-05 | INFO | `#deferred-responses`, L2531-L2562 | `samples/GuidedTour/TourSession.cs:2422`, `:2569`; poller use at `:2399`, `:2548` | Agents must respect `Retry-After`; `429 slow_down` is a polling state-machine response, not a generic terminal failure. | Inherits SDK-11: the tour narratives say each poll honors `Retry-After`, but the confirmed SDK finding says `DeferredPoller` ignores `Retry-After` and treats `429` as terminal. | Readers are taught compliant polling semantics while the exercised SDK path does not provide them. | 8 |

## Verified compliant

- Auth-token endpoint examples in this slice sign the `/token` POST with the agent token and include `resource_token` plus `presented_token`, matching `#ps-token-endpoint` L936-L945 — `samples/GuidedTour/TourSession.cs:2207-2220`, `:2284-2290`, `:3071-3078`.
- Person-token acquisition uses a resource identifier and conditionally includes `mission_s256`; the narrative correctly says the mission hash flows into person/resource/auth tokens, matching `#missions` L1309-L1313 and `#mission-log` L1458-L1460 — `samples/GuidedTour/TourSession.cs:2106-2118`.
- Interaction-code display is not itself a secret leak: draft-11 says the code is a visible correlation identifier, not an authorization credential, and display is an allowed user-direction mechanism (`#interaction-code-format`, L2394-L2413). The slice does not display private key material; it does render bound JWTs/access tokens for education (`TokenJwt`/`TokenDecoded` at `TourSession.cs:1775`, `:2048`, `:2138`, `:2244`, `:2381`, `:2583`).
- Call-chain result text correctly explains directed `sub` values must differ per downstream resource and must not be copied forward, matching `#directed-sub-chaining` L1875-L1884 — `samples/GuidedTour/TourSession.cs:3399-3427`.

## Not assessed / out of slice

- `samples/GuidedTour/TourSession.cs` L3501 onward, including the rest of federation, mission, capability, and revocation walkthroughs.
- `CodeSnippets.*` constants and the mock server/resource implementations behind the displayed requests.
- Revocation behavior: no revocation flow is implemented in the reviewed line range.
