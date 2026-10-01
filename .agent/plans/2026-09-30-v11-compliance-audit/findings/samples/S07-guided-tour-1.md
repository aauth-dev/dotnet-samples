# S07 — Guided Tour session, part 1

Spec slice: `aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md` (#resource-access-modes, #agent-token-structure, #resource-token-structure, #person-token-structure, #auth-token-structure, #keying-material, #covered-components, #requirement-values). Files read: `samples/GuidedTour/TourSession.cs` lines 1–1750.

## Findings

| ID | Sev | Spec (anchor, line) | Code (file:line) | Requirement | Observed | Adversarial scenario | Conf |
|---|---|---|---|---|---|---|---|
| S07-01 | HIGH | (#keying-material, L2179), (#keying-material, L2196) | `samples/GuidedTour/TourSession.cs:136`, `:151`, `:157-159`, `:200-204`, `:833-855` | Agents MUST present a `jwt` Signature-Key token carrying `cnf` for AAuth resource/PS/AS requests, MUST NOT use `jwks_uri` or `hwk`, and `jkt-jwt` is only for AP key refresh. | The tour still exposes identity signing modes `hwk`, `jwks_uri`, and `jkt-jwt`, routes them to Profile endpoints, and `BuildSigningHandler` calls `UseHwk()`, `UseJwks(...)`, and `UseJktJwt(...)` for AAuth resource requests. | A learner selects the Identity flow's default `SigningMode.Hwk`; the request teaches and sends a prohibited draft-11 Signature-Key scheme. A conforming draft-11 resource rejects it, while the tour presents it as valid identity-based AAuth. | 10 |
| S07-02 | LOW | (#resource-access-modes, L134), (#resource-access-modes, L230) | `samples/GuidedTour/TourSession.cs:164-168` | Draft-11 has five resource access modes: agent identity, resource-managed, person identity, PS authorization, and federated authorization; governance/missions are orthogonal. | The `ResourceBaseUrl` explanation says the suite has “four servers, one per access mode” and lists identity, three-party, mission, and federated. It omits resource-managed and person-identity, and treats mission governance as an access mode. | A reader internalizes an obsolete/four-mode model and misses resource-managed/person-identity access; later steps around Inbox and missions are harder to reconcile with draft-11. | 9 |

## Verified compliant

- Token type strings in the step text use draft-11 `aa-agent+jwt`, `aa-person+jwt`, and `aa-auth+jwt` — `TourSession.cs:352`, `:407`, `:415` vs (#agent-token-structure, L512), (#person-token-structure, L856), (#auth-token-structure, L1768).
- Resource-token explanatory text uses `presented_jti` and `agent_jkt`, not stale `agent`/`act` names — `TourSession.cs:39-41`, `:413`, `:424`, `:454` vs (#resource-token-structure, L746-L750).
- Resource-managed AAuth-Access retry text says the `authorization` field is covered by the HTTP signature — `TourSession.cs:49-52`, `:384` vs (#covered-components, L2216-L2225) and the AAuth scheme registration note (L2999).
- Bootstrap key display exposes only the public JWK and thumbprint; the narrative says the private key stays local — `TourSession.cs:1645-1661`.

## Not assessed / out of slice

- `TourSession.cs` after line 1750, including most concrete step implementations and UI/code-snippet strings.
- Other GuidedTour files and mock Profile/Inbox/Calendar/Wallet/PS/AS resources that actually accept or reject the flows.
- Inherited SDK findings were not re-attributed unless directly made worse by lines 1–1750; the signing-mode issue above is sample-specific misuse of available SDK options, not merely an inherited SDK defect.
