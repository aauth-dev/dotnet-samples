# S02 — MockPersonServer supporting code

Spec slice: `aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md` L999-L1126, L1191-L1287, L1307-L1568, L2842-L2850, L2898-L2918, L2953-L2959. Files read: `samples/MockPersonServer/ConsentBridgePersonPendingStore.cs`, `ConsentDashboard.cs`, `ConsentRegistry.cs`, `ConsentStore.cs`, `MissionGovernance.cs`, `PersonConsentDecisions.cs`, `SampleIdentityClaimsAsserter.cs`, `ScriptMissionTokenConsent.cs`; `samples/ConsentSupport/PersonServerConsent.cs`, `PersonServerApprovalPrompt.razor`; contextual reads: `samples/MockPersonServer/Program.cs`, `src/AAuth/Server/BrowserConsentSessions.cs`.

## Findings

| ID | Sev | Spec (anchor, line) | Code (file:line) | Requirement | Observed | Adversarial scenario | Conf |
|---|---|---|---|---|---|---|---|
| S02-01 | HIGH | `#untrusted-input`, L2844; `#agent-person-binding`, L2916 | `samples/MockPersonServer/SampleIdentityClaimsAsserter.cs:45-47`, `:52-54`, `:73-74`, `:81`, `:88`; `samples/MockPersonServer/ConsentBridgePersonPendingStore.cs:56-60` | Token claims are untrusted and must be validated before processing; returning/new agents are recognized by the agent-token `(iss, sub)` binding, not by a display-like prefix. | The demo grants privileged `roles`/`groups` to any agent whose asserted id starts with `aauth:demo@`, regardless of agent-token issuer, key, or an enrolled admin allow-list. The bridge repeats the same prefix test when converting stored consent into an allowed pending entry. | A copied/deployed PS, or any allowed sample agent provider, can mint a verified agent token with `sub = aauth:demo@attacker.example`; the PS will assert `calendar.owner`-style roles for the person, making role-protected resources treat the attacker-controlled agent as admin. | 8 |
| S02-INFO-01 | INFO | `#agent-person-binding`, L2914-L2916 | `samples/MockPersonServer/SampleIdentityClaimsAsserter.cs:58-62`; `samples/MockPersonServer/ConsentStore.cs:12-19` | Attribute to confirmed SDK/sample limitation rather than a new defect. | Inherits SDK-07/A11-04 style limitation: the isolated demo has no persistent multi-person agent binding or first-resource enrollment screen, and person-token requests return the demo subject before the non-mission consent gate. Single-user localhost demo context prevents a separate severity here. | If copied into a multi-user PS without adding binding storage and enrollment UI, a new agent/resource gets identity issuance without the person seeing a new-agent authorization surface. | 8 |
| S02-INFO-02 | INFO | `#audit-endpoint`, L1245-L1257, L1287 | `samples/MockPersonServer/MissionGovernance.cs:196-203` | Attribute to confirmed A15-005 rather than a new defect. | Inherits A15-005: the sample audit sink records only action and description/detail, not optional `parameters` or `result`, so the mission log is not a complete audit record when those fields are supplied. | An agent logs a tool call with sensitive parameters/result; the PS acknowledges it, but later supervision/audit cannot inspect those fields. | 9 |

## Verified compliant

- Dashboard approval endpoints require a dashboard session plus CSRF: sign-in validates hidden CSRF, approve/deny require signed-in `session.Person` and `X-CSRF-Token` (`ConsentDashboard.cs:93-104`, `:128-137`), matching `#ps-approval-endpoint-auth` for the non-loopback dashboard.
- Dashboard access is explicitly local/demo-gated when no real operator auth exists (`ConsentDashboard.cs:19-35`, `:49-57`), fitting the loopback-only exemption in `#ps-approval-endpoint-auth` L2908-L2910.
- Direct `/interaction` approval/denial forms carry the SDK browser-consent hidden `session` and `csrf` fields (`Program.cs:948-954`, `:963-1030`; `BrowserConsentSessions.cs:250-273`); the scoped decision code is reached only after that check.
- Agent-asserted dashboard content is attributed and rendered as text, not HTML/Markdown: JSON values are inserted with `textContent`/`createTextNode`, and justification is labelled “The agent says (not verified)” (`ConsentDashboard.cs:212-217`, `:306-311`, `:345-350`), satisfying `#consent-presentation` L1033-L1041 and `#untrusted-input` L2844.
- Direct interaction consent also separates resource-asserted and agent-asserted sections and HTML-encodes justification/platform/device (`Program.cs:927-947`).
- Directed subjects are pairwise by resource and do not vary by agent/key (`SampleIdentityClaimsAsserter.cs:21-23`, `:55`; `ConsentBridgePersonPendingStore.cs:57`), matching `#directed-identifiers` L2955-L2957 for the single demo person.
- Mission pending entries bind poll/withdraw access to the originating verified agent issuer, subject, and key thumbprint, and refuse browser decisions after expiry (`MissionGovernance.cs:268-282`).
- Mission/pending dashboard state treats undecided expired mission prompts as expired rather than decidable (`ConsentRegistry.cs:119-127`, `:141-144`).
- ConsentSupport Razor prompt uses Blazor attribute/text binding and `Interaction.BuildUserUrl()` in attributes rather than raw markup (`PersonServerApprovalPrompt.razor:4-30`, `:58-59`).

## Not assessed / out of slice

- Full `Program.cs` endpoint behavior was read only where necessary to verify CSRF/rendering around scoped decision helpers; complete endpoint conformance belongs to other sample slices.
- Underlying SDK findings SDK-01..SDK-18 and MED table items were not re-audited here except where noted as inherited INFO.
- R3 document/operation consent and Events behavior are outside this assignment.
