# S05 — Agent-side samples

Spec slice: `aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md` L508–L544,
L770–L781, L924–L1126, L1290–L1300, L1307–L1568, L1816–L1825, L1846–L1939,
L2358–L2442, L2478–L2564. Files read:
`samples/Concierge/{Program.cs,PendingStore.cs,ChainCaptureHandler.cs,README.md,appsettings.json,Concierge.csproj}`,
`samples/MissionAgent/{Program.cs,README.md}`,
`samples/AgentConsole/{Program.cs,README.md,AgentConsole.csproj}`,
`samples/SampleApp/{Program.cs,SampleAgents.cs,EnrollmentService.cs,README.md,appsettings*.json,Components/Pages/{CallChain,MissionCallChain,SubAgent,Deferred}.razor}`,
`samples/EventAgent/{Program.cs,README.md}`,
`samples/LiveWhoAmITest/{Program.cs,LiveInteropValidation.cs}`,
`aauth-agent-console/aauth:demo@ap.example.json`. Excluded `bin/` and `obj/`.

## Findings

| ID | Sev | Spec (anchor, line) | Code (file:line) | Requirement | Observed | Adversarial scenario | Conf |
|---|---|---|---|---|---|---|---|
| S05-001 | HIGH | `#interaction-chaining`, L1886 | `samples/Concierge/Program.cs:213-224`; `samples/Concierge/PendingStore.cs:13-18`; `samples/SampleApp/Components/Pages/CallChain.razor:106-112`, `:286-292` | An intermediary that propagates downstream interaction MUST return its own `202`, own interaction code, and own `Location`. | Concierge stores and re-emits the downstream PS `interaction.url` and `code`; SampleApp then special-cases resource interactions back into PS consent URLs. This is more than inheriting SDK A18-003 because the sample's own pending store and docs encode the pass-through pattern. | A caller cannot compare/consume an intermediary-owned code because none exists; the downstream PS code is exposed as if it were the Concierge's challenge, so another conforming agent cannot reason about the intermediary's interaction lifecycle. | 9 |
| S05-002 | MEDIUM | `#deferred-responses`, L2523; `#polling-error-codes`, L2625 | `samples/Concierge/Program.cs:219-224`, `:316-317` | A deferred body status is `"pending"` while waiting (unrecognized is tolerated by agents); an unrecognized/consumed interaction code is `410 invalid_code`. | Concierge returns `{"status":"interaction_required"}` for pending interaction and returns `404 unknown_pending` for missing/mismatched pending IDs. | A strict test harness or copied intermediary sample emits non-draft-11 polling shapes; tolerant agents continue for the status value, but terminal error handling is incompatible with the polling table. | 8 |
| S05-003 | LOW | `#agent-token-usage`, L530-L534; `#auth-token-structure`, L1770-L1781; `#ps-token-endpoint`, L936-L942 | `samples/AgentConsole/Program.cs:323-335`; `samples/EventAgent/Program.cs:24-25` | Token-bearing headers/bodies are protocol credentials or directed identifiers and should not be exposed in reusable sample logging beyond explicit debugging. | AgentConsole prints all request and response headers after signed requests, which can include `Signature-Key`, `Authorization: AAuth`, and `AAuth-Requirement` resource tokens; EventAgent prints full exchange JSON. No private key material was seen. | Users paste CLI output into issue trackers and disclose short-lived PoP tokens, directed `sub` values, resource tokens, or opaque `AAuth-Access` receipts. PoP limits replay, so this is a sample-hygiene issue rather than an auth bypass. | 7 |
| S05-004 | LOW | `#mission-approval`, L1412-L1414 | `samples/MissionAgent/Program.cs:195-221`; `samples/MissionAgent/README.md:48-50`, `:95` | Mission approval returns `s256` plus a base64url mission blob; agents SHOULD verify `s256` over the decoded bytes. | MissionAgent prose calls the mission response a “signed approval blob”. The surrounding code/comment correctly describes the digest, but the signed wording is draft-inaccurate. | A developer copying the README believes signature verification exists on the mission blob and skips digest verification/audit blob custody. | 8 |
| S05-005 | LOW | `#resource-challenge-verification`, L770-L781 | `samples/LiveWhoAmITest/Program.cs:249-252`, `:300-302` | `requirement=auth-token` with `resource-token` is the draft-11 challenge path the agent verifies and sends to the PS. | LiveWhoAmITest error text still calls this a “Draft-10 scoped challenge” and “draft-10 resource token”. | A live-interop user misattributes a draft-11 challenge failure to the wrong spec generation. | 9 |
| S05-INFO-001 | INFO | `#interaction-relay`, L2404-L2407 | `samples/AgentConsole/Program.cs:201-207`, `:219-224`; `samples/MissionAgent/Program.cs:337-349`; `samples/LiveWhoAmITest/Program.cs:275-286`; `samples/SampleApp/Components/Pages/Deferred.razor:216-222` | Agents with a PS SHOULD relay interactions to the PS interaction endpoint before directing the user. | These samples surface `BuildUserUrl()` directly through SDK callbacks. This inherits SDK A07-004/A13-04; not counted as a new defect. | User-facing samples normalize direct presentation instead of PS relay/fallback. | 8 |
| S05-INFO-002 | INFO | `#auth-token-response-verification`, L1816-L1825; `#deferred-responses`, L2531 | SDK findings ledger | Agents relying on the SDK inherit auth-token response verification and deferred polling behavior. | AgentConsole, MissionAgent, SampleApp and LiveWhoAmITest use SDK challenge handling, so they inherit A10-01 (auth-token response verification is not performed by the agent) and SDK-11 (auth-token deferred polling ignores `Retry-After` / treats `429` terminal). Not counted as sample defects. | Same as SDK findings when the sample is used as the agent implementation. | 7 |

## Verified compliant

- Root `aauth-agent-console/aauth:demo@ap.example.json:1` contains only a local key handle/KIDs and AP endpoints; I found no private key material or token value.
- AgentConsole persists only metadata and explicitly says the key remains in the keystore and the token is not cached — `samples/AgentConsole/Program.cs:163-171`.
- Concierge avoids the SDK-01 unsafe verifier path by setting `ResourceIdentifier` and explicit issuer allow-lists on both the PS-issued and AS-issued branches — `samples/Concierge/Program.cs:116-119`, `:157-160`.
- Concierge acts as its own intermediary agent provider (`SelfIssued.Issuer = conciergeUrl`, `Subject = agentId`) as required for call chaining identity — `samples/Concierge/Program.cs:53-56`; spec `#intermediary-agent-identity`, L1858-L1866.
- MissionAgent proposes mission completion rather than declaring it locally — `samples/MissionAgent/Program.cs:303-306`; spec `#mission-completion`, L1505-L1507.
- SubAgent page describes parent-mediated authorization with `subagent_token`, parent-signed exchange, and auth token bound to the worker key — `samples/SampleApp/Components/Pages/SubAgent.razor:29-36`, `:104-116`; spec `#sub-agents`, L1917-L1937.
- EventAgent persists under `~/.aauth/event-agent` and prints consent/evidence only; no private key literal was present in the scoped source — `samples/EventAgent/Program.cs:6-16`, `samples/EventAgent/README.md:10-16`.

## Not assessed / out of slice

- The implementations behind `FederatedWorkerScenario`, `EventDemoSession`, SDK token exchange, governance clients, `DeferredState`, and `PersonServerConsent` live outside this assignment; I only assessed how the scoped samples call or describe them.
- Playwright tests were searched for corroborating prose but not exhaustively audited as normative sample code.
- I did not run builds, tests, servers, live tunnels, or restore packages per the brief.
