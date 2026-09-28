# Wallet Protocol Scenarios

## Run the Scenarios

Run `make demo` from the repository root. Open `/wallet-protocol` in
[SampleApp](http://localhost:5240/wallet-protocol) or
[GuidedTour](http://localhost:5400/wallet-protocol). Select a scenario, advance
its numbered steps, and complete any consent link. Reset creates a fresh agent
and session. `make demo-keycloak` uses the real configured IdP policy instead
of the isolated stub consent page.

Wallet remains a travel-wallet resource. These scenarios inspect and withdraw
its grants; they do not implement payment settlement. Both apps use the same
[WalletDemoSession](../../samples/CapabilitySupport/WalletDemoSession.cs),
[displayed C#](../../samples/CapabilitySupport/WalletScenarioCode.cs) and
[browser assertions](../../tests/e2e/helpers/wallet-protocol.ts).

## AS Clarification

1. Enroll a new key with the AP and obtain its assigned agent identity.
2. Request Wallet review access. The resource returns an AS-audience challenge.
3. Exchange through the PS, answer AS clarification and complete consent. The PS
   retains the authenticated pending context; the SDK sends an explicit
   `clarification_response` action and polls for the signed grant.
4. Read Wallet with the approved `wallet.review` grant.
5. Attempt a charge with that grant; Wallet rejects the out-of-scope operation.

Cancellation sends signed DELETE to the pending exchange. It does not approve
the request or mint a grant. Browser correlation codes are not approval tokens;
the host requires an authenticated decision session and CSRF protection.

```mermaid
sequenceDiagram
    participant Agent
    participant Wallet
    participant PS
    participant AS
    Agent->>Wallet: Signed review request, agent JWT
    Wallet-->>Agent: 401, resource_token aud=AS
    Agent->>PS: Signed token request, resource_token
    PS->>AS: Signed federation, agent_token and resource_token
    AS-->>PS: 202, clarification and pending Location
    PS-->>Agent: 202, relayed clarification and PS Location
    Agent->>PS: POST action=clarification_response
    PS->>AS: POST action=clarification_response
    Note over PS,AS: Consent and policy decision precede grant delivery
    Agent->>PS: Signed pending GET
    PS-->>Agent: AS-issued auth_token
    Agent->>Wallet: Review with auth_token
    Wallet-->>Agent: 200; charge with same scope is rejected
```

## Chaining an AS-Issued Grant

Draft-11 has no direct agent-to-AS path: every token request goes to a PS, and
an intermediary routes to the PS its upstream token names (an auth token's
`ps`), which federates with the Wallet's AS. The sample still labels this flow
`DirectAs`.

1. Enroll a new agent.
2. Request Concierge Wallet access and retain the AS-audience resource token.
3. Complete consent and obtain an AS-issued upstream grant with no mission.
4. Call Concierge with that grant. Concierge signs with its own agent JWT,
   requests a Wallet person token at the grant's PS with the grant as
   `upstream_token`, and sends the same `upstream_token` with the Wallet
   resource token and that person token (`presented_token`). The upstream grant
   travels in the request body, never as Concierge's HTTP carrier.
5. Present the original Concierge grant directly to Wallet; the audience fails.
6. Repeat the legitimate delegated read.

```mermaid
sequenceDiagram
    participant Agent
    participant Concierge
    participant PS
    participant Wallet
    participant AS
    Agent->>Concierge: Request with upstream AS auth_token
    Concierge->>PS: Person token request, upstream_token (resource = Wallet)
    PS-->>Concierge: Wallet person token
    Concierge->>Wallet: Request with Wallet person token
    Wallet-->>Concierge: 401, resource_token
    Concierge->>PS: resource_token, presented_token, upstream_token
    PS->>AS: Signed federation, agent_token (Concierge), presented_token, upstream_token
    AS->>AS: Validate upstream audience and PS, presented token, scope
    AS-->>PS: Downstream auth_token (ps, sub; no agent or act claim)
    PS-->>Concierge: Downstream auth_token
    Concierge->>Wallet: Retry with downstream auth_token
    Wallet-->>Concierge: 200
    Concierge-->>Agent: Combined result
```

## Issuer-Qualified Revocation

1. Enroll a new agent.
2. Request Wallet access and retain the resource challenge.
3. Complete consent and obtain the Wallet grant, retaining its `iss` and `jti`.
4. Read Wallet with that grant.
5. Try withdrawal as the agent. Wallet rejects the unauthorized revoker.
6. Ask the sample PS to withdraw the grant. The PS signs the actual resource
   revocation body `{"iss":"<issuer>","jti":"<id>"}`; repeating it is idempotent.
7. Reuse the withdrawn grant and observe the `401` rejection.
8. Obtain a fresh grant through the normal consent callback. Its new `jti`
   restores the Wallet read without undoing the old revocation.

The issuer/id values above are placeholders taken from a verified grant, not
literal credentials. The resource keys revocation by `(iss, jti)` and verifies
the revoker independently. Revocation does not renew a token or extend its expiry.

## Verification and Sources

The shared browser tests run in both app-local Playwright projects and cover
clarification answer/cancel, scope rejection, AS-issued upstream grant audience
rejection, idempotent withdrawal, recovery callbacks, reset and narrow layouts.
Captures show the requests visible to the scenario transport; the builder's
separate PS exchange channel is verified by endpoint tests, not invented in the
inspector.

- [Clarification](../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#clarification-chat)
- [Call chaining](call-chaining.md)
- [Revocation](../server/replay-detection.md#revocation-endpoint)
- [Capability evidence](../../.agent/plans/2026-09-08-aauth-v10-spec-migration/capability-scenarios.md)