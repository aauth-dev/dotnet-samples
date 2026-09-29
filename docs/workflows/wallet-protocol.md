# Wallet Protocol Scenarios

## Run the Scenarios

Run `make demo` from the repository root. Open
[SampleApp](http://localhost:5240/wallet-protocol) and select a scenario,
advance its numbered steps, and complete any consent link. Reset creates a
fresh agent and session. The
[GuidedTour](http://localhost:5400/tour?flow=WalletProtocol) runs the same
scenarios as flow 13 with the standard step list, sequence diagram and payload
inspector: one step per wire exchange, with consent, clarification and poll
steps that adapt to what the PS and Access Server actually answer. `make demo-keycloak` uses the real configured IdP policy instead
of the isolated stub consent page.

Wallet remains a travel-wallet resource. These scenarios inspect and withdraw
its grants; they do not implement payment settlement. SampleApp uses
[WalletDemoSession](../../samples/CapabilitySupport/WalletDemoSession.cs) and
[browser assertions](../../tests/e2e/helpers/wallet-protocol.ts); the tour's
steps live in [TourSession.Capabilities.cs](../../samples/GuidedTour/TourSession.Capabilities.cs).
Both show the same [displayed C#](../../samples/CapabilitySupport/WalletScenarioCode.cs).

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
`ps`), which federates with the Wallet's AS. The sample calls this flow
`AsGrantChaining`.

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

## Federated Revocation

1. Enroll a new agent.
2. Request Wallet access and retain the resource challenge and the person token
   the agent presented.
3. Complete consent. The PS federates to the Wallet's AS with that person token
   as `presented_token`, and the AS issues the Wallet grant against it.
4. Read Wallet with that grant.
5. Try withdrawal as the agent. An agent signs with its agent token, not as a
   server, so Wallet answers `403 unsupported_iss`.
6. Ask the sample PS to terminate the access it federated. The PS signs
   `{"jti":"<person token id>","exp":<its exp>}` to the AS revocation
   endpoint; the AS records it and revokes the auth token it issued against
   that person token at the Wallet, then reports the Wallet in `downstream`.
   Repeating it is idempotent.
7. Reuse the withdrawn grant and observe the `401` rejection.
8. Obtain a fresh person token and grant through the normal consent callback.
   Its new `jti` restores the Wallet read without undoing the old revocation.

The id values above are placeholders taken from a verified token, not literal
credentials. The request names no issuer: each recipient keys the revocation
by `(verified signer, jti)`, so the PS can revoke only its own person token and
only the AS can revoke the grant it issued. Revocation does not renew a token or
extend its expiry.

```mermaid
sequenceDiagram
    participant Agent
    participant PS
    participant AS
    participant Wallet
    Agent->>PS: Terminate federated access, person_token
    PS->>AS: Signed revocation {jti, exp} of the presented person token
    AS->>Wallet: Signed revocation {jti, exp} of the AS-issued auth token
    Wallet-->>AS: 200
    AS-->>PS: 200, downstream [Wallet]
    PS-->>Agent: 200
```

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