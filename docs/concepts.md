# Protocol Concepts

AAuth is a protocol for autonomous agent authorization. This page maps protocol concepts to SDK types. For the full interactive protocol reference, see the [AAuth Explorer](https://explorer.aauth.dev/).

## The Four Participants

| Role | Description | SDK Types |
|------|-------------|-----------|
| **Agent** | HTTP client acting on behalf of a person. Signs every request. | `AAuthSigningHandler`, `ChallengeHandler`, `AAuthKey` |
| **Resource** | Protected API. Verifies signatures, issues resource tokens. | `AAuthVerificationMiddleware`, `AAuthVerifier`, `ResourceTokenBuilder` |
| **Person Server (PS)** | Represents the user. Manages consent, federates to AS. | `TokenExchangeClient`, `ServerMetadata` |
| **Access Server (AS)** | Issues auth tokens. Enforces resource access policy. | `AuthTokenBuilder` |

> **Agent Provider (AP)** is a supporting role — it issues agent tokens binding keys to identities (`AgentProviderClient`) but is not one of the four protocol participants. The AP and the agent never share a keystore: the agent holds the **private** durable key locally in its own `IKeyStore`; the AP holds only the **public** key, indexed by JWK thumbprint. At refresh time the AP identifies the agent from the HTTP signature, not from any string the agent sends. See [Bootstrap & Enrollment](workflows/bootstrap-enrollment.md#key-identifiers-what-goes-where) for the three identifiers in play.

## Three Layers

### 1. Identity (Signing)

How the agent proves who it is. Built on HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)) and the Signature-Key header.

SDK: `ISignatureKeyProvider` implementations → `AAuthSigningHandler`

Four signing modes (see [Signing Mode Comparison](https://explorer.aauth.dev/signing/compare)):

- **Anonymous** — no signature (public endpoints)
- **Pseudonymous** (`hwk`) — `HwkSignatureKeyProvider`
- **Agent Identity** (`jwks_uri`) — `JwksUriSignatureKeyProvider`
- **Agent Token** (`jwt`) — `JwtSignatureKeyProvider`

### 2. Resource Access

How a resource decides what the agent may do. See [Access Mode Comparison](https://explorer.aauth.dev/access/compare).

Four modes:

- **Identity-Based** — Resource trusts the signature directly. No tokens beyond the agent token.
- **Resource-Managed** (2-party) — Resource handles auth itself (interaction/OAuth) and issues an opaque `AAuth-Access` token. SDK: agent `WithResourceManagedAccess()`; resource `AddAAuthResourceManaged()` + `ctx.RequireAAuthInteraction(scope)` + `app.MapAAuthInteractionPoll()`, reading the token with `ResolveAAuthAccessAsync` (the consent page records approval via `IInteractionPendingStore.Approve`)
- **PS-Asserted** (3-party) — Resource issues resource token → agent exchanges at PS → auth token. SDK: `ChallengeHandler`, `TokenExchangeClient`
- **Federated** (4-party) — PS delegates to Access Server. SDK: same agent-side types; AS is the PS's concern.

Experimental R3 rich requests layer content-addressed operation documents
(`r3_uri`/`r3_s256`, `r3_granted`, `r3_conditional`) onto the federated shape.
See [Rich Resource Requests (R3)](workflows/rich-resource-requests.md).

### 3. Governance (Missions)

Optional layer. The agent proposes a mission — a Markdown **description** of intent plus an optional list of **tools** — and the PS approves it (§Mission Creation, §Mission Approval).
SDK: `Mission`, `AAuthMissionHeader`

The two kinds of authority a mission governs are handled **asymmetrically**, and this is the key idea:

- **Tools are *declared*.** A tool is an action the agent runs **itself** (a tool call, file write, sending a message) — no resource is involved. Because the PS can't observe a local action, the mission must name the tools up front: the approved `approved_tools` are pre-approved and resolve at the **permission endpoint** without a PS round-trip; any other action is referred to the user (§Permission Endpoint). SDK: `Mission.ApprovedTools`, `PermissionClient`.
- **Scopes are *evaluated*, never declared.** A scope authorizes access to a remote **resource** (an API), carried in an **auth token** via the challenge → exchange → retry pattern (§Scopes). A mission proposal contains **no scopes**. Instead, when the agent later exchanges a resource token, the PS judges that requested scope *against the mission's natural-language description*: if it fits the stated intent it is granted silently (gate 2a), and prior decisions are remembered for the rest of the mission; otherwise the user is prompted (§Scopes — *"The PS evaluates requested scopes against mission context"*; §Agent Token Request). SDK: `AAuthScopeRequirement`, `AAuthVerificationResult.Scopes`.

In short: **a mission lists the tools the agent may run locally, but it does not list scopes — the PS decides, per request, whether a requested resource scope fits the mission's intent.** Scopes and AS policy stay enforced by the resource and its Access Server; the mission is "a further restriction applied by the PS" (§Rationale).

See [Missions](https://explorer.aauth.dev/missions/compare). For the SDK surface, see [Missions](advanced/missions.md), [Mission Governance Clients](advanced/mission-governance-clients.md), and [Mission Governance (Server)](server/mission-governance.md).

## Token Types

| Token | Type Header | Issued By | Purpose | SDK |
|-------|-------------|-----------|---------|-----|
| Agent Token | `aa-agent+jwt` | Agent Provider or Self | Binds key → identity | `AgentTokenBuilder` |
| Resource Token | `aa-resource+jwt` | Resource | Challenge: "get auth from my PS/AS" | `ResourceTokenBuilder` |
| Auth Token | `aa-auth+jwt` | PS or AS | Proves user authorized this agent | `AuthTokenBuilder` |

## HTTP Headers AAuth Uses

| Header | Direction | Purpose | SDK |
|--------|-----------|---------|-----|
| `Signature-Key` | Request | Carries keying material (scheme-dependent) | `SignatureKeyHeader`, `ISignatureKeyProvider` |
| `Signature-Input` | Request | Declares covered components + params | `AAuthSigningHandler` |
| `Signature` | Request | The actual signature | `AAuthSigningHandler` |
| `Signature-Error` | Response | Machine-readable verification error | `SignatureError` |
| `AAuth-Requirement` | Response | What the resource needs (auth-token, interaction) | `AAuthRequirementHeader` |
| `AAuth-Capabilities` | Request | Agent declares supported flows | `AAuthCapabilitiesHeader` |

## Further Reading

- [AAuth Explorer](https://explorer.aauth.dev/) — interactive protocol walkthrough
- [HTTP Signatures Profile](https://explorer.aauth.dev/foundations/profile) — what AAuth pins from RFC 9421
- [Signature-Key Schemes](https://explorer.aauth.dev/foundations/schemes) — the four schemes side-by-side
- [Error Model](https://explorer.aauth.dev/foundations/errors) — Signature-Error codes
