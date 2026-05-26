# Protocol Concepts

AAuth is a protocol for autonomous agent authorization. This page maps protocol concepts to SDK types. For the full interactive protocol reference, see the [AAuth Explorer](https://explorer.aauth.dev/).

## The Four Participants

| Role | Description | SDK Types |
|------|-------------|-----------|
| **Agent** | HTTP client acting on behalf of a person. Signs every request. | `AAuthSigningHandler`, `ChallengeHandler`, `AAuthKey` |
| **Resource** | Protected API. Verifies signatures, issues resource tokens. | `AAuthVerificationMiddleware`, `AAuthVerifier`, `ResourceTokenBuilder` |
| **Person Server (PS)** | Represents the user. Manages consent, federates to AS. | `TokenExchangeClient`, `ServerMetadata` |
| **Access Server (AS)** | Issues auth tokens. Enforces resource access policy. | `AuthTokenBuilder` |

> **Agent Provider (AP)** is a supporting role — it issues agent tokens binding keys to identities (`AgentProviderClient`) but is not one of the four protocol participants.

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
- **Resource-Managed** — Resource handles auth itself (interaction/OAuth). SDK: `IOpaqueTokenStore`
- **PS-Asserted** (3-party) — Resource issues resource token → agent exchanges at PS → auth token. SDK: `ChallengeHandler`, `TokenExchangeClient`
- **Federated** (4-party) — PS delegates to Access Server. SDK: same agent-side types; AS is the PS's concern.

### 3. Governance (Missions)

Optional layer. Agent proposes missions; PS approves and scopes permissions.
SDK: `AAuthMission`, `AAuthMissionHeader`

See [Missions](https://explorer.aauth.dev/missions/compare).

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
