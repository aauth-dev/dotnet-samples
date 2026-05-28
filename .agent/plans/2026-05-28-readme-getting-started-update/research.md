# Research: README & Getting Started Documentation Update

## Objective

Update the main `README.md` and `docs/getting-started.md` to include a clear three-party (PS-Asserted) flow example with a mermaid diagram, self-hosted agent setup, resource-side code, and an agent calling the resource. The getting started guide should also expand coverage of AP roles, enrollment models, key types, and supported flows.

## Source Material

### Spec Terminology (draft-hardt-oauth-aauth-protocol)

| Term | Definition |
|------|------------|
| **Person** | User or organization on whose behalf an agent acts |
| **Agent** | HTTP client acting on behalf of a person; identified by `aauth:local@domain` URI |
| **Agent Provider (AP)** | Server managing agent identity; issues agent tokens binding key → identity; publishes `/.well-known/aauth-agent.json` |
| **Resource** | Protected API; verifies signatures, issues resource tokens; publishes `/.well-known/aauth-resource.json` |
| **Person Server (PS)** | Represents the person; manages consent, asserts identity, brokers authorization; publishes `/.well-known/aauth-person.json` |
| **Access Server (AS)** | Policy engine; issues auth tokens on behalf of a resource; publishes `/.well-known/aauth-access.json` |
| **Agent Token** | `aa-agent+jwt` — binds agent key → identity; issued by AP or self-issued |
| **Resource Token** | `aa-resource+jwt` — challenge from resource saying "get auth from my PS/AS" |
| **Auth Token** | `aa-auth+jwt` — proves user authorized this agent; issued by PS or AS |
| **Mission** | Scoped authorization context for governance (orthogonal to access modes) |

### Resource Access Modes (spec §Protocol Overview)

1. **Identity-Based** — Agent + Resource only. Resource trusts signed identity directly.
2. **Resource-Managed (two-party)** — Resource handles auth itself (interaction, OAuth, internal policy).
3. **PS-Asserted (three-party)** — Resource issues resource token (aud=PS) → agent exchanges at PS → gets auth token → presents to resource.
4. **Federated (four-party)** — Resource has its own AS; PS federates with AS.

### PS-Asserted Flow (Three-Party) — Spec §PS-Asserted Access

Sequence from spec:

1. Agent sends signed request to resource (Signature-Key: sig=jwt with agent token)
2. Resource reads PS URL from `ps` claim in agent token
3. Resource returns 401 + `AAuth-Requirement: requirement=auth-token` with a `resource_token` (aud=PS URL)
4. Agent POSTs resource token to PS token endpoint (signed request)
5. PS validates agent token, confirms user consent (immediate or deferred)
6. PS returns `auth_token` (`aa-auth+jwt`) with identity claims (sub, email, etc.)
7. Agent retries original request with auth token in Signature-Key

### Signing Modes (spec §Agent Identity + HTTP Signature Keys)

| Mode | Scheme | Use Case |
|------|--------|----------|
| Pseudonymous | `sig=hwk` | Rate-limiting by key, no identity needed |
| Agent Identity | `sig=jwks_uri` | Identity-based access without PS flows |
| Agent Token | `sig=jwt` | Full PS/AS authorization flows |
| Key Rotation | `sig=jkt-jwt` | Naming JWT binds ephemeral key to stable identity |

### Agent Token Acquisition (spec §Agent Token)

Two models:
1. **Self-hosted agents** — Agent has stable URL, publishes own `/.well-known/aauth-agent.json`, self-signs tokens. No external AP.
2. **Enrolled agents** — CLI/desktop/mobile; register with external AP; AP issues tokens.

Key facts from spec:
- Agent generates Ed25519 keypair
- Agent proves identity to AP (platform-specific mechanism)
- AP issues agent token binding public key to agent identifier
- Token lifetime: max 24 hours (spec: "SHOULD NOT exceed 24 hours")
- `cnf.jwk` in agent token contains agent's public key
- Optional `ps` claim identifies agent's person server

### Self-Hosted Agent Details (spec §Roles + bootstrap spec)

Per spec §Roles: "A self-hosted agent is its own agent provider, self-issuing agent tokens signed by a JWKS-published key the user controls."

Requirements:
- Stable HTTPS URL
- Publish `/.well-known/aauth-agent.json` (metadata with `jwks_uri`)
- Self-sign agent tokens with private key
- JWKS endpoint publishes the public key

### Resource-Side Verification (SDK)

From SDK docs:
- `UseAAuthVerification()` middleware verifies HTTP signatures + JWT issuer
- `ResourceTokenBuilder` issues challenge tokens
- `AddAAuthResource()` DI registration
- `MapAAuthWellKnown()` serves discovery metadata

### User Consent in Three-Party Flow

From spec: "PS validates the agent token, confirms user consent (or defers), and returns an auth token."

The PS can:
- Grant immediately (pre-authorized or auto-consent policy)
- Defer (202 Accepted with `requirement=interaction`) — agent polls until user consents
- Deny (403)

The SDK `ChallengeHandler` handles the 401 → exchange → retry cycle automatically. For deferred consent, the handler also handles polling with `InteractionWaitMode`.

## SDK Types Mapping

| Concept | SDK Type |
|---------|----------|
| Key generation | `AAuthKey.Generate()` |
| Key storage | `IKeyStore`, `FileKeyStore` |
| Client builder | `AAuthClientBuilder` |
| HTTP signing | `AAuthSigningHandler` |
| Challenge handling | `ChallengeHandler` |
| Token exchange | `TokenExchangeClient` |
| Self-issued tokens | `AgentTokenBuilder`, `SelfIssuedTokenRefresher` |
| AP enrollment | `AAuthClientBuilder.Bootstrap()` |
| AP token refresh | `AgentProviderTokenRefresher` |
| Resource verification | `AAuthVerificationMiddleware`, `AAuthVerifier` |
| Resource tokens | `ResourceTokenBuilder` |
| Auth tokens | `AuthTokenBuilder` |
| Resource metadata | `AAuthResourceMetadataOptions`, `MapAAuthResourceWellKnown()` |
| Agent metadata | `AAuthAgentMetadataOptions`, `MapAAuthAgentWellKnown()` |
| DI | `AddAAuthAgent()`, `AddAAuthResource()` |

## Existing Documentation Gaps

### README.md

- Three-party flow example exists but lacks a visual mermaid diagram
- No resource-side code example
- No end-to-end walk-through of what happens in the 3-party exchange
- AP role described only in a sidebar note

### docs/getting-started.md

- Self-hosted agent section exists but could be clearer about WHY self-hosting works (stable URL = own AP)
- Bootstrap/enrollment section exists but doesn't explain what an AP fundamentally does
- No resource-side setup example
- No overview of which flows are supported and when to use each
- Key types not explicitly enumerated (only Ed25519 mentioned)

## Open Questions

- None — spec, SDK, and existing docs provide sufficient detail.
