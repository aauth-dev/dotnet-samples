# Glossary & Acronyms

A single reference for the acronyms, abbreviations, and short protocol terms
used across this repository (samples, SDK, docs). AAuth-specific and
cryptographic terms come first; general tech terms are at the bottom.

Canonical expansions follow the AAuth specification drafts under
[`aauth-spec/`](../aauth-spec/) (the Terminology sections of
[the protocol draft](../aauth-spec/v02/draft-hardt-oauth-aauth-protocol.md) and
[the bootstrap draft](../aauth-spec/v02/draft-hardt-aauth-bootstrap.md)).

> **Keep this current.** When you introduce a new acronym anywhere in the repo,
> add it here. Treat this file as the source of truth for expansions.

## AAuth protocol roles

| Term | Expansion | In AAuth |
|------|-----------|----------|
| **Agent** | _(not abbreviated)_ | The HTTP client acting on a person's behalf; identified as `aauth:local@domain`. |
| **Resource** | _(not abbreviated)_ | A server protecting APIs/data; verifies the signature and may challenge for an auth token. |
| **PS** | Person Server | The user-chosen server that brokers consent, governs missions, and mints auth tokens for the agent. |
| **AS** | Access Server | A resource's own policy engine in four-party (federated) access; evaluates policy and mints auth tokens. |
| **AP** | Agent Provider | Issues agent tokens and hosts the per-agent JWKS; the agent's enrollment authority. |
| **Concierge** | _(sample name)_ | The demo's intermediate call-chain service — a resource that also acts as an agent downstream. |
| **Aria** | _(demo persona)_ | The AI travel-assistant agent used as the narrative throughout the samples. |

## AAuth tokens & claims

| Term | Expansion | In AAuth |
|------|-----------|----------|
| **agent token** | `aa-agent+jwt` | Binds the agent's signing key to its identity (issued by an AP or self-issued). |
| **resource token** | `aa-resource+jwt` | A resource's `401` challenge: "get an auth token from my PS/AS." `aud` = PS or AS. |
| **auth token** | `aa-auth+jwt` | Proves the user authorized this agent for a scope; minted by a PS or AS. |
| **sub** | subject | Identifier of the principal the token is about (often directed/pairwise per resource). |
| **aud** | audience | The intended recipient — the PS or AS URL for a resource token; the resource for an auth token. |
| **iss** | issuer | URL of the entity that issued the token. |
| **jti** | JWT ID | Unique token id used for replay detection. |
| **iat** | issued at | Unix timestamp the token was issued. |
| **exp** | expiration time | Unix timestamp after which the token is invalid. |
| **cnf** | confirmation | Holds `jwk`, the public key the token is bound to (proof-of-possession). |
| **act** | actor | Nested claim recording the delegation chain in call chaining. |
| **dwk** | Discovery Well-Known | The well-known metadata document name for key discovery (e.g. `aauth-agent.json`); keys are fetched from `{iss}/.well-known/{dwk}`. |
| **kid** | key ID | Selects one key from a JWKS. |
| **typ** | type | JWT header value naming the token type (`aa-agent+jwt`, etc.). |
| **alg** | algorithm | JWT header value naming the signing algorithm (e.g. `EdDSA`). |
| **ps** | _(agent-token claim)_ | The Person Server URL bound to the agent. |
| **scope** | _(claim)_ | The authorization requested/granted (e.g. `calendar.read`, `wallet.charge`). |
| **s256** | SHA-256 (content hash) | Identifies a mission (or R3 document) by the hash of its content. |
| **directed `sub`** | _(concept)_ | A subject identifier scoped to a single resource. |
| **pairwise `sub`** | _(concept)_ | A subject identifier unique per PS↔resource pair. |

## AAuth signing modes & key schemes

| Term | Expansion | In AAuth |
|------|-----------|----------|
| **hwk** | HTTP Web Key | Pseudonymous scheme: the agent sends its **public key inline** in `Signature-Key`. Resource learns only a key thumbprint. |
| **jwks_uri** | JWKS URI | Agent-identity scheme: `Signature-Key` carries a **URL + `kid`**; the resource fetches the JWKS to resolve a named identity. |
| **jwt** | _(JWT scheme)_ | Agent-token scheme: the full agent token travels inline; required for all PS/AS flows. |
| **jkt-jwt** | JWK Thumbprint + JWT | Key-rotation scheme: a durable key signs a self-issued naming JWT (`jkt-s256+jwt`) that embeds the durable public key and delegates to an ephemeral signing key via `cnf.jwk`. Self-anchored — `iss` is the durable key's thumbprint URN. Access stays pseudonymous (the durable thumbprint is the stable identity). |
| **jkt** | JWK Thumbprint (RFC 7638) | SHA-256 hash of a JWK — a short, stable fingerprint used to reference a key. |
| **durable key** | _(bootstrap term)_ | Long-lived enrollment-anchor key (often hardware-backed); signs only at refresh. |
| **ephemeral key** | _(bootstrap term)_ | Short-lived key that signs HTTP requests; rotated via `jkt-jwt`. |

## Cryptography & standards

| Term | Expansion | In AAuth |
|------|-----------|----------|
| **JWK** | JSON Web Key (RFC 7517) | A public/private key expressed as JSON. |
| **JWKS** | JSON Web Key Set | A set of JWKs published at a URL (e.g. `/.well-known/jwks.json`). |
| **JWT** | JSON Web Token (RFC 7519) | A signed JSON token carrying claims. |
| **JWS** | JSON Web Signature (RFC 7515) | The signature structure underlying a signed JWT. |
| **RFC 9421** | HTTP Message Signatures | The standard AAuth uses to sign HTTP requests. |
| **RFC 7638** | JWK Thumbprint | How a key's `jkt` fingerprint is computed. |
| **RFC 7517** | JSON Web Key | The JWK format. |
| **RFC 8693** | OAuth 2.0 Token Exchange | Delegation / token-exchange semantics referenced by call chaining. |
| **PoP** | Proof-of-Possession | Proving control of the private key bound to a token (`cnf.jwk`). |
| **EdDSA** | Edwards-Curve Digital Signature Algorithm | Default signing algorithm (Ed25519). |
| **ECDSA / EC** | Elliptic Curve Digital Signature Algorithm | P-256 signing, supported for interop. |
| **SHA-256** | Secure Hash Algorithm, 256-bit | Hash used for thumbprints and `s256` content hashes. |
| **base64url** | _(encoding)_ | URL-safe base64 without padding, used throughout JOSE. |
| **TLS** | Transport Layer Security | Encryption under HTTPS. |
| **TPM** | Trusted Platform Module | Hardware key store (Windows/Linux) for durable keys. |
| **HSM** | Hardware Security Module | Dedicated cryptographic hardware for key storage. |
| **KMS** | Key Management Service | Managed key backend (a custom `IKeyStore` target). |

## Authorization & access control

| Term | Expansion | In AAuth |
|------|-----------|----------|
| **OAuth** | _(not abbreviated)_ | The OAuth 2.0 framework AAuth builds on conceptually. |
| **OIDC** | OpenID Connect | Identity layer referenced for claim semantics (`sub`, `email`, etc.). |
| **UMA** | User-Managed Access | The grant the Keycloak Access Server adapter uses to get a policy decision. |
| **RBAC** | Role-Based Access Control | Authorization by role (e.g. `wallet.payer`, `calendar.owner`). |
| **ABAC** | Attribute-Based Access Control | Authorization by attributes pushed to the AS (e.g. tenant, group). |
| **Identity-Based** | _(access mode)_ | Two-party: the resource decides from the signature alone. |
| **Resource-Managed** | _(access mode)_ | Two-party: the resource runs its own authorization (interaction/OAuth/policy). |
| **PS-Asserted** | _(access mode)_ | Three-party: the resource delegates to the agent's PS. |
| **Federated** | _(access mode)_ | Four-party: the resource has its own AS; the PS federates to it. |

## Well-known documents & HTTP headers

| Term | Meaning |
|------|---------|
| `aauth-agent.json` | AP/agent metadata document (`/.well-known/`). |
| `aauth-person.json` | PS metadata document. |
| `aauth-resource.json` | Resource metadata document. |
| `aauth-access.json` | AS metadata document. |
| `jwks.json` | The published key set used to verify signatures. |
| **Signature-Key** | Request header conveying the signing key material (inline JWK, JWKS reference, or JWT). |
| **Signature-Input** | RFC 9421 header listing which request components are covered by the signature. |
| **Signature-Error** | Response header conveying a signature-verification failure code. |
| **AAuth-Requirement** | Response header on `401`/`202` signalling what is required (`auth-token`, `interaction`, `claims`). |
| **AAuth-Mission** | Header carrying the mission pointer `{approver, s256}`. |
| **AAuth-Capabilities** | Header advertising agent/server capabilities. |
| **AAuth-Access** | Header carrying an opaque access token in resource-managed access. |

## Protocol concepts

| Term | Meaning |
|------|---------|
| **Mission** | A durable, human-approved statement of intent plus pre-approved tools; the PS governs every later request under it. |
| **Mission Log** | The PS-held, ordered record of token/permission/audit/clarification events within a mission. |
| **Bootstrap / Enrollment** | How an agent first acquires an agent token (AP enrollment, or self-issuing for hosted services). |
| **Refresh** | Obtaining a fresh agent token using the durable key (chaining a new ephemeral key via `jkt-jwt`). |
| **Challenge → Exchange → Retry** | The PS-asserted pattern: `401` + resource token → exchange at PS → retry with the auth token. |
| **Call chaining** | A resource acting as an agent downstream, passing the caller's auth token as `upstream_token`; recorded in nested `act`. |
| **Interaction Chaining** | Propagating a downstream consent requirement back up the chain to the original agent. |
| **Clarification** | A PS follow-up question during a token/permission request; the agent answers before the user approves. |
| **Justification** | A Markdown reason the agent supplies for an access request, shown at consent. |
| **R3** | Rich Resource Requests — the AAuth extension describing resource operations (out of scope for these samples). |

## Platform attestation

| Term | Expansion / Meaning |
|------|---------------------|
| **WebAuthn** | Web Authentication — hardware/biometric user verification at enrollment. |
| **App Attest** | Apple's app/device attestation. |
| **Play Integrity** | Google's Android device-integrity attestation. |
| **Secure Enclave** | Apple hardware key store. |
| **StrongBox / Android Keystore** | Android hardware-backed key stores. |
| **IndexedDB** | Browser storage used for non-extractable web-agent keys. |

## General technology

| Term | Expansion |
|------|-----------|
| **SDK** | Software Development Kit (the `AAuth` NuGet package). |
| **DI** | Dependency Injection. |
| **CLI** | Command-Line Interface. |
| **UI** | User Interface. |
| **HTTP / HTTPS** | HyperText Transfer Protocol (Secure). |
| **URL / URI** | Uniform Resource Locator / Identifier (e.g. the `aauth:` agent-id scheme). |
| **JSON** | JavaScript Object Notation. |
| **JOSE** | JavaScript Object Signing and Encryption (the JWK/JWS/JWT family). |
| **ASP.NET / Kestrel** | The .NET web framework and its HTTP server hosting the samples. |
| **Blazor** | The .NET UI framework used by GuidedTour and SampleApp. |
| **Keycloak** | The open-source identity provider used as the live Access Server in `make demo-keycloak`. |
| **MCP** | Model Context Protocol (referenced as a resource-operation vocabulary). |
| **CI** | Continuous Integration. |
