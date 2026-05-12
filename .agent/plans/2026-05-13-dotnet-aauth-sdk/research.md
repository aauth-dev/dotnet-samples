# .NET AAuth SDK & Samples: Research Document

> Research-only. No implementation.
> Created 2026-05-13 as part of plan `2026-05-13-dotnet-aauth-sdk`.

## 1. Source Repositories

| Repository | URL | Purpose | Language |
|---|---|---|---|
| **AAuth** (spec) | <https://github.com/dickhardt/AAuth> | Protocol specifications (draft-01) | Markdown / IETF |
| **packages-js** | <https://github.com/aauth-dev/packages-js> | Reference TypeScript SDK (v0.9.0) | TypeScript / Node |
| **whoami** | <https://github.com/aauth-dev/whoami> | Reference resource server (Cloudflare Worker) | TypeScript / Hono |
| **aauth-full-demo** | <https://github.com/christian-posta/aauth-full-demo> | Multi-agent demo with gateway & Keycloak | Python / Go / React |
| **dotnet-samples** | <https://github.com/aauth-dev/dotnet-samples> | This repo — target for .NET implementation | C# / .NET 10 |

Spec commit: `c090879` (2026-05-11). Tagged: `draft-hardt-oauth-aauth-protocol-01`.

---

## 2. Protocol Summary

AAuth is a four-party agent-to-resource authorization protocol. Every HTTP request carries a cryptographic proof-of-possession signature. There are no bearer tokens — stolen tokens are useless without the private key.

### 2.1 Parties

| Party | Role | Metadata endpoint |
|---|---|---|
| **Agent Provider (AP)** | Issues agent tokens, manages agent identity | `/.well-known/aauth-agent.json` |
| **Person Server (PS)** | User's chosen authority; consent, missions, audit | `/.well-known/aauth-person.json` |
| **Resource** | Protected API | `/.well-known/aauth-resource.json` |
| **Access Server (AS)** | Optional policy engine for resource (four-party mode) | `/.well-known/aauth-access.json` |

### 2.2 Four Authorization Modes (Progressive)

1. **Identity-based** — Agent signs request with agent token; resource trusts agent identity alone.
2. **Resource-managed (two-party)** — Resource handles its own authorization via interactions / opaque `AAuth-Access` tokens.
3. **PS-asserted (three-party)** — Resource issues a `resource_token` (audience = PS). Agent exchanges it at PS for an `auth_token`. Agent presents auth_token to resource.
4. **Federated (four-party)** — Resource token audience = AS. PS calls AS on the agent's behalf. AS evaluates policy and returns auth_token through PS.

### 2.3 Token Types

| Token | JWT `typ` | Issuer | Lifetime | Key claim |
|---|---|---|---|---|
| Agent Token | `aa-agent+jwt` | AP | ≤ 24h (recommended 1h) | `cnf.jwk` = agent's public key |
| Resource Token | `aa-resource+jwt` | Resource | ≤ 5 min | `agent_jkt` = JWK thumbprint of agent key |
| Auth Token | `aa-auth+jwt` | PS or AS | ≤ 1h | `cnf.jwk` = agent's public key |

### 2.4 HTTP Signature Scheme (RFC 9421)

Every AAuth request includes three headers:

- **`Signature-Input`**: `sig=("@method" "@authority" "@path" "signature-key");created=UNIX_TIMESTAMP`
- **`Signature`**: Base64url-encoded signature bytes wrapped in colons.
- **`Signature-Key`**: Carries the token. Schemes:
  - `sig=jwt;jwt="eyJ..."` — Direct JWT (agent token or auth token)
  - `sig=hwk;jwk={...}` — Inline public key
  - `sig=jkt-jwt;jwt="eyJ..."` — JWT naming a delegation chain
  - `sig=jwks_uri;jwks_uri="https://..."` — JWKS endpoint reference

### 2.5 Deferred Response Pattern

Any endpoint may return `202 Accepted` with:
- `Location` header — polling URL (GET)
- `Retry-After` header — polling interval
- `AAuth-Requirement` header — what's needed (interaction, auth-token, clarification, claims)

### 2.6 Mission System

Scoped authorization context for agent governance: proposal → clarification → approval → execution → completion. Mission hash (`s256`) carried in `AAuth-Mission` header.

### 2.7 R3 (Rich Resource Requests)

Resources advertise API vocabularies (MCP, OpenAPI, gRPC, etc.). Auth tokens carry `r3_granted` and `r3_conditional` operation lists. R3 documents are content-addressed and opaque to agents.

---

## 3. Reference Implementation Inventory

### 3.1 packages-js (TypeScript SDK)

Nine packages, organized by concern:

#### Core Packages

| Package | What it does | .NET equivalent needed |
|---|---|---|
| **local-keys** | Key management: discover backends, generate keys, resolve signing key, create/sign agent tokens, config file I/O (`~/.aauth/config.json`), OS keychain storage | `AAuth.Keys` or similar |
| **hardware-keys** | Native NAPI-RS bindings for YubiKey PIV (slot 9e) & macOS Secure Enclave | `AAuth.HardwareKeys` (Yubico .NET SDK) |
| **mcp-agent** | Agent-side: `createAAuthFetch()` (signed HTTP client), `exchangeToken()`, `pollDeferred()`, challenge-response handling, `AAuth-Capabilities` / `AAuth-Mission` headers | `AAuth.Agent` / `AAuth.HttpClient` |
| **mcp-server** | Server-side: `verifyToken()`, `buildAAuthHeader()`, `createResourceToken()`, `InteractionManager` | `AAuth.Server` / `AAuth.Middleware` |

#### CLI / Tool Packages

| Package | What it does | .NET equivalent needed |
|---|---|---|
| **bootstrap** | CLI: `discover`, `generate`, `sign-token`, `public-key`, `add-agent`, `config`, `show`, `skill` (hosting platform instructions) | `dotnet aauth` CLI tool |
| **fetch** | CLI: Make authenticated HTTP requests (`authorize-only`, full flow, R3) | `dotnet aauth-fetch` or integrated into CLI |

#### Transport Packages

| Package | What it does | .NET equivalent needed |
|---|---|---|
| **mcp-stdio** | stdio-to-HTTP bridge for MCP with AAuth signatures | `AAuth.Mcp.Stdio` |
| **mcp-openclaw** | OpenClaw plugin: discover & register remote MCP tools with prefixed names | `AAuth.Mcp.OpenClaw` |

#### Test Infrastructure

| Package | What it does | .NET equivalent needed |
|---|---|---|
| **e2e** | Integration tests, mock server helpers, test key factories | `AAuth.Tests` |

### 3.2 External Dependency: `@hellocoop/httpsig`

**Source**: <https://github.com/hellocoop/packages-js/tree/main/httpsig>

Provides RFC 9421 HTTP Message Signature creation and verification plus the Signature-Key header extension. The AAuth packages wrap this with AAuth-specific header injection.

**.NET equivalent**: No mature RFC 9421 library exists for .NET. This will need to be implemented or a C# port created. Key operations:
- Serialize covered components into signature base string
- Sign with Ed25519 / ES256 / RS256
- Format `Signature-Input` and `Signature` headers per RFC 9421
- Parse and verify inbound signatures

### 3.3 whoami Resource Server

A stateless Cloudflare Worker implementing a minimal AAuth resource server. Key behaviors:

- Serves `/.well-known/aauth-resource.json` and `/.well-known/jwks.json`
- On `GET /` without signature → `401` + `Accept-Signature`
- On `GET /` with agent token → verifies HTTP sig, fetches AP metadata/JWKS, verifies JWT, mints `resource_token`, returns `401` + `AAuth-Requirement: requirement=auth-token; resource-token="..."`
- On `GET /` with auth token → verifies HTTP sig, fetches PS metadata/JWKS, verifies JWT (`aud` must match, `scope` must include `whoami`), returns `200` with identity claims

### 3.4 aauth-full-demo

Multi-component demo showing real-world agent-to-agent flows:

| Component | Technology | Port for .NET |
|---|---|---|
| Backend API | Python / FastAPI | ASP.NET Core Web API |
| Supply Chain Agent | Python / A2A protocol | .NET agent service |
| Market Analysis Agent | Python / A2A protocol | .NET agent service |
| Agent Gateway | Go binary (envoy-like) | Can reuse Go binary or build ASP.NET YARP proxy |
| AAuth Service | Go (gRPC ext_authz) | ASP.NET gRPC service or middleware |
| Supply Chain UI | React / Vite | Blazor or static React (optional) |
| Keycloak | Java (Docker) | Can reuse Keycloak Docker image |
| Person Server | Go (in gateway binary) | .NET minimal API |

---

## 4. What the .NET Repo Needs

### 4.1 Core Library: `AAuth.Core`

Foundational types and cryptographic operations shared by all other packages.

| Component | Responsibility | Key .NET APIs |
|---|---|---|
| **JWK handling** | Parse, create, serialize JWK / JWKS; compute JWK thumbprint (RFC 7638) | `System.Security.Cryptography`, `Microsoft.IdentityModel.Tokens` |
| **JWT creation & verification** | Sign/verify `aa-agent+jwt`, `aa-resource+jwt`, `aa-auth+jwt` | `System.IdentityModel.Tokens.Jwt`, `Microsoft.IdentityModel.JsonWebTokens` |
| **Ed25519 support** | Key generation, signing, verification | .NET 9+ has `EdDSA` in `System.Security.Cryptography`; earlier versions need `NSec` or `BouncyCastle` |
| **RFC 9421 HTTP signatures** | Create signature base, sign, format headers; parse and verify inbound signatures | Custom implementation (no existing .NET library) |
| **Signature-Key header** | Parse/create `sig=jwt`, `sig=hwk`, `sig=jkt-jwt`, `sig=jwks_uri` schemes | Custom parser/formatter |
| **AAuth headers** | Parse/create `AAuth-Requirement`, `AAuth-Access`, `AAuth-Mission`, `AAuth-Capabilities` | Custom, RFC 8941 structured fields |
| **Metadata discovery** | Fetch and cache `/.well-known/aauth-{agent,person,resource,access}.json` | `HttpClient` + in-memory cache |
| **JWKS discovery & cache** | Fetch, cache, refresh JWKS with rate limiting (≥ 1 min between fetches) | `HttpClient` + `IMemoryCache` |
| **Agent identifiers** | Validate `aauth:local@domain` format | Regex / custom parser |
| **Server identifiers** | Validate HTTPS-only, no port/path/query | `Uri` parsing |

**Algorithms to support**:
- EdDSA Ed25519 (MUST)
- ECDSA P-256 / ES256 (SHOULD)
- RS256 (optional, for YubiKey compatibility)

### 4.2 Agent Library: `AAuth.Agent`

Agent-side protocol operations.

| Component | Responsibility | Reference impl |
|---|---|---|
| **Signed HttpClient** | `DelegatingHandler` that adds `Signature-Input`, `Signature`, `Signature-Key` to every outbound request | `mcp-agent/src/signed-fetch.ts` → `createSignedFetch()` |
| **Agent token management** | Create self-issued agent tokens, cache, refresh before expiry | `local-keys/src/agent-token.ts` |
| **Token exchange** | POST resource_token to PS token_endpoint, receive auth_token | `mcp-agent/src/token-exchange.ts` |
| **Deferred polling** | Poll `Location` URL respecting `Retry-After`, handle terminal responses | `mcp-agent/src/deferred.ts` |
| **Challenge-response** | Parse `AAuth-Requirement`, extract resource_token, orchestrate exchange, retry | `mcp-agent/src/signed-fetch.ts` |
| **Mission operations** | Propose, clarify, approve, complete missions at PS | Protocol spec §Mission |
| **Interaction handling** | Detect interaction requirements, surface URL + code to user | `mcp-agent/src/interaction.ts` |

### 4.3 Server Library: `AAuth.Server`

Resource server and Person Server protocol operations.

| Component | Responsibility | Reference impl |
|---|---|---|
| **ASP.NET middleware** | Verify HTTP signatures on inbound requests, extract token claims | `mcp-server/src/verify.ts` |
| **Resource token minting** | Create `aa-resource+jwt` with `aud`, `agent`, `agent_jkt`, `scope` | `whoami/src/index.ts` |
| **Auth token verification** | Verify `aa-auth+jwt` from PS/AS, check `aud`, `scope`, `cnf.jwk` binding | `whoami/src/index.ts` |
| **Well-known endpoints** | Serve `aauth-resource.json`, `jwks.json` | `whoami/src/index.ts` |
| **AAuth-Requirement builder** | Build response headers for 401/202 challenge flows | `mcp-server/src/headers.ts` |

### 4.4 Key Management: `AAuth.Keys`

| Component | Responsibility | Reference impl |
|---|---|---|
| **Software key backend** | Generate Ed25519/ES256 keys, store in OS credential store | `local-keys/src/backends/software.ts` |
| **Hardware key backend** | YubiKey PIV via Yubico .NET SDK (slot 9e, no PIN) | `hardware-keys/` (NAPI-RS) |
| **Config file** | Read/write `~/.aauth/config.json` (agents, keys, hosting metadata) | `local-keys/src/config.ts` |
| **Key resolution** | Match JWKS thumbprints against local keys, prefer hardware over software | `local-keys/src/resolve.ts` |

### 4.5 CLI Tool: `dotnet-aauth`

| Command | Responsibility | Reference impl |
|---|---|---|
| `discover` | List available key backends (software, yubikey, etc.) | `bootstrap/src/cli.ts` |
| `generate` | Generate key pair for a backend + algorithm | `bootstrap/src/cli.ts` |
| `sign-token` | Create agent token JWT, output to stdout | `bootstrap/src/cli.ts` |
| `public-key` | Output public JWK/JWKS | `bootstrap/src/cli.ts` |
| `add-agent` | Register agent URL + hosting platform in config | `bootstrap/src/cli.ts` |
| `fetch` | Make AAuth-signed HTTP request | `fetch/src/cli.ts` |
| `config` | Show current config | `bootstrap/src/cli.ts` |

### 4.6 Sample Applications

#### Minimal Resource Server (whoami equivalent)

A single ASP.NET Core Minimal API that:
- Serves well-known metadata and JWKS
- Verifies HTTP signatures on `GET /`
- Issues resource tokens (three-party challenge)
- Verifies auth tokens and returns identity claims
- Stateless, runs standalone

#### Minimal Agent Console App

A console app that:
- Generates or loads a signing key
- Creates an agent token
- Makes a signed HTTP request to a resource
- Handles the three-party challenge-response flow
- Displays the result

#### Full Demo (aauth-full-demo equivalent)

A multi-project solution showing agent-to-agent communication:
- ASP.NET Core backend API (replaces Python FastAPI)
- Agent services communicating via signed HTTP
- Policy enforcement middleware
- Integration with Keycloak for user auth (reuse Docker image)
- Integration tests

---

## 5. Cryptographic Operations Inventory

### 5.1 Operations Needed

| Operation | Used for | .NET API |
|---|---|---|
| Ed25519 key generation | Agent identity keys | `EdDSA.Create(EdAlgorithm.Ed25519)` (.NET 9+) |
| Ed25519 sign/verify | HTTP signatures, JWT signing | `EdDSA.SignData()` / `TryVerifyData()` |
| ECDSA P-256 key generation | Alternative agent keys | `ECDsa.Create(ECCurve.NamedCurves.nistP256)` |
| ECDSA P-256 sign/verify | HTTP signatures, JWT signing | `ECDsa.SignData()` / `VerifyData()` |
| RSA-256 sign/verify | YubiKey compatibility | `RSA.Create()` |
| JWK thumbprint (RFC 7638) | `agent_jkt`, key matching | Custom: canonical JSON of `{crv, kty, x}` → SHA-256 → base64url |
| SHA-256 hash | Content-Digest header, mission `s256`, R3 `r3_s256` | `SHA256.HashData()` |
| Base64url encode/decode | JWT, signatures, digests | `Base64Url.EncodeToString()` (.NET 9+) or `WebEncoders.Base64UrlEncode()` |
| JSON Canonicalization (RFC 8785) | Mission hash verification | Custom or library (no standard .NET impl) |

### 5.2 .NET Crypto Availability

| Algorithm | .NET 10 | .NET 8 | NuGet fallback |
|---|---|---|---|
| Ed25519 | `System.Security.Cryptography.EdDSA` | Not available | `NSec.Cryptography` or `BouncyCastle` |
| ECDSA P-256 | `System.Security.Cryptography.ECDsa` | Same | Built-in |
| RSA | `System.Security.Cryptography.RSA` | Same | Built-in |
| JWT | `Microsoft.IdentityModel.JsonWebTokens` | Same | NuGet `Microsoft.IdentityModel.JsonWebTokens` |
| Base64url | `System.Buffers.Text.Base64Url` | Not available | `Microsoft.AspNetCore.WebUtilities` |

Since the devcontainer targets .NET 10, native Ed25519 and Base64url are available.

---

## 6. RFC 9421 HTTP Message Signatures — Implementation Notes

No existing .NET library implements RFC 9421. Key implementation concerns:

### 6.1 Signature Base Construction

```
"@method": POST
"@authority": resource.example
"@path": /authorize
"signature-key": sig=jwt;jwt="eyJ..."
```

Format: `"{component}": {value}\n` for each covered component, then:
```
"@signature-params": ("@method" "@authority" "@path" "signature-key");created=1730217600
```

### 6.2 Signing

Sign the signature base bytes with the agent's private key using the appropriate algorithm (Ed25519 or ES256).

### 6.3 Header Format

```
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:base64url_encoded_signature:
Signature-Key: sig=jwt;jwt="eyJ..."
```

### 6.4 Verification

1. Parse `Signature-Input` to get covered components and `created` timestamp.
2. Check `created` is within signature window (default 60 seconds).
3. Reconstruct signature base from request.
4. Extract public key from `Signature-Key` (decode JWT → `cnf.jwk`).
5. Verify signature against reconstructed base.

---

## 7. Key Design Decisions for .NET

### 7.1 Package Structure

**Option A: Single NuGet package** — simpler for samples, all-in-one.
**Option B: Modular packages** (mirrors packages-js) — better for production, tree-shakeable.

**Recommendation**: Start with a single library project (`AAuth`) for the samples repo. Split later for production NuGet packages.

### 7.2 HttpClient Integration

Use `DelegatingHandler` for the agent-side signing:

```
HttpClient → AAuthSigningHandler → HttpClientHandler → Network
```

The handler intercepts outbound requests, adds signature headers, and can auto-handle 401 challenge-response by:
1. Detecting `AAuth-Requirement` header
2. Extracting resource token
3. Exchanging at PS for auth token
4. Retrying with auth token

### 7.3 ASP.NET Middleware Integration

Use ASP.NET Core middleware for the server side:

```
Request → AAuthMiddleware (verify sig) → [Controller] → Response
```

Or use an `IAuthorizationHandler` / policy-based auth for more granular control.

### 7.4 Key Storage

| Platform | Storage | .NET API |
|---|---|---|
| Windows | DPAPI / Credential Manager | `ProtectedData` / `Windows.Security.Credentials` |
| macOS | Keychain | P/Invoke or file-based with encryption |
| Linux | Secret Service / libsecret | P/Invoke or file-based with encryption |
| Cross-platform fallback | Encrypted file in `~/.aauth/` | `Aes` + `ProtectedData` |

For the samples, a simple file-based approach (matching `~/.aauth/config.json`) is sufficient.

---

## 8. Suggested Project Structure

```
dotnet-samples/
├── aauth-spec/
│   ├── SPEC-VERSION.md
│   ├── draft-hardt-oauth-aauth-protocol.md
│   ├── draft-hardt-aauth-r3.md
│   └── draft-hardt-aauth-bootstrap.md
├── src/
│   └── AAuth/                        # Core library
│       ├── AAuth.csproj
│       ├── Crypto/
│       │   ├── Ed25519.cs            # Key gen, sign, verify
│       │   ├── JwkThumbprint.cs      # RFC 7638
│       │   └── ContentDigest.cs      # SHA-256 content digest
│       ├── HttpSig/
│       │   ├── SignatureBase.cs       # RFC 9421 signature base
│       │   ├── HttpSigSigner.cs      # Create Signature + Signature-Input
│       │   ├── HttpSigVerifier.cs    # Verify inbound signatures
│       │   └── SignatureKey.cs       # Parse/create Signature-Key header
│       ├── Tokens/
│       │   ├── AgentToken.cs         # Create/verify aa-agent+jwt
│       │   ├── ResourceToken.cs      # Create/verify aa-resource+jwt
│       │   └── AuthToken.cs          # Create/verify aa-auth+jwt
│       ├── Discovery/
│       │   ├── MetadataClient.cs     # Fetch .well-known metadata
│       │   └── JwksClient.cs         # Fetch + cache JWKS
│       ├── Headers/
│       │   ├── AAuthRequirement.cs   # Parse/build AAuth-Requirement
│       │   ├── AAuthAccess.cs        # Parse/build AAuth-Access
│       │   └── AAuthMission.cs       # Parse/build AAuth-Mission
│       ├── Agent/
│       │   ├── AAuthSigningHandler.cs    # DelegatingHandler for outbound
│       │   ├── TokenExchange.cs          # Exchange resource_token → auth_token
│       │   ├── DeferredPoller.cs         # Poll Location with Retry-After
│       │   └── ChallengeHandler.cs       # Orchestrate 401 → exchange → retry
│       ├── Server/
│       │   ├── AAuthMiddleware.cs        # ASP.NET middleware for inbound
│       │   ├── ResourceTokenMinter.cs    # Create resource tokens
│       │   └── WellKnownEndpoints.cs     # Map well-known routes
│       └── Keys/
│           ├── KeyConfig.cs              # ~/.aauth/config.json model
│           ├── SoftwareBackend.cs        # Generate + store keys
│           └── KeyResolver.cs            # Find best key for an agent URL
├── samples/
│   ├── WhoAmI/                       # Minimal resource server
│   │   ├── WhoAmI.csproj
│   │   └── Program.cs
│   ├── AgentConsole/                 # Minimal agent console app
│   │   ├── AgentConsole.csproj
│   │   └── Program.cs
│   └── FullDemo/                     # Multi-agent demo
│       ├── FullDemo.sln
│       ├── BackendApi/               # ASP.NET Core Web API
│       ├── SupplyChainAgent/         # Agent service
│       └── MarketAnalysisAgent/      # Agent service
├── tests/
│   ├── AAuth.Tests/                  # Unit tests
│   │   ├── AAuth.Tests.csproj
│   │   ├── HttpSig/
│   │   ├── Tokens/
│   │   └── Crypto/
│   └── AAuth.IntegrationTests/      # Integration tests
│       ├── AAuth.IntegrationTests.csproj
│       └── ThreePartyFlowTests.cs
├── tools/
│   └── AAuth.Cli/                    # dotnet tool (bootstrap + fetch)
│       ├── AAuth.Cli.csproj
│       └── Program.cs
└── hello-world/                      # Existing
```

---

## 9. Implementation Priority

### Phase 1 — Core + Minimal Agent (prove the protocol works)

1. **RFC 9421 HTTP signatures** — create and verify. This is the hardest part with no existing .NET library.
2. **JWK / JWKS / JWK thumbprint** — key serialization and discovery.
3. **Agent token creation** (`aa-agent+jwt`) — self-issued JWT with `cnf.jwk`.
4. **Signed `HttpClient`** — `DelegatingHandler` that signs outbound requests.
5. **Minimal console agent** — generate key, create agent token, make signed request.

### Phase 2 — Resource Server + Three-Party Flow

6. **ASP.NET middleware** — verify inbound HTTP signatures.
7. **Resource token minting** (`aa-resource+jwt`).
8. **Well-known metadata endpoints**.
9. **Minimal WhoAmI server** — port of the whoami Worker.
10. **Token exchange** — agent exchanges resource token at PS for auth token.
11. **Challenge-response** — auto-handle 401 with exchange and retry.

### Phase 3 — CLI + Key Management

12. **Config file** — read/write `~/.aauth/config.json`.
13. **Software key backend** — generate and persist keys.
14. **Bootstrap CLI** — `discover`, `generate`, `sign-token`, `public-key`, `add-agent`.
15. **Fetch CLI** — make authenticated requests from command line.

### Phase 4 — Full Demo

16. **Backend API** — ASP.NET Core equivalent of the Python FastAPI backend.
17. **Agent services** — supply chain + market analysis.
18. **Integration tests** — end-to-end flows for Mode 1, Mode 3, user consent.
19. **Gateway integration** — configure the Go agent gateway with .NET backends (or build YARP-based alternative).

### Phase 5 — Advanced (optional)

20. **Hardware key support** — YubiKey via Yubico .NET SDK.
21. **R3 operations** — vocabulary-based authorization.
22. **Mission system** — full mission lifecycle.
23. **MCP transports** — stdio bridge, OpenClaw plugin.

---

## 10. Key NuGet Dependencies

| Package | Purpose | Version |
|---|---|---|
| `Microsoft.IdentityModel.JsonWebTokens` | JWT creation and verification | Latest |
| `Microsoft.IdentityModel.Tokens` | JWK, JWKS, token validation parameters | Latest |
| `System.Security.Cryptography` | Ed25519, ECDSA, RSA, SHA-256 (built into .NET 10) | — |
| `Microsoft.AspNetCore.WebUtilities` | Base64url encoding (if not using .NET 10 built-in) | Latest |
| `Yubico.YubiKey` | YubiKey PIV operations (Phase 5) | Latest |
| `NSec.Cryptography` | Ed25519 fallback if targeting < .NET 9 | Latest |

---

## 11. Test Strategy

### Unit Tests

- **HTTP signature creation**: Known test vectors → verify signature base + output matches.
- **HTTP signature verification**: Known good/bad signatures → verify accept/reject.
- **JWT creation**: Create agent/resource/auth tokens → decode and verify claims.
- **JWT verification**: Valid + expired + wrong-audience + wrong-key → verify behavior.
- **JWK thumbprint**: Known keys → verify thumbprint matches expected value.
- **Header parsing**: Various `AAuth-Requirement`, `Signature-Key` formats → verify parsed correctly.

### Integration Tests

- **Identity-based flow**: Agent → signed request → resource verifies → 200.
- **Three-party flow**: Agent → resource (401 + resource_token) → PS (auth_token) → resource (200).
- **Deferred flow**: Agent → resource (202) → poll → terminal response.
- **Token refresh**: Agent token near expiry → auto-refresh → successful request.

### Test Infrastructure

The packages-js `e2e` package provides patterns for:
- In-memory test key factories (generate Ed25519 key pairs on the fly)
- Mock HTTP servers (return canned well-known metadata, JWKS, tokens)
- Challenge flow simulation

The .NET equivalent should use `WebApplicationFactory<T>` for in-process ASP.NET testing and `HttpMessageHandler` mocks for outbound call testing.

---

## 12. Gaps and Open Questions

1. **RFC 9421 in .NET**: No existing library. Must be built from scratch. This is the single biggest implementation effort. Consider contributing to the ecosystem.

2. **Ed25519 JWT support in Microsoft.IdentityModel**: The `Microsoft.IdentityModel` libraries have limited Ed25519 support. May need custom `SignatureProvider` and `CryptoProvider` implementations.

3. **JSON Canonicalization (RFC 8785)**: Needed for mission hash verification. No standard .NET library; need custom implementation or port.

4. **Agent Gateway**: The Go-based agent gateway binary can be reused as-is. Building a .NET equivalent (using YARP reverse proxy) is optional but would make the demo fully .NET.

5. **Person Server**: The demo uses the gateway's built-in PS. A standalone .NET Person Server sample would complete the four-party story.

6. **MCP integration**: The `ModelContextProtocol` .NET SDK exists. Integrating AAuth signing with MCP transports is a Phase 5 concern.

7. **Scope of "samples" vs "SDK"**: The packages-js repo is a production SDK. The dotnet-samples repo is positioned as samples. Decide whether to build production-quality library code or sample-quality code with appropriate caveats.
