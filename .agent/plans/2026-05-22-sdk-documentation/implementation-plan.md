# Implementation Plan: SDK Documentation (`docs/`)

> Created 2026-05-22. Branch: `docs/sdk-usage-guide`

## Goal

Add a `docs/` folder with comprehensive Markdown documentation covering how to
use the .NET AAuth SDK for all workflows, signing modes, and server
implementation scenarios. Each document is self-contained but cross-links to
related pages and to the [AAuth Explorer](https://explorer.aauth.dev/) as the
canonical protocol reference.

## Design Decisions

- **Target audience**: .NET developers integrating AAuth into agents or
  resources. Assumes familiarity with ASP.NET Core DI and `HttpClient` pipeline
  but no AAuth protocol knowledge.
- **Format**: Markdown with fenced C# code blocks. No generated API docs (those
  can come later via docfx/xmldoc).
- **Explorer links**: Every doc links to the relevant
  [explorer.aauth.dev](https://explorer.aauth.dev/) page as the golden
  source of truth for protocol concepts.
- **Code samples**: Minimal, runnable snippets. Reference the `samples/` folder
  for full working examples.

---

## Folder Structure

```
docs/
├── README.md                         # Index / table of contents
├── getting-started.md                # Install, first request, project setup
├── concepts.md                       # Protocol overview for SDK users
├── signing-modes/
│   ├── overview.md                   # Signing mode comparison + when to use each
│   ├── pseudonymous-hwk.md           # sig=hwk usage
│   ├── agent-identity-jwks-uri.md    # sig=jwks_uri usage
│   ├── agent-token-jwt.md            # sig=jwt usage
│   └── key-rotation-jkt-jwt.md       # sig=jkt-jwt usage
├── workflows/
│   ├── identity-based-access.md      # 2-step: sign → 200
│   ├── resource-managed-access.md    # Interaction-based 2-party flow
│   ├── ps-asserted-access.md         # 3-party: resource token → PS → auth token
│   ├── federated-access.md           # 4-party: PS → AS federation
│   ├── bootstrap-enrollment.md       # Agent keygen + AP enrollment
│   └── deferred-consent.md           # Polling, interaction URLs, user approval
├── server/
│   ├── verification-middleware.md    # AAuthVerificationMiddleware setup
│   ├── resource-metadata.md          # Well-known endpoints, metadata config
│   ├── token-issuance.md             # ResourceTokenBuilder, AuthTokenBuilder
│   ├── replay-detection.md           # IJtiStore, revocation
│   └── multi-scheme-verification.md  # ISignatureKeyResolver, IKeyLookup
├── advanced/
│   ├── missions.md                   # Mission proposal, approval, headers
│   ├── platform-attestation.md       # IPlatformAttestor seam
│   ├── key-management.md             # IKeyStore, KeyStore, InMemoryKeyStore
│   └── error-handling.md             # Signature-Error, TokenError, PollingError
└── reference/
    └── configuration.md              # DI registration, options, timeouts
```

---

## Phase 1: Foundation Docs (README, Getting Started, Concepts)

### Deliverables

| File | Content |
|------|---------|
| `docs/README.md` | Index with table of contents linking all docs; quick-start pointer; explorer links |
| `docs/getting-started.md` | NuGet install, `AAuthKey.Generate()`, first signed request with `AAuthSigningHandler`, verify response |
| `docs/concepts.md` | Protocol overview: 4 participants, 3 layers (identity, access, governance); links to [explorer home](https://explorer.aauth.dev/), [signing compare](https://explorer.aauth.dev/signing/compare), [access compare](https://explorer.aauth.dev/access/compare) |

### Definition of Done

- [ ] `docs/README.md` created with full ToC and nav links.
- [ ] `docs/getting-started.md` has install + first-request code that compiles.
- [ ] `docs/concepts.md` maps explorer concepts to SDK types.
- [ ] All explorer links verified reachable.

---

## Phase 2: Signing Mode Docs

### Deliverables

| File | Content | Explorer Link |
|------|---------|---------------|
| `docs/signing-modes/overview.md` | Comparison table (Anonymous/Pseudonymous/Identity/Token); when to use; capability matrix | [Signing Compare](https://explorer.aauth.dev/signing/compare) |
| `docs/signing-modes/pseudonymous-hwk.md` | `HwkSignatureKeyProvider` usage; what resource sees; rate-limiting use case | [Pseudonymous demo](https://explorer.aauth.dev/signing/pseudonymous) |
| `docs/signing-modes/agent-identity-jwks-uri.md` | `JwksUriSignatureKeyProvider` usage; JWKS hosting; replacing API keys | [Identity demo](https://explorer.aauth.dev/signing/identity) |
| `docs/signing-modes/agent-token-jwt.md` | `JwtSignatureKeyProvider` usage; agent token lifecycle; PS requirement | [Federated demo](https://explorer.aauth.dev/access/federated) |
| `docs/signing-modes/key-rotation-jkt-jwt.md` | `JktJwtSignatureKeyProvider`; durable→ephemeral delegation; bootstrap refresh | [Schemes reference](https://explorer.aauth.dev/foundations/schemes) |

### Definition of Done

- [ ] Each signing mode doc has: overview, code sample, "what resource learns" section, when-to-use guidance.
- [ ] `overview.md` includes the full capability matrix from explorer.
- [ ] Links to relevant explorer pages in each doc.
- [ ] Code samples reference real SDK types (`ISignatureKeyProvider` implementations).

---

## Phase 3: Workflow Docs

### Deliverables

| File | Content | Explorer Link |
|------|---------|---------------|
| `docs/workflows/identity-based-access.md` | Simplest flow: sign request → 200. Identity/pseudonymous modes. No PS. | [Identity-based](https://explorer.aauth.dev/access/identity-based) |
| `docs/workflows/resource-managed-access.md` | Resource handles auth via interaction; `AAuth-Access` opaque token | [Resource-managed](https://explorer.aauth.dev/access/resource-managed) |
| `docs/workflows/ps-asserted-access.md` | 3-party: `ChallengeHandler`, `TokenExchangeClient`, resource token → auth token | [PS-asserted](https://explorer.aauth.dev/access/ps-asserted) |
| `docs/workflows/federated-access.md` | 4-party: PS→AS federation; resource token audience = AS | [Federated](https://explorer.aauth.dev/access/federated) |
| `docs/workflows/bootstrap-enrollment.md` | `AgentProviderClient.EnrollAsync()`; key generation; agent token retrieval | [Schemes](https://explorer.aauth.dev/foundations/schemes) |
| `docs/workflows/deferred-consent.md` | `DeferredPoller`; `IInteractionPresenter`; polling lifecycle; user approval | [PS-asserted](https://explorer.aauth.dev/access/ps-asserted) |

### Definition of Done

- [ ] Each workflow doc has: sequence diagram (Mermaid), code walkthrough, error scenarios.
- [ ] `ps-asserted-access.md` covers both autonomous (immediate) and deferred (polling) paths.
- [ ] `bootstrap-enrollment.md` explains AP metadata discovery.
- [ ] Cross-links between workflow docs and signing mode docs.

---

## Phase 4: Server Implementation Docs

### Deliverables

| File | Content | Explorer Link |
|------|---------|---------------|
| `docs/server/verification-middleware.md` | `app.UseAAuthVerification()` setup; DI registration; `AAuthVerifier` config; extracting parsed key info | [HTTP Signatures Profile](https://explorer.aauth.dev/foundations/profile) |
| `docs/server/resource-metadata.md` | `app.MapAAuthResourceMetadata()`; `AAuthResourceMetadataOptions`; JWKS endpoint | [Schemes](https://explorer.aauth.dev/foundations/schemes) |
| `docs/server/token-issuance.md` | `ResourceTokenBuilder`; `AuthTokenBuilder`; token lifetime; audience; scope | [PS-asserted](https://explorer.aauth.dev/access/ps-asserted) |
| `docs/server/replay-detection.md` | `IJtiStore`; `InMemoryJtiStore`; revocation endpoint; `app.MapRevocationEndpoint()` | [Error Model](https://explorer.aauth.dev/foundations/errors) |
| `docs/server/multi-scheme-verification.md` | `ISignatureKeyResolver`; `DefaultSignatureKeyResolver`; `IKeyLookup` for hwk; `JwksClient` for jwks_uri | [Schemes](https://explorer.aauth.dev/foundations/schemes) |

### Definition of Done

- [ ] Each server doc has: minimal DI setup, middleware pipeline, code sample.
- [ ] `verification-middleware.md` covers `Signature-Error` header emission.
- [ ] `multi-scheme-verification.md` explains which `IKeyLookup`/`JwksClient` each scheme needs.
- [ ] `replay-detection.md` covers both in-memory and production considerations.

---

## Phase 5: Advanced Topics + Reference

### Deliverables

| File | Content | Explorer Link |
|------|---------|---------------|
| `docs/advanced/missions.md` | `AAuthMission`; `AAuthMissionHeader`; proposal/approval lifecycle | [Missions](https://explorer.aauth.dev/missions/compare), [Lifecycle](https://explorer.aauth.dev/missions/lifecycle) |
| `docs/advanced/platform-attestation.md` | `IPlatformAttestor`; `NoopAttestor`; WebAuthn/App Attest seam | — |
| `docs/advanced/key-management.md` | `IKeyStore`; `KeyStore` (file-based); `InMemoryKeyStore`; custom backends | — |
| `docs/advanced/error-handling.md` | `SignatureError` codes; `TokenErrorCode`; `PollingErrorCode`; exception hierarchy | [Error Model](https://explorer.aauth.dev/foundations/errors) |
| `docs/reference/configuration.md` | All DI registrations; `DeferredPollerOptions`; `MetadataClient` TTL; `AAuthResourceMetadataOptions`; signature freshness window | — |

### Definition of Done

- [ ] `missions.md` links to explorer lifecycle and call-chaining pages.
- [ ] `error-handling.md` includes the full error code table with HTTP status codes.
- [ ] `configuration.md` is a single reference for all configurable options.
- [ ] All docs cross-link where relevant.

---

## Phase 6: Final Review + README Integration

### Deliverables

| Item | Description |
|------|-------------|
| Top-level `README.md` update | Add "Documentation" section pointing to `docs/` |
| Link audit | Verify all inter-doc links and explorer links resolve |
| Code compilation check | Extract all fenced C# into a test or verify manually |

### Definition of Done

- [ ] Top-level README links to `docs/README.md`.
- [ ] All internal `[link](path)` references resolve.
- [ ] All `https://explorer.aauth.dev/...` links return 200.
- [ ] No broken code fences (all snippets have language hint).

---

## Explorer Reference Map

| Explorer Page | Relevant Docs |
|---------------|---------------|
| [Home](https://explorer.aauth.dev/) | `concepts.md` |
| [Signing Compare](https://explorer.aauth.dev/signing/compare) | `signing-modes/overview.md` |
| [Pseudonymous](https://explorer.aauth.dev/signing/pseudonymous) | `signing-modes/pseudonymous-hwk.md` |
| [Agent Identity](https://explorer.aauth.dev/signing/identity) | `signing-modes/agent-identity-jwks-uri.md` |
| [Schemes](https://explorer.aauth.dev/foundations/schemes) | `signing-modes/key-rotation-jkt-jwt.md`, `server/multi-scheme-verification.md` |
| [HTTP Signatures Profile](https://explorer.aauth.dev/foundations/profile) | `server/verification-middleware.md` |
| [Error Model](https://explorer.aauth.dev/foundations/errors) | `advanced/error-handling.md`, `server/replay-detection.md` |
| [Identity-Based](https://explorer.aauth.dev/access/identity-based) | `workflows/identity-based-access.md` |
| [Resource-Managed](https://explorer.aauth.dev/access/resource-managed) | `workflows/resource-managed-access.md` |
| [PS-Asserted](https://explorer.aauth.dev/access/ps-asserted) | `workflows/ps-asserted-access.md`, `workflows/deferred-consent.md` |
| [Federated](https://explorer.aauth.dev/access/federated) | `workflows/federated-access.md` |
| [Missions Compare](https://explorer.aauth.dev/missions/compare) | `advanced/missions.md` |
| [Mission Lifecycle](https://explorer.aauth.dev/missions/lifecycle) | `advanced/missions.md` |
| [Call Chaining](https://explorer.aauth.dev/advanced/call-chaining) | `advanced/missions.md` |

---

## Out of Scope

| Item | Reason |
|------|--------|
| Auto-generated API reference (docfx/xmldoc) | Separate tooling concern; can layer on later |
| Video/interactive tutorials | Different medium; explorer serves this role |
| Multi-language SDK docs | This repo is .NET only |
| Spec authoring/editing | Spec lives in `aauth-spec/`; docs explain usage, not protocol design |
