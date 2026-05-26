# Self-Issued Agent Identity — Implementation Plan

## Overview

Clarify in documentation and samples that hosted agents (ASP.NET Core services,
any server with a stable HTTPS URL) are their own AP and self-issue agent tokens.
The external MockAgentProvider exists only for client-type agents (CLI, mobile,
browser) that cannot host metadata at a stable URL.

## Context

- **Spec:** `draft-hardt-oauth-aauth-protocol` §Roles (Agent + AP collocation),
  `draft-hardt-aauth-bootstrap` §Self-Hosted Agents.
- **Trigger:** Orchestrator was incorrectly enrolling with external AP; now
  self-issues. Need to document and propagate the pattern.
- **Branch:** `feature/call-chaining-sdk-plan` (continues current work).

---

## Phase 1: Documentation — Self-Issued Identity Guide

**Goal:** Add a new doc explaining when agents self-issue vs use an external AP,
with code examples for each path.

### Files

| File | Action |
|------|--------|
| `docs/concepts.md` | **Modify** — add section on Agent + AP collocation |
| `docs/signing-modes/agent-token-jwt.md` | **Modify** — add self-issuance subsection |
| `docs/advanced/self-issued-identity.md` | **New** — full guide: taxonomy, when to self-issue, code recipe, metadata setup |

### Content Outline for `docs/advanced/self-issued-identity.md`

1. **When to self-issue** — the decision rule (can you host `/.well-known/aauth-agent.json`?)
2. **Agent taxonomy table** — web/mobile/desktop → external AP; hosted service → self-issue
3. **Self-issuance recipe** — `AgentTokenBuilder` + `MapAAuthAgentWellKnown` in 10 lines
4. **Comparison with external AP** — enrollment/refresh ceremony vs on-demand issuance
5. **Key management** — single key serves as both AP signing key and agent signing key
6. **When you still need an AP** — client agents, attestation, device management

### Definition of Done

- [ ] `docs/advanced/self-issued-identity.md` exists with taxonomy + code recipe
- [ ] `docs/concepts.md` references self-issued identity with a link
- [ ] `docs/signing-modes/agent-token-jwt.md` has self-issuance subsection

---

## Phase 2: Sample Cleanup — Orchestrator

**Goal:** Remove dead AP config from Orchestrator and document it as the
canonical self-issued hosted agent example.

### Files

| File | Action |
|------|--------|
| `samples/Orchestrator/Program.cs` | **Modify** — remove unused `apUrl` config variable; update `agentId` to use orchestrator domain |
| `samples/Orchestrator/appsettings.json` | **Modify** — remove `AgentProvider` key |
| `samples/Orchestrator/README.md` | **Modify** — document self-issued identity pattern |

### Changes

- Remove `apUrl` variable (currently read but unused after self-issue fix).
- Change `agentId` from `aauth:orchestrator@ap.example` to
  `aauth:orchestrator@localhost:5200` — the domain should be the agent's own
  since it's its own AP.
- Update README to explain why the Orchestrator self-issues.
- Remove the commented-out interaction-chaining example that references old AP
  enrollment pattern.

### Definition of Done

- [ ] No reference to `AgentProvider` in Orchestrator config or code
- [ ] `agentId` domain matches orchestrator's own URL
- [ ] README explains self-issued identity
- [ ] Commented-out old AP code removed
- [ ] All tests pass

---

## Phase 3: Sample Cleanup — GuidedTour

**Goal:** `EnsureAgentReadyAsync()` (silent background setup for non-Bootstrap
flows) switches to self-issuance. The Bootstrap mode remains the one explicit
enrollment demo — it walks through key gen → AP discovery → enrolment
step-by-step in the UI.

### Background

GuidedTour has enrollment in two places:

1. **Bootstrap mode** (`TourMode.Bootstrap`) — explicit user-visible steps
   (BootstrapStepDiscoverApAsync + BootstrapStepEnrolAsync). This IS the
   enrollment demo use case. **Keep as-is.**
2. **`EnsureAgentReadyAsync()`** — called silently before all non-Bootstrap
   flows (Identity, Autonomous, Deferred, CallChain). Currently enrolls with
   AP when `AgentProviderUrl` is configured. These flows demo resource access,
   consent, and call chaining — not enrollment. **Switch to self-issue.**

### Files

| File | Action |
|------|--------|
| `samples/GuidedTour/TourSession.cs` | **Modify** — `EnsureAgentReadyAsync()`: always self-issue (remove AP enrollment branch); keep Bootstrap mode's explicit enrol steps unchanged |
| `samples/GuidedTour/appsettings.json` | **Modify** — keep `AgentProviderUrl` (needed for Bootstrap mode demo) but add comment clarifying it's only for Bootstrap |
| `samples/GuidedTour/README.md` | **Modify** — document that Bootstrap demos enrollment; other modes self-issue |

### Changes

- In `EnsureAgentReadyAsync()`: remove the `if (!string.IsNullOrWhiteSpace(_options.AgentProviderUrl))` AP enrollment
  branch. Make the self-sign path the only path (using the tour server's own
  URL as issuer, not `"https://ap.example"`).
- Update self-sign issuer to match the GuidedTour's own URL so the token is
  spec-correct (issuer == agent's own domain for self-issued tokens).
- Bootstrap mode (`BootstrapStepDiscoverApAsync` + `BootstrapStepEnrolAsync`)
  remains unchanged — it still talks to MockAgentProvider to demo enrollment.

### Definition of Done

- [ ] `EnsureAgentReadyAsync()` always self-issues (no AP enrollment)
- [ ] Bootstrap mode still demos AP enrollment when `AgentProviderUrl` configured
- [ ] Identity/Autonomous/Deferred/CallChain flows work without MockAgentProvider
- [ ] README documents Bootstrap as the enrollment demo
- [ ] All tests pass

---

## Phase 4: Sample Cleanup — SampleApp (Partial)

**Goal:** Remove AP enrollment from workflows that don't demo enrollment.
Keep enrollment only in the JWKS URI page (which explicitly demonstrates
AP-issued identity verified via the AP's JWKS endpoint).

### Background

SampleApp is a hosted ASP.NET Core Blazor server with 5 workflows:

| Page | Purpose | Enrollment? |
|------|---------|-------------|
| HWK (Pseudonymous) | Demos pseudonymous key access | No |
| **JWKS URI (Identity)** | Demos AP-issued identity verified via AP's JWKS | **Keep** — the AP relationship IS the point |
| JWT (Direct Grant) | Demos three-party PS token exchange | Remove — self-issue works |
| Deferred (User Consent) | Demos deferred consent + polling | Remove — self-issue works |
| Call Chain (Multi-Agent) | Demos multi-hop delegation | Remove — self-issue works |

The JWKS URI page is the one enrollment use case: the resource calls the AP's
`jwks_uri` to verify the agent's key, which fundamentally requires a real AP
relationship.

### Files

| File | Action |
|------|--------|
| `samples/SampleApp/Program.cs` | **Modify** — add self-issued agent identity (key + `MapAAuthAgentWellKnown`) |
| `samples/SampleApp/EnrollmentService.cs` | **Keep** — still needed for JWKS URI page |
| `samples/SampleApp/Components/Pages/Jwt.razor` | **Modify** — use self-issued token instead of enrollment |
| `samples/SampleApp/Components/Pages/Deferred.razor` | **Modify** — use self-issued token instead of enrollment |
| `samples/SampleApp/Components/Pages/CallChain.razor` | **Modify** — use self-issued token instead of enrollment |
| `samples/SampleApp/Components/Pages/JwksUri.razor` | **No change** — keeps AP enrollment |
| `samples/SampleApp/appsettings.json` | **Modify** — add self-issued config (own URL); keep AP config for JWKS URI page |

### Changes

- Add self-issued agent identity to `Program.cs`: generate key, register
  `MapAAuthAgentWellKnown`, expose signing key as a service for pages to use.
- JWT, Deferred, CallChain pages: replace "1. Enrol" step with self-issued
  token (no button needed — token is available immediately).
- JWKS URI page: unchanged — keeps the "1. Enrol with Agent Provider" button
  because the AP's JWKS is what makes this workflow meaningful.

### Definition of Done

- [ ] JWT, Deferred, CallChain pages work without MockAgentProvider running
- [ ] JWKS URI page still enrolls with AP and shows JWKS URI
- [ ] Self-issued agent metadata published at `/.well-known/aauth-agent.json`
- [ ] All tests pass

---

## Phase 5: MockAgentProvider Scope Clarification

**Goal:** Clarify that MockAgentProvider exists for: AgentConsole (CLI),
SampleApp JWKS URI page, and GuidedTour Bootstrap mode only.

### Files

| File | Action |
|------|--------|
| `samples/MockAgentProvider/README.md` | **Modify** — explain scope: client agents + enrollment demos only |
| `samples/README.md` | **Modify** — architecture diagram noting which services need AP |

### Definition of Done

- [ ] MockAgentProvider README states it's for client-type agents and explicit enrollment demos
- [ ] Top-level samples README clarifies AP is not needed for hosted services
- [ ] `make` targets document which targets require MockAgentProvider

---

## Phase 6: Getting Started Guide Update

**Goal:** Update the getting-started guide to present two clear paths from the
start rather than leading all agents through AP enrollment.

### Files

| File | Action |
|------|--------|
| `docs/getting-started.md` | **Modify** — two-path introduction |

### Changes

- Add a "Choose your path" section early:
  - **Hosted service** (server with stable URL) → self-issue, no AP needed
  - **Client agent** (CLI, browser, mobile) → enroll with AP
- Link to `docs/advanced/self-issued-identity.md` for the hosted path
- Keep existing AP enrollment walkthrough for the client path

### Definition of Done

- [ ] Getting-started has clear fork pointing readers to the right path
- [ ] Hosted-service path links to self-issued identity doc
- [ ] No false implication that all agents need an AP

---

## Out of Scope

| Item | Reason |
|------|--------|
| SampleApp JWKS URI page enrollment removal | That page explicitly demos AP-issued identity — AP is the point |
| AgentConsole changes | CLI agent correctly uses external AP |
| MockAgentProvider removal | Still needed for Bootstrap demo + JWKS URI page + AgentConsole |
| Self-issued token rotation/expiry policy | Future work; current samples use short-lived tokens |
| Production key management (HSM, Vault) | Out of scope for samples |
