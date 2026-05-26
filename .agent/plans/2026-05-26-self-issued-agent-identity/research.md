# Self-Issued Agent Identity — Research

## Spec Basis

### Roles — Agent + AP Collocation (main spec §Roles)

> Agent, AP, Resource, PS, and AS are **roles**, not deployment units. Each role
> has its own protocol identity — the Agent by an `aauth:local@domain` URI
> attested by an agent token, and AP, Resource, PS, and AS each by a distinct
> HTTPS URL with metadata published at a distinct well-known path. A single
> deployment unit MAY fill multiple roles, by hosting metadata for multiple
> server roles under a shared origin and/or by holding an agent token in addition
> to acting as a server. The protocol treats each role independently regardless
> of collocation — every interaction is a normal protocol exchange between role
> identifiers, even when the underlying servers are the same.
>
> Common collocations:
> - **Resource + Agent**: A resource acts as an agent for downstream calls,
>   publishing agent metadata at `/.well-known/aauth-agent.json` so downstream
>   parties can verify its identity. See (§call-chaining).
> - **Agent + AP**: A self-hosted agent is its own agent provider, self-issuing
>   agent tokens signed by a JWKS-published key the user controls. See
>   [@?I-D.hardt-aauth-bootstrap].

### Agent Token Structure (main spec §Agent Token Structure)

> Required payload claims:
> - `iss`: Agent provider URL
> - `dwk`: `aauth-agent.json` — the well-known metadata document name for key
>   discovery ([@!I-D.hardt-httpbis-signature-key])
> - `sub`: Agent identifier (stable across key rotations)
> - `cnf`: Confirmation claim ([@!RFC7800]) with `jwk` containing the agent's
>   public key

### Agent Token Verification (main spec §Agent Token Verification)

> 1. Decode the JWT header. Verify `typ` is `aa-agent+jwt`.
> 2. Verify `dwk` is `aauth-agent.json`. Discover the issuer's JWKS via
>    `{iss}/.well-known/{dwk}` per the HTTP Signature Keys specification.
>    Locate the key matching the JWT header `kid` and verify the JWT signature.
> 3. Verify `exp` is in the future and `iat` is not in the future.
> 4. Verify `iss` is a valid HTTPS URL conforming to the Server Identifier
>    requirements.
> 5. Verify `cnf.jwk` matches the key used to sign the HTTP request.

**Key implication for self-issued agents:** step 2 fetches `{iss}/.well-known/aauth-agent.json`
to find the JWKS. For a self-issued agent, `iss` == the agent's own URL, so the
verifier resolves the agent's own `/.well-known/aauth-agent.json` → `jwks_uri`
→ finds the signing key. This is why self-hosted agents MUST publish metadata at
their own URL — it's how verifiers discover the signing key.

### Call Chaining Identity (main spec §Call Chaining Identity)

> When a resource acts as an agent in call chaining, it uses its own signing key
> and presents its own credentials. The resource MUST publish agent metadata so
> downstream parties can verify its identity.

### Multi-Hop Resource Access (main spec §Multi-Hop Resource Access)

> Because the resource acts as an agent, it MUST have its own agent identity — it
> MUST publish agent metadata at `/.well-known/aauth-agent.json` so that
> downstream resources and ASes can verify its identity.

### Upstream Token Verification (main spec §Upstream Token Verification)

> When the PS receives an `upstream_token` parameter in a call chaining request:
> 1. Perform Auth Token Verification on the upstream token.
> 2. Verify `iss` is a trusted AS (an AS whose auth token the PS previously
>    brokered).
> 3. Verify the `aud` in the upstream token matches the resource that is now
>    acting as an agent (i.e., the upstream token was issued for the intermediary
>    resource).

**Implication:** For self-issued intermediaries, `agent_token.iss` ==
intermediary URL == `aud` in the upstream token. The PS can match them.

### Bootstrap Spec — Self-Hosted Agents (§Self-Hosted Agents)

> A self-hosted agent runs under a domain the user controls. The agent publishes
> its AP metadata document at `/.well-known/aauth-agent.json` per
> [@!I-D.hardt-oauth-aauth-protocol]; the JWKS itself is hosted at any HTTPS URL
> referenced by the metadata's `jwks_uri`. The corresponding private key should
> be hardware-bound where the platform supports it.
>
> Self-hosted agents act as their own AP — they self-issue agent tokens signed by
> the JWKS-published key. There is no separate AP to refresh against, so the
> two-key pattern does not apply: the JWKS-published key serves both as the AP
> signing key (signing self-issued agent tokens) and as the key whose public part
> appears in `agent_token.cnf.jwk` (signing HTTP messages). Because the trust
> anchor is a key the user controls and publishes, no platform attestation step
> exists. Other parties verify the agent token signature against the published
> JWKS, exactly as they would for any other AP.

### Bootstrap Spec — Self-Hosted Refresh (§Refresh Patterns)

> Self-hosted agents self-issue agent tokens. There is no separate refresh
> ceremony — the agent generates a new agent token signed by its JWKS-published
> key whenever needed. The two-key pattern does not apply.

### Bootstrap Spec — Self-Hosted Enrollment (§Per-Platform Enrollment Sketches)

> 1. User generates a hardware-bound key on their machine.
> 2. User publishes an AP metadata document at `/.well-known/aauth-agent.json`
>    per [@!I-D.hardt-oauth-aauth-protocol], with `jwks_uri` pointing to a JWKS
>    containing the public part of that key.
> 3. The agent self-issues an agent token signed by that key as needed.
>
> There is no separate enrollment step — publication of the JWKS is the
> enrollment.

### Bootstrap Spec — Per-Platform Key Handling (§Per-Platform Key Handling)

> Self-hosted agents (§self-hosted-agents) use a single key — the JWKS-published
> key serves as both the AP signing key and the agent's signing key, since there
> is no separate AP to refresh against.

### Platform Values (main spec IANA registry)

| Platform | Description |
|----------|-------------|
| `web` | Browser-based agent |
| `mobile` | iOS/Android native |
| `desktop` | Native desktop app |
| `workload` | Headless workload identity |
| `self-hosted` | User-controlled deployment under a domain the user controls |

### Agent Provider Metadata (main spec §Agent Provider Metadata)

> Published at `/.well-known/aauth-agent.json`:
> ```json
> {
>   "issuer": "https://agent.example",
>   "jwks_uri": "https://agent.example/.well-known/jwks.json",
>   "client_name": "Example AI Assistant"
> }
> ```
>
> Fields:
> - `issuer` (REQUIRED): The agent provider's HTTPS URL (the `domain` in agent
>   identifiers it issues). This is the value placed in the `iss` claim of agent
>   tokens.
> - `jwks_uri` (REQUIRED): URL to the agent provider's JSON Web Key Set

## Agent Taxonomy: Who Needs an External AP

| Agent Type | Needs External AP | Reason |
|-----------|-------------------|--------|
| Browser web app | Yes | No stable HTTPS URL to host metadata; can't self-sign JWTs server-side |
| Mobile native app | Yes | No stable HTTPS URL; keys are device-bound in Secure Enclave/StrongBox |
| Desktop native app | Yes | No stable HTTPS URL; keys are in local TPM/Keychain |
| CLI tool (AgentConsole) | Yes | Same as desktop — client-side, no server URL |
| ASP.NET Core service | **No** | Hosted at stable URL; publishes metadata; signs with own key |
| Intermediary (Resource+Agent) | **No** | Hosted; publishes `aauth-agent.json` at own URL; self-issues |
| Any server-side workload | **No** | Has stable URL + can host JWKS |

## Key Insight

The dividing line is: **can the agent publish `/.well-known/aauth-agent.json` at
a stable HTTPS URL it controls?**

- Yes → self-issue (Agent + AP collocation). No enrollment, no refresh endpoint.
- No → needs external AP (enrollment + refresh ceremony).

For self-issued agents, token verification still works per spec:
1. Verifier receives `agent_token.iss` = agent's own URL (e.g., `http://localhost:5400`)
2. Verifier fetches `{iss}/.well-known/aauth-agent.json` → gets `jwks_uri`
3. Verifier fetches JWKS → finds the `kid` → verifies JWT signature
4. Verifier verifies `cnf.jwk` matches the HTTP signature key

The self-issued pattern is indistinguishable from an external AP from the
verifier's perspective — the only difference is that `iss` happens to be the
agent's own URL rather than a third-party AP URL.

In this SDK's samples, **AgentConsole** is the only sample that wholly depends
on MockAgentProvider. **SampleApp** needs it only for its JWKS URI page (which
demos AP-issued identity verification). **GuidedTour** needs it only for
Bootstrap mode (which demos the enrollment ceremony). Every other workflow in
those hosted services can and should self-issue.

## Implementation Pattern for Self-Issued Agents

From the spec sections above, a hosted service that self-issues needs:

1. **Generate a signing key** on startup
2. **Publish metadata** at `/.well-known/aauth-agent.json` with `issuer` and `jwks_uri`
3. **Publish JWKS** at the `jwks_uri` URL containing the public key
4. **Self-issue tokens** via `AgentTokenBuilder` with `Issuer` = own URL

The SDK already supports this via:
- `AAuthKey.Generate()` — key generation
- `MapAAuthAgentWellKnown(options)` — publishes metadata + JWKS
- `AgentTokenBuilder` — builds the JWT (when `ConfirmationKey` is null, `Key`
  serves as both signing key and `cnf.jwk`)

The `WithTokenRefresh` callback on `AAuthClientBuilder` can simply call
`AgentTokenBuilder.Build()` each time — no AP round-trip needed.

## Current State of Samples

| Sample | Current AP Usage | Correct Posture |
|--------|-----------------|-----------------|
| AgentConsole | Enrolls with MockAgentProvider | ✅ Correct — CLI agent needs AP |
| SampleApp | Enrolls via `EnrollmentService` for all pages | ⚠️ Partial fix: keep enrollment on JWKS URI page only; JWT/Deferred/CallChain should self-issue |
| Orchestrator | Self-issues (`SelfIssueAgentToken()`) | ✅ Already fixed (dead config remains) |
| GuidedTour | Enrolls if AP configured, else self-signs | ⚠️ Bootstrap mode: keep (explicit enrollment demo); `EnsureAgentReadyAsync`: switch to self-issue |
| MockAgentProvider | N/A (is the AP) | ✅ Exists for Bootstrap demo + JWKS URI page + AgentConsole |
| WhoAmI | Pure resource, no agent role | ✅ Correct |
| MockPersonServer | Pure PS/AS, no agent role | ✅ Correct |

## Per-Workflow Enrollment Analysis

### SampleApp Workflows

SampleApp is a hosted ASP.NET Core Blazor server (stable URL). Its
`EnrollmentService` runs as a shared singleton — whichever page triggers
`EnsureEnrolledAsync()` first performs the actual enrollment.

| Page | Shows Enrollment in UI? | Why It Uses Enrollment | Self-Issue OK? |
|------|:-:|---|:-:|
| HWK (Pseudonymous) | No | Doesn't use enrollment at all | N/A |
| **JWKS URI (Identity)** | **Yes** — "1. Enrol" button | Resource verifies agent key via AP's `jwks_uri` — AP relationship IS the point | **No** — must keep |
| JWT (Direct Grant) | Yes — "1. Enrol" button | Gets token to call resource, but the demo is three-party exchange, not enrollment | **Yes** |
| Deferred (User Consent) | Yes — "1. Enrol" button | Gets token, but demo is deferred consent polling | **Yes** |
| Call Chain (Multi-Agent) | Yes — "1. Enrol" button | Gets token, but demo is multi-hop delegation | **Yes** |

**Decision:** Keep enrollment only for JWKS URI page. Other pages switch to
self-issuance (hosted service publishes own `aauth-agent.json` + JWKS).

### GuidedTour Workflows

GuidedTour is a hosted ASP.NET Core Blazor server that educates users about
AAuth flows via step-by-step walkthrough.

| TourMode | Enrollment Location | User-Visible Steps? | Action |
|----------|---|:-:|---|
| **Bootstrap** | `BootstrapStepDiscoverApAsync` + `BootstrapStepEnrolAsync` | **Yes** — shown as steps 2–3 in timeline | **Keep** — this IS the enrollment demo |
| Identity | `EnsureAgentReadyAsync()` | No — silent background | **Remove** — self-issue |
| Autonomous | `EnsureAgentReadyAsync()` | No — silent background | **Remove** — self-issue |
| Deferred | `EnsureAgentReadyAsync()` | No — silent background | **Remove** — self-issue |
| CallChain | `EnsureAgentReadyAsync()` | No — silent background | **Remove** — self-issue |

**Decision:** `EnsureAgentReadyAsync()` always self-issues. Bootstrap mode keeps
its explicit AP enrollment steps for the enrollment demo.

## SDK Support for Self-Issuance

`AgentTokenBuilder` already supports self-issuance:

```csharp
var token = new AgentTokenBuilder
{
    Issuer = "https://my-service.example",   // service's own URL
    Subject = "aauth:my-service@my-service.example",
    KeyId = "key-1",
    Key = mySigningKey,        // same key for signing + cnf
    PersonServer = psUrl,      // optional
}.Build();
```

When `ConfirmationKey` is null, `Key` is used as both the signing key and the
confirmation key — exactly the self-hosted pattern.

## Documentation Gaps

1. No doc explains when to self-issue vs use an external AP.
2. No doc explains the Agent + AP collocation pattern for hosted services.
3. The getting-started guide leads all agents through AP enrollment.
4. The Orchestrator sample previously used external AP (now fixed), but
   the pattern isn't documented as a reusable recipe.
5. MockAgentProvider README doesn't clarify it's only for client-type agents.
6. SampleApp presents enrollment as mandatory for all workflows, even those
   where the hosted server could self-issue.
7. GuidedTour's `EnsureAgentReadyAsync()` enrolls silently for non-Bootstrap
   flows, creating an unnecessary runtime dependency on MockAgentProvider.
