# Research — PS/AS whitelisting spec-compliance (any-verifiable-counterparty trust)

Research-only document for a future initiative: making the .NET AAuth SDK's
PS/AS trust-lists match the draft-08 trust model, where trust is **open or
dynamically established** by default. Two fail-closed deviations exist (see the
audit): (#1) the resource's inbound `TrustedAuthTokenIssuers` rejects every auth
token when unset, contradicting the **PS-asserted (three-party)** posture *"any
agent's PS can assert identity claims to any resource without bilateral setup"*;
and (#4) the PS's outbound `TrustedAccessServers` refuses all four-party
federation when unset, contradicting *"AAuth does not require a separate
registration step."*

Spec source:
[`aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md`](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md)
(draft-08, the version the SDK targets — see
[`aauth-spec/SPEC-VERSION.md`](../../../aauth-spec/SPEC-VERSION.md)).

No implementation steps here. This document records the spec grounding, the exact
divergence, and the full blast radius so an implementation plan can be written
against it.

> **Update (2026-06): scope broadened to ALL PS/AS whitelisting.** The original
> document covered only the three-party resource default. A full audit of every
> PS/AS trust-list in the SDK (see [PS/AS whitelisting audit](#psas-whitelisting-audit-all-five-trust-lists))
> found the SDK is **internally inconsistent**: it ships **two** fail-closed
> deviations of the same shape — (1) the resource's inbound `TrustedAuthTokenIssuers`
> and (4) the PS's outbound `TrustedAccessServers` (PS→AS federation) — alongside
> **two** already-compliant permissive-by-default templates — (2)
> `TrustedAgentProviderIssuers` and (3) the AS's inbound `TrustedPersonServers`.
> Both deviations reject by default where the spec allows open / dynamically-
> established trust. The PS→AS deviation was previously mislabeled "out of scope";
> it is now an in-scope second deviation. Sections below are updated in place; the
> original three-party material is retained and is deviation #1.

## Design invariants

This initiative is bound by **two** invariants. An implementation that satisfies
one but violates the other is not acceptable.

1. **Spec-compliant by default.** With nothing configured, the SDK MUST behave as
   draft-08 specifies: accept any *verifiable* counterparty and namespace by
   `iss` (#1, §Trust Posture L2716), and let the AS establish trust dynamically
   (#4, §PS-AS Trust Establishment L1581). "Verifiable" is unchanged — `iss` is
   HTTPS, JWKS resolves, signature verifies, binding checks pass. Trust
   configuration only ever *narrows* this floor.
2. **No new API-surface complexity.** No new options types, no new DI calls, no
   new pipeline stages. Each existing options object gains **one** optional
   property — a predicate delegate — beside the static set it already exposes,
   following the established `Trusted*` property pattern. Trust is then expressible
   three ways, in increasing specificity, all optional and all defaulting to open:
   - **Trust any** — leave both unset (the default; nothing to configure).
   - **Static allow-list** — the existing `IReadOnlySet<string>` / config array.
   - **Custom policy** — a `Func<string,bool>` evaluated per `iss` during token
     verification.
   Constraints **compose by AND** (each only tightens), so the default is open and
   any added constraint can only remove trust, never grant it.

## Research method

Read the draft-08 resource-access, auth-token-verification, trust-posture, and
adoption-path sections directly and **re-verified every line citation against the
vendored source** before recording it. Audited the SDK verification surface and
every `TrustedAuthTokenIssuers` / `RequireIssuerVerification` / `TrustedPersonServers`
call site with workspace-wide search (high result caps to avoid grep truncation),
then read the highest-stakes sites (middleware enforcement, option docstrings,
two conformance tests, getting-started docs) in full. All claims below were
verified directly against source — no subagent delegation. Line numbers are
precise to the current vendor; `{#anchor}` is the durable reference where the
section has one (several relevant subsections have **no** anchor and are cited by
line only).

## Spec grounding (verified)

### 1. The agent declares the PS; the resource follows it

- The **person** chooses their PS; it is *not imposed by any other party*
  (§Terminology — Person Server, L191).
- That choice is carried in the agent token's **`ps` claim**, *"Configured per
  agent instance (e.g., set by the agent provider or chosen by the person
  deploying the agent)"* (§Consuming a Resource, L506; §Agent Token Structure —
  `ps`, L573).
- The resource **discovers the PS from the `ps` claim** and issues a resource
  token with `aud` = PS URL (§PS-Asserted Access (Three-Party), L312; restated
  L510, L613, L702; §Resource Token Structure — `aud`, L807).
- **Exception — call chaining:** an intermediary resource acting as a downstream
  agent routes from the upstream auth token's `mission.approver` / `iss`, **not**
  the calling agent's `ps` claim — *"The `ps` claim in the calling agent's agent
  token is NOT used for this routing"* (§Call Chaining, {#call-chaining}, L1755).

> Conclusion: in the first-hop three-party flow the agent (via its token's `ps`
> claim) determines the resource-token audience, and the resource accepts
> *"whichever PS the agent declares."*

### 2. PS-asserted access requires NO bilateral setup / allow-list

- *"Any agent's PS can assert identity claims to any resource without bilateral
  setup; the resource namespaces those claims by the asserting PS — the same
  `sub` value from a different PS is a different subject."* (§PS-Asserted Access
  (Three-Party), L312.)
- §Trust Posture in PS-Asserted Access (L2716): the resource *"accepts identity
  claims and consent from whichever PS the agent declares … Resources MUST apply
  their own policy on the resulting claims rather than treating the PS-issued auth
  token as a bearer authorization."* Trust is enforced by **namespacing on
  `(iss, sub)`** (L2718–2724), not by gating on a known-PS list.
- Resource Adoption Path step 3 is literally titled **"Accept identity claims from
  any PS"** (L2661).

### 3. Resource-side auth-token verification has no allow-list step

§Auth Token Verification (L1707) — what a resource MUST check when an auth token
arrives:

- **JWT Trust Verification** (L1711): (1) `typ = aa-auth+jwt`; (2) `dwk` is
  `aauth-access.json` or `aauth-person.json`, **discover the issuer's JWKS via
  `{iss}/.well-known/{dwk}`** and verify the JWT signature; (3) `exp`/`iat`
  temporal; (4) **`iss` is a valid HTTPS URL.**
- **Request-Context Binding** (L1718): (5) `aud` = resource's own id; (6) `agent`
  matches signing context; (7) `cnf.jwk` PoP; (8) `act` well-formed; (9) at least
  one of `sub`/`scope`.

There is **no step requiring `iss` to be a member of a pre-configured trust set.**
The issuer is trusted because its JWKS resolves and the signature verifies;
authorization is then the resource's own policy on the namespaced claims.

### 4. Where the spec DOES require / permit pre-established trust

These are distinct mechanisms. Two are spec-**mandated** trusted-issuer checks
(keep them); one is the four-party AS↔PS federation, where the spec **permits both
pre-established and dynamically-established** trust — which is the crux of the
second deviation found in the audit below.

- **Four-party PS↔AS federation:** *"The PS and the resource's AS must have a
  trust relationship before the AS will issue auth tokens. This trust may be
  pre-established … **or established dynamically** through the AS's token endpoint
  responses — interaction, payment, or claims."* (§Consuming a Resource, L516;
  §PS-AS Trust Establishment, L1581.) Crucially: *"AAuth does not require a
  separate registration step before the protocol can be used"* (L1581), and
  *"Claims only: The AS may trust any PS … without requiring a prior
  relationship"* (L1584). So a fail-closed PS that refuses to even **call** an AS
  it hasn't pre-listed forecloses the spec's dynamic-trust path — see deviation #4.
  - **AS side (compliant):** the AS deciding which PSes may federate is
    permissive-by-default — enforced in
    [`src/AAuth/Access/AAuthAccessServerEndpoints.cs`](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs#L199)
    only `when trustedPsHosts.Count > 0`. Matches L1581.
  - **PS side (deviation #4):** the PS deciding which ASes it will call is
    fail-closed — see audit below.
- **Upstream token verification (call chaining), spec-MANDATED — keep:**
  *"Verify `iss` is a trusted issuer (a PS or AS whose auth token the recipient
  previously brokered or is authorized to extend)."* (§Upstream Token
  Verification, {#upstream-token-verification}, L1742.)
- **Revocation, spec-MANDATED — keep:** accept revocation only *"from the issuer
  of the token being revoked or from a trusted PS."* (§Token Revocation,
  {#token-revocation}, L2302.)

## PS/AS whitelisting audit (all five trust-lists)

Every place the SDK gates on a configured set of PS/AS identifiers, and its
verdict against the spec. The unifying test: **does the spec say trust may be
open or dynamically established for this exact code path?** If yes, fail-closed-
by-default is a deviation.

| # | Mechanism | Role / direction | Default when unset | Enforcement | Spec | Verdict |
|---|---|---|---|---|---|---|
| 1 | `AAuthVerificationOptions.TrustedAuthTokenIssuers` | Resource ← inbound auth token | **reject all** | [middleware L425](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L425) | L1707 (no allow-list step); L2716 / L2661 "any PS, namespace by (iss,sub)" | **DEVIATION** |
| 2 | `AAuthVerificationOptions.TrustedAgentProviderIssuers` | Resource ← inbound agent token | accept any verifiable | [middleware L351](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L351) | resource verifies AP JWKS; AP "trusted by the person", not the resource (L189) | **compliant** (template) — gains uniform predicate |
| 3 | `AAuthAccessServerOptions.TrustedPersonServers` | AS ← inbound PS federation | accept any PS | [AS L199](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs#L199) (`Count > 0` guard) | L1581 "no separate registration step"; L1584 "any PS … without prior relationship" | **compliant** (template) — + uniform predicate; empty → deny-all |
| 4 | `AAuthPersonServerOptions.TrustedAccessServers` | PS → outbound AS federation | **refuse all federation (403)** | [PS L829](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L829) (`Count == 0` rejects) | L1581 trust "established dynamically … first token request"; "no separate registration step" | **DEVIATION** |
| 5 | call-chaining `trustedUpstreamIssuers` | PS ← inbound upstream token | set = `{self} ∪ TrustedAccessServers` | [PS L598](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L598) → [validator L106](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs#L106) | L1742 "trusted issuer … previously brokered or authorized to extend" — **MANDATED** | **keep**; set inherits #4's pre-config limit |

Key findings:

- **Two deviations, same shape (#1, #4):** fail-closed-by-default where the spec
  allows open or dynamically-established trust. #1 blocks "any PS" three-party
  identity assertion; #4 blocks dynamic PS→AS federation (a PS with no pre-listed
  AS cannot do four-party at all, contradicting L1581 "does not require a separate
  registration step").
- **Two compliant templates (#2, #3):** permissive-by-default, restrict-when-set.
  These prove the correct shape already lives in the codebase — the fix makes #1
  and #4 match them. Notably the **AS-side** federation gate (#3) is spec-correct
  while the **PS-side** gate (#4) is not, in the same four-party flow.
- **One mandated check to keep (#5):** §Upstream Token Verification (L1742) is a
  MUST. The set `{self} ∪ TrustedAccessServers` is correct for "previously
  brokered" (self) and "authorized to extend" (the AS list), but it inherits #4's
  config dependency: a four-party upstream from a dynamically-trusted (un-listed)
  AS would be rejected. If #4 gains a dynamic path, #5's set construction should
  follow so chains through dynamically-trusted ASes verify.

## Current SDK behavior (audited)

### Deviation #1 — resource inbound auth token (`TrustedAuthTokenIssuers`)

The divergence is a single enforcement branch and its default.

- **Enforcement site:**
  [`src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs`](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L424)
  `VerifyAuthTokenIssuerAsync` (L405) does, after checking `iss` is HTTPS:

  ```csharp
  var trusted = _options.TrustedAuthTokenIssuers;
  if (trusted is null || trusted.Count == 0 || !trusted.Contains(iss))
      throw new TokenVerificationException(
          $"Auth token issuer '{iss}' is not in the trusted issuers list ...");
  ```

  So `null`/empty rejects **all** auth tokens — fail-closed by default. This is
  stricter than §Auth Token Verification (L1707), which never requires allow-list
  membership.

- **Contrast — the agent-provider path already matches the spec.** In the same
  file (L351) `TrustedAgentProviderIssuers` uses the permissive shape:

  ```csharp
  if (_options.TrustedAgentProviderIssuers is { } trusted && !trusted.Contains(iss))
      throw new TokenVerificationException(...);
  ```

  `null` = accept any issuer whose JWKS resolves. The spec-compliant target for
  `TrustedAuthTokenIssuers` is **exactly this shape**.

- **Option + docstring** assert the fail-closed contract:
  [`AAuthVerificationOptions.cs`](../../../src/AAuth/Server/Verification/AAuthVerificationOptions.cs#L19)
  — *"When `null` or empty, every auth token is rejected — a resource MUST declare
  which Person Servers it trusts."*

### Documentation already contradicts the code

[`docs/getting-started.md`](../../../docs/getting-started.md#L250) already describes
the **spec-compliant** behavior the code does not implement:

- L250: *"any PS can assert identity claims to any resource without bilateral
  setup — the resource namespaces claims by the PS's issuer URL … Resources that
  want to restrict which PSes they accept set `TrustedAuthTokenIssuers`."*
- L321 (code comment in the sample): *"Omit `TrustedAuthTokenIssuers` to accept
  any PS dynamically — claims are namespaced by issuer."*

Under the current code, omitting it accepts **nothing**. The fix reconciles code
with these docs; other docs (below) assert the opposite and must be reconciled the
other way.

### Deviation #4 — PS outbound federation (`TrustedAccessServers`)

The four-party PS→AS federation handler is fail-closed: a PS with no pre-listed AS
refuses to federate at all.

- **Enforcement site:**
  [`src/AAuth/Person/AAuthPersonServerEndpoints.cs`](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L829)
  `HandleFederatedAsync`:

  ```csharp
  if (trustedAccessServers.Count == 0
      || !trustedAccessServers.Contains(resourceAudience.TrimEnd('/')))
  {
      return Results.Json(
          new { error = "untrusted_access_server", detail = $"'{resourceAudience}' is not a trusted Access Server." },
          statusCode: StatusCodes.Status403Forbidden);
  }
  ```

- **Spec conflict.** §PS-AS Trust Establishment (L1581): *"Trust between the PS and
  AS may be pre-established out of band **or emerge dynamically from the AS's
  response to the PS's first token request — AAuth does not require a separate
  registration step**."* The resource token's `aud` (which the PS reads to route)
  is signed by the resource and names the resource's **own** AS — it is not an
  arbitrary attacker-chosen URL. The dynamic-trust mechanisms (interaction /
  payment / claims, L1582–1584) require the PS to actually **call** the AS first;
  the fail-closed gate forecloses that path. Net: a PS that omits the list cannot
  perform four-party federation at all, contradicting L1581.
- **Option docstring encodes the deviation:**
  [`AAuthPersonServerEndpoints.cs`](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L68)
  — *"Empty disables the four-party branch (every request must be audienced to
  this PS)."* The PS-side docs ([token-issuance.md L256](../../../docs/server/token-issuance.md#L256),
  [configuration.md L70](../../../docs/reference/configuration.md#L70)) consistently
  say *"null/empty ⇒ three-party only"* — i.e. the docs faithfully describe the
  deviation (unlike #1, where getting-started.md already describes the fix).
- **Compliant template is the AS side in the same flow.** The AS's inbound gate
  ([AS L199](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs#L199)) only
  restricts `when trustedPsHosts.Count > 0`. The PS-side fix mirrors this shape.

## Proposed model — default-open, optionally tightened

All four trust-lists adopt one trust-decision model. The two deviations (#1, #4)
flip their default from closed to open to reach it; the two already-open templates
(#2, #3) gain the same optional policy delegate for a uniform surface. The
decision for a candidate URL `id`
(an auth-token `iss` for #1, a resource-token `aud` for #4) is:

```csharp
bool trusted =
    (set is null       || set.Contains(id)) &&   // static allow-list (existing)
    (policy is null    || policy(id));            // custom predicate (new)
// both null ⇒ trusted == true ⇒ accept any verifiable counterparty (spec default)
```

This single expression yields every mode and resolves the `null`-vs-empty
question for free:

| Configuration | Effective trust |
|---|---|
| neither set nor policy | **accept any** verifiable counterparty (spec default) |
| non-empty set only | accept only listed `id` |
| **empty** set only | deny all (`Contains` always false) — a deliberate kill-switch |
| policy only | accept iff `policy(id)` |
| set **and** policy | accept iff in set **and** `policy(id)` (both narrow) |

Signature verification and all binding checks are unchanged — the trust check
only ever *narrows* the verifiable floor, never widens it. The existing
`401`/`403` rejection paths and error codes are reused; only the default flips
from closed to open. The mandated upstream-issuer check (#5, L1742) stays; if #4
federates dynamically, #5's `{self} ∪ TrustedAccessServers` set is widened the
same way (an optional predicate there is follow-through, not required).

## Proposed API surface (illustrative)

Minimal, additive, pattern-consistent: **one** optional delegate per options
object that already carries a set. No new types, no new DI calls, no new pipeline
stages — the predicate rides the same forwarders the set already uses
(blast-radius sections B / G).

### How "allow all" works (the default)

There is **no `AllowAny` flag** — allow-all is simply what the trust expression
evaluates to when nothing is configured. With both `set` and `policy` unset:

```csharp
trusted = (set is null    || …)   // set is null    ⇒ short-circuits to true (set never consulted)
       && (policy is null || …);  // policy is null ⇒ short-circuits to true (policy never consulted)
// ⇒ trusted == true for every id ⇒ accept any verifiable counterparty
```

It is "global" because the trust options live on the **global options object**
(`UseAAuth(o => …)` / the DI registration) and apply to every endpoint in the
pipeline — so *not configuring trust there is the global allow-all*. There is
nothing to switch on; the spec-compliant default is the absence of a constraint.

A consumer who wants to **state** allow-all explicitly (intent / audit) writes the
trivial predicate instead of relying on the implicit null:

```csharp
app.UseAAuth(o => o.IsTrustedAuthTokenIssuer = _ => true); // explicit allow-all
```

We deliberately do **not** add an `AllowAnyAuthTokenIssuer` bool: it would create a
tri-state (flag vs. `null` vs. empty set) and duplicate what `null` already means,
violating invariant 2. Trade-off (invariant 1): open-by-default means a resource
that *intended* to restrict but forgot is silently open — that is the spec-mandated
posture, and restriction is always an explicit opt-in (set and/or predicate). The
four-party samples model explicit pinning so the "tighten" path is the one shown.

### Relationship to `RequireIssuerVerification` (two layers, not one)

Trust here is **two layered gates**, and the whitelist/predicate is the *inner*
one — they are orthogonal and must not be conflated:

1. **`RequireIssuerVerification` (crypto gate, default `true`)** — verifies the
   auth/agent token's JWT signature against the issuer's published JWKS at
   `{iss}/.well-known/{dwk}`. This decides *whether* `iss` is authentic.
2. **`TrustedAuthTokenIssuers` / `IsTrustedAuthTokenIssuer` (policy gate)** — of the
   issuers that cryptographically verify, *which* the resource accepts.

The policy gate runs **inside** the crypto gate: `VerifyAuthTokenIssuerAsync`
(which holds the whitelist + predicate) is invoked only when
`RequireIssuerVerification == true` **and** the carrier is an `aa-auth+jwt`
([middleware L217–L243](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L217)).
Consequences:

- **There is no `WithIssuerVerification()` method.** `RequireIssuerVerification`
  is a `bool` (default `true`), set directly or via
  `AAuthVerificationOptions.SignatureOnly()`. Per-endpoint, `.RequireAAuth(...)`
  runs with it **on**; `.RequireAAuthSignature(...)` (identity-based /
  resource-managed, two-party) runs with it **off**.
- On signature-only endpoints there is no auth token, so the whitelist/predicate
  is **never consulted** — trust rests on the HTTP-signature PoP alone.
  Whitelisting an *unverified* `iss` would be meaningless (an attacker can set any
  `iss`), so the SDK couples them: you cannot whitelist without verifying.
- **Flipping the default to "accept any PS" does not weaken verification.** Crypto
  verification stays on; "any PS" means "any PS whose signature verifies against
  its JWKS" — the *verifiable* floor of invariant 1. The whitelist/predicate only
  ever *narrows* that verified set; it never substitutes for verification.

| `RequireIssuerVerification` | set / predicate | Effect |
|---|---|---|
| `true` (default) | neither | accept any **verifiable** issuer (new spec default) |
| `true` | set and/or predicate | accept the verifiable subset that also passes policy |
| `false` (signature-only) | n/a | no auth token presented; whitelist/predicate not consulted |

> The **top** and **bottom** rows are footguns — a startup warning flags each
> without changing behavior. See
> [Startup diagnostics](#startup-diagnostics-footgun-guards).

### Resource (#1) — `AAuthVerificationOptions`

```csharp
public sealed class AAuthVerificationOptions
{
    // existing — static allow-list (unchanged)
    public IReadOnlySet<string>? TrustedAuthTokenIssuers { get; init; }

    // new — custom per-issuer policy, evaluated during auth-token verification.
    // null ⇒ no policy constraint. Composed by AND with the set above.
    public Func<string, bool>? IsTrustedAuthTokenIssuer { get; init; }
}
```

Consumer usage — all modes flow through today's `UseAAuth(o => …)` lambda, so the
config/DI shape is unchanged:

```csharp
// 1. Trust any verifiable PS (spec default) — nothing to configure
app.UseAAuth();

// 2. Static allow-list (existing behavior, unchanged)
app.UseAAuth(o => o.TrustedAuthTokenIssuers = new HashSet<string> { "https://ps.example" });

// 3. Custom policy delegate (new) — e.g. allow any *.trusted.example PS
app.UseAAuth(o => o.IsTrustedAuthTokenIssuer =
    iss => new Uri(iss).Host.EndsWith(".trusted.example", StringComparison.OrdinalIgnoreCase));

// 4. Both (narrowing) — a listed PS that also clears the policy
app.UseAAuth(o =>
{
    o.TrustedAuthTokenIssuers   = new HashSet<string> { "https://ps.example" };
    o.IsTrustedAuthTokenIssuer  = iss => tenantAllows(iss);
});
```

The same property is mirrored on the thin forwarders (`AAuthServerOptions`,
`AAuthResourcePipelineOptions`, `AAuthEndpointRequirement`) — copy-only, exactly
as `TrustedAuthTokenIssuers` is forwarded today.

### PS federation (#4) — `AAuthPersonServerOptions`

```csharp
public sealed class AAuthPersonServerOptions
{
    // existing — static allow-list (unchanged)
    public IReadOnlyCollection<string>? TrustedAccessServers { get; init; }

    // new — custom per-AS policy, evaluated before the PS→AS federation call.
    public Func<string, bool>? IsTrustedAccessServer { get; init; }
}
```

### Enforcement (same site, same shape, new default)

Resource — [`AAuthVerificationMiddleware.cs`](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L424):

```csharp
var set    = _options.TrustedAuthTokenIssuers;
var policy = _options.IsTrustedAuthTokenIssuer;
var trusted = (set is null || set.Contains(iss)) && (policy is null || policy(iss));
if (!trusted)
    throw new TokenVerificationException($"Auth token issuer '{iss}' is not trusted by policy.");
```

PS — [`AAuthPersonServerEndpoints.cs`](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L829): same
`(set …) && (policy …)` shape replaces the current `Count == 0 || !Contains`
gate. **Implementation note:** the PS code currently collapses `null` and empty
`TrustedAccessServers` (both via `?? Array.Empty`); to honor the table above
(null = open, empty = deny-all) it must preserve which was supplied — carry the
original nullable collection, not just the materialized `HashSet`.

> **Naming.** `IsTrusted{AuthTokenIssuer,AccessServer}` reads as the predicate it
> is and pairs with the existing `Trusted{AuthTokenIssuers,AccessServers}` set.
> Alternative `…TrustPolicy`; recommend `IsTrusted…` for the question-form read.

### Out-of-band: config (appsettings) is unaffected

Delegates are code-only by nature; JSON-config consumers continue to use the
static set (`AAuth:TrustedPersonServers`, `MockPersonServer:TrustedAccessServers`).
No config schema changes. The predicate is purely a programmatic tightening hook
for consumers that need dynamic policy (host suffix, tenant table, feature flag).


## Startup diagnostics (footgun guards)

Spec compliance fixes the *default behavior* (open); it does not stop us from
*telling the implementor* what they got. Two rows of the
`RequireIssuerVerification` table are footguns worth a one-time startup signal.
Both are **diagnostics only** — they never change behavior, so they remain
spec-compliant (a warning is not a policy).

### TOP row — implicit open ("accept any verifiable PS")

When an auth-token-capable pipeline (`RequireIssuerVerification == true`,
`RequireAuthToken` mode) has **neither** a set **nor** a predicate, log a startup
`Warning`:

> "This resource accepts auth tokens from ANY verifiable Person Server because no
> `TrustedAuthTokenIssuers` / `IsTrustedAuthTokenIssuer` policy is configured. This
> is the AAuth spec default for PS-asserted access; set a policy to restrict."

The warning fires **only on the implicit default** — when *both* are null.
Providing *any* policy counts as a decision and silences it, including the
explicit allow-all predicate:

```csharp
app.UseAAuth(o => o.IsTrustedAuthTokenIssuer = _ => true); // intentional open — no warning
```

This turns the footgun into an informed choice: a deployment that *means* to be
open states it once (and stays quiet); a deployment that *forgot* to restrict sees
the warning. No spec tension — behavior is open either way; only the log differs.
The named sentinel `AAuthTrust.Any` (decided: shipped) reads better than `_ => true`
and is greppable for audit; either suppresses the warning (any non-null predicate
does).

### BOTTOM row — configured-but-ignored

When `RequireIssuerVerification == false` (signature-only) **and** a trust set or
predicate **is** configured on the same options object, the trust policy is dead —
a contradiction the implementor almost certainly did not intend. **Decided:
fail-fast** — throw `InvalidOperationException` at construction:

> "`TrustedAuthTokenIssuers` / `IsTrustedAuthTokenIssuer` is configured but
> `RequireIssuerVerification` is false (signature-only); the trust policy would be
> silently ignored. Move it to an auth-token (`RequireAAuth`) pipeline, or remove
> it."

Throwing (not warning) is right here: a silently-bypassed security control must
not reach production, the contradiction is unambiguous and local to a single
options object, and it matches the SDK's existing construction-time guard
("RequireIssuerVerification is enabled but MetadataClient/JwksClient are not
registered",
[middleware L224](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L224)).
This is **config validation, not a runtime policy change** — valid configs behave
exactly as before. Two scope notes:

- It triggers **only when a trust policy is also set**; a plain
  `AAuthVerificationOptions.SignatureOnly()` / `.RequireAAuthSignature(...)`
  endpoint (no policy) is unaffected.
- It lives in `UseAAuthVerification` / `AAuthVerificationOptions` validation. The
  unified `UseAAuth` path is **structurally immune** — the forwarder only passes the
  trust policy into the `RequireAuthToken` branch (issuer verification on) and uses
  `SignatureOnly()` (no policy) for `RequireAAuthSignature`
  ([AAuthEndpointExtensions L150–164](../../../src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs#L150))
  — so the contradiction can only arise via the low-level middleware with a
  hand-built options object. A defensive check there is still cheap.

### Symmetric PS-side (#4)

The TOP guard applies to the PS too: with neither `TrustedAccessServers` nor
`IsTrustedAccessServer`, the PS will federate to any AS named in a verified
resource token — warn once at startup unless a policy (incl. `_ => true`) states
intent. The BOTTOM case has no PS analog (federation always verifies the resource
token first).

### Where it lives

Startup-time `ILogger` calls at pipeline construction (`UseAAuth` /
`UseAAuthVerification` / the PS/AS `Map*` extensions) — additive, no new surface.
The options-level BOTTOM contradiction is the cheap, high-value check. The TOP
variant "a trust policy is set but every route is `RequireAAuthSignature`" needs an
endpoint-metadata scan and is lower priority.

## Blast radius — deviation #1 (resource `TrustedAuthTokenIssuers`)

### A. SDK core — behavior change (1 site + its default contract)

| File | What | Change class |
|---|---|---|
| [`src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs`](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L424) | the fail-closed `null/empty/!contains` branch | **behavioral** |
| [`src/AAuth/Server/Verification/AAuthVerificationOptions.cs`](../../../src/AAuth/Server/Verification/AAuthVerificationOptions.cs#L19) | `TrustedAuthTokenIssuers` docstring (fail-closed contract) | doc/contract |

### B. SDK option plumbing — forwarders (no behavior of their own)

These only copy the property down the pipeline; they change only if the property's
default contract is restated in XML docs. No logic change. Each also gains the new
`IsTrustedAuthTokenIssuer` (`Func<string,bool>?`) property, forwarded identically
to the existing set (one added line per file):

- [`src/AAuth/Server/Endpoints/AAuthEndpointRequirement.cs`](../../../src/AAuth/Server/Endpoints/AAuthEndpointRequirement.cs#L42) (`AAuthServerOptions.TrustedAuthTokenIssuers`)
- [`src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs`](../../../src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs#L163) (forwards into `AAuthVerificationOptions`)
- [`src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs`](../../../src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs#L30)
- [`src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs`](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs#L202)

### C. Tests — must flip (encode the current fail-closed default)

| File | Test | Action |
|---|---|---|
| [`tests/AAuth.Conformance/HttpSignatures/VerificationMiddlewareTests.cs`](../../../tests/AAuth.Conformance/HttpSignatures/VerificationMiddlewareTests.cs#L378) | `RejectsAuthTokenWhenNoTrustedIssuersConfigured` ("empty set rejects all") | **invert**: unset ⇒ accept any verifiable PS, namespaced by `iss` |
| same file, L366 | `RejectsAuthTokenFromUntrustedPsIssuer` (explicit list excludes issuer) | **keep** — explicit restriction still rejects |

Tests that set an explicit list and stay green (regression guards): `…#L74`
(VerificationMiddlewareTests positive), ChallengeMiddlewareTests (L168),
AuthorizationIntegrationTests (L124), UseAAuthIntermediaryTests (L157),
ActivityDiagnosticsTests (L353),
[`CalendarFlowTests`](../../../tests/AAuth.Tests/Integration/CalendarFlowTests.cs#L191)
(the `other-ps.test` negative case is an *explicit* restriction — stays valid).
`AAuthVerificationOptionsTests` only asserts `RequireIssuerVerification` default —
unaffected.

### D. Samples — explicit setters keep working (no required change)

All of these set the list explicitly, so behavior is unchanged. They become
**optional** demonstrations of restriction rather than mandatory configuration; a
plan may choose to add one "omit = accept any PS" demo but need not edit these:

- [`samples/Concierge/Program.cs`](../../../samples/Concierge/Program.cs#L90) (`{ psUrl }`)
- [`samples/MockResourceServers/Calendar/Program.cs`](../../../samples/MockResourceServers/Calendar/Program.cs#L70) and [`Trips/Program.cs`](../../../samples/MockResourceServers/Trips/Program.cs#L69) (`AAuth:TrustedPersonServers` → `:5100`)
- [`samples/MockResourceServers/Wallet/Program.cs`](../../../samples/MockResourceServers/Wallet/Program.cs#L70) (`trustedAccessServers` — four-party AS pinning)
- [`samples/SampleApp/Components/Pages/Jwt.razor`](../../../samples/SampleApp/Components/Pages/Jwt.razor#L72), [`Mission.razor`](../../../samples/SampleApp/Components/Pages/Mission.razor#L158), [`Deferred.razor`](../../../samples/SampleApp/Components/Pages/Deferred.razor#L76)

### E. Docs — reconcile the fail-closed wording

[`docs/getting-started.md`](../../../docs/getting-started.md#L250) is **already
correct** (omit ⇒ accept any). The following assert fail-closed and must be
updated to "omit ⇒ accept any verifiable PS (namespaced by `iss`); set the list to
restrict":

- [`docs/server/verification-middleware.md`](../../../docs/server/verification-middleware.md#L88) (the "Auth-token issuer trust is fail-closed" callout)
- [`docs/reference/configuration.md`](../../../docs/reference/configuration.md#L22) (two rows: L22, L42; and the `AAuth:TrustedPersonServers` row at L278)
- [`docs/server/authn-authz.md`](../../../docs/server/authn-authz.md#L85)
- [`docs/reference/dependency-injection.md`](../../../docs/reference/dependency-injection.md#L159)
- [`README.md`](../../../README.md#L205)
- [`docs/server/authorization-policies.md`](../../../docs/server/authorization-policies.md#L107), [`docs/server/challenge-middleware.md`](../../../docs/server/challenge-middleware.md#L143) (cross-references — verify wording)

## Blast radius — deviation #4 (PS `TrustedAccessServers`)

### G. SDK core — behavior change

| File | What | Change class |
|---|---|---|
| [`src/AAuth/Person/AAuthPersonServerEndpoints.cs`](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L829) | `HandleFederatedAsync` fail-closed `Count == 0` gate → `(set …) && (policy …)` | **behavioral** |
| same file, [L68](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L68) | `TrustedAccessServers` docstring + new `IsTrustedAccessServer` predicate property | doc/contract + additive |
| same file, [L177](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L177) | preserve `null`-vs-empty when materializing `trustedAccessServers` | **behavioral** |
| same file, [L598](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L598) | `trustedUpstreamIssuers` set (#5) — widen if #4 gains a dynamic path | follow-through |

Note: the four-party branch needs an AS to call. With a dynamic default the PS
must still **route** from the verified resource-token `aud` and discover the AS
metadata at `{aud}/.well-known/aauth-access.json` (§PS-AS Federation, L1575) — the
routing already exists; only the pre-list gate is removed.

### H. Tests — must flip

| File | What | Action |
|---|---|---|
| [`tests/AAuth.Tests/Integration/MockPersonServerFederationTests.cs`](../../../tests/AAuth.Tests/Integration/MockPersonServerFederationTests.cs#L180) | sets `MockPersonServer:TrustedAccessServers:0` | add a case: **omit** ⇒ PS federates to the AS named in `aud` |
| [`tests/AAuth.Conformance/Person/PersonServerMapperTests.cs`](../../../tests/AAuth.Conformance/Person/PersonServerMapperTests.cs#L74) | sets `TrustedAccessServers` explicitly | keep (explicit restriction still works) |

### I. Samples + docs

- Samples set the list explicitly, so behavior is unchanged:
  [`samples/MockPersonServer/Program.cs`](../../../samples/MockPersonServer/Program.cs#L159) (config `MockPersonServer:TrustedAccessServers` → `:5500`).
- Docs assert "null/empty ⇒ three-party only" and must be reconciled:
  [`docs/server/token-issuance.md`](../../../docs/server/token-issuance.md#L256),
  [`docs/reference/configuration.md`](../../../docs/reference/configuration.md#L70),
  [`docs/reference/dependency-injection.md`](../../../docs/reference/dependency-injection.md#L475),
  [`docs/workflows/federated-access.md`](../../../docs/workflows/federated-access.md#L116),
  [`samples/MockPersonServer/README.md`](../../../samples/MockPersonServer/README.md#L136).

## Uniformity additions (#2, #3)

Decided (invariant 2): give the two already-open templates the same predicate so
all four trust-lists read identically. **Additive only** — their default stays
open — with one nuance for #3.

```csharp
// AAuthVerificationOptions (resource ← agent token, #2)
public IReadOnlySet<string>? TrustedAgentProviderIssuers { get; init; }   // existing
public Func<string, bool>?   IsTrustedAgentProviderIssuer { get; init; }  // new

// AAuthAccessServerOptions (AS ← PS federation, #3)
public IReadOnlyCollection<string>? TrustedPersonServers { get; init; }   // existing
public Func<string, bool>?          IsTrustedPersonServer { get; init; }  // new
```

- **#2** [`AAuthVerificationMiddleware.cs` L351](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L351)
  already does `null`=open / empty=deny-all (`is { }`); only the predicate
  AND-clause is added. No default change.
- **#3** [`AAuthAccessServerEndpoints.cs` L199](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs#L199)
  uses a `Count > 0` guard, so it currently treats **empty = open**. Adopting the
  shared `(set is null || set.Contains(id)) && (policy is null || policy(id))`
  shape flips its empty-set case open → deny-all (and needs the same `null`-vs-
  empty preservation as #4). This is a small behavior change to an otherwise-
  compliant gate, taken for a single `null`=open / empty=deny-all rule across all
  four. Per the repo's no-backwards-compat guiding principle, take it.

Forwarders that surface these (e.g. `AAuthResourcePipelineOptions` for #2) gain the
predicate copy-only, as in section B.

## Out of scope (verified spec-compliant or separately-mandated)

- **Gates #2 and #3** stay out of the *behavioral* fix scope (already open by
  default) but gain the additive uniform predicate — see
  [Uniformity additions](#uniformity-additions-2-3). The only behavior nuance is
  #3's empty-set case (open → deny-all) for a consistent rule.
- **Upstream/call-chaining issuer check (#5, L1742)** and **revocation trusted-PS
  check (L2302)** — spec-MANDATED trusted-issuer rules; keep. (#5's *set* is
  widened only as a follow-through to #4 — section G.)
- `RequireIssuerVerification` semantics and `SignatureOnly()` — unchanged.

## Gaps & open questions

1. **`null`-vs-empty — RESOLVED by the model.** The AND expression makes `null`
   set = open and empty set = deny-all fall out naturally (see
   [Proposed model](#proposed-model--default-open-optionally-tightened)). Carry
   this convention to #4 by preserving the null/empty distinction the PS code
   currently collapses. Remaining decision: confirm `TrustedAgentProviderIssuers`
   (#2) keeps its current `is { }` semantics (null = open, empty = deny-all is
   already true there) so all four mechanisms read identically.
2. **Set + predicate composition.** Confirmed **AND** (each narrows). Worth a
   one-line doc note so consumers don't expect OR ("in set OR policy allows").
   A predicate alone is the general form; the set is sugar for
   `iss => set.Contains(iss)`.
3. **Predicate signature.** `Func<string,bool>` over `iss` per the requirement.
   Decide whether a second, richer overload is ever needed (e.g. `dwk` to gate PS
   vs AS differently, or the parsed claims for tenant-aware policy). Default:
   ship `Func<string,bool>` only; add context later if a real case appears.
4. **Symmetry to #2/#3 — DECIDED: make uniform.** Add the same `IsTrusted*`
   predicate to `TrustedAgentProviderIssuers` (#2) and AS `TrustedPersonServers`
   (#3) in the same pass (see [Uniformity additions](#uniformity-additions-2-3)).
   Additive only, except #3's empty-set case flips open → deny-all for a uniform
   `null`=open / empty=deny-all rule across all four.
5. **Four-party resources using `TrustedAuthTokenIssuers` to pin their AS**
   (e.g. Wallet). Under the new default, a four-party resource that *omits* the
   list would accept any verifiable AS/PS issuer. Confirm whether four-party
   samples should keep pinning explicitly (recommended: yes — keep Wallet's
   explicit set as the documented four-party pattern).
6. **Policy-layer namespacing — RESOLVED (already implemented).** The spec's
   safety rests on the resource namespacing claims by `(iss, sub)` (L2718). The
   SDK already does this:
   [`AAuthAuthenticationHandler`](../../../src/AAuth/Server/Verification/AAuthAuthenticationHandler.cs)
   emits `aauth:issuer` and a pre-computed `aauth:sub_iss` composite
   (`{iss}|{sub}`), and namespaces `sub`/roles/groups by `Claim.Issuer = iss`,
   with a comment citing "the same `sub` from a different PS is a different
   subject." So "accept any PS" is safe by construction — no new namespacing work.
7. **Conformance coverage.** Add explicit positive conformance tests — for #1,
   "unset list accepts an auth token from an arbitrary verifiable PS and surfaces
   `iss` for namespacing"; for #4, "unset list lets the PS federate to the AS named
   in a verified resource token's `aud`" — to lock the spec-compliant defaults in.
8. **PS→AS dynamic federation safety (#4).** Forwarding to the AS named in `aud`
   means the PS makes an outbound call to a resource-designated URL. The resource
   token is signed/verified and names the resource's own AS, so it is not
   attacker-arbitrary — but confirm the PS validates `aud` is HTTPS, applies
   timeouts, and (recommended) still surfaces an operator-configurable allow-list
   for deployments that want pre-establishment. Decide whether `null` = dynamic
   and empty = "three-party only" (preserves the current lockdown affordance),
   mirroring the #1 `null`-vs-empty question.
9. **#5 set construction follow-through.** If #4 federates dynamically, a
   four-party upstream token (issued by a not-pre-listed AS) must still pass the
   mandated §Upstream Token Verification check (L1742). Decide how the PS
   determines an AS is "authorized to extend" without a static list (e.g. trust an
   AS it successfully federated with during this mission).
10. **Startup footgun diagnostics — DECIDED.** Per
    [Startup diagnostics](#startup-diagnostics-footgun-guards): TOP implicit-open
    → `Warning`, suppressed by any explicit policy (incl. `_ => true`). BOTTOM
    configured-but-ignored (`RequireIssuerVerification == false` with a trust set /
    predicate) → **fail-fast** (`InvalidOperationException` at construction; valid
    configs unaffected). Sentinel → **ship `AAuthTrust.Any`** (one `static readonly
    Func<string,bool>`) as the readable, greppable "intentional open" marker
    (Option B). TOP warning is diagnostics-only (no spec impact); the BOTTOM throw
    is config validation (no impact on valid configs).

## Source references (verified line numbers)

| Claim | Anchor | Line |
|---|---|---|
| PS chosen by person | §Terminology — Person Server | L191 |
| Resource follows `ps` claim; "any PS, no bilateral setup; namespace by (iss,sub)" | §PS-Asserted Access (Three-Party) | L310 / L312 |
| `ps` configured per agent | §Consuming a Resource / §Agent Token Structure | L506 / L573 |
| Resource token `aud` = PS | §Resource Token Structure | L807 |
| Auth Token Verification (no allow-list step) | §Auth Token Verification | L1707 |
| JWT Trust steps (discover JWKS via `{iss}/.well-known/{dwk}`; `iss` valid HTTPS) | (subsection) | L1711 |
| Request-Context Binding (`aud`/PoP/`agent`/`act`/`sub`\|`scope`) | (subsection) | L1718 |
| Trust Posture — apply own policy, namespace by (iss,sub) | §Trust Posture in PS-Asserted Access | L2716 |
| Resource Adoption Path — "Accept identity claims from any PS" | §Resource Adoption Path | L2655 / L2661 |
| Four-party PS↔AS trust required | §Consuming a Resource / §PS-AS Federation | L516 / L1573 |
| PS routes from resource-token `aud`; discovers AS metadata | §PS-AS Federation | L1575 |
| Trust pre-established **or dynamic**; "no separate registration step" | §PS-AS Trust Establishment | L1581 |
| Dynamic mechanisms (interaction / payment / claims); "any PS … without prior relationship" | §PS-AS Trust Establishment | L1582 / L1584 |
| Upstream trusted-issuer (call chaining) — MANDATED | §Upstream Token Verification | L1742 |
| Revocation from trusted PS — MANDATED | §Token Revocation | L2302 |
| Call-chaining routing ignores `ps` claim | §Call Chaining | L1755 |
