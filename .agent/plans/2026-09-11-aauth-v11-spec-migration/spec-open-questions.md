---
description: Open questions and specification gaps for Dick Hardt from the draft-11 WIP review.
---

# AAuth draft-11 WIP: questions for Dick Hardt

> **Update (2026-09):** Dick answered all 18 questions in
> [AAuth PR #162](https://github.com/dickhardt/AAuth/pull/162), merged 2026-09-14,
> and draft-11 was published on 2026-09-25. The snapshot links below point at the
> WIP files replaced in [`aauth-spec/v11/`](../../../aauth-spec/v11/); read those
> lines at git commit `e6d18a3`.

Date: 2026-09-11. Status: open; no answers or interpretations are assumed.

Dick, we are preparing the .NET SDK migration from draft-10 to the draft-11
working text. These are the places where we need clarification, or where two
parts of the specification appear to disagree. They are questions about the
protocol, not requests for decisions about our .NET API design.

We reviewed AAuth commit
[`55ae44cc`](https://github.com/dickhardt/AAuth/tree/55ae44cc3a07da29c4d6821c3800569ac77b9441),
dated 2026-09-08. At capture time, draft-10 was still the latest published IETF
revision. Section links open the editor's drafts and may change; the snapshot
links preserve the exact lines behind each question.

Terms: PS means person server, AS means access server, and AP means agent provider.
An intermediary is a resource that calls another resource on the caller's behalf.

## Core behavior

### 1. Where are the new Signature Keys errors defined?

The protocol uses `clock_skew` and `revoked_jwt`. We could not find either in
published Signature Keys draft-08 or its working source at commit
[`10a7563b`](https://github.com/dickhardt/signature-key/tree/10a7563beecb2a461d5b412549a69d49f97f500c).

Which Signature Keys revision should we use? Until it is available, should we
treat these as provisional AAuth error codes?

See [Expiry and the Refresh Margin](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#refresh-margin)
([snapshot L1388](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1388))
and [Token Revocation](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#token-revocation)
([snapshot L2461](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2461)).

### 2. Which key and audience should an upstream token bind?

The auth token presented by the original caller normally contains that caller's
key in `cnf`. The call-chaining text instead says the upstream token contains
the intermediary's key. It also imports the usual auth-token verification rules,
which compare the confirmation key with the HTTP request signer.

Whose key should `upstream_token.cnf` contain, and what should the PS/AS compare
it with? Is the intermediary passing the caller's original token, or obtaining
a different token first?

The audience rule also compares upstream `aud` with the intermediary's agent
token `iss`, which identifies its AP. Must an intermediary be its own AP, or is
another way of proving the resource-to-agent relationship intended?

See [Call Chaining](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#call-chaining)
([snapshot L1955](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1955))
and [Upstream Token Verification](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#upstream-token-verification)
([snapshot L1936](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1936),
[L1938](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1938)).

### 3. How does an intermediary prove whose person and mission it uses?

The person-token endpoint says the PS must have issued the upstream `sub`.
In four-party access, the upstream token itself was issued by an AS. Does this
mean the subject was originally assigned by the PS and copied into the AS token?
What record or proof should the PS use to resolve that person?

The endpoint also checks that a mission belongs to the requesting agent, but
the intermediary is acting under the caller's mission. How should that ownership
check work after the `act` chain has been removed?

See [Person Token Endpoint](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#person-token-endpoint)
([snapshot L944](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L944),
[L948](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L948))
and [Call Chaining](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#call-chaining)
([snapshot L1953](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1953)).

### 4. How should protected Events tickets identify the agent?

Events requires a subscription ticket to be bound to the agent that requested
it. Draft-11 auth tokens no longer tell the resource the agent's identity.

Should the resource bind the ticket to the verified signing key, then learn the
agent's identity from the AP-issued subscribe token when the ticket is used?
What checks are needed to make that binding sufficient? A person's `sub` cannot
be used as the agent's identifier.

See [Pre-Authorized Subscription URL Security](https://dickhardt.github.io/AAuth/draft-hardt-aauth-events.html#pre-authorized-subscription-url-security)
([snapshot L607](../../../aauth-spec/v11/draft-hardt-aauth-events.md#L607))
and [Auth Token Structure](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#auth-token-structure)
([snapshot L1884](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1884)).

### 5. Does a clarification update need a new presented token?

An `updated_request` can contain a new resource token. Its required unchanged
fields do not include `presented_jti`, so the new resource token could name a
different person or auth token. Verification still requires the presented
token's `jti` to match exactly.

Should `updated_request` also carry `presented_token` when that value changes?
Please clarify the request bodies for both agent-to-PS and PS-to-AS updates,
and which person and mission fields must stay unchanged. We expect the new
pair to be checked together before replacing the pending request.

See [Updated Request](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#updated-request)
([snapshot L1194](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1194))
and [Resource Token Verification](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#resource-token-verification)
([snapshot L903](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L903)).

### 6. When is a person token required instead of an auth token?

One section says a resource must verify a person token before issuing a
resource token. Another explicitly allows a verified person token or auth token.

Is the intended rule: person token at the authorization endpoint and for the
first grant, but either token for runtime step-up or per-call challenges?
We assume a resource does not need to retain an earlier person token to handle
a later auth-token challenge.

See [Resource Access and Resource Tokens](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#resource-tokens)
([snapshot L674](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L674)),
[Authorization Endpoint Request](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#authorization-endpoint-request)
([snapshot L688](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L688)),
and [Resource Token](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#resource-token)
([snapshot L858](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L858)).

### 7. Should a repeated completion return the result or 410?

Deferred auth-token completion and R3 per-call grants must return the saved
result when the same grant is presented again. The general pending-URL security
rule says to return `410 Gone` after a terminal response.

Do the saved-result rules override the general 410 rule for these flows?
Also, if two grants approve identical proposal bytes, should each grant have
its own execution record rather than sharing one record by proposal hash?

See [Deferred Delivery](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#deferred-auth-token)
([snapshot L810](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L810)),
[R3 Per-Call Flow](https://dickhardt.github.io/AAuth/draft-hardt-aauth-r3.html#per-call-flow)
([snapshot L702](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L702)),
and [Pending URL Security](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#pending-url-security)
([snapshot L2909](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2909)).

### 8. How should a client recover from a revoked auth token?

A resource rejecting a revoked auth token is advised to return a fresh
resource-token challenge. That challenge names the revoked auth token as the
presented token. The token endpoint can then reject it as
`revoked_presented_token`, whose recovery instructions say to obtain a fresh
person token and a fresh resource token.

Should the client go straight to fresh person-token acquisition? If so, should
the recommended challenge signal that path rather than invite an exchange
using the revoked token?

See [Token Revocation](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#token-revocation)
([snapshot L2461](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2461))
and [Token Endpoint Error Codes](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#token-endpoint-error-codes)
([snapshot L2353](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2353)).

## Time and identity

### 9. Does the five-minute refresh margin exclude resource tokens?

The guidance says not to present a token with fewer than five minutes left.
Resource tokens themselves should last no more than five minutes, so almost
every freshly issued resource token would fall inside that margin.

Should the margin apply to agent, person and reusable auth tokens, but not
resource tokens being submitted for exchange?

See [Expiry and the Refresh Margin](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#refresh-margin)
([snapshot L1390](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1390))
and [Resource Token Structure](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#resource-token-structure)
([snapshot L892](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L892)).

### 10. Which lifetime checks are mandatory?

The refresh section says `exp - iat` MUST NOT exceed the limit for the token
type. Agent and resource token lifetimes instead use SHOULD NOT for their
24-hour and five-minute limits.

Must verifiers reject tokens above those limits, or may an issuer exceed a
recommended limit for a justified reason? Also, please confirm that rejecting
an `iat` too far in the future remains optional, even though `clock_skew` is
listed in the verification procedure.

See [Expiry and the Refresh Margin](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#refresh-margin)
([snapshot L1386](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1386),
[L1388](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1388)),
[Agent Token Structure](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#agent-token-structure)
([snapshot L545](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L545)),
[Resource Token Structure](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#resource-token-structure)
([snapshot L892](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L892)),
and [Verification](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#verification)
([snapshot L2574](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2574)).

### 11. Can a claims response change the subject?

The federation section says the presented token already supplies person
identity and that claims requests are for additional claims. The claims
section still says the response includes a directed `sub`.

Can the AS request `sub` again? If it is repeated, must it exactly match the
verified presented-token subject? We expect a conflicting value to be rejected,
not to replace the person already identified by the resource.

See [PS-to-AS Token Request](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#ps-to-as-token-request)
([snapshot L1686](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1686))
and [Claims Required](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#requirement-claims)
([snapshot L1777](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1777)).

## Optional companion behavior

These questions matter if we implement result-release approval or Budgets.
They do not require those optional features to be added to the core migration.

### 12. Can result-release approval cover metered execution?

R3 says not to execute before approval when execution is itself billed,
metered or audited. Its later discussion considers the cost of a metered call
that ran but whose result was not released.

Is that discussion future work outside the currently allowed release flow?
It also says Budgets leaves failed-call accounting open, while the pinned
Budgets text assigns that choice to the resource's metering policy. Should
those descriptions be aligned?

See [Approving Release Rather Than Execution](https://dickhardt.github.io/AAuth/draft-hardt-aauth-r3.html#release-gating)
([snapshot L722](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L722),
[L745](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L745))
and [Budgets: Failed Calls](https://dickhardt.github.io/AAuth/draft-hardt-aauth-budgets.html#failed-calls)
([snapshot L867](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L867)).

### 13. What does cost mean on a refused request?

Budgets says a refused request must not draw down the budget. The exhaustion
example nevertheless includes a positive `cost` value.

Is that value an estimate of the refused operation, or actual consumption?
What should the resource return so the client does not count a refusal as
spent budget?

See [Budget Exhaustion](https://dickhardt.github.io/AAuth/draft-hardt-aauth-budgets.html#exhaustion)
([snapshot L710](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L710),
[L722](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L722)).

### 14. What is the audience of a signed usage response?

One section uses the requesting PS/AS server identifier for `aud`. Another
says to use the caller's `jwks_uri`. Those URLs can be different.

Which value should the issuer put in the response, and which should the
recipient check?

See [Usage Response](https://dickhardt.github.io/AAuth/draft-hardt-aauth-budgets.html#usage-response)
([snapshot L942](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L942))
and [Usage Authorization](https://dickhardt.github.io/AAuth/draft-hardt-aauth-budgets.html#usage-authorization)
([snapshot L1007](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L1007)).

## Snapshot gaps and wording

These include the gaps found when we downloaded the WIP snapshot. The missing
Signature Keys error definitions are covered by question 1 rather than repeated.

### 15. Can the interop profile include the presented-token steps?

The profile's auth-token flow still says the PS looks up the person token.
Its parent/sub-agent exchange lists `resource_token` and `subagent_token`, but
not the now-required `presented_token`.

Can those flows be updated to show the agent supplying the actual presented
token, including the parent forwarding the worker's token? We are following
the core protocol rather than treating a PS lookup as a replacement.

See [Interop Profile: Surface 4](https://github.com/dickhardt/AAuth/blob/55ae44cc3a07da29c4d6821c3800569ac77b9441/interop-demo-profile.md#surface-4--auth-token-issuance-and-presentation)
([snapshot L52](../../../aauth-spec/v11/interop-demo-profile.md#L52)),
[Surface 5](https://github.com/dickhardt/AAuth/blob/55ae44cc3a07da29c4d6821c3800569ac77b9441/interop-demo-profile.md#surface-5--parent-mediated-sub-agent-token-handling)
([snapshot L75](../../../aauth-spec/v11/interop-demo-profile.md#L75)),
and [Auth Token Request](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#auth-token-request)
([snapshot L1004](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1004)).

### 16. Can superseded history entries be marked clearly?

The draft-11 history describes earlier decisions that later entries reverse.
Examples include avoiding distinct revocation errors before adding them, and
adding `mission_expired` before folding it into `mission_terminated`.

Can those entries be marked as superseded, or can a short final-state summary
be added? We are using the current governing sections, but someone reading the
history to migrate could otherwise implement an intermediate design.

See [Document History](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#document-history)
([snapshot L3269](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L3269)),
[Token Revocation](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#token-revocation)
([snapshot L2461](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2461)),
and [Mission Status Errors](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#mission-status-errors)
([snapshot L1645](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1645)).

### 17. Where is the Supervision Protocol companion?

The core text names an AAuth Supervision Protocol, but there was no matching
source document in the AAuth commit we downloaded. Mission control operations
are also left to a companion specification.

Is there a draft or repository we should reference? Are supervision and mission
control covered by the same companion or separate ones? Until those documents
are available, should implementations leave these integrations outside the
base protocol rather than define their own wire contract?

See [Roles](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#roles)
([snapshot L456](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L456))
and [Person Server Metadata](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#ps-metadata)
([snapshot L2743](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2743)).

### 18. Can person-token exposure wording distinguish identity from access?

The person-token section explains that a resource may grant access based on
identity alone. The exposure section says disclosure of a person token gives
an unintended party an identifier and no access.

Could the exposure wording distinguish two cases: a third party stealing the
token cannot use it without the signing key, but the legitimate key holder can
use it at a resource that grants identity-based access? That would keep the
security explanation consistent without suggesting the PS granted scopes.

See [Person Token](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#person-tokens)
([snapshot L576](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L576))
and [Person Token Exposure](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html#person-token-exposure)
([snapshot L2947](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2947)).