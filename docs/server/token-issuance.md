# Token Issuance

> [Token Types](https://explorer.aauth.dev/foundations/tokens) | [Token Lifecycle](https://explorer.aauth.dev/tokens/lifecycle)

## Overview

The SDK provides builders for all four AAuth JWT token types (agent, person,
resource, and auth tokens). Each produces a
compact JWT (`header.payload.signature`) signed by the configured `IAAuthSigner`.
`BuildAsync(cancellationToken)` awaits the signer, so a remote signer (HSM, KMS)
can sign without blocking a thread.
Built-in keys support Ed25519 (`AAuthKey`) and ES256 (`EcdsaAAuthKey`); the key's
algorithm determines `alg`. Ed25519 examples are not a universal algorithm
requirement. Choose a supported algorithm that the recipient accepts.

Most hosts never call these builders directly: `UseAAuth` / `UseAAuthChallenge`
mint resource tokens, and `MapAAuthPersonServer` / `MapAAuthAccessServer` mint
person and auth tokens. The builders are the primitives those helpers use.

## Resource Tokens (`aa-resource+jwt`)

Issued by a resource to challenge an agent that presented a **person token** (or
an auth token, on a step-up). A resource token names the token it was issued
against: `ps`, `sub`, `presented_jti`, and the agent's key thumbprint, plus
`mission_s256` and `tenant` copied from the presented token. It carries no agent
identifier. `aud` is the resource's AS (four-party) or the person's PS
(three-party).

The simplest way to mint one is from the verified assertion the verification
middleware stored, so every copied claim comes from the verified token:

```csharp
using AAuth.Server.Challenge;

// The person or auth token the agent presented, verified by UseAAuthVerification.
var presented = context.GetAAuthVerifiedAssertion()!;
var resourceToken = await AAuthChallengeMiddleware.BuildResourceTokenAsync(
    challengeOptions, presented, scope: "read write");

// Return as 401 challenge (sets the AAuth-Requirement header:
// requirement=auth-token; resource-token="...")
return context.ChallengeAAuth(resourceToken);
```

The underlying builder takes the same values explicitly:

```csharp
using AAuth.Tokens;

var resourceToken = await new ResourceTokenBuilder
{
    Issuer = "https://resource.example",
    Audience = "https://as.example",          // resource's AS, or the person's PS (three-party)
    PersonServer = "https://ps.example",      // person token iss, or auth token ps
    Subject = verifiedToken.Subject!,         // sub of the presented token
    PresentedJti = verifiedToken.Jti,         // jti of the presented token
    AgentJkt = agentConfirmationKey.ComputeJwkThumbprint(), // verified HTTP signing key
    MissionS256 = verifiedToken.MissionS256,  // copied unchanged when present
    Tenant = verifiedToken.Tenant,            // copied when present
    Key = resourceSigningKey,
    KeyId = "resource-key-1",
    Scope = "read write",                     // requested scope
    Lifetime = TimeSpan.FromMinutes(5),       // default: 5 min
}.BuildAsync();
```

### ResourceTokenBuilder Properties

| Property | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `Issuer` | Yes | — | Resource URL (becomes `iss`) |
| `Audience` | Yes | — | Resource's AS, or the PS that issued the presented token (becomes `aud`) |
| `PersonServer` | Yes | — | The person's PS (becomes `ps`) |
| `Subject` | Yes | — | `sub` of the presented token |
| `PresentedJti` | Yes | — | `jti` of the presented person or auth token (becomes `presented_jti`) |
| `AgentJkt` | Yes | — | Agent's key thumbprint (becomes `agent_jkt`) |
| `Key` | Yes | — | Signing key |
| `KeyId` | Yes | — | Key ID (goes in JWT header `kid`) |
| `MissionS256` | No | — | `mission_s256` copied unchanged from the presented token |
| `Tenant` | No | — | `tenant` copied from the presented token |
| `Scope` | No | — | Space-separated scopes |
| `Account` | No | — | Echoed `account` from the authorization request |
| `LoginHint` | No | — | `login_hint` for the PS |
| `Interaction` | No | — | Resource-initiated interaction (`url` + `code`) |
| `Lifetime` | No | 5 min | Token validity duration |
| `IssuedAt` | No | Now | Override issuance time |
| `TokenId` | No | Auto | Custom `jti` (auto-generated UUID if omitted) |

## Person Tokens (`aa-person+jwt`)

Issued by a Person Server's `person_token_endpoint` to identify the person to one
resource. The agent presents it in `Signature-Key` in place of its agent token.
A person token is identity, not authorization: it carries no `scope` or
`account`, and a recipient rejects it wherever an auth token is required.
`MapAAuthPersonServer` mints these at `POST /person`.

```csharp
var personToken = await new PersonTokenBuilder
{
    Issuer = "https://ps.example",
    Audience = "https://resource.example",   // the resource this token identifies the person to
    Subject = directedSubject,               // directed sub for this resource
    ConfirmationKey = agentPublicKey,        // binds the token to the agent's key
    AgentTokenExpiresAt = verifiedAgent.ExpiresAt, // never outlives the agent token
    Key = psSigningKey,
    KeyId = "ps-key-1",
    MissionS256 = mission.S256,              // optional: the mission the agent named
}.BuildAsync();
```

## Auth Tokens (`aa-auth+jwt`)

Issued by a Person Server or Access Server to grant access. Bound to the agent's
confirmation key. The person is identified by `(ps, sub)`; an auth token carries
no agent identifier and no delegation chain.

```csharp
var verifiedAgent = await tokenVerifier.VerifyWithJwksAsync(
    agentToken, metadata, jwks,
    AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk,
    expectedAudience: null);
var authToken = await new AuthTokenBuilder
{
    AgentTokenExpiresAt = verifiedAgent.ExpiresAt,
    Issuer = "https://ps.example",
    Audience = "https://resource.example",    // resource that will accept this
    PersonServer = "https://ps.example",      // ps: the issuer (three-party) or the federating PS
    Subject = directedSubject,                // sub copied from the resource token
    AgentConfirmationKey = agentPublicKey,    // binds token to agent's key
    Key = psSigningKey,
    KeyId = "ps-key-1",
    Dwk = AuthTokenBuilder.PersonDwk,        // "aauth-person.json" (or AccessDwk for AS)
    Scope = "read",
    Lifetime = TimeSpan.FromHours(1),
}.BuildAsync();
```

### AuthTokenBuilder Properties

| Property | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `Issuer` | Yes | — | PS or AS URL (becomes `iss`) |
| `Audience` | Yes | — | Resource URL (becomes `aud`) |
| `PersonServer` | Yes | — | The person's PS (becomes `ps`) |
| `Subject` | Yes | — | Directed person identifier copied from the resource token |
| `AgentConfirmationKey` | Yes | — | Agent's public key (bound via `cnf.jwk`) |
| `AgentTokenExpiresAt` | Yes | None | Expiry from the verified agent token; no unbounded default |
| `AuthorizationExpiresAt` | No | None | Additional verified ceiling (presented, parent, upstream, or mission expiry) |
| `Key` | Yes | — | PS/AS signing key |
| `KeyId` | Yes | — | Key ID (JWT header `kid`) |
| `Dwk` | No | `"aauth-person.json"` | Discovery well-known path (`PersonDwk` or `AccessDwk`) |
| `Scope` | No | — | Granted scope |
| `MissionS256` | No | — | `mission_s256` copied from the resource token |
| `Tenant` | No | — | `tenant` copied from the resource token |
| `Lifetime` | No | 1 hour | Positive requested lifetime, at most one hour; capped by verified expiry |
| `TimeProvider` | No | System | Clock used to reject expired contexts and determine issuance time |
| `IssuedAt` | No | Now | Override issuance time |
| `TokenId` | No | Auto | Custom `jti` |

The builder rejects expired source contexts, nonpositive lifetimes, and lifetimes
over one hour. `IssuedAt` does not bypass the current-clock expiry check. For
sub-agent issuance, use the verified child's expiry and confirmation key; pass
the earlier verified parent/upstream expiry as `AuthorizationExpiresAt`.

PS, AS, and R3 pending state retains the original verified ceilings. A fresh poll
carrier does not extend them. Consent that finishes after expiry cannot mint a
new token. Success responses calculate `expires_in` from the issued token's
remaining Unix seconds, including after deferred delivery.
When a pending or federated decision is tied to a mission, the PS evaluates the
mission before generic deferred expiry. A mission whose `expires_at` has passed
auto-terminates with `termination_reason:"expired"` and the poll returns
`403 mission_terminated`.

`AdditionalClaims` accepts identity extensions such as `email`, but rejects
`iss`, `dwk`, `aud`, `jti`, `ps`, `cnf`, `iat`, `exp`, `nbf`, `sub`, `scope`,
`mission_s256`, `account`, `tenant`, `roles`, and `groups`, even when their typed
properties are unset. It also rejects the draft-10 `agent`, `act`, and `mission`
claims, which an auth token no longer carries. Set supported identity fields
through the named builder properties. AS claims requests and pushes cannot supply
protocol-owned fields; `sub`, `tenant`, `roles`, and `groups` use the typed
identity projection path.

### Person Server vs Access Server

```csharp
// Person Server issues:
var personDwk = AuthTokenBuilder.PersonDwk;  // "aauth-person.json"

// Access Server issues:
var accessDwk = AuthTokenBuilder.AccessDwk;  // "aauth-access.json"
```

The `Dwk` determines which `.well-known` document an agent fetches to find the issuer's public key for verification.

## Agent Tokens (`aa-agent+jwt`)

Issued by an Agent Provider to bind an agent's key to its identity.

```csharp
var agentToken = await new AgentTokenBuilder
{
    Issuer = "https://ap.example",
    Subject = "aauth:myapp@ap.example",
    Key = apSigningKey,
    KeyId = "ap-key-1",
    ConfirmationKey = agentPublicKey,          // binds token to this key
    PersonServer = "https://ps.example",       // optional
    Lifetime = TimeSpan.FromHours(24),
}.BuildAsync();
```

## Token Verification

Use `TokenVerifier` to validate tokens received from other parties:

```csharp
var verifier = new TokenVerifier
{
    ClockSkew = TimeSpan.FromSeconds(30)
};

// Verify a resource token
var result = verifier.Verify(
    jwt: resourceTokenString,
    issuerKey: resourcePublicKey,
    expectedType: ResourceTokenBuilder.TokenType,
    expectedDwk: ResourceTokenBuilder.ResourceDwk,
    expectedAudience: "https://ps.example");

// Verify an auth token (also checks cnf.jwk against the HTTP signing key)
var auth = verifier.VerifyAuthToken(
    jwt: authTokenString,
    issuerKey: psPublicKey,
    expectedAudience: "https://resource.example",
    httpSignatureKey: agentKey);

// Verify a person token presented in Signature-Key (identity, not authorization)
var person = verifier.VerifyPersonToken(
    jwt: heldToken,
    issuerKey: psPublicKey,
    expectedAudience: "https://resource.example",
    httpSignatureKey: agentKey);
```

### Verifying a resource token and its presented token (PS/AS side)

An agent's auth token request carries a `resource_token` **and** the
`presented_token` it names — the person or auth token the agent presented to the
resource. The recipient MUST verify both before minting an auth token (spec
§Resource Token Verification). `VerifyResourceTokenAsync` performs JWKS discovery
and the resource-token checks; `VerifyPresentedTokenAsync` then verifies the
presented token and the pair:

```csharp
var body = await context.Request.ReadFromJsonAsync<JsonObject>();
var presentedToken = (string)body!["presented_token"]!;

var verified = await verifier.VerifyResourceTokenAsync(
    jwt: resourceTokenString,
    expectedAudience: psIssuer,                 // this PS/AS own identifier (aud)
    expectedAgentJkt: confirmationKey.ComputeJwkThumbprint(), // from the verified HTTP signature
    metadata: metadataClient,                   // resolves {iss}/.well-known/aauth-resource.json
    jwks: jwksClient,                           // resolves the resource's signing key
    expectedPersonServer: psIssuer);            // a PS verifies that ps names itself

var presented = await verifier.VerifyPresentedTokenAsync(
    presentedToken, verified, metadataClient, jwksClient);
```

At a PS, `expectedPersonServer` is the local PS identifier. At an AS, it is the
authenticated PS caller's identifier, never a value taken from the request body
or the resource token. The AS also validates retained upstream context before
document fetch, policy evaluation, consent, or issuance:

```csharp
var body = await context.Request.ReadFromJsonAsync<JsonObject>();
var presentedToken = (string)body!["presented_token"]!;

var verified = await verifier.VerifyResourceTokenAsync(
    resourceTokenString, asIssuer,
    issuance.ConfirmationKey.ComputeJwkThumbprint(), metadataClient, jwksClient,
    expectedPersonServer: authenticatedPsIdentifier);
await verifier.VerifyPresentedTokenAsync(presentedToken, verified, metadataClient, jwksClient);
issuance.ValidateResourceContext(verified.Payload);
```

The checks (failure throws `TokenVerificationException`):

| # | Check | Detail |
|---|-------|--------|
| 1 | `typ` | Must be `aa-resource+jwt` |
| 2 | `dwk` + signature | `dwk=aauth-resource.json`; key resolved from `{iss}/.well-known/aauth-resource.json` → `jwks_uri` |
| 3 | `exp` / `iat` | `exp` is in the future with zero tolerance; optional future `iat` honours `ClockSkew` |
| 4 | `aud` | Equals `expectedAudience` |
| 5 | `agent_jkt` | Equals the presenting agent's key thumbprint (PoP binding); the sub-agent's for a parent-mediated sub-agent request |
| 6 | `ps` | Equals `expectedPersonServer`: the local PS, or the authenticated PS caller at an AS |
| 7 | `presented_token` | `VerifyPresentedTokenAsync`: a person or auth token whose `aud` is the resource token's `iss` and whose `cnf.jwk` matches `agent_jkt`; its `jti` equals `presented_jti`, its PS (`iss` or `ps`) equals `ps`, and `sub`, `mission_s256`, and `tenant` match exactly |

Map failures to the spec error response — `expired_resource_token` /
`invalid_resource_token` for the resource token and a pair mismatch,
`expired_presented_token` / `invalid_presented_token` for the presented token
itself (`TokenVerificationException.Credential` says which), and
`revoked_<parameter>_token` (400) when a parameter token was revoked — and
derive the consent screen and the issued auth token only from the verified
payload. When the resource token carries `mission_s256`, a PS also verifies the
mission is active and unexpired. The SDK host helpers
`MapAAuthPersonServer` / `MapAAuthAccessServer` run exactly these checks
internally; the [`samples/MockPersonServer`](../../samples/MockPersonServer/)
adopts the PS helper rather than hand-rolling them.

## Mission Claims

When a request is governed by a mission, the mission travels through the tokens as
the `mission_s256` string claim — the mission's `s256`, never the mission content
itself (§Person Token Structure, §Resource Token Structure, §Auth Token
Structure). The approving PS is named beside it: the `iss` of a person token, the
`ps` of a resource or auth token. `MissionReference` names and validates it, and
each builder exposes a `MissionS256` property:

```csharp
namespace AAuth.Tokens;

public static class MissionReference
{
    public const string ClaimName = "mission_s256";
    public static bool IsValid(string? value);
    public static string? Read(JsonObject? document);
}
```

The PS stamps `mission_s256` into the person token when the agent names the
mission on its person token request. The resource copies it from the presented
token into the resource token it issues — every resource does this; there is no
opt-in (see
[Challenge Middleware](challenge-middleware.md#missions-in-resource-tokens)). The
PS carries it into the auth token it mints, and `VerifyPresentedTokenAsync`
rejects a resource token whose `mission_s256` differs from its presented token's,
which makes mission stripping detectable. Immediate and deferred issuance retain
the verified mission unchanged, including R3 AS responses validated by the PS.

For the full PS-side evaluation of mission context, see
[Mission Governance (Server)](mission-governance.md).

## One-Call Person Server (`MapAAuthPersonServer`)

The builders above are the primitives. The whole Person Server token pipeline
also ships as a single host helper, `MapAAuthPersonServer` — the PS
counterpart to [`MapAAuthAccessServer`](../workflows/federated-access.md#access-server-side-code).
One call publishes the `/.well-known/aauth-person.json` metadata (including
`person_token_endpoint` and `auth_token_endpoint`) + JWKS, verifies the RFC 9421
request signature, and maps both token endpoints:

- **`POST /person`** (`person_token_endpoint`) — issues a person token
  (`aa-person+jwt`) for the named `resource`, optionally under a `mission_s256`
  the agent owns, or under the mission of an `upstream_token` when chaining.
- **`POST /token`** (`auth_token_endpoint`) — verifies the `resource_token` and
  its `presented_token`, then routes on the resource token's `aud` (§PS-AS
  Federation):
  - **`aud` = this PS** → three-party (PS-asserted): mint the auth token directly
    (`dwk=aauth-person.json`, `iss`=PS).
  - **`aud` = a trusted Access Server** → four-party (federated): forward a signed
    PS→AS request (resource token plus a presented token) via
    `AccessServerClient` and return the AS-issued auth token after the §Auth
    Token Delivery check.

The host owns all AAuth crypto; the identity and consent decision is delegated to
a pluggable `IIdentityClaimsAsserter`. Register the Person Server with
`AddAAuthPersonServer`, then map it:

```csharp
using AAuth.Person;

// The identity/consent seam is the PS counterpart to IAccessPolicy. Deferred
// consent decisions park in the default InMemoryPersonPendingStore.
builder.Services.AddAAuthPersonServer(configure: options =>
    {
        options.Issuer       = psIssuer;
        options.SigningKeys  = new AAuthSigningKeySet(PsKid, psKey);
        options.DefaultScope = "calendar.read";
    })
    // Unset ⇒ federate to verified aud; empty ⇒ three-party only.
    .WithTrust(trust => trust.AccessServers.Allowed = trustedAccessServers)
    .UseClaimsAsserter(new DefaultIdentityClaimsAsserter("user-42"))
    .WithFederation();

var app = builder.Build();

// One call maps /.well-known + JWKS, request-signature verification,
// POST /person, POST /token, and GET /pending/{id}.
app.MapAAuthPersonServer();
```

The options are validated at startup. A missing issuer or signing key fails
`app.StartAsync()` (and `MapAAuthPersonServer()`) with an
`OptionsValidationException`. Each seam resolves from the builder's `Use*`
helper, then from an unkeyed DI registration, then from the SDK default. To bind
from `AAuth:PersonServer`, load the key through `KeyHandle`, or co-host several
instances with `MatchIssuerHost`, see
[Person Server and Access Server Registration](../reference/dependency-injection.md#person-server-and-access-server-registration).

### AAuthPersonServerOptions Properties

| Property | Type | Required | Default | Description |
|----------|------|:--------:|---------|-------------|
| `Issuer` | `string` | Yes | — | HTTPS URL of this PS (`iss` of minted auth tokens); validated at startup |
| `SigningKeys` | `AAuthSigningKeySet` | One of `SigningKeys` / `KeyHandle` | empty | Signing keys published at the PS JWKS; tokens are signed with the active key. Supports Ed25519 and ES256 keys |
| `KeyHandle` | `string?` | One of `SigningKeys` / `KeyHandle` | `null` | Handle in the registered `IKeyStore` to load the signing key from when `SigningKeys` is empty |
| `KeyId` | `string?` | No | `null` | `kid` for the key loaded from `KeyHandle` (default: its JWK thumbprint) |
| `MatchIssuerHost` | `bool` | No | `false` | Serve this instance only for requests whose `Host` is the issuer's authority; set it when several roles or instances share one host |
| `TokenPath` | `string` | No | `/token` | The auth token endpoint path (`auth_token_endpoint`) |
| `PersonTokenPath` | `string` | No | `/person` | The person token endpoint path (`person_token_endpoint`) |
| `RevocationPath` | `string` | No | `/revoke` | The revocation endpoint path |
| `PendingPathPrefix` | `string` | No | `/pending` | The deferred-consent poll path prefix |
| `DefaultScope` | `string` | No | `""` | Scope assumed when the resource token omits one |
| `PairwiseSubjectSecrets` | `IDictionary<string,string>` | Production | empty | Versioned HMAC secrets for default pairwise `sub` derivation. Development/test use an ephemeral secret with a warning |
| `ActivePairwiseSubjectKeyId` | `string?` | No | `null` | Key id used for new derived subjects; existing enrollments keep their stored subject/key version |
| `InteractionPath` | `string` | No | `/interaction` | Path the host maps for the consent page |
| `Trust` | `AAuthTrustOptions` | No | `new()` | `Trust.AccessServers` governs the Access Server URLs the PS will federate to. Unconfigured ⇒ federate to the AS named in a verified resource token's `aud` (the spec default); `Allowed` empty ⇒ three-party only (four-party disabled); non-empty ⇒ restrict to the listed Access Servers. `Predicate` AND-composes; assign `AAuthTrust.Any` to federate to any verifiable AS explicitly. |
| `InteractionEndpointPath` | `string?` | No | `null` | Signed §Interaction Endpoint path; advertised in metadata as issuer + path when set or when `.WithGovernance()` supplies `/mission-interaction`. It never falls back to `InteractionPath`. |
| `MissionPath` | `string?` | No | `null` | Mission endpoint path; advertised in `aauth-person.json` as issuer + path (the PS maps the endpoint) |
| `PermissionPath` | `string?` | No | `null` | Permission endpoint path; advertised in `aauth-person.json` as issuer + path (the PS maps the endpoint) |
| `AuditPath` | `string?` | No | `null` | Audit endpoint path; advertised in `aauth-person.json` as issuer + path (the PS maps the endpoint) |
| `UnsignedPathPrefixes` | `IReadOnlyCollection<string>?` | No | `null` | Extra path prefixes the mapper's signature verification skips (e.g. the PS's own unsigned `/admin` consent surface) |

The token inventory is a seam, not an option. Use `.UseTokenInventory(inventory)`
on the builder, or resolve the default with
`GetRequiredKeyedService<IJtiStore>(AAuthPersonServerBuilder.DefaultName)`.

### The `IIdentityClaimsAsserter` seam

The asserter is the only PS-specific decision the helper cannot make for you —
it returns the stable internal `AAuthPersonKey`, an optional explicit directed
`sub` (plus optional `tenant` / `roles` / `groups` / additional claims), and the
consent verdict. It mirrors `IAccessPolicy` on the AS side:

```csharp
public interface IIdentityClaimsAsserter
{
    Task<IdentityAssertion> AssertAsync(
        IdentityAssertionRequest request, CancellationToken cancellationToken = default);
}
```

The host maps the returned `IdentityAssertion` to the spec wire response:

| `IdentityAssertion` | Wire response |
| --- | --- |
| `IdentityAssertion.Assert(personKey, subject, …)` | host-approved identity/consent: record enrollment, then mint the person/auth token (three-party) or push the claims (four-party) |
| `IdentityAssertion.Deny(reason)` | `403 denied` |
| `IdentityAssertion.NeedsConsent()` | `202` + `AAuth-Requirement: requirement=interaction` + `Location` (poll `GET /pending/{id}`) |

`Assert` is the host's approval decision. If it supplies an explicit directed
`subject` for a resource the person has not used before, the SDK records the
first-resource enrollment before minting; it does not infer a person key later
from a presented or upstream token. If `subject` is omitted, the SDK derives the
pairwise subject from `personKey`, fetches resource metadata for the first
issuance, and parks for consent unless the enrollment already exists.

When the asserter returns `NeedsConsent()`, the helper parks the request and
returns the `202`; the host's own interaction page (mapped at `InteractionPath`)
collects the user's decision and resolves the parked entry via
`IPersonPendingStore.MarkAllowed(...)` / `MarkDenied(...)`, after which the
polling agent receives the minted token (or `403`). The consent UI stays a host
concern — the SDK only owns the protocol mechanics.

A consent dashboard, or any other channel the PS already controls, needs two
more seams:

- **See every parked request.** Register an `IPersonPendingObserver` (keyed by
  the Person Server name, or unkeyed). The PS calls `OnParked(entry)` once for
  each request it parks, whichever `IPersonPendingStore` holds it.
- **Decide without the link.** The spec lets the host of the interaction URL
  complete it over its own channel; the code is consumed then (#user-interaction).
  `entry.Browser.CompleteOutOfBandAsync(entry.Lifecycle, apply)` runs `apply`
  under the request's gate, so it never interleaves with a decision on the
  consent page, and consumes the code when `apply` reports the decision applied.
  `apply` checks that the request is still undecided and records the verdict
  (for example with `MarkAllowed`).

```csharp
builder.Services.AddSingleton<IPersonPendingObserver, DashboardFeed>();

// On the dashboard's approve button:
var decided = await entry.Browser.CompleteOutOfBandAsync(entry.Lifecycle, ct =>
{
    if (entry.Status != PersonPendingStatus.Pending) return Task.FromResult(false);
    pending.MarkAllowed(entry.Id, personKey: new AAuthPersonKey("internal-person-id"), subject: directedSubject);
    return Task.FromResult(true);
}, cancellationToken);

sealed class DashboardFeed : IPersonPendingObserver
{
    public void OnParked(PersonPendingEntry entry) { /* list it on the dashboard */ }
}
```

MockPersonServer's `ConsentRegistry` and `PersonConsentDecisions` are a complete
example.

A consent surface carries content from two sources, and the spec requires the
PS to keep them visually apart and to attribute the agent's words to the agent.
The request and the parked entry hand you both:

| Source | Property | Carries |
| --- | --- | --- |
| Resource-asserted | `ResourceContext` | The verified resource token's claims |
| Agent-asserted | `AgentAsserted` (`AgentAssertedContent`) | The request's `justification`, `platform` and `device`; `null` when the agent sent none |

`IMissionTokenConsent` receives the same `AgentAsserted` on
`MissionTokenConsentContext`, so a supervision server sees the same
distinction. Treat agent-asserted content as untrusted: sanitize the Markdown
`Justification` before rendering, and don't decide on it alone when
resource-asserted content covers the same operation. MockPersonServer's consent
page renders it in a separate "The agent says (not verified)" panel. A request
whose `justification`, `platform` or `device` isn't a string gets `400
invalid_request`. `platform`, when present, must be one of the vendored registry
values `web`, `mobile`, `desktop`, `workload` or `self-hosted`; `device` must be
printable Unicode and at most 64 scalar values; and a present malformed
`capabilities` value (non-array, non-string member, empty string, or invalid
HTTP token) is also `400 invalid_request`. `capabilities: []` is a deliberate
empty declaration, distinct from omitting `capabilities`.

The shipped [`DefaultIdentityClaimsAsserter`](../../samples/MockPersonServer/)
asserts a fixed directed `sub` with no prompt (a non-interactive demo PS); a
production PS swaps in an implementation that derives the principal's directed
identity and consent decision.

### Mission three-gate packaging

When the resource token carries `mission_s256`, `MapAAuthPersonServer` packages
the mission three-gate token-issuance mechanics, using the `IMissionStore` /
`IMissionLog` primitives (in-memory by default; the builder's `.WithGovernance()`
calls [`AddAAuthGovernance()`](mission-governance.md) for the governance seams):

1. **Unknown, foreign, or terminated mission** → `404 mission_not_found` or
   `403 mission_terminated` (an expired mission counts as terminated).
2. **Prior consent on record** for the `(resource, scope)` → silent mint, logged
   `PriorConsent` (identity from the asserter).
3. **Otherwise** → the `IMissionTokenConsent` seam decides: `Grant` (silent
   in-scope, logged `InScope`), `Deny` (`403`), `Clarify` (emit the normative
   `requirement=clarification` round-trip), or `Interact` (park a `202` and hold
   for a user verdict). A grant after a prompt is logged `OutOfScope`.

The SDK owns the **protocol** — the `requirement=clarification` 202, the
pending-URL `GET`/`POST`/`DELETE` round-trip, and the mission-log entries — while
`IMissionTokenConsent` owns **how** the decision is made (a consent screen, a
scripted test, or an LLM reviewer). Identity on a grant always comes from
`IIdentityClaimsAsserter`. See [Mission Governance (Server)](mission-governance.md)
for the full model.

## Further Reading

- [Verification Middleware](verification-middleware.md) — signature verification before token logic
- [Replay Detection](replay-detection.md) — signature-keyed replay (tokens stay reusable; `jti` is for revocation)
- [Mission Governance (Server)](mission-governance.md) — evaluating mission context at the PS
