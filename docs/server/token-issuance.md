# Token Issuance

> [Token Types](https://explorer.aauth.dev/foundations/tokens) | [Token Lifecycle](https://explorer.aauth.dev/tokens/lifecycle)

## Overview

The SDK provides builders for all three AAuth JWT token types. Each produces a compact JWT (`header.payload.signature`) signed with Ed25519.

## Resource Tokens (`aa-resource+jwt`)

Issued by a resource to challenge the agent. Contains the audience (Access Server URL) and the agent's key thumbprint.

```csharp
using AAuth.Tokens;

var resourceToken = new ResourceTokenBuilder
{
    Issuer = "https://resource.example",
    Audience = "https://as.example",          // where agent exchanges this
    Agent = "aauth:myapp@ap.example",         // agent identifier
    AgentJkt = keyInfo.Jkt!,                  // from parsed signature key
    Key = resourceSigningKey,                 // Ed25519 key
    KeyId = "resource-key-1",
    Scope = "read write",                     // requested scope
    Lifetime = TimeSpan.FromMinutes(5),       // default: 5 min
}.Build();

// Return as 401 challenge (sets the AAuth-Requirement header:
// requirement=auth-token; resource-token="...")
return context.ChallengeAAuth(resourceToken);
```

### ResourceTokenBuilder Properties

| Property | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `Issuer` | Yes | — | Resource URL (becomes `iss`) |
| `Audience` | Yes | — | AS/PS URL where agent exchanges (becomes `aud`) |
| `Agent` | Yes | — | Agent identifier (becomes `agent`) |
| `AgentJkt` | Yes | — | Agent's key thumbprint (for binding) |
| `Key` | Yes | — | Signing key |
| `KeyId` | Yes | — | Key ID (goes in JWT header `kid`) |
| `Scope` | No | — | Space-separated scopes |
| `Lifetime` | No | 5 min | Token validity duration |
| `IssuedAt` | No | Now | Override issuance time |
| `TokenId` | No | Auto | Custom `jti` (auto-generated UUID if omitted) |

## Auth Tokens (`aa-auth+jwt`)

Issued by a Person Server or Access Server to grant access. Bound to the agent's confirmation key.

```csharp
var authToken = new AuthTokenBuilder
{
    Issuer = "https://ps.example",
    Audience = "https://resource.example",    // resource that will accept this
    Agent = "aauth:myapp@ap.example",
    AgentConfirmationKey = agentPublicKey,    // binds token to agent's key
    Key = psSigningKey,
    KeyId = "ps-key-1",
    Dwk = AuthTokenBuilder.PersonDwk,        // "aauth-person.json" (or AccessDwk for AS)
    Scope = "read",
    Subject = "user@example.com",            // optional: person identifier
    Lifetime = TimeSpan.FromHours(1),
}.Build();
```

### AuthTokenBuilder Properties

| Property | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `Issuer` | Yes | — | PS or AS URL (becomes `iss`) |
| `Audience` | Yes | — | Resource URL (becomes `aud`) |
| `Agent` | Yes | — | Agent identifier |
| `AgentConfirmationKey` | Yes | — | Agent's public key (bound via `cnf.jkt`) |
| `Key` | Yes | — | PS/AS signing key |
| `KeyId` | Yes | — | Key ID (JWT header `kid`) |
| `Dwk` | No | `"aauth-person.json"` | Discovery well-known path (`PersonDwk` or `AccessDwk`) |
| `Scope` | No | — | Granted scope |
| `Subject` | No | — | Person identifier |
| `Lifetime` | No | 1 hour | Token validity |
| `IssuedAt` | No | Now | Override issuance time |
| `TokenId` | No | Auto | Custom `jti` |

### Person Server vs Access Server

```csharp
// Person Server issues:
Dwk = AuthTokenBuilder.PersonDwk  // "aauth-person.json"

// Access Server issues:
Dwk = AuthTokenBuilder.AccessDwk  // "aauth-access.json"
```

The `Dwk` determines which `.well-known` document an agent fetches to find the issuer's public key for verification.

## Agent Tokens (`aa-agent+jwt`)

Issued by an Agent Provider to bind an agent's key to its identity.

```csharp
var agentToken = new AgentTokenBuilder
{
    Issuer = "https://ap.example",
    Subject = "aauth:myapp@ap.example",
    Key = apSigningKey,
    KeyId = "ap-key-1",
    ConfirmationKey = agentPublicKey,          // binds token to this key
    PersonServer = "https://ps.example",       // optional
    Lifetime = TimeSpan.FromHours(24),
}.Build();
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

// Verify an auth token (also checks agent key binding)
var auth = verifier.VerifyAuthToken(
    jwt: authTokenString,
    issuerKey: psPublicKey,
    expectedAudience: "https://resource.example",
    httpSignatureKey: agentKey,
    expectedAgentId: "aauth:myapp@ap.example");
```

### Verifying a presented resource token (PS/AS side)

When an agent exchanges a `resource_token` at the PS/AS `/token` endpoint, the
recipient MUST verify it before minting an auth token (spec §"Resource Token
Verification"). `VerifyResourceTokenAsync` performs JWKS discovery and all seven
recipient checks in one call:

```csharp
var verified = await verifier.VerifyResourceTokenAsync(
    jwt: resourceTokenString,
    expectedAudience: psIssuer,                 // this PS/AS own identifier (aud)
    expectedAgentId: agentId,                   // from the verified HTTP signature
    expectedAgentJkt: confirmationKey.ComputeJwkThumbprint(),
    metadata: metadataClient,                   // resolves {iss}/.well-known/aauth-resource.json
    jwks: jwksClient,                           // resolves the resource's signing key
    expectedApprover: null);                    // optional: mission.approver constraint
```

The seven checks (failure throws `TokenVerificationException`):

| # | Check | Detail |
|---|-------|--------|
| 1 | `typ` | Must be `aa-resource+jwt` |
| 2 | `dwk` + signature | `dwk=aauth-resource.json`; key resolved from `{iss}/.well-known/aauth-resource.json` → `jwks_uri` |
| 3 | `exp` / `iat` | Within validity (honours `ClockSkew`) |
| 4 | `aud` | Equals `expectedAudience` |
| 5 | `agent` | Equals `expectedAgentId` from the verified HTTP signature |
| 6 | `agent_jkt` | Equals the presenting agent's key thumbprint (PoP binding) |
| 7 | `mission.approver` | When `expectedApprover` is set, must match |

Map failures to the spec error response — `expired_resource_token` for an expired
token, otherwise `invalid_resource_token` — and derive the consent screen and the
issued auth token only from the verified payload. The SDK host helpers
`MapAAuthPersonServer` / `MapAAuthAccessServer` run exactly these checks
internally; the [`samples/MockPersonServer`](../../samples/MockPersonServer/)
adopts the PS helper rather than hand-rolling them.

## Mission Claims

When a request is governed by a mission, the mission travels through the tokens as
a `mission` claim — `{ approver, s256 }` — never the mission content itself
(§Resource Token Structure, §Auth Token Structure). The SDK models it with
`MissionClaim`:

```csharp
namespace AAuth.Tokens;

public sealed record MissionClaim(string Approver, string S256)
{
    public JsonObject ToJsonObject();
    public static MissionClaim? FromPayload(JsonObject? payload);
}
```

A mission-aware resource copies the mission object from the `AAuth-Mission`
request header into the resource token it issues, so the mission context reaches
the PS even when the resource is not the approver. Enable it with
`ChallengeOptions.MissionAware` — see
[Challenge Middleware](challenge-middleware.md#mission-aware-resources). The PS
echoes the same claim into the auth token it mints. When verifying a presented
resource token the recipient MAY constrain `mission.approver` via
`expectedApprover` (check 7 above).

For the full PS-side evaluation of mission context, see
[Mission Governance (Server)](mission-governance.md).

## One-Call Person Server (`MapAAuthPersonServer`)

The builders above are the primitives. The whole Person Server token-endpoint
pipeline also ships as a single host helper, `MapAAuthPersonServer` — the PS
counterpart to [`MapAAuthAccessServer`](../workflows/federated-access.md#access-server-side-code).
One call publishes the `/.well-known/aauth-person.json` metadata + JWKS, verifies
the RFC 9421 request signature, verifies the presented `resource_token`, and then
routes on the resource token's `aud` (§PS-AS Federation):

- **`aud` = this PS** → three-party (PS-asserted): mint the auth token directly
  (`dwk=aauth-person.json`, `iss`=PS).
- **`aud` = a trusted Access Server** → four-party (federated): forward a signed
  PS→AS request via `AccessServerClient` and return the AS-issued auth token after
  the §Auth Token Delivery check.

The host owns all AAuth crypto; the identity and consent decision is delegated to
a pluggable `IIdentityClaimsAsserter`.

```csharp
using AAuth.Person;

// The identity/consent seam (the PS counterpart to IAccessPolicy) and the store
// that parks deferred consent decisions.
builder.Services.AddSingleton<IIdentityClaimsAsserter>(new DefaultIdentityClaimsAsserter("user-42"));
builder.Services.AddSingleton<IPersonPendingStore, InMemoryPersonPendingStore>();

var app = builder.Build();

// One call maps /.well-known + JWKS, request-signature verification,
// POST /token, and GET /pending/{id}.
app.MapAAuthPersonServer(new AAuthPersonServerOptions
{
    Issuer               = psIssuer,
    SigningKeys          = new Dictionary<string, AAuthKey> { [PsKid] = psKey },
    DefaultScope         = "calendar.read",
    TrustedAccessServers = trustedAccessServers,   // omit ⇒ three-party only
});
```

### AAuthPersonServerOptions Properties

| Property | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `Issuer` | Yes | — | HTTPS URL of this PS (`iss` of minted auth tokens) |
| `SigningKeys` | Yes | — | `kid → AAuthKey` map published at the PS JWKS |
| `TokenPath` | No | `/token` | The token endpoint path |
| `PendingPathPrefix` | No | `/pending` | The deferred-consent poll path prefix |
| `DefaultScope` | No | `""` | Scope assumed when the resource token omits one |
| `InteractionPath` | No | `/interaction` | Path the host maps for the consent page |
| `TrustedAccessServers` | No | `null` | Access Server URLs the PS will federate to; `null`/empty ⇒ three-party only |
| `InteractionEndpoint` | No | `null` | §Interaction Endpoint URL advertised in metadata (falls back to `InteractionPath`) |
| `MissionEndpoint` / `PermissionEndpoint` / `AuditEndpoint` | No | `null` | Governance endpoint URLs advertised in `aauth-person.json` (the PS maps the endpoints) |
| `UnsignedPathPrefixes` | No | `null` | Extra path prefixes the mapper's signature verification skips (e.g. the PS's own unsigned `/admin` consent surface) |

### The `IIdentityClaimsAsserter` seam

The asserter is the only PS-specific decision the helper cannot make for you —
it returns the directed `sub` (plus optional `tenant` / `roles` / `groups` /
additional claims) and the consent verdict. It mirrors `IAccessPolicy` on the AS
side:

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
| `IdentityAssertion.Assert(sub, …)` | mint the auth token (three-party) / push the claims (four-party) |
| `IdentityAssertion.Deny(reason)` | `403 denied` |
| `IdentityAssertion.NeedsConsent()` | `202` + `AAuth-Requirement: requirement=interaction` + `Location` (poll `GET /pending/{id}`) |

When the asserter returns `NeedsConsent()`, the helper parks the request and
returns the `202`; the host's own interaction page (mapped at `InteractionPath`)
collects the user's decision and resolves the parked entry via
`IPersonPendingStore.MarkAllowed(...)` / `MarkDenied(...)`, after which the
polling agent receives the minted token (or `403`). The consent UI stays a host
concern — the SDK only owns the protocol mechanics.

The shipped [`DefaultIdentityClaimsAsserter`](../../samples/MockPersonServer/)
asserts a fixed directed `sub` with no prompt (a non-interactive demo PS); a
production PS swaps in an implementation that derives the principal's directed
identity and consent decision.

### Mission three-gate packaging

When the resource token carries a `mission` claim, `MapAAuthPersonServer` packages
the mission three-gate token-issuance mechanics, using the `IMissionStore` /
`IMissionLog` primitives registered by
[`AddAAuthGovernance()`](mission-governance.md):

1. **Terminated mission** → `403 mission_terminated`.
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
