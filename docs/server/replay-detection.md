# Replay Detection and Revocation

> [Signature Security](https://explorer.aauth.dev/foundations/signatures)

## Overview

An auth token (and a `jkt-jwt` naming JWT) is a **reusable** proof-of-possession
credential: the agent re-signs and presents it on every request, so replay
protection cannot live on the token itself. Per the spec's §Freshness and Replay,
the `created` timestamp is the primary defense — a captured signature is unusable
once its validity window (default 60 s) closes — and a verifier MAY additionally
reject a captured signature *replayed within* that window. This profile defines no
nonce mechanism.

The verification middleware implements that optional defense by recording the
**verified signature** for the freshness window via `IJtiStore`. The signature
cryptographically binds the spec's replay tuple `(signing-key-thumbprint, created,
@method, @authority, @path)` **plus** the covered `signature-key` (the carrier), so
an exact captured-signature replay collides and is rejected, while legitimately
distinct requests — a fresh `created`, a different carrier, a different path —
never do. A valid, non-revoked auth token remains reusable with fresh signatures.
Token revocation is keyed by `TokenKey(issuer, tokenId)`, never by a bare `jti`.
The request carries only `jti` and `exp`; the issuer is the caller's verified
signing identity, so a caller revokes only its own tokens
([Token Revocation](../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#token-revocation)).

## IJtiStore Interface

```csharp
namespace AAuth.Server;

public interface IJtiStore
{
    Task<bool> TryRecordRequestAsync(string requestKey, DateTimeOffset expiration, CancellationToken ct = default);
    Task<bool> RegisterAsync(TokenKey token, DateTimeOffset expiration, CancellationToken ct = default);
    Task RevokeAsync(TokenKey token, DateTimeOffset expiresAt, CancellationToken ct = default);
    Task<bool> IsRevokedAsync(TokenKey token, CancellationToken ct = default);
    Task<bool> RegisterGrantAsync(IReadOnlyCollection<TokenKey> sources, TokenGrant grant, CancellationToken ct = default);
    Task<IReadOnlyList<TokenGrant>> GetGrantsAsync(TokenKey source, CancellationToken ct = default);
}
```

`TryRecordRequestAsync` records verified signatures in a separate namespace.
`RegisterAsync` records verified tokens without consuming them. It cannot revive
a revoked token. `RevokeAsync` records the pair whether or not the store has
seen it, so a later registration or presentation is refused; an unseen entry is
kept until `expiresAt` plus retention, and repeating a revocation changes
nothing. `RegisterGrantAsync` atomically checks
all source tokens and records the issued or provided token's exact issuer, ID,
resource recipient, and expiration. Do not populate this inventory from unverified
JWT claims.

## Built-in: InMemoryJtiStore

Thread-safe development implementation. State is lost on restart; it is not a
durable production backend. By default, each token/request inventory admits at
most 100,000 entries. Capacity exhaustion fails closed instead of evicting active
revocations. Token entries, including revocations of unseen tokens, remain for
one hour after their expiry, after which the
pair becomes unknown. Cleanup runs opportunistically at most once per minute,
or explicitly through `Cleanup()`. Inject the same `TimeProvider` as the verifier
when testing with a fixed clock.

```csharp
using AAuth;

// DI extension (recommended) — registers IJtiStore automatically
builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
    options.EnableReplayDetection = true;
});
```

<details>
<summary>Override the JTI store (building block)</summary>

```csharp
using AAuth.Server;

// AddAAuthResource registers InMemoryJtiStore by default (via TryAdd), so
// register your own IJtiStore first to override it.
builder.Services.AddSingleton<IJtiStore>(new InMemoryJtiStore());
builder.Services.AddAAuthResource(options => options.Issuer = "https://resource.example");

var app = builder.Build();

var jtiStore = app.Services.GetRequiredService<IJtiStore>();
```

</details>

## Custom Implementations

Distributed deployments must implement the complete `IJtiStore` contract in a
shared backend. Use a composite key or an unambiguous encoding of both strings,
not delimiter concatenation. Registration, revocation, and source-to-grant
association need transactional isolation: once source revocation wins, no new
grant may be attached to that source. Preserve known invalid tokens for the
configured retention period, keep request replay separate, and persist recipient
records so delivery retries survive restarts. A bare Redis SET/GET sketch is not
sufficient for these guarantees.

## Revocation Endpoint

The endpoint verifies the caller's server identity through HTTP Message
Signatures. Callers sign with `jwks_uri`, `jwks`, or `self-jwt`; an agent
signing with its agent token is not a server and is answered `unsupported_iss`.
That verified identity is the issuer of the revoked token, so the endpoint
records `(caller, jti)` and a caller can never touch another issuer's tokens.

The generic mapper is deny-by-default. Use `UseAAuth()` after routing for its
endpoint metadata, or place it behind explicitly configured verification that
accepts the server-signing scheme:

```csharp
using AAuth.Server;

// Records revocations in the DI-registered IJtiStore (AddAAuthResource registers one);
// mapping throws when none is registered.
app.MapAAuthRevocationEndpoint("/revoke", options =>
    options.IsAcceptedIssuer = issuer => issuer == "https://ps.example");
```

`IsAcceptedIssuer` decides whose revocations the recipient accepts; assign
`AAuthTrust.Any` to accept any verified issuer. `MaxTokenLifetime` (default 24
hours) bounds the `exp` a revocation may name, and so how long an unseen
revocation is held. `Limits` (on by default: 10,000 unexpired entries and 600
requests a minute per issuer) bounds what one accepted issuer can send; set it to
`null` to turn the bounds off.

```http
Content-Type: application/json

{ "jti": "token-id-to-revoke", "exp": 1788727813 }
```

`exp` is the revoked token's own expiration in seconds. The endpoint enforces,
in order:

| Condition | Response |
|-----------|----------|
| Caller has no verified AAuth signature | `401 Unauthorized` (`invalid_request`); a failed signature is `401` with `Signature-Error` |
| Signature does not cover `content-digest` and `content-type` | `401` with `Signature-Error: error=invalid_input` and `required_input` |
| Caller is not a server, or not accepted | `403 Forbidden` (`unsupported_iss`) |
| Malformed JSON, or missing/malformed `jti` or `exp`, or `exp` beyond `MaxTokenLifetime` | `400 Bad Request` (`invalid_request`) |
| The issuer is over its entry or rate bound | `429 Too Many Requests` (`rate_limited`) with `Retry-After` |
| The revocation cannot be recorded (inventory full) | `500 Internal Server Error` (`server_error`) |
| Recorded, seen or not, including repeated revocation | `200 OK` once every downstream revocation is terminal |
| The cascade outlasts `DeferAfter` (default 20 s; `Prefer: wait` can shorten it) | `202 Accepted` with `Location: /revoke/pending/{id}`; the revoker polls it with a signed `GET` under the same identity (others get `404`) until the `200` |

There is no "not found". A recipient that cascades reports each recipient it
revoked at; `error` is present only when that revocation did not succeed:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{ "downstream": [ { "recipient": "https://resource.example", "error": "revocation_unavailable" } ] }
```

`revocation_unsupported` means the recipient publishes no `revocation_endpoint`
or answered `unsupported_iss`; `revocation_unavailable` means it did not answer,
failed with `5xx`, or sent a malformed response. A `200` with nothing downstream
has an empty body, and a PS always answers its agent provider with an empty body
(`ReportDownstream = false`).

`RevocationClient` accepts a signed, admitted `HttpClient`, sends `{jti, exp}`
with `content-type` and `content-digest` covered, and parses the answer:

```csharp
var client = new RevocationClient(signedHttp);
var result = await client.RevokeAsync(
    new Uri("https://resource.example/revoke"),
    "token-id-to-revoke",
    DateTimeOffset.FromUnixTimeSeconds(1788727813));
// result.Failure is null once recorded; result.Downstream carries the recipient's report.
```

Advertise it in resource metadata:

```csharp
builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
    options.RevocationEndpoint = "https://resource.example/revoke";
});

// After builder.Build():
app.MapAAuthWellKnown();
```

## Source Token Lifecycle

Core PS/AS mappers and the R3 AS advertise and map `/revoke` and accept any
verified issuer; their verification requires `content-type` and
`content-digest` in the signature. Core PS/AS options expose `RevocationPath`
and `ConfigureRevocation`. A resource registered with `AddAAuthResource` maps
the same issuer pipeline with one call; it verifies the server-signing schemes,
records into the DI `IJtiStore`, cascades to recorded grants and signs downstream
revocations as the resource with its active key:

```csharp
var inventory = app.MapAAuthIssuerRevocation("/revoke", options =>
    options.IsAcceptedIssuer = issuer => issuer is "https://ps.example" or "https://as.example");
```

`MapAAuthRevocationEndpoint` above is the lower-level endpoint for hosts that
bring their own verification.
Register `IJtiStore` in DI to supply a durable inventory and `RevocationClient`
to supply an admitted custom signed transport. Defaults are in-memory inventory
and a server-signed, pinned HTTP transport.

The PS records the verified parent and child source tokens, retains their keys
through consent and federation, and records grants with each exact resource
recipient. A revocation is recorded first; the recipient then revokes each
grant it issued at that grant's resource, signing as itself. A PS never revokes
an AS-issued grant directly: where an AS issued a grant against a token of the
PS's (a presented person token or an upstream token), the PS revokes that token
at the AS, and the AS revokes the auth tokens it issued against it. Deferred
delivery rechecks the original source, so a fresh agent token cannot revive
consent tied to a revoked predecessor.

Local revocation is not rolled back when delivery fails. Repeating a revocation
records nothing new and re-attempts every downstream revocation. A resource
records a revocation for a token it never verified, so that grant is refused
when it is presented later.

Unreached recipients learn nothing from local JWKS verification and remain
bounded by token lifetime, at most one hour for auth tokens. See the
[revocation exposure limits](../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2767).
Deployments needing shorter exposure should issue shorter-lived tokens and use a
durable retry mechanism. The SDK's in-memory sample does not provide restart-safe
delivery or a background retry service.

## Further Reading

- [Verification Middleware](verification-middleware.md)
- [Token Issuance](token-issuance.md) — token builders auto-generate `jti` values
- [Error Handling](../advanced/error-handling.md)
