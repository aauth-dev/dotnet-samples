---
title: Replay Detection and Revocation
description: Independent request replay protection and issuer-qualified token revocation.
---

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
The wire identity is `(iss,jti)`; both strings are required by
[Token Revocation](../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2361).

## IJtiStore Interface

```csharp
namespace AAuth.Server;

public interface IJtiStore
{
    Task<bool> TryRecordRequestAsync(string requestKey, DateTimeOffset expiration, CancellationToken ct = default);
    Task<bool> RegisterAsync(TokenKey token, DateTimeOffset expiration, CancellationToken ct = default);
    Task<bool> RevokeAsync(TokenKey token, CancellationToken ct = default);
    Task<bool> IsRevokedAsync(TokenKey token, CancellationToken ct = default);
    Task<bool> RegisterGrantAsync(IReadOnlyCollection<TokenKey> sources, TokenGrant grant, CancellationToken ct = default);
    Task<IReadOnlyList<TokenGrant>> GetGrantsAsync(TokenKey source, CancellationToken ct = default);
}
```

`TryRecordRequestAsync` records verified signatures in a separate namespace.
`RegisterAsync` records verified tokens without consuming them. It cannot revive
a revoked token. `RevokeAsync` returns false for an unknown pair and true for a
known token, including repeated revocation. `RegisterGrantAsync` atomically checks
all source tokens and records the issued or provided token's exact issuer, ID,
resource recipient, and expiration. Do not populate this inventory from unverified
JWT claims.

## Built-in: InMemoryJtiStore

Thread-safe development implementation. State is lost on restart; it is not a
durable production backend. By default, each token/request inventory admits at
most 100,000 entries. Capacity exhaustion fails closed instead of evicting active
revocations. Token tombstones remain for one hour after expiry, after which the
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
Signatures and authorizes it against the requested token pair. An AP-issued agent
token identifies its holder, not the AP. Revokers use `jwks_uri`, `jwks`, or
`self-jwt`; a token's issuer or subject claim is not substituted for caller identity.

The generic mapper is deny-by-default. Use `UseAAuth()` after routing for its
endpoint metadata, or place it behind explicitly configured verification that
accepts the server-signing scheme:

```csharp
using AAuth.Server;

app.MapAAuthRevocationEndpoint(
    jtiStore,
    configure: options =>
    {
        options.AllowTokenIssuer = true;
        options.TrustedPersonServers = ["https://ps.example"];
    },
    path: "/revoke");
```

`AllowTokenIssuer` compares the authenticated caller to the target `TokenKey.Issuer`.
`TrustedPersonServers` explicitly trusts a PS to revoke provided tokens.
`IsTrustedPersonServer(caller, token)` permits a target-aware PS policy. These
rules are OR-composed; an unconfigured generic endpoint authorizes no caller.

```http
Content-Type: application/json

{ "iss": "https://issuer.example", "jti": "token-id-to-revoke" }
```

The endpoint enforces, in order:

| Condition | Response |
|-----------|----------|
| Caller has no verified AAuth signature | `401 Unauthorized` (`invalid_request`) |
| Missing, empty, or non-string `iss` or `jti` | `400 Bad Request` (`invalid_request`) |
| Verified caller cannot revoke the target pair | `403 Forbidden` (`untrusted_revoker`) |
| Authorized caller, unknown pair | `404 Not Found` (`unknown_token`) |
| Known pair, including repeated revocation | `200 OK` |
| Local revocation succeeded but cascade is incomplete | `502 Bad Gateway` (`revocation_incomplete`) |

`RevocationClient` accepts a signed, admitted `HttpClient` and sends the typed pair:

```csharp
var client = new RevocationClient(signedHttp);
var status = await client.RevokeAsync(
    new Uri("https://resource.example/revoke"),
    new TokenKey("https://issuer.example", "token-id-to-revoke"));
```

Advertise it in resource metadata:

```csharp
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = "https://resource.example",
    RevocationEndpoint = "https://resource.example/revoke"
});
```

## Source Token Lifecycle

Core PS/AS mappers and the R3 AS advertise and map `/revoke`, explicitly allowing
an authenticated token issuer. Core PS/AS options expose `RevocationPath` and
`ConfigureRevocation`; custom issuer hosts can use `MapAAuthIssuerRevocation`.
Register `IJtiStore` in DI to supply a durable inventory and `RevocationClient`
to supply an admitted custom signed transport. Defaults are in-memory inventory
and a server-signed, pinned HTTP transport.

The PS records the verified parent and child source tokens, retains their keys
through consent and federation, and records grants with each exact resource
recipient. AP revocation blocks subsequent source use and attempts every recorded
resource revocation. Deferred delivery rechecks the original source, so a fresh
agent token cannot revive consent tied to a revoked predecessor. The PS also
tracks verified AS-provided grants, preserving the AS issuer in each cascade.

Local revocation is not rolled back when delivery fails. A missing endpoint,
unreachable resource, or resource 404 produces an incomplete result; repeated
source revocation retries the outstanding recipient set. A resource recognizes
tokens it has actually verified, so a never-presented grant may return 404.
No successful cascade is claimed for that response.

Unreached recipients learn nothing from local JWKS verification and remain
bounded by token lifetime, at most one hour for auth tokens. See the
[revocation exposure limits](../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2395).
Deployments needing shorter exposure should issue shorter-lived tokens and use a
durable retry mechanism. The SDK's in-memory sample does not provide restart-safe
delivery or a background retry service.

## Further Reading

- [Verification Middleware](verification-middleware.md)
- [Token Issuance](token-issuance.md) — token builders auto-generate `jti` values
- [Error Handling](../advanced/error-handling.md)
