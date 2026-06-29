# Verification Middleware

`AAuthVerificationMiddleware` performs HTTP signature verification (RFC 9421 PoP) and JWT issuer signature verification in a single pass.

> **Prefer the high-level pipeline for the common case.** `app.UseAAuth(...)` after
> `app.UseRouting()` runs this verification middleware (and, for auth-token
> endpoints, the challenge) for every endpoint marked with `.RequireAAuth(...)` /
> `.RequireAAuthSignature(...)`. Use `UseAAuthVerification` directly only when
> composing a custom, low-level pipeline.

> For how verification fits into the full authN/authZ pipeline and the
> minimal-API vs classic-MVC wiring, see
> [Authentication and Authorization](authn-authz.md).

## Registration

```csharp
using AAuth;
using AAuth.Server.Verification;

// AddAAuthResource registers the verifier, the discovery clients (pooled
// handler), and the JTI store — no manual HttpClient/discovery wiring.
builder.Services.AddAAuthResource(o =>
{
    o.Issuer = "https://resource.example";
    o.SigningKeys["key-1"] = resourceKey;
});

var app = builder.Build();

app.UseAAuthVerification(new AAuthVerificationOptions
{
    ResourceIdentifier = "https://resource.example",
    RequireIssuerVerification = true,
});
```

## What It Verifies

1. **HTTP Signature (RFC 9421)**: Validates `Signature`, `Signature-Input`, and `Signature-Key` headers. Confirms covered components (`@method`, `@authority`, `@path`, `signature-key`) match the request.

2. **Signature-Key Resolution**: Parses the scheme (`jwt`, `hwk`, `jkt-jwt`, `jwks_uri`) and resolves the public key accordingly.

3. **JWT Issuer Verification** (when `RequireIssuerVerification = true`): Fetches the issuer's JWKS via metadata discovery and verifies the token's signature against the issuer's published keys.

## Options

```csharp
public sealed class AAuthVerificationOptions
{
    // The resource's own identifier (used for audience checks).
    // When null, audience validation is skipped entirely.
    public string? ResourceIdentifier { get; init; }

    // Whether to verify JWT signatures against the issuer's JWKS (default: true)
    public bool RequireIssuerVerification { get; init; } = true;

    // Optional allow-list of trusted agent provider issuers.
    // null = accept any verifiable AP; empty = deny all; non-empty = restrict.
    public IReadOnlySet<string>? TrustedAgentProviderIssuers { get; init; }

    // Optional predicate AND-composed with TrustedAgentProviderIssuers.
    public Func<string, bool>? IsTrustedAgentProviderIssuer { get; init; }

    // Allow-list of trusted auth token issuers (Person Servers / Access Servers).
    // null = accept any *verifiable* PS (the spec default — the JWT signature
    // still verifies against the issuer's JWKS); empty = deny all; non-empty =
    // restrict to the listed issuers. AND-composed with IsTrustedAuthTokenIssuer.
    public IReadOnlySet<string>? TrustedAuthTokenIssuers { get; init; }

    // Optional predicate AND-composed with TrustedAuthTokenIssuers (each only
    // narrows). Assign AAuthTrust.Any to trust any verifiable issuer explicitly.
    public Func<string, bool>? IsTrustedAuthTokenIssuer { get; init; }

    // Maximum depth of nested act claims (default: 10)
    public int MaxActDepth { get; init; } = 10;

    // Tolerance for exp/iat validation (default: 30s)
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(30);

    // Maximum future skew for HTTP signature timestamps (default: 5s)
    public TimeSpan MaxFutureSkew { get; init; } = TimeSpan.FromSeconds(5);

    // Clock source for all time checks (null = UtcNow; inject for testing)
    public Func<DateTimeOffset>? Clock { get; init; }
}
```

### Behavior by Configuration

| `RequireIssuerVerification` | `ResourceIdentifier` | Effect |
|:--:|:--:|:--|
| `true` | set | Full verification: HTTP sig + JWT issuer JWKS + aud + PoP + agent |
| `true` | `null` | Verifies JWT issuer sig + PoP, but skips `aud` check |
| `false` | any | HTTP signature only — no JWT issuer verification |

> **Auth-token issuer trust is open by default, narrowed by policy.** This is a
> two-layer model. `RequireIssuerVerification` is the crypto gate (unchanged):
> when `true`, an auth token's `iss` JWKS signature must verify. The trust policy
> only *narrows* that verifiable floor — "accept any PS" means "any PS whose
> signature verifies"; the policy never replaces verification.
>
> - `TrustedAuthTokenIssuers = null` (unset) ⇒ accept any *verifiable* Person
>   Server, namespaced by `iss` (the AAuth spec default).
> - empty set ⇒ deny all PS-asserted tokens (a deliberate kill-switch).
> - non-empty set ⇒ restrict to the listed issuers.
> - `IsTrustedAuthTokenIssuer` ⇒ a `Func<string, bool>` predicate AND-composed
>   with the set (each only narrows). Assign `AAuthTrust.Any` to trust any
>   verifiable issuer explicitly and suppress the open-trust startup warning.
>
> ```csharp
> app.UseAAuthVerification(new AAuthVerificationOptions
> {
>     ResourceIdentifier = "https://api.example.com",
>     RequireIssuerVerification = true,
>     TrustedAuthTokenIssuers = new HashSet<string> { "https://person.example.com" },
> });
> ```
>
> Two startup guards (diagnostics only — neither changes runtime behavior): when
> issuer verification is on and no trust policy is configured, a `Warning` is
> logged because the resource accepts any verifiable PS; and configuring a trust
> policy while `RequireIssuerVerification == false` throws
> `InvalidOperationException` (the policy would otherwise be silently ignored).
>
> **False positive on signature-only resources.** A resource that uses `UseAAuth`
> with **only** `RequireAAuthSignature` endpoints (no auth-token / `RequireAAuth`
> endpoints) and no auth-token trust policy still logs the open-trust `Warning` —
> the SDK can't tell at startup whether any auth-token endpoint exists, so it warns
> conservatively. It is benign. Suppress it by assigning any policy — e.g.
> `o.IsTrustedAuthTokenIssuer = AAuthTrust.Any` — to declare the unused auth-token
> path intentionally open.
>
> Signature-only flows (`hwk` / `jkt-jwt` / `jwks_uri`) carry no `iss`
> assertion and are unaffected by this allow-list.

### Subject namespacing by asserting PS

The canonical user identity is the **`(iss, sub)` pair**: the same `sub` value
asserted by two different Person Servers denotes two different users. Every
PS-asserted identity claim the handler emits (`NameIdentifier`, `Role`,
`aauth:group`) carries `Claim.Issuer == iss` for provenance, and a composite
`aauth:sub_iss` (`{iss}|{sub}`) claim is surfaced so resources can match a local
user record on the full key rather than on `sub` alone.

Each endpoint declares its access mode on the route — `.RequireAAuth(...)` for
auth-token (three-party / four-party) endpoints and `.RequireAAuthSignature(...)`
for signature-only (identity-based) endpoints. A single `UseAAuth` placed after
`UseRouting` then runs the right verification (and, for auth-token endpoints, the
challenge) for each matched endpoint from its metadata — no per-path `UseWhen`
branching. This is the pattern the Profile and Calendar samples use:

```csharp
app.UseRouting();

// One pipeline for every signing mode. Resource-level config is trust only;
// key and issuer default from the DI-registered metadata.
app.UseAAuth(o => o.TrustedAuthTokenIssuers = trustedPersonServers);

app.UseAuthentication();
app.UseAuthorization();

// Pseudonymous (hwk) / agent-identity (jwks_uri) — signature only, no JWT verification.
app.MapGet("/pseudonymous", handler).RequireAAuthSignature();
app.MapGet("/identified", handler).RequireAAuthSignature(identified: true);

// Three-party (jwt) — full issuer + audience verification, plus a per-endpoint
// challenge requesting the scope this route protects.
app.MapGet("/events", handler).RequireAAuth(scope: "calendar.read");
app.MapGet("/events/write", handler).RequireAAuth(scope: "calendar.write");
```

After routing, `UseAuthentication`/`UseAuthorization` run globally and each route's
`.RequireAAuth(...)` policy decides what it requires.

See `samples/MockResourceServers/` for the complete working examples.

## Verification Result

After successful verification, the middleware stores an `AAuthVerificationResult` in `HttpContext.Features`:

```csharp
app.MapGet("/protected", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;
    // result.Level: Pseudonymous | Identified | Authorized
    // result.Scheme: "jwt" | "hwk" | "jkt-jwt" | "jwks_uri"
    // result.Agent: agent identifier
    // result.Scopes: granted scopes (auth tokens only)
    // result.Roles: enterprise roles from the auth token (IReadOnlySet<string>)
    // result.Groups: enterprise groups from the auth token (IReadOnlySet<string>)
    // result.IssuerVerified: whether JWKS verification passed
    // result.Jkt: key thumbprint
});
```

`Roles` and `Groups` are populated from the verified auth token's `roles` and
`groups` claims and are empty for signature-only or agent-token requests. The
authentication handler maps `Roles` to the standard `ClaimTypes.Role` claim and
emits one `aauth:group` claim per group.

## Error Responses

On verification failure, the middleware returns `401 Unauthorized` with a `Signature-Error` header:

| Error Code | Meaning |
|------------|---------|
| `invalid_request` | Missing required signature headers |
| `invalid_input` | Covered components don't match the required set (see the `required_input` parameter) |
| `invalid_signature` | Signature verification failed |
| `unsupported_algorithm` | Signature algorithm not supported |
| `invalid_key` | Signature key malformed or unusable |
| `unknown_key` | Referenced key could not be resolved |
| `invalid_jwt` | JWT parsing/issuer verification failed |
| `expired_jwt` | Token JWT expired |

## OpenTelemetry Integration

When `Activity.Current` is present, the middleware enriches it with tags. See [Observability](../advanced/observability.md).

## Call Chaining Verification

When verifying auth tokens from call-chaining scenarios, the middleware validates the optional nested `act` chain:

- the HTTP request signer's agent identity is the token's top-level `agent` claim
- `act` is OPTIONAL (absent for direct authorization); when present, `act.agent` names the upstream delegator
- Nested `act` depth cannot exceed `MaxActDepth` (default 10)
- Each nested level must contain an `agent` field

The `UpstreamAuthTokenFeature` is set on the HttpContext when a valid auth token is verified, making the upstream token available to downstream `WithCallChaining(httpContext)` calls:

```csharp
app.UseAAuthVerification(new AAuthVerificationOptions
{
    ResourceIdentifier = "https://concierge.example",
    RequireIssuerVerification = true,
    MaxActDepth = 5,              // limit chain depth for this resource
    ClockSkew = TimeSpan.FromSeconds(60), // generous skew for distributed systems
});

app.MapGet("/", async (HttpContext ctx) =>
{
    // Middleware verified the auth token and set the feature.
    // WithCallChaining reads the upstream token from it automatically.
    using var client = new AAuthClientBuilder(myKey)
        .WithTokenRefresh(refreshFunc)
        .WithCallChaining(ctx)
        .Build();

    return await client.GetStringAsync("https://downstream.example");
});
```

## Egress Admission (SSRF Prevention)

When verifying `jwks_uri` (and any issuer metadata it is discovered from), the
verifier fetches a URL controlled by the asserted signer. An unconstrained
verifier can be induced to fetch attacker-chosen internal URLs (SSRF). Per
[`draft-hardt-httpbis-signature-key-05`](../../aauth-spec/v08/draft-hardt-httpbis-signature-key-05.txt)
§6.3, apply **egress admission** before any outbound fetch. This is a
deployment-level control (HTTP stack, network policy, firewall), not signature
logic:

- Require HTTPS for all outbound fetches.
- Enforce response-size and timeout limits.
- Refuse or constrain redirects — at minimum, do not follow redirects to a
  different host.
- Reject private, loopback, and link-local destination addresses unless a
  deployment explicitly allows them.
- Defend against DNS rebinding by pinning the resolved IP for the connection.
- Treat a cross-origin `jwks_uri` (JWKS host ≠ metadata host) as requiring
  explicit deployment admission.

The SDK relies on the host's `HttpClient`/network policy for these controls;
configure them in the resource's deployment rather than per request.
