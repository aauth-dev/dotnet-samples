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

app.UseAAuthVerification();
```

The options start with the registered `MetadataClient`'s egress policy, then apply
any `services.Configure<AAuthVerificationOptions>(...)` registrations, then the
delegate passed here. `AddAAuthResource` sets `ResourceIdentifier` to its
`Issuer` unless you set one explicitly, so auth-token and person-token `aud` is
always checked against this resource.

## What It Verifies

1. Parse matching dictionary labels and validate required components and timestamps.
2. Apply the endpoint's scheme policy and resolve key material. For JWT carriers,
    verify the expected token type, issuer signature and claims before using `cnf.jwk`.
3. Verify the HTTP signature in covered-component order, including `expires`,
    key binding and required additional fields. Ignore the signature `alg` parameter.
4. Apply issuer and endpoint authorization policy. A valid auth token that is
   missing the endpoint scope is stepped up with `401 requirement=auth-token`;
   other authorization denials are 403s with no signature-error or
   signature-negotiation headers.

## Options

```csharp
public sealed class AAuthVerificationOptions
{
    // The resource's own identifier; auth-token and person-token `aud` must equal it.
    // AddAAuthResource derives it from its Issuer. When no identifier is known,
    // auth and person tokens are rejected (Signature-Error: invalid_request).
    public string? ResourceIdentifier { get; init; }

    public IReadOnlyList<string> AcceptedSchemes { get; init; } = ["jwt"];
    public string SignatureLabel { get; init; } = "sig";
    public IReadOnlyCollection<string> RequiredComponents { get; init; } = [];

    // Agent Provider, auth-token issuer and person-token issuer trust. Unset rules
    // accept any *verifiable* issuer (the spec default — the JWT signature still
    // verifies against the issuer's JWKS); an empty Allowed set denies all.
    public AAuthTrustOptions Trust { get; init; } = new();

    // Tolerance for optional future iat validation; exp has zero tolerance (default: 30s)
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(30);

    // Clock source for all time checks (default: TimeProvider.System; inject for testing)
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}
```

### Behavior by Configuration

| Scheme Policy | `ResourceIdentifier` | Effect |
|:--:|:--:|:--|
| Default `jwt` | set | Issuer JWT, audience, confirmation binding and HTTP signature |
| Default `jwt` | `null` | Agent tokens verify; auth and person tokens are rejected with `invalid_request` |
| Explicit generic schemes | any | Scheme-specific verified resolution; JWT trust remains mandatory |

> **Auth-token issuer trust is open by default, narrowed by policy.** This is a
> two-layer model. An auth token's issuer JWKS signature must verify. The trust policy
> only *narrows* that verifiable floor — "accept any PS" means "any PS whose
> signature verifies"; the policy never replaces verification.
>
> - `Trust.AuthTokenIssuers` unset ⇒ accept any *verifiable* Person
>   Server, namespaced by `iss` (the AAuth spec default).
> - empty `Allowed` set ⇒ deny all PS-asserted tokens (a deliberate kill-switch).
> - non-empty `Allowed` set ⇒ restrict to the listed issuers.
> - `Predicate` / `PredicateAsync` ⇒ predicates AND-composed
>   with the set (each only narrows). Assign `AAuthTrust.Any` to trust any
>   verifiable issuer explicitly and suppress the open-trust startup warning.
> - `Trust.Policy`, or an `IAAuthTrustPolicy` registered in DI, replaces the rules;
>   `.RequireAAuth(scope, trust: policy)` replaces the resource-wide trust for one endpoint.
>
> ```csharp
> app.UseAAuthVerification(options =>
> {
>     options.ResourceIdentifier = "https://api.example.com";
>     options.Trust.AuthTokenIssuers.Allowed = new HashSet<string> { "https://person.example.com" };
> });
> ```
>
> With no explicit trust policy, a startup warning identifies open issuer trust.
> There is no option to accept unverified JWT issuer assertions.
>
> **False positive on signature-only resources.** A resource that uses `UseAAuth`
> with **only** `RequireAAuthSignature` endpoints (no auth-token / `RequireAAuth`
> endpoints) and no auth-token trust policy still logs the open-trust `Warning` —
> the SDK can't tell at startup whether any auth-token endpoint exists, so it warns
> conservatively. It is benign. Suppress it by assigning any policy — e.g.
> `o.Trust.AuthTokenIssuers.Predicate = AAuthTrust.Any` — to declare the unused auth-token
> path intentionally open.
>
> Generic HWK/direct-JWKS/naming-JWT/server-discovery profiles do not assert a
> PS authorization grant. Naming JWTs still require their own JWT validation;
> server-discovery `id` must match admitted metadata. The auth-token issuer
> allow-list is not a substitute for those checks.

### Subject namespacing by asserting PS

The canonical user identity is the **`(iss, sub)` pair**: the same `sub` value
asserted by two different Person Servers denotes two different users. Every
PS-asserted identity claim the handler emits (`NameIdentifier`, `Role`,
`aauth:group`) carries `Claim.Issuer == iss` for provenance, and a composite
`aauth:sub_iss` (`{iss}|{sub}`) claim is surfaced so resources can match a local
user record on the full key rather than on `sub` alone.

Each endpoint declares its access mode on the route — `.RequireAAuth(...)` for
auth-token (three-party / four-party) endpoints and `.RequireAAuthSignature(...)`
for identity-level proof endpoints. Generic carriers require explicit generic
profile configuration; ordinary AAuth identity access still uses an agent JWT.
A single `UseAAuth` placed after
`UseRouting` then runs the right verification (and, for auth-token endpoints, the
challenge) for each matched endpoint from its metadata — no per-path `UseWhen`
branching. This is the pattern the Profile and Calendar samples use:

```csharp
app.UseRouting();

// One pipeline for every signing mode. Resource-level config is trust only;
// key and issuer default from the DI-registered metadata.
app.UseAAuth(o => o.Trust.AuthTokenIssuers.Allowed = trustedPersonServers);

app.UseAuthentication();
app.UseAuthorization();

// Identity-level routes still validate any presented JWT assertion.
app.MapGet("/pseudonymous", handler).RequireGenericSignature();
app.MapGet("/identified", handler).RequireGenericSignature(identified: true);

// Three-party (jwt) — full issuer + audience verification, plus a per-endpoint
// challenge requesting the scope this route protects. A narrower auth token can
// be stepped up with a new resource token for that scope.
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
    // result.Agent: agent identifier (agent tokens only; person and auth tokens name no agent)
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
| `revoked_jwt` | The token's `(iss, jti)` was revoked, including a revocation recorded before the token was first seen |

The PS and AS token endpoints answer a revoked `Signature-Key` token the same way.

## OpenTelemetry Integration

When `Activity.Current` is present, the middleware enriches it with tags. See [Observability](../advanced/observability.md).

## Call Chaining Verification

Draft-11 has no delegation chain claim: an auth token names the person
(`ps`, `sub`) and binds the agent's key through `cnf.jwk`, with no `agent` or
`act` claim. The token a calling agent presents to an intermediary is the
**upstream token** for the intermediary's downstream requests (§Call Chaining).

The `UpstreamAuthTokenFeature` is set on the HttpContext when a valid person or
auth token is verified under the `jwt` scheme, making the upstream token
available to downstream `WithCallChaining(httpContext)` calls. The downstream PS
verifies it as `upstream_token` (its `aud` must be the intermediary's agent-token
`iss`):

```csharp
app.UseAAuthVerification(options =>
{
    options.ResourceIdentifier = "https://concierge.example";
    options.ClockSkew = TimeSpan.FromSeconds(60); // generous iat skew for distributed systems; exp has zero tolerance
});

app.MapGet("/", async (HttpContext ctx) =>
{
    // Middleware verified the person or auth token and set the feature.
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
[`draft-hardt-httpbis-signature-key-09`](../../aauth-spec/v11/draft-hardt-httpbis-signature-key-09.txt)
§7.3, apply **egress admission** before any outbound fetch. This is a
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
