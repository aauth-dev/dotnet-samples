# Challenge Middleware

`AAuthChallengeMiddleware` automatically issues 401 challenges with resource tokens when an agent presents only an agent token but the resource requires an auth token.

> **Prefer the high-level pipeline for the common case.** `app.UseAAuth(...)` after
> `app.UseRouting()` runs this challenge middleware internally for every endpoint
> marked with `.RequireAAuth(...)`, minting a resource token that requests exactly
> that endpoint's scope. Use `UseAAuthChallenge` directly only when composing a
> custom, low-level pipeline.

## Registration

```csharp
using AAuth;
using AAuth.Server.Challenge;
using AAuth.Server.Verification;

// Must be registered AFTER UseAAuthVerification
app.UseAAuthChallenge(new ChallengeOptions
{
    AccessMode = AAuthAccessMode.RequireAuthToken,
});
```

## Access Modes

```csharp
public enum AAuthAccessMode
{
    // Accept any verified identity without requiring auth token
    IdentityOnly,

    // Require auth token — issue 401 challenge if only agent token present
    RequireAuthToken,

    // Resource manages authorization itself (two-party) — challenge middleware
    // passes through; endpoints issue/validate the AAuth-Access opaque token
    ResourceManaged,
}
```

## How It Works

1. `UseAAuthVerification` runs first and stores `AAuthVerificationResult` in features
2. If `AccessMode` is `RequireAuthToken` and the token is an agent token (not auth token):
   - Middleware mints a resource token (`aa-resource+jwt`) scoped to the request
   - Returns `401 Unauthorized` with `AAuth-Requirement: requirement=auth-token; resource-token="<jwt>"`
3. The agent's `ChallengeHandler` catches the 401, exchanges the resource token at its PS, and retries

## Challenge Options

```csharp
public sealed class ChallengeOptions
{
    // How to handle access decisions
    public AAuthAccessMode AccessMode { get; init; } = AAuthAccessMode.RequireAuthToken;

    // Resource signing key for minting resource tokens
    public AAuthKey? ResourceSigningKey { get; init; }

    // Key identifier for the resource signing key (kid in the resource token header)
    public string? ResourceKeyId { get; init; }

    // Resource identifier (used as iss in the resource token)
    public string? ResourceIdentifier { get; init; }

    // Explicit audience for resource tokens (e.g. the AS URL in a four-party flow).
    // When null, audience is resolved from the agent token's ps claim (three-party).
    public string? PersonServerAudience { get; init; }

    // Default scopes to request in the resource token (space-separated)
    public string? DefaultScopes { get; init; }

    // Allowed Signature-Key schemes (null = allow all)
    public IReadOnlySet<string>? AllowedSignatureKeySchemes { get; init; }

    // When true, copy the AAuth-Mission header's mission object into the
    // issued resource token so the mission context flows to the PS (default false)
    public bool MissionAware { get; init; }
}
```

## Mission-Aware Resources

Set `MissionAware = true` to make the resource carry mission context forward. When
a challenged request includes a valid `AAuth-Mission` header, the issued resource
token includes the mission object (`approver` + `s256`), so the mission reaches the
PS even when the resource is not the approver (§Terminology). When `false` (the
default) the header is ignored.

```csharp
app.UseAAuthChallenge(new ChallengeOptions
{
    AccessMode = AAuthAccessMode.RequireAuthToken,
    ResourceSigningKey = resourceKey,
    ResourceIdentifier = resourceUrl,
    MissionAware = true, // copy AAuth-Mission into the resource token
});
```

See [Missions](../advanced/missions.md#the-binding-chain) for how the mission
claim threads through the tokens, and
[Token Issuance](token-issuance.md#mission-claims) for the claim itself.

## Typical Pipeline

> This is the low-level composition that `app.UseAAuth(...)` runs internally for
> each `.RequireAAuth(...)` endpoint. Prefer `UseRouting` + `UseAAuth` +
> `.RequireAAuth(...)` for the common case; reach for the two middleware directly
> only for fully custom pipelines.

```csharp
app.UseAAuthVerification(new AAuthVerificationOptions
{
    ResourceIdentifier = "https://resource.example",
    RequireIssuerVerification = true,
});

app.UseAAuthChallenge(new ChallengeOptions
{
    AccessMode = AAuthAccessMode.RequireAuthToken,
});

// Endpoints below here see only authorized requests
app.MapGet("/data", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;
    // result.Level == AAuthLevel.Authorized
});
```

## Per-Endpoint Scope Challenges

With the high-level pipeline, the scope each endpoint challenges for is declared on
the endpoint itself with `.RequireAAuth(scope: ...)`. The single `UseAAuth`
middleware mints a resource token requesting exactly that scope when only an agent
token is presented. This is the pattern the Calendar sample uses: `/events`
challenges for `calendar.read`, while the step-up `/events/write` endpoint
challenges for `calendar.write`.

```csharp
app.UseRouting();
app.UseAAuth(o => o.TrustedAuthTokenIssuers = trustedPersonServers);
app.UseAuthentication();
app.UseAuthorization();

// /events — three-party baseline. Challenges for the base scope.
app.MapGet("/events", handler).RequireAAuth(scope: "calendar.read");

// /events/write — step-up. Challenges for the elevated scope.
app.MapGet("/events/write", handler).RequireAAuth(scope: "calendar.write");
```

Because each endpoint declares its own scope, an agent that lacks the required scope
receives a challenge for that endpoint's scope and re-exchanges at its PS for an
auth token carrying it. See `samples/MockResourceServers/Calendar` for the full set
of endpoints.
