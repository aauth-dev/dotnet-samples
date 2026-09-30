# Challenge Middleware

`AAuthChallengeMiddleware` automatically issues 401 challenges when the resource
requires an auth token: an agent token alone is answered with
`requirement=person-token`, and a verified person token is answered with
`requirement=auth-token` and a resource token naming that person token.

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
app.UseAAuthChallenge(options => options.AccessMode = AAuthAccessMode.RequireAuthToken);
```

The options start from any `services.Configure<ChallengeOptions>(...)`
registrations; the delegate then adjusts them for this pipeline.

## Access Modes

```csharp
public enum AAuthAccessMode
{
    // Accept any verified identity without requiring auth token
    IdentityOnly,

    // Require auth token — challenge for a person token, then for an auth token
    RequireAuthToken,

    // Require the agent's own agent token — bare requirement=agent-token otherwise
    AgentTokenRequired,

    // Require a person token — bare requirement=person-token otherwise
    PersonTokenRequired,

    // Resource manages authorization itself (two-party) — challenge middleware
    // passes through; endpoints issue/validate the AAuth-Access opaque token
    ResourceManaged,
}
```

## How It Works

1. `UseAAuthVerification` runs first and stores `AAuthVerificationResult` in features
2. If `AccessMode` is `AgentTokenRequired`, only an AAuth agent token passes;
   person tokens, auth tokens, and generic signatures get
   `401 AAuth-Requirement: requirement=agent-token`.
3. If `AccessMode` is `PersonTokenRequired`, only an AAuth person token passes;
   missing, agent-token, auth-token, and generic callers get
   `401 AAuth-Requirement: requirement=person-token`.
4. If `AccessMode` is `RequireAuthToken`:
   - An **agent token** alone gets `401 Unauthorized` with
     `AAuth-Requirement: requirement=person-token` (§Person Token Required). A
     resource issues a resource token only after it verifies a person or auth
     token, because the resource token names the token it was issued against.
   - A verified **person token** gets a resource token (`aa-resource+jwt`)
     scoped to the request and
     `401 Unauthorized` with `AAuth-Requirement: requirement=auth-token; resource-token="<jwt>"`
     (§Auth Token Required).
   - A verified **auth token** passes through.
5. The agent's `ChallengeHandler` catches each 401: it requests a person token at
   its PS's `person_token_endpoint`, retries, then sends the resource token and
   the person token it presented (`presented_token`) to the PS's
   `auth_token_endpoint`, and retries with the auth token.

The resource token names the presented token: `ps` and `sub` come from it (a
person token's `iss`, an auth token's `ps`), `presented_jti` is its `jti`,
`agent_jkt` is the thumbprint of the key that signed the request, and
`mission_s256` and `tenant` are copied when present. `aud` is the resource's
`AccessServer` (four-party) or the person's PS (three-party). A custom endpoint
can mint the same token from the verified assertion with
`AAuthChallengeMiddleware.BuildResourceTokenAsync(options, presented, scope, ...)`,
which accepts only verified person-token or auth-token assertions and also
accepts an optional `interaction` and `loginHint`.

## Challenge Options

```csharp
public sealed class ChallengeOptions
{
    // How to handle access decisions
    public AAuthAccessMode AccessMode { get; init; } = AAuthAccessMode.RequireAuthToken;

    // Resource signing keys for minting resource tokens; the JWKS publishes
    // every key and resource tokens are signed with the active one (its kid
    // goes in the resource token header)
    public AAuthSigningKeySet? ResourceSigningKeys { get; init; }

    // Resource identifier (used as iss in the resource token)
    public string? ResourceIdentifier { get; init; }

    // The resource's own Access Server (four-party): the resource-token aud.
    // When null, aud is the PS that issued the presented token (three-party).
    public string? AccessServer { get; init; }

    // Default scopes to request in the resource token (space-separated)
    public string? DefaultScopes { get; init; }

    // Accepted Signature-Key schemes are configured on AAuthVerificationOptions.
}
```

## Missions in Resource Tokens

Every resource carries mission context forward; there is no opt-in. When the
presented person or auth token carries `mission_s256`, the challenge middleware
copies it into the resource token, and the PS rejects a resource token whose
`mission_s256` differs from the presented token's (§Resource Token
Verification). There is no mission request header to read.

```csharp
app.UseAAuthChallenge(options =>
{
    options.AccessMode = AAuthAccessMode.RequireAuthToken;
    options.ResourceSigningKeys = new AAuthSigningKeySet(keyId, resourceKey);
    options.ResourceIdentifier = resourceUrl;
    // mission_s256 and tenant are copied from the presented token automatically
});
```

See [Missions](../advanced/missions.md#the-binding-chain) for how `mission_s256`
threads through the tokens, and
[Token Issuance](token-issuance.md#mission-claims) for the claim itself.

## Typical Pipeline

> This is the low-level composition that `app.UseAAuth(...)` runs internally for
> each `.RequireAAuth(...)` endpoint. Prefer `UseRouting` + `UseAAuth` +
> `.RequireAAuth(...)` for the common case; reach for the two middleware directly
> only for fully custom pipelines.

```csharp
app.UseAAuthVerification(options => options.ResourceIdentifier = "https://resource.example");

app.UseAAuthChallenge(options => options.AccessMode = AAuthAccessMode.RequireAuthToken);

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
middleware mints a resource token requesting exactly that scope when a person
token is presented. This is the pattern the Calendar sample uses: `/events`
challenges for `calendar.read`, while the step-up `/events/write` endpoint
challenges for `calendar.write`.

```csharp
app.UseRouting();
app.UseAAuth(o => o.Trust.AuthTokenIssuers.Allowed = trustedPersonServers);
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

## Holding an Invocation (`202` Delivery)

A resource can deliver `requirement=auth-token` as a `202 Accepted` instead of a
`401`. It holds the invocation, and the agent completes it by polling the
pending URL with signed `GET`s. Use this for a non-idempotent call the agent
shouldn't resend. `IAAuthHeldInvocations` does the bookkeeping:

- the first poll that presents a valid auth token for the resource token's
  `agent_jkt` and required scopes runs the invocation, once;
- the result is kept, keyed by that token's `jti`, until the token's `exp`, and
  a repeat of the same token gets it back without running the invocation again;
- a different token after completion gets `410`, and another key gets `404`.

The endpoint declares its operation with `WithHeldInvocation(name, execute)`, and
its handler parks the request with `HoldAsync`, passing the request data the
operation needs as `state`. Only the operation name and that state are stored;
the `execute` delegate stays in process, registered on the endpoint.

```csharp
builder.Services.AddAAuthHeldInvocations();     // pending URLs are /aauth/held/{id}

// After builder.Build():
app.MapPost("/orders", (HttpContext context, IAAuthHeldInvocations held) =>
        held.HoldAsync(context, resourceToken, ["orders.write"], new JsonObject { ["item"] = "hotel" }))
    .WithHeldInvocation("orders", (context, state, ct) =>
        Task.FromResult(HeldInvocationResult.Json(new { order = 1, item = (string?)state?["item"] },
            StatusCodes.Status201Created)));
app.MapAAuthHeldInvocations();                  // behind the resource's AAuth verification
```

The agent side needs no configuration: the challenge handler exchanges the
resource token for an auth token, then polls the `Location`. It never resends
the original request body. The shipped samples keep answering with `401`.

`AddAAuthHeldInvocations(o => ...)` sets `PathPrefix`, `PendingLifetime` (or pass
`pendingLifetime` to `WithHeldInvocation`) and `TimeProvider`. It registers three
seams with `TryAdd`, so an implementation registered first wins:

- `IAAuthHeldInvocationStore` — parked invocations (`InMemoryHeldInvocationStore`);
- `IAAuthSingleUseGate` — one execution per auth-token `jti` and the retained
  result (`InMemorySingleUseGate`);
- `IAAuthHeldInvocations` — the hold and poll logic over the two stores.

The in-memory defaults lose state on restart and are not shared across
instances; `MapAAuthHeldInvocations` logs a warning when they are used outside
Development. To scale out, register shared implementations of both stores before
`AddAAuthHeldInvocations`, and keep operation names unique and stable across
instances.

The gate also enforces R3 per-call single use without a `202`: `ExecuteOnceAsync`
runs once per grant and answers later presentations from the retained result.

```csharp
var gate = app.Services.GetRequiredService<IAAuthSingleUseGate>();
var retained = await gate.ExecuteOnceAsync("auth-token-jti", DateTimeOffset.UtcNow.AddMinutes(5),
    ct => Task.FromResult(HeldInvocationResult.Json(new { confirmed = true })));
IResult reply = retained.ToResult();
```
