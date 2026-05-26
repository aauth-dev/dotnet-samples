# Call-Chaining SDK — API Design

## Intermediary Server Setup (Complete Example)

```csharp
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var orchestratorUrl = "https://orchestrator.example";
var orchestratorKey = EdDsaAAuthKey.Generate();

// ─── Well-known metadata (MUST per §Call Chaining Identity) ─────────
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions { /* ... */ });
app.MapAAuthAgentWellKnown(new AAuthAgentMetadataOptions
{
    Issuer  = orchestratorUrl,
    JwksUri = $"{orchestratorUrl}/.well-known/jwks.json",
});
// Also available: MapAAuthPersonServerWellKnown, MapAAuthAccessServerWellKnown

// ─── Intermediary middleware ────────────────────────────────────────
// Composes UseAAuthVerification + UseAAuthChallenge in spec order.
// Agent tokens get a 401 + resource token; only verified aa-auth+jwt
// requests reach your endpoint handlers.
app.UseAAuthIntermediary(
    new AAuthVerificationOptions
    {
        ResourceIdentifier       = orchestratorUrl,
        RequireIssuerVerification = true,
        // Phase 11 — tune verification behavior:
        MaxActDepth   = 10,                         // default; defensive chain depth limit
        ClockSkew     = TimeSpan.FromSeconds(30),   // default; token temporal tolerance
        MaxFutureSkew = TimeSpan.FromSeconds(5),    // default; signature drift tolerance
    },
    new ChallengeOptions
    {
        AccessMode         = AAuthAccessMode.RequireAuthToken,
        ResourceSigningKey = orchestratorKey,
        ResourceKeyId      = "orch-1",
        ResourceIdentifier = orchestratorUrl,
        DefaultScopes      = "orchestrate",
    });

// ─── Endpoint ───────────────────────────────────────────────────────
app.MapGet("/", async (HttpContext ctx) =>
{
    using var downstream = new AAuthClientBuilder(myAgentKey)
        .WithTokenRefresh(refreshFunc)
        .WithCallChaining(ctx)          // implicitly enables challenge handling
        .Build();

    var response = await downstream.GetAsync("https://downstream.example/data");
    return Results.Ok(await response.Content.ReadAsStringAsync());
});

app.Run();
```

## Key APIs

### `UseAAuthIntermediary`

```csharp
public static IApplicationBuilder UseAAuthIntermediary(
    this IApplicationBuilder app,
    AAuthVerificationOptions verificationOptions,
    ChallengeOptions challengeOptions);
```

Registers verification and auto-challenge middleware in the correct order.
After this call, endpoint handlers are guaranteed to receive only verified
`aa-auth+jwt` callers.

### `WithCallChaining` (3 overloads)

```csharp
// From HttpContext (most common for ASP.NET Core intermediaries):
builder.WithCallChaining(HttpContext httpContext);

// From a captured token string:
builder.WithCallChaining(string upstreamAuthToken);

// From a delegate (lazy evaluation):
builder.WithCallChaining(Func<string?> upstreamTokenProvider);
```

When a downstream resource returns a 401 challenge, the SDK:

1. Resolves the PS/AS via `CallChainingRouter` (§Call Chaining routing rules).
2. Exchanges the resource token at that PS/AS with `upstream_token` in the body.
3. Signs the exchange request with the intermediary's own agent key.
4. Retries the downstream request with the chained auth token.

### `CallChainingRouter.ResolveDownstreamServer`

```csharp
public static class CallChainingRouter
{
    // Pure function — no network, no side effects.
    public static string ResolveDownstreamServer(string upstreamAuthToken);
}
```

Routing priority:

| # | Condition | Target |
|---|-----------|--------|
| 1 | `mission.approver` present and valid | PS at approver URL |
| 2 | No mission | PS/AS at `iss` claim |

Invalid `mission.approver` throws (fail-fast — never falls through to `iss`).

### `UpstreamAuthTokenFeature`

```csharp
public sealed class UpstreamAuthTokenFeature
{
    public string Token { get; }
}
```

Set on `HttpContext.Features` by the verification middleware when the inbound
request carries a verified `aa-auth+jwt`. Avoids re-parsing `Signature-Key`.

## Lower-Level Usage

For custom retry logic, transport wiring, or manual exchange control:

```csharp
// 1. Read the upstream token from middleware output.
var upstream = ctx.Features.Get<UpstreamAuthTokenFeature>()!.Token;

// 2. Resolve target PS/AS.
var target = CallChainingRouter.ResolveDownstreamServer(upstream);

// 3. Exchange manually.
var handler = new CallChainingHandler(exchangeClient, options);
var chained = await handler.ExchangeForDownstreamAsync(
    upstream,
    resourceTokenFromChallenge,
    onInteractionRequired: async (interaction, ct) =>
    {
        // Propagate 202 back to original caller, or log, etc.
    });

// 4. Present the chained token.
using var client = new AAuthClientBuilder(myKey)
    .UseJwt(chained)
    .Build();
var result = await client.GetAsync(downstreamUrl);
```

## What the SDK Does NOT Do

| Concern | Responsibility |
|---------|---------------|
| Publish `/.well-known/aauth-agent.json` | Deployment / app startup (use `MapAAuthAgentWellKnown`) |
| Propagate 202/interaction back to original caller | Application code (callback provided) |
| Evaluate mission/governance policy (PS step 5) | PS business logic (`UpstreamTokenValidator` provides `UpstreamAct`; policy is PS's responsibility) |
| Synthesize new `AAuth-Mission` headers | Application — SDK only forwards existing mission context |

## PS-Side Helpers

### `UpstreamTokenValidator`

For PS implementers receiving `upstream_token` in a call-chaining exchange:

```csharp
var validator = new UpstreamTokenValidator(jwksClient, tokenVerifier);

var result = await validator.ValidateAsync(
    upstreamToken,
    expectedAudience: "https://orchestrator.example",  // intermediary's URL
    trustedIssuers: new HashSet<string> { "https://as.example" });

if (!result.IsValid)
    return Results.Json(new { error = result.Error }, statusCode: 400);

// Build downstream auth token with nested act chain:
var downstream = new AuthTokenBuilder
{
    Issuer = psUrl,
    Audience = downstreamResourceUrl,
    Agent = intermediaryAgentId,
    UpstreamAct = result.UpstreamAct,   // ← nests the full chain
    // ...
}.Build();
```

### `ActChainReader`

Utility to walk and extract the full delegation chain from auth tokens:

```csharp
// Get the full chain (outermost → innermost):
var chain = ActChainReader.GetDelegationChain(authTokenPayload);
// → ["orchestrator-id", "original-agent-id"]

// Get the original requester (deepest nested act.sub):
var original = ActChainReader.GetOriginalActor(authTokenPayload);

// Get chain depth (1 = direct, 2+ = chained):
var depth = ActChainReader.GetChainDepth(authTokenPayload);
```

## AAuth-Mission Forwarding

When an upstream auth token contains `mission.approver`, the intermediary should
forward the mission context to downstream resources. The SDK provides an opt-in
handler:

```csharp
using var downstream = new AAuthClientBuilder(myAgentKey)
    .WithCallChaining(ctx)
    .WithMissionForwarding()   // auto-emits AAuth-Mission when mission.approver present
    .Build();
```

`MissionForwardingHandler` reads the upstream auth token's `mission` claim and
emits a structured `AAuth-Mission` header on outbound requests. It only
**forwards** existing mission context — it never synthesizes new missions.

## Configuration Surface

All behavioral settings are exposed through options classes so consumers can tune
defaults without reaching into internal components.

### Server-Side (Verification)

```csharp
new AAuthVerificationOptions
{
    ResourceIdentifier       = "https://my-resource.example",
    RequireIssuerVerification = true,

    // Tuning — all have sensible defaults:
    MaxActDepth   = 10,                         // max nested act claim depth
    ClockSkew     = TimeSpan.FromSeconds(30),   // token exp/nbf tolerance
    MaxFutureSkew = TimeSpan.FromSeconds(5),    // signature timestamp drift
    Clock         = null,                       // inject for deterministic tests
}
```

### Client-Side (Challenge Handling / Interaction Handling)

```csharp
new ChallengeHandlingOptions
{
    // Poller tuning:
    MinPollInterval    = TimeSpan.FromMilliseconds(100),  // floor for poll backoff
    DefaultPollInterval = TimeSpan.FromSeconds(5),
    PollingTimeout     = TimeSpan.FromMinutes(5),
    PreferWaitSeconds  = 45,                             // Prefer: wait=N header
    OnPoll             = (attempt, elapsed) => { /* observability */ return Task.CompletedTask; },
}

// InteractionHandlingOptions has full parity with the above poller settings.
```

### Clock Injection (Testing)

All components accept a shared `Clock` function for deterministic tests:

```csharp
var testClock = () => new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

new AAuthVerificationOptions { Clock = testClock }
// Clock threads through to TokenVerifier.Clock and AAuthVerifier.Clock
```
