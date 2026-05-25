# Call Chaining

Call chaining enables multi-hop delegation where a resource acts as an agent to downstream resources, preserving the full authorization chain via nested `act` claims.

## Scenario

```
Agent A → Orchestrator (Resource B) → WhoAmI (Resource C)
```

1. Agent A calls Resource B with an agent token → Resource B challenges with a resource token
2. Agent A exchanges at PS → gets an auth token for Resource B
3. Agent A retries with auth token → Resource B accepts
4. Resource B calls Resource C with its own agent token → Resource C challenges
5. Resource B exchanges at PS with `upstream_token` = Agent A's auth token
6. PS mints a chained auth token with nested `act` → Resource B retries
7. Resource C sees the full delegation chain in the `act` claim

## Running the Sample

```bash
make demo-sample   # starts WhoAmI, PS, AP, Orchestrator, SampleApp
```

Then open <http://localhost:5240/call-chain> to see the flow in action.
The Orchestrator runs on port 5200, acting as both resource (verifies callers) and agent (calls WhoAmI on port 5000).

## SDK Support

### Client Side — Challenge Handling (Transparent)

The calling agent uses standard challenge handling. The SDK automatically handles the 401 → exchange → retry cycle:

```csharp
using var client = new AAuthClientBuilder(key)
    .WithTokenRefresh(async (ctx, ct) =>
    {
        var ap = new AgentProviderClient(new HttpClient(), keyStore);
        return await ap.RefreshAsync(refreshEndpoint, keyId, ct);
    })
    .WithChallengeHandling(personServer)
    .Build();

// The Orchestrator challenges with 401 + resource token.
// SDK handles the exchange transparently.
var response = await client.GetAsync("https://orchestrator.example");
```

### Intermediate Service — Simplified API

An intermediate service registers `UseAAuthIntermediary` once and builds a
downstream client with `WithCallChaining(HttpContext)`. The SDK handles
the entire flow — incoming verification, agent-token challenge, downstream
challenge, `upstream_token` exchange, and retry — with no manual JWT
inspection, header parsing, or second-client construction.

```csharp
// 1. Server-side: verification + auto-challenge in spec-compliant order.
app.UseAAuthIntermediary(
    new AAuthVerificationOptions
    {
        ResourceIdentifier = orchestratorUrl,
        RequireIssuerVerification = true,
    },
    new ChallengeOptions
    {
        AccessMode        = AAuthAccessMode.RequireAuthToken,
        ResourceSigningKey = orchestratorKey,
        ResourceKeyId     = "orch-1",
        ResourceIdentifier = orchestratorUrl,
        DefaultScopes     = "orchestrate",
    });

// 2. Endpoint: only reached with a verified aa-auth+jwt caller.
app.MapGet("/", async (HttpContext ctx) =>
{
    using var downstream = new AAuthClientBuilder(myAgentKey)
        .WithTokenRefresh(refreshFunc)
        .WithChallengeHandling()
        .WithCallChaining(ctx)         // ← auto-forwards upstream_token
        .Build();

    var response = await downstream.GetAsync(downstreamUrl);
    return Results.Ok(await response.Content.ReadAsStringAsync());
});
```

Under the hood, `WithCallChaining(ctx)` reads the verified upstream auth
token from `HttpContext.Features` (set by the verification middleware),
routes the exchange via `CallChainingRouter` per §Call Chaining of the
spec, and passes the upstream token as `upstream_token` so the PS builds
the nested `act` chain (§Upstream Token Verification).

> **Mission propagation:** `WithCallChaining` does not synthesize or
> strip the `AAuth-Mission` header. Mission context is conveyed by the
> upstream auth token's `mission.approver` / `mission.s256` claims and by
> the application's own outbound header emission policy. Mission-aware
> intermediaries are responsible for emitting `AAuth-Mission` on
> outbound requests when their application semantics require it.

### Lower-Level Building Blocks

If you need to drive the chained exchange manually (for example, to
combine it with custom retry/transport logic), the SDK exposes:

```csharp
// Pure-function routing per §Call Chaining (mission.approver else iss).
var target = CallChainingRouter.ResolveDownstreamServer(upstreamAuthToken);

// One-shot helper that wraps TokenExchangeClient with the right routing
// + upstream_token plumbing + 202/interaction propagation.
var helper = new CallChainingHandler(exchangeClient, options);
var chained = await helper.ExchangeForDownstreamAsync(
    upstreamAuthToken,
    resourceToken,
    onInteractionRequired: async (interaction, ct) => { /* display URL */ });
```

### UseJwt — Presenting a Pre-Acquired Token

When code already holds a token (from a prior exchange or out-of-band
issuance), use `UseJwt` to present it directly without token refresh:

```csharp
// UseJwt(string) — static token
using var client = new AAuthClientBuilder(key)
    .UseJwt(chainedAuthToken)
    .Build();

// UseJwt(Func<string>) — dynamic token
using var client = new AAuthClientBuilder(key)
    .UseJwt(() => GetLatestToken())
    .Build();
```

### Token Exchange with upstream_token

When calling `TokenExchangeClient.ExchangeAsync` directly, pass the
upstream auth token via the `upstreamToken` parameter:

```csharp
var exchange = new TokenExchangeClient(signedClient, metadata);
var downstreamToken = await exchange.ExchangeAsync(
    personServer: "https://ps.example",
    resourceToken: resourceToken,
    onInteractionRequired: null,
    pollerOptions: null,
    upstreamToken: incomingAuthToken); // preserves delegation chain
```

The SDK includes the upstream token as `upstream_token` in the POST body to the PS token endpoint.

### Auth Token Builder — Nested Act Claims

When an auth token carries delegation context, the `act` claim is nested:

```json
{
  "iss": "https://ps.example",
  "sub": "pairwise-sub",
  "agent": "aauth:orchestrator@ap.example",
  "act": {
    "sub": "aauth:orchestrator@ap.example",
    "act": {
      "sub": "aauth:agent-a@ap.example"
    }
  }
}
```

The `AuthTokenBuilder` supports this via `UpstreamAct`:

```csharp
var token = new AuthTokenBuilder
{
    Issuer = psIssuer,
    Audience = downstreamResource,
    Agent = resourceBAgent,
    AgentConfirmationKey = resourceBKey,
    Key = psKey,
    KeyId = "ps-key-1",
    Scope = "downstream:read",
    UpstreamAct = upstreamActClaim, // nested JsonObject
}.Build();
```

## AgentConsole Support

Pass `--upstream-token` to include an upstream auth token in the exchange:

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000 \
  --ap http://localhost:5301 --ps http://localhost:5100 \
  --upstream-token "eyJ..."
```

Or test the full call chain through the Orchestrator:

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5200 \
  --ap http://localhost:5301 --ps http://localhost:5100
```

## Verification at the Final Resource

The final resource (WhoAmI) validates the chained auth token using standard middleware with `RequireIssuerVerification = true`. The middleware verifies:

- JWT signature against the PS's JWKS
- `aud` matches the resource's identifier
- `cnf.jwk` matches the request signing key (PoP binding)
- `act.sub` matches the presenting agent

The `act` claim is available in the response for audit/logging purposes but is not verified recursively — that responsibility lies with the PS that minted the token.
