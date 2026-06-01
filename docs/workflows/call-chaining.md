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
The Orchestrator runs on port 5200, acting as both resource (verifies callers) and agent (calls WhoAmI's three-party `/jwt` endpoint on port 5000).

## SDK Support

### Client Side — Challenge Handling (Transparent)

The calling agent uses standard challenge handling. The SDK automatically handles the 401 → exchange → retry cycle:

```csharp
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;

var keyStore = FileKeyStore.Default();
var localKeyHandle = configuration["AAuth:LocalKeyHandle"]!;
var key = await keyStore.LoadAsync(localKeyHandle)
    ?? throw new InvalidOperationException("Key not found.");
var refreshEndpoint = configuration["AAuth:ApRefreshEndpoint"]!;

using var client = new AAuthClientBuilder(key)
    .WithTokenRefresh(AgentProviderTokenRefresher.Create(refreshEndpoint, localKeyHandle)
        .WithKeyStore(keyStore)
        .Build())
    .WithChallengeHandling(personServer)
    .Build();

// The Orchestrator challenges with 401 + resource token.
// SDK handles the exchange transparently.
var response = await client.GetAsync("https://orchestrator.example");
```

### Intermediate Service — Resource + Agent Pattern

The intermediate service (Orchestrator) acts as both a resource and an agent.

#### Simplified Pattern (Recommended)

Use `UseAAuthIntermediary` for verification + challenge, and `WithCallChaining(ctx)` for automatic downstream routing:

```csharp
// Middleware: verify callers + auto-challenge agent tokens
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known"),
    branch => branch.UseAAuthIntermediary(
        new AAuthVerificationOptions
        {
            ResourceIdentifier = orchestratorUrl,
            RequireIssuerVerification = true,
        },
        new ChallengeOptions
        {
            AccessMode = AAuthAccessMode.RequireAuthToken,
            ResourceSigningKey = orchestratorKey,
            ResourceKeyId = "orch-1",
            ResourceIdentifier = orchestratorUrl,
        }));

// Only auth-token callers reach this handler
app.MapGet("/", async (HttpContext ctx) =>
{
    using var downstream = new AAuthClientBuilder(myKey)
        .WithTokenRefresh(refreshFunc)
        .WithCallChaining(ctx)  // reads upstream token from UpstreamAuthTokenFeature
        .Build();

    var response = await downstream.GetAsync(downstreamUrl);
    var body = await response.Content.ReadAsStringAsync();
    return Results.Ok(JsonNode.Parse(body));
});
```

`WithCallChaining(ctx)` automatically:
- Reads the upstream auth token from `UpstreamAuthTokenFeature` (set by verification middleware)
- Routes the downstream exchange to the correct PS/AS via `CallChainingRouter`
- Passes `upstream_token` in the exchange POST body to preserve the delegation chain
- Handles the full 401 → exchange → retry cycle transparently

#### Lower-Level Pattern

For full control over the exchange, use the building blocks directly:

```csharp
// 1. Verify incoming requests with full issuer verification
app.UseAAuthVerification(new AAuthVerificationOptions
{
    ResourceIdentifier = orchestratorUrl,
    RequireIssuerVerification = true,
});

app.MapGet("/", async (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;
    var tokenType = ctx.GetAAuthTokenType();

    // Agent token → challenge the caller
    if (tokenType == AAuthTokenType.AgentToken)
    {
        var rt = new ResourceTokenBuilder
        {
            Issuer = orchestratorUrl,
            Audience = parsed.Payload?["ps"]?.ToString(),
            Agent = parsed.Payload?["sub"]?.ToString(),
            AgentJkt = parsed.ConfirmationKey!.ComputeJwkThumbprint(),
            Key = orchestratorKey,
            KeyId = "orch-1",
            Scope = "orchestrate",
        }.Build();

        return ctx.ChallengeAAuth(rt);
    }

    // Auth token → forward downstream with call chaining
    var upstreamAuthToken = parsed.Jwt; // caller's auth token

    // 2. Exchange at PS WITH upstream_token
    var exchange = new TokenExchangeClient(signedClient, metadata);
    var chained = await exchange.ExchangeAsync(
        personServer, resourceToken,
        new TokenExchangeRequest { UpstreamToken = upstreamAuthToken });

    // 3. Call downstream with the chained auth token
    using var downstream = new AAuthClientBuilder(myKey)
        .UseJwt(chained)
        .Build();
    var result = await downstream.GetAsync(whoamiUrl); // e.g. http://localhost:5000/jwt
    // ...
});
```

### UseJwt — Presenting a Pre-Acquired Token

When an intermediary already holds a token (from exchange), use `UseJwt` to present it directly without token refresh:

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

When calling `TokenExchangeClient.ExchangeAsync`, pass the upstream auth token:

```csharp
var exchange = new TokenExchangeClient(signedClient, metadata);
var downstreamToken = await exchange.ExchangeAsync(
    personServer: "https://ps.example",
    resourceToken: resourceToken,
    new TokenExchangeRequest { UpstreamToken = incomingAuthToken }); // preserves delegation chain
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
dotnet run --project samples/AgentConsole -- http://localhost:5000/jwt \
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

## PS-Side — Upstream Token Validation

When a PS receives an `upstream_token` parameter during a call-chaining exchange, it must validate the token per §Upstream Token Verification. Use `UpstreamTokenValidator`:

```csharp
// Register in DI
builder.Services.AddSingleton(sp =>
    new UpstreamTokenValidator(
        sp.GetRequiredService<MetadataClient>(),
        sp.GetRequiredService<JwksClient>()));

// In the token endpoint handler
var validator = app.Services.GetRequiredService<UpstreamTokenValidator>();
var trustedIssuers = new HashSet<string> { psIssuer };

var result = await validator.ValidateAsync(
    upstreamToken,
    expectedAudience: intermediaryResourceUrl, // aud must match the caller
    trustedIssuers,
    intermediaryAgentId: intermediaryAgentId);  // constructs nested act

if (!result.IsValid)
    return Results.BadRequest(new { error = "invalid_upstream_token", detail = result.Error });

// result.UpstreamAct is ready to use in AuthTokenBuilder
var authToken = new AuthTokenBuilder
{
    Issuer = psIssuer,
    Audience = downstreamResource,
    Agent = intermediaryAgentId,
    AgentConfirmationKey = intermediaryKey,
    Key = psKey, KeyId = "ps-1",
    Scope = "downstream:read",
    UpstreamAct = result.UpstreamAct, // fully nested delegation chain
}.Build();
```

The validator performs:
1. JWT signature verification via issuer JWKS discovery
2. Issuer trust check against provided set
3. Audience binding (aud == intermediary resource URL)
4. Act chain well-formedness (each level has `sub`, depth within limits)
5. Consistency check (`act.sub` == `agent` claim)
6. Nested act construction when `intermediaryAgentId` is provided

## PS-Side — Auth Token Delivery Validation

When the PS receives an auth token response from an AS (four-party flow), it must verify the response before returning it to the agent. Use `AuthTokenResponseValidator`:

```csharp
var deliveryValidator = new AuthTokenResponseValidator(metadata, jwks);

var result = await deliveryValidator.ValidateAsync(
    authToken: responseFromAs,
    expectedIssuer: asUrl,             // must match the AS we sent to
    expectedAudience: resourceUrl,     // downstream resource
    expectedAgentId: agentId,          // the requesting agent
    agentKey: agentSigningKey,         // cnf.jwk binding check
    expectedActContext: upstreamAct,   // chain consistency (optional)
    requestedScope: "data.read");      // scope narrowing check

if (!result.IsValid)
    return Results.BadRequest(new { error = "delivery_verification_failed" });
```

## Act Chain Utilities

### Reading the Delegation Chain

Resources can inspect the full delegation chain for authorization policy:

```csharp
var payload = verifiedToken.Payload;
var chain = ActChainReader.GetDelegationChain(payload);
// ["aauth:orchestrator@ap.example", "aauth:agent-a@ap.example"]

var immediate = ActChainReader.GetImmediateActor(payload);
// "aauth:orchestrator@ap.example"

var original = ActChainReader.GetOriginalActor(payload);
// "aauth:agent-a@ap.example"

var depth = ActChainReader.GetChainDepth(payload);
// 2
```

### Building Nested Act Claims

PS implementations constructing downstream tokens can use `ActChainBuilder`:

```csharp
// Wrap upstream act inside new intermediary act
var nestedAct = ActChainBuilder.BuildNestedAct(
    intermediaryAgentId: "aauth:orch@ap.example",
    upstreamAct: validatedUpstreamAct);
// { "sub": "aauth:orch@ap.example", "act": { "sub": "aauth:agent@ap.example" } }

// Validate chain before issuing
bool valid = ActChainBuilder.ValidateChain(nestedAct, maxDepth: 10);
```

## See Also

- [Interaction Chaining](../advanced/interaction-chaining.md) — propagating a downstream consent requirement back up the chain when a hop needs human approval (the multi-actor, human-in-the-loop variant of this workflow).
- [Deferred Consent](deferred-consent.md) — agent-side handling of a `202` interaction requirement.
