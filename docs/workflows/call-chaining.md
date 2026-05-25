# Call Chaining

Call chaining enables multi-hop delegation where a resource acts as an agent to downstream resources, preserving the full authorization chain via nested `act` claims.

## Scenario

```
Agent A → Resource B → Resource C
```

1. Agent A calls Resource B with an auth token
2. Resource B needs to call Resource C on behalf of A
3. Resource B exchanges A's auth token (as `upstream_token`) at its own PS
4. The PS/AS mints a new auth token with nested `act` claims preserving the delegation chain

## SDK Support

### Client Side — Upstream Token

When calling `TokenExchangeClient.ExchangeAsync`, pass the upstream auth token:

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

### Server Side — CallChainingHandler

For resources that act as agents, `CallChainingHandler` provides routing logic:

```csharp
var handler = new CallChainingHandler(
    exchangeClient: exchange,
    resolveDownstream: mission => ResolveDownstreamServer(mission));

var downstreamToken = await handler.ExchangeForDownstreamAsync(
    upstreamAuthToken, resourceToken, cancellationToken);
```

### Auth Token Builder — Nested Act Claims

When an auth token carries delegation context, the `act` claim is nested:

```json
{
  "iss": "https://ps-b.example",
  "sub": "pairwise-sub-b",
  "agent": "aauth:resource-b@ap.example",
  "act": {
    "sub": "pairwise-sub-a",
    "act": {
      "sub": "original-user"
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
AgentConsole https://resource-c.example/data \
  --ap https://ap.example \
  --ps https://ps.example \
  --upstream-token "eyJ..."
```
