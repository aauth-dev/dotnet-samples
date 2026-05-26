# Interaction Chaining

When an intermediary resource calls a downstream resource and the downstream PS/AS requires user consent, the intermediary must propagate the interaction requirement back through the call chain to the original agent.

## Spec Requirement (§Interaction Chaining)

> When a resource acting as an agent receives a `202 Accepted` response with `AAuth-Requirement: requirement=interaction`, and the resource needs to propagate this interaction requirement to its caller, it MUST return a `202 Accepted` response to the original agent with its own `AAuth-Requirement` header containing `requirement=interaction` and its own interaction code. The resource MUST provide its own `Location` URL for the original agent to poll. When the user completes interaction and the resource obtains the downstream auth token, the resource completes the original request and returns the result at its pending URL.

## Flow Diagram

```
Agent A → Orchestrator (Resource B) → Downstream PS
                                      ← 202 + requirement=interaction
         ← 202 + requirement=interaction (Orchestrator's own URL/code)

Agent A opens interaction URL in browser...
User completes consent...

Agent A → Orchestrator (polls Location)
         Orchestrator polls downstream PS → gets auth token → retries downstream
         ← 200 (final result)
```

## SDK Support: `onInteractionRequired` Callback

The `CallChainingHandler.ExchangeForDownstreamAsync` and `TokenExchangeClient.ExchangeAsync` both accept an `onInteractionRequired` callback. Use this to propagate the interaction back to your caller:

```csharp
app.MapGet("/", async (HttpContext ctx) =>
{
    using var downstream = new AAuthClientBuilder(myKey)
        .WithTokenRefresh(refreshFunc)
        .WithCallChaining(ctx)
        .WithChallengeHandling(opts =>
        {
            opts.OnInteractionRequired = async (interaction, ct) =>
            {
                // The downstream PS requires user consent.
                // Store a pending request and return 202 to the caller.
                var pendingId = PendingRequests.Create(ctx, interaction);

                ctx.Response.StatusCode = 202;
                ctx.Response.Headers["Location"] = $"/pending/{pendingId}";
                ctx.Response.Headers["AAuth-Requirement"] =
                    $"requirement=interaction; url=\"{BuildInteractionUrl(pendingId)}\"; " +
                    $"code=\"{interaction.Code}\"";
                await ctx.Response.WriteAsJsonAsync(new { status = "pending" }, ct);
            };
        })
        .Build();

    var response = await downstream.GetAsync(downstreamUrl);
    return Results.Ok(await response.Content.ReadFromJsonAsync<JsonNode>());
});
```

## Manual Pattern (Without Builder)

For full control over the interaction-chaining flow using `CallChainingHandler` directly:

```csharp
app.MapGet("/", async (HttpContext ctx) =>
{
    var upstream = ctx.Features.Get<UpstreamAuthTokenFeature>()!;

    var chainHandler = new CallChainingHandler(exchangeClient, options);

    try
    {
        var chainedToken = await chainHandler.ExchangeForDownstreamAsync(
            upstream.Token,
            resourceToken,
            onInteractionRequired: async (interaction, ct) =>
            {
                // Propagate: store pending state and inform caller
                var pendingId = await StorePendingAsync(ctx.Request, interaction);
                ctx.Response.StatusCode = 202;
                ctx.Response.Headers["Location"] = $"/pending/{pendingId}";
                ctx.Response.Headers["AAuth-Requirement"] =
                    $"requirement=interaction; url=\"/interact/{pendingId}\"; code=\"{interaction.Code}\"";
            },
            pollerOptions: new DeferredPollerOptions
            {
                MaxTotalWait = TimeSpan.FromMinutes(5),
                PreferWaitSeconds = 45,
            });

        // Exchange succeeded — call downstream with chained token
        using var client = new AAuthClientBuilder(myKey)
            .UseJwt(chainedToken)
            .Build();
        return Results.Ok(await client.GetFromJsonAsync<JsonNode>(downstreamUrl));
    }
    catch (AAuthInteractionTimeoutException)
    {
        return Results.StatusCode(504); // Gateway Timeout
    }
});
```

## Pending Request Management

The intermediary must manage pending requests:

1. **Store**: When `onInteractionRequired` fires, store the request context and downstream interaction details.
2. **Poll endpoint**: Expose a `/pending/{id}` endpoint that the original agent polls.
3. **Background completion**: When user consent completes, the downstream PS issues the token. The intermediary completes the original request.
4. **Cleanup**: Expire stale pending requests.

This is application-specific logic that the SDK intentionally does not automate, as different architectures (stateless, queue-backed, actor-based) require different implementations.

## Future Enhancement: Automatic Propagation Middleware

A future SDK version may provide an `InteractionPropagationMiddleware` that:

- Automatically returns 202 to the caller when downstream interaction is needed
- Manages a pending-request store (pluggable: in-memory, Redis, database)
- Exposes a polling endpoint
- Completes the original request when downstream interaction resolves

This would further reduce boilerplate for common intermediary patterns. Track progress in the SDK roadmap.

## See Also

- [Call Chaining](../workflows/call-chaining.md) — overall call-chaining workflow
- [Error Handling](error-handling.md) — `AAuthInteractionTimeoutException` and `AAuthInteractionDeniedException`
- [Deferred Consent](../workflows/deferred-consent.md) — agent-side 202 handling
