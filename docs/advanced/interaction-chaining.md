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

## SDK Support: throw `AAuthInteractionChainedException`

When the downstream PS/AS requires consent, the intermediary's exchange surfaces an
`onInteractionRequired` callback. The intermediary cannot block and poll on the caller's
behalf — there is no user attached to the inbound request to relay the consent URL to.
Instead, the callback **throws** `AAuthInteractionChainedException` to abort the exchange
*before* the SDK starts its blocking poll. The endpoint catches that exception, parks the
flow, and re-emits its **own** `202 Accepted` to the caller:

```csharp
async Task<IResult> RunChainAsync(HttpContext ctx, string upstreamToken)
{
    using var downstream = AAuthClientBuilder.SelfIssuing(orchestratorKey)
        .As(orchestratorUrl, agentId)
        .WithKid(orchestratorKid)
        .WithPersonServer(psUrl)
        .WithCallChaining(upstreamToken)
        .WithChallengeHandling(opts =>
        {
            // No user to relay to — abort the exchange and re-emit upward.
            opts.OnInteractionRequired = (interaction, _) =>
                throw new AAuthInteractionChainedException(interaction);
        })
        .Build();

    var response = await downstream.GetAsync($"{downstreamUrl}/jwt");
    var body = await response.Content.ReadFromJsonAsync<JsonNode>();
    return Results.Ok(new { chain = "ok", downstream = body });
}

app.MapGet("/", async (HttpContext ctx, PendingStore pending) =>
{
    var upstream = ctx.Features.Get<UpstreamAuthTokenFeature>()?.Token;
    if (upstream is null) return Results.Unauthorized();

    try
    {
        return await RunChainAsync(ctx, upstream);
    }
    catch (AAuthInteractionChainedException ex)
    {
        // Downstream needs consent. Park the upstream token + the downstream
        // interaction details, then re-emit our OWN 202 to the caller.
        var entry = pending.Add(upstream, ex.Interaction.Url, ex.Interaction.Code);
        return ReEmitChainedInteraction(ctx, entry);
    }
});
```

Throwing from the callback is what makes this work: the exchange wraps the callback in
`try { await onInteractionRequired(...) } finally { ... }` with **no** `catch`, so the
exception unwinds before `DeferredPoller.PollAsync` runs. There is no blocked poll and no
double-write to the response.

### Re-emitting the chained 202

`ReEmitChainedInteraction` writes the intermediary's own `202` carrying *its* poll URL and
the downstream interaction's `url`/`code` (the user approves the downstream resource
directly):

```csharp
IResult ReEmitChainedInteraction(HttpContext ctx, PendingStore.Entry entry)
{
    ctx.Response.Headers.Location = $"/pending/{entry.Id}";
    ctx.Response.Headers["Retry-After"] = "1";
    ctx.Response.Headers.CacheControl = "no-store";
    ctx.Response.Headers[AAuthRequirementHeader.Name] =
        Interaction.Format(entry.InteractionUrl, entry.InteractionCode);
    return Results.Json(new { status = "interaction_required" }, statusCode: 202);
}
```

### Resuming at the poll endpoint

When the agent polls `/pending/{id}`, the intermediary retries the chain. If consent has
been granted the exchange now succeeds and the final result is returned; if it is still
pending the same chained `202` is re-emitted; a denial maps to `403`:

```csharp
app.MapGet("/pending/{id}", async (HttpContext ctx, string id, PendingStore pending) =>
{
    var entry = pending.Get(id);
    if (entry is null)
        return Results.Json(new { error = "unknown_pending" }, statusCode: 404);

    try
    {
        var result = await RunChainAsync(ctx, entry.UpstreamToken);
        pending.Remove(id);
        return result;
    }
    catch (AAuthInteractionChainedException)
    {
        // Still waiting — re-emit (same url/code; consent is keyed by triple).
        return ReEmitChainedInteraction(ctx, entry);
    }
    catch (AAuthInteractionDeniedException)
    {
        pending.Remove(id);
        return Results.Json(new { error = "access_denied" }, statusCode: 403);
    }
});
```

> **Why not write the `202` from inside the callback?** Returning normally from
> `onInteractionRequired` tells the SDK to *block and poll* for the downstream token. An
> intermediary has no user to wait on, so it would hang for the full polling budget and
> then try to complete a response the endpoint may have already written. Throwing
> `AAuthInteractionChainedException` is the correct, non-blocking abort.

## Agent side: surfacing the chained 202

The original agent must handle **two** interaction points: the hop-1 PS challenge (via
`WithChallengeHandling`) and the hop-2 chained `202` the intermediary re-emits (a *resource*
`202`, handled by the top-level interaction pipeline via `WithInteractionHandling`). Wire
both so either hop can surface a consent URL:

```csharp
using var client = AAuthClientBuilder.SelfIssuing(agentKey)
    .As(issuer, agentId)
    .WithKid(kid)
    .WithPersonServer(psUrl)
    .WithChallengeHandling(opts =>          // hop 1: PS exchange 202
    {
        opts.OnInteractionRequired = (interaction, _) =>
            SurfaceToUser(interaction.BuildUserUrl());
    })
    .WithInteractionHandling(opts =>        // hop 2: intermediary's chained 202
    {
        opts.OnInteractionRequired = (userUrl, code, _) =>
            SurfaceToUser(userUrl);
    })
    .Build();

var response = await client.GetAsync(intermediaryUrl);
```

`ChallengeHandler` only acts on `401` challenges, so the intermediary's `202` would pass
straight through unless `WithInteractionHandling` is also configured.

## Manual Pattern (Without Builder)

For full control over the interaction-chaining flow using `CallChainingHandler` directly,
apply the same throw-to-abort rule inside the `onInteractionRequired` callback:

```csharp
app.MapGet("/", async (HttpContext ctx, PendingStore pending) =>
{
    var upstream = ctx.Features.Get<UpstreamAuthTokenFeature>()!;
    var chainHandler = new CallChainingHandler(exchangeClient, options);

    try
    {
        var chainedToken = await chainHandler.ExchangeForDownstreamAsync(
            upstream.Token,
            resourceToken,
            onInteractionRequired: (interaction, _) =>
                // Abort before the blocking poll; the endpoint re-emits its own 202.
                throw new AAuthInteractionChainedException(interaction),
            pollerOptions: new DeferredPollerOptions
            {
                MaxTotalWait = TimeSpan.FromMinutes(5),
                PreferWaitSeconds = 45,
            });

        // Exchange succeeded — call downstream with the chained token.
        using var client = new AAuthClientBuilder(myKey)
            .UseJwt(chainedToken)
            .Build();
        return Results.Ok(await client.GetFromJsonAsync<JsonNode>(downstreamUrl));
    }
    catch (AAuthInteractionChainedException ex)
    {
        var entry = pending.Add(upstream.Token, ex.Interaction.Url, ex.Interaction.Code);
        return ReEmitChainedInteraction(ctx, entry);
    }
});
```

> **Note:** With `PreferWaitSeconds` set on a directly constructed `TokenExchangeClient`/`DeferredPoller`, ensure the underlying `HttpClient.Timeout` is greater than `PreferWaitSeconds` (or `Timeout.InfiniteTimeSpan`). A default `HttpClient` (100s timeout) would abort the in-flight long-poll with a `TaskCanceledException`. Clients built via `AAuthClientBuilder` already use `Timeout.InfiniteTimeSpan`.

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
