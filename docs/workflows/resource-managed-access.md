# Resource-Managed Access

> [Live demo](https://explorer.aauth.dev/access/resource-managed) | [Access Mode Comparison](https://explorer.aauth.dev/access/compare)

## Overview

The resource handles authorization itself — via user interaction, existing OAuth/OIDC, or internal policy. After authorization, the resource returns an opaque access token for subsequent calls. Two-party only (agent + resource).

This is the AAuth mode for resources that authorize requests themselves — the
role a first-party OAuth deployment fills when a service runs its own
authorization server alongside its API. The resource is both the authority that
mints the opaque token and the API that accepts it, and that token MAY wrap an
existing OAuth access token. When authorization is delegated to a separate
authority, that authority is a Person Server or Access Server — see
[PS authorization](ps-asserted-access.md) and [federated](federated-access.md)
access.

Runnable demo: the **Inbox** resource server (`samples/MockResourceServers/Inbox`, `:5004`) and the SampleApp [`/inbox`](http://localhost:5240/inbox) page / GuidedTour **Resource-Managed** flow.

All AAuth resource access uses the `jwt` Signature-Key scheme with an agent or
auth token. Here an `aa-agent+jwt` authenticates the agent; the opaque
`AAuth-Access` credential carries the Inbox's authorization. These are different
credentials. Generic `hwk` signing is not this access mode.

GuidedTour acts as its own AP and self-issues locally using its published issuer
and key. SampleApp signs enrollment with an external AP on first use, retains
its durable key handle, and lazily obtains a fresh agent JWT from the AP. That
provisioning/refresh is separate from resource authorization. The resource can
discover the issuer's metadata/key to verify the JWT, but performs no PS/AS
authorization exchange.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Agent
    participant Resource
    participant User
    Note over Agent: Setup complete: self-issued or AP-enrolled agent JWT
    Agent->>Resource: GET /data (jwt + HTTP proof)
    Resource-->>Agent: 202 + Location + requirement=interaction; url; code
    User->>Resource: Completes interaction at resource's page
    Agent->>Resource: GET /pending/<id> (poll)
    Resource-->>Agent: 200 + AAuth-Access: <opaque-token>
    Agent->>Resource: GET /data (signed + Authorization: AAuth <token>)
    Resource-->>Agent: 200 OK
```

## Code Example

### Client-Side (Agent)

`WithResourceManagedAccess()` captures the `AAuth-Access` token and replays it as `Authorization: AAuth <token68>` (the signer covers `authorization` automatically). Combine with `WithInteractionHandling()` to drive the resource's `202 → consent → 200` handshake:

```csharp
var keyStore = FileKeyStore.Default();
var enrollment = await AAuthClientBuilder.Bootstrap("https://ap.example/enrol")
    .WithKey(keyStore.LoadOrCreate("inbox-agent"))
    .WithKeyStore(keyStore)
    .EnrolAsync();

using var client = AAuthClientBuilder.Enrolled(enrollment.Key)
    .RefreshingFrom("https://ap.example/refresh", enrollment.LocalKeyHandle)
    .WithKeyStore(keyStore)
    .WithResourceManagedAccess()
    .WithInteractionHandling(options =>
    {
        options.OnInteractionRequired = (interaction, ct) =>
        {
            Console.WriteLine($"Approve at: {interaction.BuildUserUrl()}");
            return Task.CompletedTask;
        };
    })
    .Build();

// First call drives the 202 → consent → poll handshake; the SDK captures the
// AAuth-Access token. Subsequent calls replay it, bound to the signature.
await client.GetAsync("https://resource.example/messages");
var response = await client.GetAsync("https://resource.example/messages");
```

The example combines setup and use for completeness. Persist the key handle
and configured refresh endpoint so later startups can skip enrollment. The
built client owns its refresh transport and disposes it with the pipeline.
For an already-held valid enrollment token, use
`AAuthClientBuilder.From(enrollment).WithResourceManagedAccess()`; `From` uses
that JWT without an implicit refresh or a switch to direct JWKS.

Hosted agents use `SelfIssuing(key).As(issuer, agentId).WithKid(keyId)` before
the same resource-managed/interaction options. This issues an agent token with
`cnf`, not a `self-jwt` carrier.

<details>
<summary>Manual Handling</summary>

```csharp
var response = await client.GetAsync("https://resource.example/messages");
if (response.StatusCode == HttpStatusCode.Accepted)
{
    // Parse AAuth-Requirement header for the interaction URL + code
    var requirement = AAuthRequirementHeader.Parse(
        response.Headers.GetValues("AAuth-Requirement").First());
    // Present the interaction URL to the user, then poll the Location URL.
    // On 200, read AAuth-Access and present it on the next request as
    // Authorization: AAuth <token68> (covered by the signature).
}
```

</details>

### Server-Side (endpoint helpers)

The resource resolves the inbound opaque token and opens consent interactions via `HttpContext` helpers; the module's poll endpoint mints the `AAuth-Access` token on approval (the signature binding — that `authorization` is covered — is enforced by `AAuthVerifier`):

```csharp
// One handle to the SDK-registered opaque-token store.
var store = app.Services.GetRequiredService<IOpaqueTokenStore>();

// Payload endpoint: serve when an opaque token is presented; otherwise open a
// consent interaction. The module owns code generation, the consent URL, and
// parking — the resource supplies only the scope.
app.MapGet("/messages", async (HttpContext ctx) =>
{
    var info = await ctx.ResolveAAuthAccessAsync(store, ctx.RequestAborted);
    if (info is not null)
        return Results.Ok(new { scope = info.Scope, messages });

    // No token yet → 202 with Location, Retry-After, Cache-Control: no-store and
    // AAuth-Requirement: requirement=interaction; url=...; code=...
    return ctx.RequireAAuthInteraction("inbox.read");
}).RequireAAuthSignature();

// The SDK serves the deferred-response poll target and issues the opaque token
// on approval — the resource maps no poll plumbing of its own.
app.MapAAuthInteractionPoll().RequireAAuthSignature();

// The resource's authenticated consent page consumes the correlation code,
// binds a decision session to the person and pending owner, and validates CSRF.
// Only that verified decision context can approve the stored interaction.
```

> The resource-managed `session-token` flow is separate from the protocol
> `authorization_endpoint`. A published authorization endpoint requires a
> person token and is for proactively requesting a resource token; a two-party
> resource-managed sample like Inbox should use the reactive `202 interaction`
> path instead of mapping `/authorize`.

## DI Registration

### Agent-Side

```csharp
var key = await keyStore.LoadAsync(configuration["AAuth:LocalKeyHandle"]!);

builder.Services.AddAAuthAgent("resource-managed", options =>
{
    options.Signer = key!;
    options.AgentToken = agentToken; // already-held aa-agent+jwt bound to key
    options.EnableResourceManagedAccess = true; // capture + replay AAuth-Access
    options.Interaction.OnInteractionRequired = async (interaction, ct) =>
    {
        await Surface(interaction.BuildUserUrl());
    };
    options.Interaction.PollingTimeout = TimeSpan.FromMinutes(3);
});
```

### Resource-Side

```csharp
builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
    options.SigningKeys = new() { ["key-1"] = resourceKey };
    options.AccessMode = AAuthConstants.AccessModes.SessionToken;
});

// The resource-managed module registers the opaque-token store, the interaction
// pending store, and the consent/poll wiring. The SDK owns code generation,
// parking, the poll endpoint, and token issuance.
builder.Services.AddAAuthResourceManaged(options =>
{
    options.ConsentUrl = "https://resource.example/consent";
    options.PollPath = "/pending";
});
```

The endpoints then drive the flow with `ResolveAAuthAccessAsync` /
`RequireAAuthInteraction` and `MapAAuthInteractionPoll`; the consent page records
the decision using an authenticated, owner-bound `BrowserConsentSessions`
session and the pending-store generation. See the actual
[Inbox consent endpoints](../../samples/MockResourceServers/Inbox/Program.cs).

See [Dependency Injection](../reference/dependency-injection.md) for full reference.

## Error Scenarios

| Status | Header | Cause |
|--------|--------|-------|
| 401 | `Signature-Error: invalid_signature` | Signature doesn't verify |
| 202 | `AAuth-Requirement: requirement=interaction; url=...; code=...` plus `Location` | Authorization pending — user interaction required |
| 403 | *(none)* | Interaction completed but access denied by resource policy |

## Further Reading

- [Access Mode Comparison](https://explorer.aauth.dev/access/compare)
- [Identity-Based Access](identity-based-access.md)
- [PS authorization access](ps-asserted-access.md)
