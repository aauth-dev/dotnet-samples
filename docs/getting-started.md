# Getting Started

## Prerequisites

- [.NET 10+](https://dotnet.microsoft.com/download) SDK

## Install

```bash
dotnet add package AAuth --prerelease
```

Or, if working within this repository, add a project reference:

```bash
dotnet add reference src/AAuth/AAuth.csproj
```

## Generate a Key

```csharp
using AAuth.Crypto;

var key = AAuthKey.Generate(); // Ed25519 keypair
var publicJwk = key.ToPublicJwk(); // Export for registration
var thumbprint = key.ComputeJwkThumbprint(); // JWK thumbprint (S256)
```

## Make Your First Signed Request

The simplest mode is pseudonymous (HWK) — no Agent Provider needed:

```csharp
using AAuth.Crypto;
using AAuth.HttpSig;

var key = AAuthKey.Generate();

using var client = new AAuthClientBuilder(key)
    .UseHwk()
    .Build();

var response = await client.GetAsync("https://resource.example/data");
// Request is signed with HTTP Message Signatures (RFC 9421)
// Resource sees: Signature-Key: sig=hwk;jkt="<thumbprint>";jwk="<public-key>"
```

### Alternative: One-liner with static factory

```csharp
using var client = AAuthSigningHandler.CreateClient(key, new HwkSignatureKeyProvider(key));
```

### Alternative: DI / IHttpClientFactory

```csharp
// In Program.cs
builder.Services.AddAAuthAgent("agent", options =>
{
    options.Key = key;
    options.PersonServer = "https://ps.example"; // omit for signing-only
});

// Inject via IHttpClientFactory
public class MyService(IHttpClientFactory factory)
{
    private readonly HttpClient _client = factory.CreateClient("agent");
}
```

## What Just Happened?

- `AAuthKey.Generate()` created an Ed25519 keypair.
- `AAuthClientBuilder` configured the HWK signing mode and produced an `HttpClient`.
- `AAuthSigningHandler` signs the request per RFC 9421 covering `@method`, `@authority`, `@path`, and `signature-key`.
- The resource verifies the signature using the inline public key from `Signature-Key`.

## Self-Issued Agent Tokens (Hosted Services)

Hosted services (web apps, APIs, orchestrators) that have a stable URL act as their own Agent Provider per spec §Self-Hosted Agents. They generate a key at startup, publish agent metadata at `/.well-known/aauth-agent.json`, and self-sign agent tokens. No external AP enrollment is needed.

```csharp
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;

var key = AAuthKey.Generate();
const string Kid = "my-service-1";
var issuer = "https://my-service.example";

// Publish agent metadata so verifiers can discover the JWKS
app.MapAAuthAgentWellKnown(new AAuthAgentMetadataOptions
{
    Issuer = issuer,
    SigningKeys = new Dictionary<string, AAuthKey> { [Kid] = key },
});

// Self-issue agent tokens for outbound requests
using var client = new AAuthClientBuilder(key)
    .WithTokenRefresh(async (ctx, ct) => new AgentTokenBuilder
    {
        Issuer = issuer,
        Subject = "aauth:my-service@my-service.example",
        KeyId = Kid,
        Key = key,
    }.Build())
    .WithChallengeHandling("https://ps.example")
    .Build();
```

## Bootstrap with an Agent Provider (CLI / Desktop Agents)

For agents that do NOT have a stable URL (CLI tools, desktop apps, mobile apps), registration with an external **Agent Provider (AP)** provides identity and key discovery. Enrollment is a **provisioning step** that runs once (in a CLI tool or setup script). The durable signing key is generated inside a keystore and never extracted — the app references it by ID. The agent token is short-lived (typically 1 hour) and refreshed automatically by the SDK.

### Provisioning (run once per device/install)

```csharp
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;

// Key is generated INSIDE the store — private material never leaves
var keyStore = FileKeyStore.Default(); // ~/.aauth/keys/ (or plug in HSM/Key Vault)

var enrol = await AAuthClientBuilder
    .Bootstrap(
        enrollEndpoint: "https://ap.example/enrol",
        agentId: "aauth:myagent@example.com")
    .WithPersonServer("https://ps.example")
    .WithKeyStore(keyStore)
    .EnrolAsync();

// Only the local key handle needs to be recorded in app config
// (the key itself is already in the keystore; defaults to the JWK thumbprint)
Console.WriteLine($"Enrolled. Add to config: AAuth:LocalKeyHandle = {enrol.LocalKeyHandle}");
```

### Application (every startup)

Load the key by handle from the store and let the SDK manage agent tokens:

```csharp
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;

var keyStore = FileKeyStore.Default();
var localKeyHandle = configuration["AAuth:LocalKeyHandle"]!;
var apRefreshEndpoint = configuration["AAuth:ApRefreshEndpoint"]!;
var key = await keyStore.LoadAsync(localKeyHandle)
    ?? throw new InvalidOperationException($"Key '{localKeyHandle}' not found. Run enrollment first.");

// The SDK acquires the agent token lazily on first request
// via WithTokenRefresh, then keeps it fresh automatically.
using var client = new AAuthClientBuilder(key)
    .WithTokenRefresh(AgentProviderTokenRefresher.Create(apRefreshEndpoint, localKeyHandle)
        .WithKeyStore(keyStore)
        .Build())
    .WithChallengeHandling("https://ps.example")
    .Build();

var response = await client.GetAsync("https://resource.example/protected");
Console.WriteLine(await response.Content.ReadAsStringAsync());
```

<details>
<summary>Step-by-Step (Advanced)</summary>

### 1. Enrol with the Agent Provider

```csharp
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;

var apClient = new AgentProviderClient(new HttpClient(), new InMemoryKeyStore());
var enrol = await apClient.EnrolAsync(
    apIssuer: "https://ap.example",
    agentId: "aauth:myagent@example.com",
    enrollEndpoint: "https://ap.example/enrol",
    personServer: "https://ps.example");

// enrol.Key            — your Ed25519 signing key (in keystore)
// enrol.LocalKeyHandle — agent-local IKeyStore handle (defaults to JWK thumbprint); persist this
// enrol.AgentTokenKid  — AP-internal JWT `kid` (opaque; diagnostic only)
// enrol.AgentToken     — initial aa-agent+jwt (short-lived, do not persist)
```

### 2. Build the Signed Client with Challenge Handling

```csharp
using var client = new AAuthClientBuilder(enrol.Key)
    .WithTokenRefresh(AgentProviderTokenRefresher.Create("https://ap.example/refresh", enrol.LocalKeyHandle)
        .WithKeyStore(keyStore)
        .Build())
    .WithChallengeHandling(personServer: "https://ps.example")
    .Build();
```

### 3. Make Requests

```csharp
var response = await client.GetAsync("https://resource.example/protected");
Console.WriteLine(await response.Content.ReadAsStringAsync());
```

</details>

<details>
<summary>Manual Pipeline Setup (Low-Level)</summary>

This shows the internal handler pipeline for educational purposes. Use `WithTokenRefresh` + `WithChallengeHandling` in production code.

```csharp
// Acquire a fresh agent token via the AP refresh endpoint
var apClient = new AgentProviderClient(new HttpClient(), keyStore);
var agentToken = await apClient.RefreshAsync("https://ap.example/refresh", keyId);

// Carrier-token holder — shared between signer and challenge handler.
var holder = new AAuthTokenHolder(agentToken);

var signingHandler = new AAuthSigningHandler(
    key, new JwtSignatureKeyProvider(() => holder.Current))
{
    InnerHandler = new HttpClientHandler(),
};

var exchangeHttp = new HttpClient(
    new AAuthSigningHandler(key, new JwtSignatureKeyProvider(() => agentToken))
    { InnerHandler = new HttpClientHandler() });

var exchange = new TokenExchangeClient(exchangeHttp, new MetadataClient(new HttpClient()));

var pipeline = new ChallengeHandler(exchange, holder, "https://ps.example")
{
    InnerHandler = signingHandler,
};

using var client = new HttpClient(pipeline);
```

</details>

### What Happens Under the Hood

1. Agent sends a signed GET → Resource replies **401** with `AAuth-Requirement: requirement=auth-token` and a `resource_token`.
2. `ChallengeHandler` extracts the resource token, POSTs it to the Person Server's token endpoint.
3. The PS validates the agent token, confirms user consent (or defers), and returns an `auth_token`.
4. `AAuthTokenHolder` is updated; the handler retries the original request signed with the auth token.
5. Subsequent requests reuse the auth token until it expires.

## Next Steps

- [Signing Modes Overview](signing-modes/overview.md) — choose the right mode for your use case
- [Identity-Based Access](workflows/identity-based-access.md) — simplest workflow
- [PS-Asserted Access](workflows/ps-asserted-access.md) — full authorization flow
- [Protocol Concepts](concepts.md) — understand the full picture

## Protocol Reference

Explore the interactive protocol specification at <https://explorer.aauth.dev/>.
