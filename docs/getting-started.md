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
// Resource sees: Signature-Key: sig=hwk;jkt="<thumbprint>"
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
- The resource verifies the signature and sees a pseudonymous key thumbprint.

## Bootstrap with an Agent Provider (Three-Party Flow)

For production scenarios, agents register with an **Agent Provider (AP)** to get an identity-bound agent token. When a resource challenges with a 401, the SDK automatically exchanges the resource token at the **Person Server (PS)** and retries.

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

// enrol.Key        — your Ed25519 signing key
// enrol.AgentToken — aa-agent+jwt issued by the AP
// enrol.KeyId      — persisted key identifier
```

### 2. Build the Signed Client with Challenge Handling

```csharp
using var client = new AAuthClientBuilder(enrol.Key)
    .UseJwt(enrol.AgentToken)
    .WithChallengeHandling(personServer: "https://ps.example")
    .Build();
```

<details>
<summary>Manual Setup (Advanced)</summary>

```csharp
// Carrier-token holder — shared between signer and challenge handler.
var holder = new AAuthTokenHolder(enrol.AgentToken);

var signingHandler = new AAuthSigningHandler(
    enrol.Key, new JwtSignatureKeyProvider(() => holder.Current))
{
    InnerHandler = new HttpClientHandler(),
};

var exchangeHttp = new HttpClient(
    new AAuthSigningHandler(enrol.Key, new JwtSignatureKeyProvider(() => enrol.AgentToken))
    { InnerHandler = new HttpClientHandler() });

var exchange = new TokenExchangeClient(exchangeHttp, new MetadataClient(new HttpClient()));

var pipeline = new ChallengeHandler(exchange, holder, "https://ps.example")
{
    InnerHandler = signingHandler,
};

using var client = new HttpClient(pipeline);
```

</details>

### 3. Make Requests

```csharp
// First request may trigger a 401 challenge — the SDK handles it transparently
var response = await client.GetAsync("https://resource.example/protected");
Console.WriteLine(await response.Content.ReadAsStringAsync());
```

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
