# PS Authorization (Three-Party)

> [Live demo](https://explorer.aauth.dev/access/ps-asserted) | [Access Mode Comparison](https://explorer.aauth.dev/access/compare)

## Overview

The resource doesn't handle authorization itself — it delegates to the agent's
Person Server. This is the three-party PS authorization mode (the
historical `ps-asserted` file name remains only for link compatibility). The
agent first presents a person token from its PS; the resource issues a resource
token naming that person token; the agent exchanges both at the PS for an auth
token; then presents the auth token back. Requires `sig=jwt` signing mode.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Agent
    participant Resource
    participant PS as Person Server
    Agent->>Resource: GET /data (signed, sig=jwt with agent token)
    Resource-->>Agent: 401 requirement=person-token
    Agent->>PS: POST /person (signed, resource in body)
    PS-->>Agent: 200 + person token (aa-person+jwt)
    Agent->>Resource: GET /data (signed, sig=jwt with person token)
    Resource-->>Agent: 401 requirement=auth-token + resource token (aud=PS; presented_jti)
    Agent->>PS: POST /token (signed, resource_token + presented_token)
    PS-->>Agent: 200 + auth token (aa-auth+jwt)
    Agent->>Resource: GET /data (signed, sig=jwt with auth token)
    Resource-->>Agent: 200 OK
```

## Code Example

Automatic handling with `AAuthClientBuilder`:

```csharp
using AAuth.Agent;
using AAuth.Crypto;
using AAuth;

// Hosted service: self-issue (no AP needed)
var key = AAuthKey.Generate();

using var client = AAuthClientBuilder.SelfIssuing(key)
    .As("https://my-service.example", "aauth:my-service@my-service.example")
    .WithKid("svc-key-1")
    .WithPersonServer("https://ps.example")
    .WithChallengeHandling()
    .Build();

var response = await client.GetAsync("https://resource.example/data");
// ChallengeHandler intercepts each 401: it requests a person token, retries,
// exchanges the resource token with that person token, swaps to the auth
// token, and retries automatically.
```

<details>
<summary>CLI/Desktop Agent (AP Enrollment)</summary>

For agents without a stable URL, enrol with an Agent Provider:

```csharp
using AAuth.Agent;
using AAuth.Crypto;
using AAuth;

IKeyStore keyStore = FileKeyStore.Default();
var localKeyHandle = configuration["AAuth:LocalKeyHandle"]!;
var key = await keyStore.LoadAsync(localKeyHandle)
    ?? throw new InvalidOperationException("Key not found. Run enrollment first.");
var apRefreshEndpoint = configuration["AAuth:ApRefreshEndpoint"]!;

using var client = AAuthClientBuilder.Enrolled(key)
    .RefreshingFrom(apRefreshEndpoint, localKeyHandle)
    .WithKeyStore(keyStore)
    .WithChallengeHandling(personServer: "https://ps.example")
    .Build();

var response = await client.GetAsync("https://resource.example/data");
```

</details>

<details>
<summary>Manual Setup (Advanced)</summary>

This shows the internal handler pipeline for educational purposes. Use `WithTokenRefresh` + `WithChallengeHandling` in production code.

```csharp
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;

IKeyStore keyStore = FileKeyStore.Default();
var key = await keyStore.LoadAsync(configuration["AAuth:LocalKeyHandle"]!);
var agentToken = "..."; // acquired via AP refresh endpoint
var tokenHolder = new AAuthTokenHolder(agentToken);

var signingHandler = new AAuthSigningHandler(key!,
    new JwtSignatureKeyProvider(() => tokenHolder.Current))
{
    InnerHandler = AAuthHttpTransport.CreateHandler()
};

using var signedClient = AAuthHttpTransport.AttachPolicy(new HttpClient(
    new AAuthSigningHandler(key!, new JwtSignatureKeyProvider(() => agentToken))
    { InnerHandler = AAuthHttpTransport.CreateHandler() }),
    AAuthEgressPolicy.Production, AAuthTransportContract.EnforcesEgressPolicy);
using var metadata = new MetadataClient();
using var jwks = new JwksClient();
var verifier = new AAuth.Tokens.TokenVerifier();
var exchange = new TokenExchangeClient(signedClient, metadata);

var challengeHandler = new ChallengeHandler(
    exchange, tokenHolder, verifier, metadata, jwks, "https://ps.example")
{
    InnerHandler = signingHandler
};

using var client = new HttpClient(challengeHandler);
var response = await client.GetAsync("https://resource.example/data");
```

</details>

## DI Registration

```csharp
using AAuth.Agent;
using AAuth.Crypto;

IKeyStore keyStore = FileKeyStore.Default();
var localKeyHandle = configuration["AAuth:LocalKeyHandle"]!;
var key = await keyStore.LoadAsync(localKeyHandle);
var apRefreshEndpoint = configuration["AAuth:ApRefreshEndpoint"]!;
using var refresher = AgentProviderTokenRefresher.Create(apRefreshEndpoint, localKeyHandle)
    .WithKeyStore(keyStore).Build();

builder.Services.AddAAuthAgent("ps-authorization", options =>
{
    options.Signer = key!;
    options.PersonServer = "https://ps.example";
    options.TokenRefresher = refresher;
});
```

This registers a named `HttpClient` with signing + automatic challenge handling. Inject via `IHttpClientFactory.CreateClient("ps-authorization")`. The `ChallengeHandler` intercepts 401 responses, obtains the person token and
exchanges the resource token at the PS, and retries transparently.

See [Dependency Injection](../reference/dependency-injection.md) for full options reference.

## Token Flow

1. Agent sends signed request with agent token → resource returns
   `401 requirement=person-token`
2. `ChallengeHandler` requests a person token at the PS's `person_token_endpoint`
   (`TokenExchangeClient.RequestPersonTokenAsync`) and retries with it → resource
   returns `401 requirement=auth-token` + a resource token naming the person token
3. `TokenExchangeClient.ExchangeAsync()` posts the resource token and the person
   token (`presented_token`) to the PS's `auth_token_endpoint`
4. PS **verifies the resource token** (`TokenVerifier.VerifyResourceTokenAsync`:
   `typ`/`dwk`/signature via the issuing resource's JWKS, `exp`/`iat`, `aud`,
   `agent_jkt`, `ps`) and **the pair** (`VerifyPresentedTokenAsync`: the presented
   token's `jti`, `sub`, `mission_s256`, and `tenant` match), identifies the agent
   from the agent token that signed the request, checks consent, and returns the
   auth token
5. `AAuthTokenHolder` is updated with the auth token
6. `ChallengeHandler` retries the original request (now with auth token in Signature-Key)

## Autonomous vs Deferred

- **Autonomous**: PS has standing consent → returns auth token immediately (step 3→4)
- **Deferred**: PS requires user approval → returns 202 + pending URL → agent starts polling immediately and surfaces the interaction (see [Deferred Consent](deferred-consent.md))

Start polling as soon as the `202` arrives, before or while the person is
shown the link. The host of the interaction URL MAY complete the interaction
over a channel it already controls, without the person visiting `url` or
presenting `code`. The code is consumed at that completion, and the pending
URL returns the terminal response
([User Interaction](../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#user-interaction),
v11 L1011). The sample MockPersonServer uses this for its
[consent dashboard](../../samples/MockPersonServer/README.md#consent-dashboard),
which lists every request waiting for the person. An agent that waits for the
person to click its own link can miss a decision made there.

## Person-Server-Side

The PS half of this flow (steps 3–4) ships as the one-call host helper
`MapAAuthPersonServer`: it publishes the PS metadata + JWKS, verifies the request
signature, maps the person token endpoint, verifies the presented
`resource_token` and `presented_token`, delegates the identity + consent
decision to a pluggable `IIdentityClaimsAsserter`, and mints the auth token (or
parks a `202` deferred consent). See
[Token Issuance → One-Call Person Server](../server/token-issuance.md#one-call-person-server-mapaauthpersonserver).

## Error Scenarios

| Status | Header/Token | Cause |
|--------|-------------|-------|
| 401 | `Signature-Error: error=invalid_signature` | Signature doesn't verify at resource |
| 401 | `Signature-Error: error=invalid_request` | Resource rejects malformed credentials or audience binding before issuing a token |
| 403 | Auth token denied | PS issued auth token but resource policy still denies |
| 202 | Pending URL from PS | Deferred consent — user approval required |

## Further Reading

- [Agent Token mode](../signing-modes/agent-token-jwt.md)
- [Deferred Consent](deferred-consent.md)
- [Federated authorization](federated-access.md)
- [Token Issuance (server)](../server/token-issuance.md)
