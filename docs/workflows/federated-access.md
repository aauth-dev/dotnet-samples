# Federated Access (Four-Party)

> [Live demo](https://explorer.aauth.dev/access/federated) | [Access Mode Comparison](https://explorer.aauth.dev/access/compare)

Overview: The resource has its own Access Server (AS) that enforces policy. The PS federates with the AS to obtain the auth token. From the agent's perspective, the flow looks identical to PS-asserted — the federation happens between PS and AS transparently.

```mermaid
sequenceDiagram
    participant Agent
    participant Resource
    participant PS as Person Server
    participant AS as Access Server
    Agent->>Resource: GET /data (signed, sig=jwt)
    Resource-->>Agent: 401 + resource token (aud=AS URL)
    Agent->>PS: POST /token (resource token)
    PS->>AS: POST /token (signed, forwards resource token)
    AS-->>PS: auth token (iss=AS)
    PS-->>Agent: auth token
    Agent->>Resource: GET /data (signed, auth token)
    Resource-->>Agent: 200 OK
```

## Agent-Side Code

Identical to PS-asserted — `WithChallengeHandling()` handles it transparently. The only difference is the resource token's `aud` points to the AS URL instead of the PS URL.

```csharp
using var client = new AAuthClientBuilder(key)
    .UseJwt(agentToken)
    .WithChallengeHandling(personServer: "https://ps.example")
    .Build();

var response = await client.GetAsync("https://resource.example/data");
```

## Key Difference from PS-Asserted

The resource token `aud` = AS URL (not PS URL). The PS recognizes this and federates to the AS rather than issuing the auth token itself.

## PS-AS Collapse

When the PS and AS are the same server, the wire protocol is unchanged — it's just an internal evaluation. No code changes needed on either side.

## Further Reading

- [PS-Asserted Access](ps-asserted-access.md)
- [Access Mode Comparison](https://explorer.aauth.dev/access/compare)
