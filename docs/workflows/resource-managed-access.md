# Resource-Managed Access

> [Live demo](https://explorer.aauth.dev/access/resource-managed) | [Access Mode Comparison](https://explorer.aauth.dev/access/compare)

## Overview

The resource handles authorization itself — via user interaction, existing OAuth/OIDC, or internal policy. After authorization, the resource returns an opaque access token for subsequent calls. Two-party only (agent + resource).

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Agent
    participant Resource
    participant User
    Agent->>Resource: GET /data (signed)
    Resource-->>Agent: 202 + AAuth-Requirement: interaction;url="...";code="..."
    User->>Resource: Completes interaction at resource's page
    Agent->>Resource: GET /pending/<id> (poll)
    Resource-->>Agent: 200 + AAuth-Access: <opaque-token>
    Agent->>Resource: GET /data (signed + Authorization: AAuth <token>)
    Resource-->>Agent: 200 OK
```

## Code Example

### Client-Side (Agent)

```csharp
// The ChallengeHandler can be configured to handle interaction requirements
// For resource-managed flows, the resource's own interaction page handles auth
// The agent polls until the resource issues an AAuth-Access token

var response = await client.GetAsync("https://resource.example/data");
if (response.StatusCode == HttpStatusCode.Accepted)
{
    // Parse AAuth-Requirement header for interaction URL
    var requirement = AAuthRequirementHeader.Parse(
        response.Headers.GetValues("AAuth-Requirement").First());
    // Present interaction URL to user
    // Poll pending URL until resolved
}
```

### Server-Side (`IOpaqueTokenStore`)

```csharp
// Resource issues opaque tokens after interaction completes
builder.Services.AddSingleton<IOpaqueTokenStore>(new InMemoryOpaqueTokenStore());
```

## Error Scenarios

| Status | Header | Cause |
|--------|--------|-------|
| 401 | `Signature-Error: invalid_signature` | Signature doesn't verify |
| 202 | `AAuth-Requirement: interaction` | Authorization pending — user interaction required |
| 403 | *(none)* | Interaction completed but access denied by resource policy |

## Further Reading

- [Access Mode Comparison](https://explorer.aauth.dev/access/compare)
- [Identity-Based Access](identity-based-access.md)
- [PS-Asserted Access](ps-asserted-access.md)
