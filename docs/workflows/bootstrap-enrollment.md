# Bootstrap & Agent Enrollment

> [Signature-Key Schemes](https://explorer.aauth.dev/foundations/schemes)

Overview: Before an agent can use `jwks_uri` or `jwt` signing modes, it must register with an Agent Provider (AP) to get an agent token. This is the bootstrap step. For `hwk` (pseudonymous), no bootstrap is needed.

## Prerequisites

- An Agent Provider URL (e.g., `https://ap.example`)
- Agent identifier (e.g., `aauth:myapp@ap.example`)

```mermaid
sequenceDiagram
    participant Agent
    participant AP as Agent Provider
    Agent->>Agent: Generate Ed25519 keypair
    Agent->>AP: GET /.well-known/aauth-agent.json
    AP-->>Agent: metadata (enrol_endpoint, jwks_uri)
    Agent->>AP: POST /enrol {agent_id, jwk, ps?}
    AP-->>Agent: {agent_token, key_id, jwks_uri}
```

## Code Example

### Using BootstrapBuilder (Recommended)

```csharp
using AAuth.HttpSig;

var (client, enrolResult) = await AAuthClientBuilder
    .Bootstrap(
        enrollEndpoint: "https://ap.example/enrol",
        agentId: "aauth:myapp@ap.example")
    .WithPersonServer("https://ps.example")
    .WithChallengeHandling()
    .EnrolAndBuildAsync();

// client is ready to use with automatic challenge handling
// enrolResult.Key, enrolResult.AgentToken, enrolResult.KeyId
```

### Manual Enrollment

```csharp
using AAuth.Agent;
using AAuth.Crypto;

var keyStore = new InMemoryKeyStore(); // or KeyStore for file-based persistence
var apClient = new AgentProviderClient(new HttpClient(), keyStore);

var result = await apClient.EnrolAsync(
    apIssuer: "https://ap.example",
    agentId: "aauth:myapp@ap.example",
    enrollEndpoint: "https://ap.example/enrol",
    personServer: "https://ps.example" // optional: include if using three-party flows
);

// result.AgentToken = the aa-agent+jwt
// result.Key = the generated signing key
// result.KeyId = the key ID at the AP
```

## What Bootstrap Produces

- An `aa-agent+jwt` token signed by the AP, containing:
  - `iss`: AP URL
  - `sub`: agent identifier (`aauth:local@domain`)
  - `cnf.jwk`: the agent's public key (bound to identity)
  - `ps`: Person Server URL (optional, only if agent has a PS)
- The agent's private key stored in `IKeyStore`
- A `key_id` assigned by the AP (stable for the key's lifetime)
- A `jwks_uri` pointing to the per-agent JWKS endpoint where the AP publishes the agent's public key (used with `scheme=jwks_uri`)

## Which Flows Need Bootstrap

| Flow | Needs Bootstrap? | Why |
|------|:----------------:|-----|
| Pseudonymous (hwk) | No | Just needs a bare keypair |
| Agent Identity (jwks_uri) | Yes | AP publishes the agent's key at a per-agent JWKS endpoint |
| Three-party (jwt) | Yes | Agent token required for PS interactions |

## Key Persistence

```csharp
// File-based (persists to ~/.aauth/keys/)
var keyStore = KeyStore.Default();

// In-memory (testing only)
var keyStore = new InMemoryKeyStore();

// Custom (KMS, HSM, etc.)
class MyKeyStore : IKeyStore { ... }
```

## Further Reading

- [Agent Token mode](../signing-modes/agent-token-jwt.md)
- [Agent Identity mode](../signing-modes/agent-identity-jwks-uri.md)
- [Key Management](../advanced/key-management.md)
