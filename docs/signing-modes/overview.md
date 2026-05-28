# Signing Modes Overview

All AAuth signing modes use HTTP Message Signatures (RFC 9421). The difference is what appears in the `Signature-Key` header and what the resource learns. See the [interactive comparison](https://explorer.aauth.dev/signing/compare).

## Comparison Table

| Mode | Scheme | Signature-Key Value | Resource Learns |
|------|--------|--------------------:|-----------------|
| Anonymous | (none) | No Signature-Key header | Nothing |
| Pseudonymous | `sig=hwk` | `sig=hwk;jkt="<thumbprint>";jwk="<key>"` | Key thumbprint + inline public key — identity unknown |
| Agent Identity | `sig=jwks_uri` | `sig=jwks_uri;uri="<url>";kid="<id>"` | Agent identifier + verifiable public key |
| Agent Token | `sig=jwt` | `sig=jwt;jwt="<compact-jws>"` | Agent identity, PS URL, bound signing key |

## When to Use Each

| Mode | Use Case | Requires |
|------|----------|----------|
| Anonymous | Public endpoints, no access control | Nothing |
| Pseudonymous (`hwk`) | Accountable access, rate-limiting by key | Just a keypair |
| Agent Identity (`jwks_uri`) | Access control by identity, replacing API keys | JWKS host (AP or self-hosted) |
| Agent Token (`jwt`) | Full PS-AS authorization flows | Token issuer (AP or self-issued) + Person Server |

## SDK Types

```csharp
using AAuth.Crypto;
using AAuth.HttpSig;

var key = AAuthKey.Generate();

// Builder API (recommended)
// For jwks_uri: kid = AP-published JWKS kid (AgentTokenKid) or self-chosen kid for self-hosted
using var client = mode switch
{
    "hwk"      => new AAuthClientBuilder(key).UseHwk().Build(),
    "jwks_uri" => new AAuthClientBuilder(key).UseJwksUri(jwksUri, kid).Build(),
    "jwt"      => new AAuthClientBuilder(key).WithTokenRefresh(refresher).WithChallengeHandling(ps).Build(),
    "jkt-jwt"  => new AAuthClientBuilder(ephemeralKey).UseJktJwt(() => namingJwt).Build(),
};

// Direct token (when you already hold a JWT — e.g., call chaining)
using var direct = new AAuthClientBuilder(key).UseJwt(preAcquiredToken).Build();
```

<details>
<summary>Manual Setup (ISignatureKeyProvider)</summary>

```csharp
ISignatureKeyProvider provider = mode switch
{
    "hwk"      => new HwkSignatureKeyProvider(key),
    "jwks_uri" => new JwksUriSignatureKeyProvider(jwksUri, kid),
    "jwt"      => new JwtSignatureKeyProvider(() => agentToken),
    "jkt-jwt"  => new JktJwtSignatureKeyProvider(ephemeralKey, () => namingJwt),
};

var handler = new AAuthSigningHandler(key, provider);
```

</details>

## Capability Matrix

| Capability | Anonymous | Pseudonymous | Agent Identity | Agent Token |
|-----------|:---------:|:------------:|:--------------:|:-----------:|
| Proof of key possession | — | ✓ | ✓ | ✓ |
| Agent identifier disclosed | — | — | ✓ | ✓ |
| Replay protection (jti) | — | — | — | ✓ |
| Remote key discovery (JWKS) | — | — | ✓ | — |
| Person Server binding | — | — | — | ✓ |

## Valid Combinations per Access Mode

Signing modes and access modes are orthogonal concepts:
- **Signing mode** = what appears in `Signature-Key` (how the agent proves identity)
- **Access mode** = how the resource decides authorization (who grants access)

The access mode determines which signing modes are valid:

| Access Mode | Valid Signing Modes | Why |
|-------------|--------------------:|-----|
| **Identity-Based** | `hwk`, `jwks_uri` | Resource decides from the signature alone. `hwk` gives pseudonymous access (key thumbprint only); `jwks_uri` gives named agent identity. No PS involvement, so `jwt` is not applicable. |
| **Resource-Managed** (two-party) | `hwk`, `jwks_uri`, `jwt` | Resource handles its own authorization (interaction, internal policy). Any signing mode works because the resource doesn't issue resource tokens to a PS — it manages access itself. |
| **PS-Asserted** (three-party) | `jwt` only | The resource issues a `resource_token` with `aud=PS`. The PS must verify the agent's identity via the agent token (`aa-agent+jwt`), which requires `scheme=jwt` in `Signature-Key`. |
| **Federated** (four-party) | `jwt` only | Same as PS-Asserted — the PS federates with the AS, but the agent-side requirement is identical: present the agent token via `scheme=jwt`. |
| **Bootstrap key rotation** | `jkt-jwt` | Special case: an ephemeral key is bound to a durable identity via a naming JWT. Used during key rotation, not as a primary access mode. |

> **Common confusion**: "Identity-Based" access mode supports the `hwk` (pseudonymous) signing mode even though `hwk` doesn't disclose a named identity. The term "Identity-Based" refers to the *access pattern* — the resource grants or denies based solely on the cryptographic signature, with no token exchange. The resource may allowlist specific key thumbprints (pseudonymous) or specific agent identifiers (`jwks_uri`). Both are "identity-based" in the sense that no PS or AS is involved.

## Anatomy of a Signed Request

Every mode produces the same three headers:

```
Signature-Key: sig=<scheme>;...       ← keying material (mode-specific)
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1700000000
Signature: sig=:base64url-ed25519-signature:
```

The `AAuthSigningHandler` handles construction automatically.

## Further Reading

- [Signing Mode Comparison](https://explorer.aauth.dev/signing/compare)
- [Signature-Key Schemes](https://explorer.aauth.dev/foundations/schemes)
- [HTTP Signatures Profile](https://explorer.aauth.dev/foundations/profile)
