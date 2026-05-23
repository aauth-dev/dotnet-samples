# Signing Modes Overview

All AAuth signing modes use HTTP Message Signatures (RFC 9421). The difference is what appears in the `Signature-Key` header and what the resource learns. See the [interactive comparison](https://explorer.aauth.dev/signing/compare).

## Comparison Table

| Mode | Scheme | Signature-Key Value | Resource Learns |
|------|--------|--------------------:|-----------------|
| Anonymous | (none) | No Signature-Key header | Nothing |
| Pseudonymous | `sig=hwk` | `sig=hwk;jkt="<thumbprint>"` | Key thumbprint — identity unknown |
| Agent Identity | `sig=jwks_uri` | `sig=jwks_uri;uri="<url>";kid="<id>"` | Agent identifier + verifiable public key |
| Agent Token | `sig=jwt` | `sig=jwt;jwt="<compact-jws>"` | Agent identity, PS URL, bound signing key |

## When to Use Each

| Mode | Use Case | Requires |
|------|----------|----------|
| Anonymous | Public endpoints, no access control | Nothing |
| Pseudonymous (`hwk`) | Accountable access, rate-limiting by key | Just a keypair |
| Agent Identity (`jwks_uri`) | Access control by identity, replacing API keys | Agent Provider + JWKS endpoint |
| Agent Token (`jwt`) | Full PS-AS authorization flows | Agent Provider + Person Server |

## SDK Types

```csharp
using AAuth.Crypto;
using AAuth.HttpSig;

var key = AAuthKey.Generate();

// Builder API (recommended)
using var client = mode switch
{
    "hwk"      => new AAuthClientBuilder(key).UseHwk().Build(),
    "jwks_uri" => new AAuthClientBuilder(key).UseJwksUri(jwksUri, kid).Build(),
    "jwt"      => new AAuthClientBuilder(key).UseJwt(agentToken).Build(),
    "jkt-jwt"  => new AAuthClientBuilder(ephemeralKey).UseJktJwt(() => namingJwt).Build(),
};
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

## Valid Combinations per Flow

| Flow | Valid Modes | Rationale |
|------|-----------|-----------|
| Identity-based (no PS) | `hwk`, `jwks_uri` | No PS-issued token available |
| Three-party (with PS) | `jwt` only | Spec: agent MUST present agent token via `scheme=jwt` |
| Bootstrap key rotation | `jkt-jwt` | Two-key delegation from durable to ephemeral |

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
