# Signing Modes Overview

All AAuth signing modes use HTTP Message Signatures (RFC 9421). The difference is what appears in the `Signature-Key` header and what the resource learns. See the [interactive comparison](https://explorer.aauth.dev/signing/compare).

## Comparison Table

| Mode | Scheme | Signature-Key Value | Resource Learns |
|------|--------|--------------------:|-----------------|
| Anonymous | (none) | No Signature-Key header | Nothing |
| Pseudonymous | `sig=hwk` | `sig=hwk;jkt="<thumbprint>";jwk="<key>"` | Key thumbprint + inline public key — identity unknown |
| Key Rotation | `sig=jkt-jwt` | `sig=jkt-jwt;jwt="<jkt-s256+jwt>"` | A durable key's thumbprint (stable pseudonym) delegating to a rotatable ephemeral key via a self-issued naming JWT |
| Agent Identity | `sig=jwks_uri` | `sig=jwks_uri;uri="<url>";kid="<id>"` | Agent identifier + verifiable public key |
| Agent Token | `sig=jwt` | `sig=jwt;jwt="<compact-jws>"` | Agent identity, PS URL, bound signing key |

## When to Use Each

| Mode | Use Case | Requires |
|------|----------|----------|
| Anonymous | Public endpoints, no access control | Nothing |
| Pseudonymous (`hwk`) | Accountable access, rate-limiting by key | Just a keypair |
| Key Rotation (`jkt-jwt`) | Pseudonymous access where the request-signing key must rotate without re-enrolment | A durable key + an ephemeral key (and the ability to mint naming JWTs) |
| Agent Identity (`jwks_uri`) | Access control by identity, replacing API keys | JWKS host (AP or self-hosted) |
| Agent Token (`jwt`) | Full PS-AS authorization flows | Token issuer (AP or self-issued) + Person Server |

### Choosing by environment

The signing mode follows from **where and how the agent's key is stored** — as
the scheme's designer puts it, *"it all depends on the environment."*

- **Secure enclave / hardware-backed key** (mobile apps, TPM) → **`jkt-jwt`**.
  The durable key lives in an enclave that can prove its own genuineness but is
  slow or impractical to invoke on every request, so the agent delegates
  request-signing to a fast ephemeral software key via a naming JWT. On **first**
  enrolment the AP drives a **platform attestation** (e.g. Apple App Attest or
  Google Play Integrity) *alongside* the `jkt-jwt` to prove the durable key is
  real enclave material; after that, the durable-key signature on each naming JWT
  is all that is needed for future agent tokens — no re-attestation per refresh.
  `jkt-jwt` was introduced specifically for this case.
- **Single software keypair, no enclave constraint** → **`hwk`**. Simplest: the
  public key travels inline and the durable key signs requests directly. Use when
  nothing forces key delegation.
- **Published / discoverable key** (a host with a stable HTTPS URL + JWKS) →
  **`jwks_uri`** (named agent identity) or **`jwt`** (full agent token for PS/AS
  flows). The verifier resolves and trusts the key through the issuer's JWKS.

This is why the same two-key `jkt-jwt` machinery serves both the enclave-refresh
case and pseudonymous resource access: the choice is environment-driven, not a
single canonical default. At an AP, the durable key is therefore **not** trusted
by pure first-use — trust is established by the enrolment-time attestation and
carried forward by the durable-key signature on each naming JWT.

## SDK Types

```csharp
using AAuth.Crypto;
using AAuth;

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
    "jkt-jwt"  => new JktJwtSignatureKeyProvider(() => namingJwt),
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
| **Identity-Based** | `hwk`, `jkt-jwt`, `jwks_uri` | Resource decides from the signature alone. `hwk` and `jkt-jwt` give pseudonymous access (key thumbprint only — `jkt-jwt` additionally supports key rotation); `jwks_uri` gives a named agent identity. No PS involvement, so `jwt` is not applicable. |
| **Resource-Managed** (two-party) | `hwk`, `jkt-jwt`, `jwks_uri`, `jwt` | Resource handles its own authorization (interaction, internal policy). Any signing mode works because the resource doesn't issue resource tokens to a PS — it manages access itself. |
| **PS-Asserted** (three-party) | `jwt` only | The resource issues a `resource_token` with `aud=PS`. The PS must verify the agent's identity via the agent token (`aa-agent+jwt`), which requires `scheme=jwt` in `Signature-Key`. |
| **Federated** (four-party) | `jwt` only | Same as PS-Asserted — the PS federates with the AS, but the agent-side requirement is identical: present the agent token via `scheme=jwt`. |

> **`jkt-jwt` is a pseudonymous *scheme*, not a separate access mode.** A durable
> key signs a naming JWT that binds a fresh ephemeral signing key (key rotation
> without re-enrolment). It is valid wherever pseudonymous access is — the Profile
> server's [`/anchored`](../../samples/MockResourceServers/Profile/README.md)
> endpoint demonstrates it under Identity-Based access (reporting
> `signingMode = "pseudonymous"`) — and it is also what the SDK uses internally at
> AP refresh (see [Bootstrap & Enrollment](../workflows/bootstrap-enrollment.md)).

> **Common confusion**: "Identity-Based" access mode supports the `hwk` (pseudonymous) signing mode even though `hwk` doesn't disclose a named identity. The term "Identity-Based" refers to the *access pattern* — the resource grants or denies based solely on the cryptographic signature, with no token exchange. The resource may allowlist specific key thumbprints (pseudonymous) or specific agent identifiers (`jwks_uri`). Both are "identity-based" in the sense that no PS or AS is involved.

## Anatomy of a Signed Request

Every mode produces the same three headers:

```
Signature-Key: sig=<scheme>;...       ← keying material (mode-specific)
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1700000000
Signature: sig=:base64url-ed25519-signature:
```

The `AAuthSigningHandler` handles construction automatically.

## Adaptive Signature Components

Every signed request always covers the four base AAuth components shown above
(`@method`, `@authority`, `@path`, `signature-key`), plus `authorization` when
that header is present. A resource MAY require **additional** covered components
(for example `content-digest` for request-body integrity, or `content-type`).
The agent discovers these in one of two ways:

1. **From resource metadata.** If you know a resource publishes
   `additional_signature_components`, seed them so the very first request
   already covers them:

   ```csharp
   using var client = new AAuthClientBuilder(key)
       .WithTokenRefresh(refresher)
       .WithChallengeHandling(ps, options =>
       {
           options.AdditionalSignatureComponents =
               new Dictionary<string, IReadOnlyList<string>>
               {
                   ["https://resource.example"] = new[] { "content-digest" },
               };
       })
       .Build();
   ```

   The dictionary is keyed by origin (`scheme://host:port`).

2. **From a `401` response.** When a resource rejects a request with
   `Signature-Error: invalid_input; required_input="content-digest"`, the
   challenge handler learns the required components, re-signs the request
   covering them, and retries **once**. Learned components are cached per
   origin, so subsequent requests to the same resource cover them up front.

Additional components are always **additive** — the base components can never
be dropped or reordered. The component value is taken from the request's own
headers at signing time. When a resource requires `content-digest` (RFC 9530)
on a body-bearing request, the signing handler **computes and attaches it
automatically** (`sha-256`) before signing, so callers do not need to set it
themselves. Any required component AAuth cannot derive on its own must be
present on the request; if such a component is absent, signing fails fast with
an `InvalidOperationException` that names the resource origin.

See [Error Handling](../advanced/error-handling.md) for the
`Signature-Error` codes and `SignatureError.ParseRequiredInput`.

## Further Reading

- [Signing Mode Comparison](https://explorer.aauth.dev/signing/compare)
- [Signature-Key Schemes](https://explorer.aauth.dev/foundations/schemes)
- [HTTP Signatures Profile](https://explorer.aauth.dev/foundations/profile)
