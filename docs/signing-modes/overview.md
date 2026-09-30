# Signing Modes Overview

AAuth agents use `jwt` for every resource, PS and AS request. The SDK also
supports generic Signature Keys schemes, separately enabled with
`RequireGenericSignature()` or `AAuthVerificationOptions.Generic()`.
Every conveyed key requires a fully specified `alg`: Ed25519 or ES256.

## Comparison Table

| Mode | Scheme | Signature-Key Value | Resource Learns |
|------|--------|--------------------:|-----------------|
| Anonymous | (none) | No Signature-Key header | Nothing |
| Pseudonymous | `sig=hwk` | `sig=hwk;kty="OKP";crv="Ed25519";x="<key>";alg="Ed25519"` | Public-key possession; locally computed thumbprint |
| Key Rotation | `sig=jkt-jwt` | `sig=jkt-jwt;jwt="<jkt-s256+jwt>"` | A durable key's thumbprint (stable pseudonym) delegating to a rotatable ephemeral key via a self-issued naming JWT |
| Server Identity | `sig=jwks_uri` | `sig=jwks_uri;id="<issuer>";dwk="<metadata-name>";kid="<key-id>"` | Metadata-verified signer identifier |
| Direct Key URL | `sig=jwks` | `sig=jwks;url="<jwks-url>";kid="<key-id>"` | Exact JWKS URL identifies signer |
| Self-Issued Assertion | `sig=self-jwt` | `sig=self-jwt;jwt="<assertion>"` | Same discovered key verifies JWT and HTTP; no cnf |
| Agent Token | `sig=jwt` | `sig=jwt;jwt="<compact-jws>"` | Agent identity, PS URL, bound signing key |

## When to Use Each

| Mode | Use Case | Requires |
|------|----------|----------|
| Anonymous | Public endpoints, no access control | Nothing |
| Pseudonymous (`hwk`) | Accountable access, rate-limiting by key | Just a keypair |
| Key Rotation (`jkt-jwt`) | Pseudonymous access where the request-signing key must rotate without re-enrolment | A durable key + an ephemeral key (and the ability to mint naming JWTs) |
| Server Identity (`jwks_uri`) | Server signing with role metadata discovery | Signer identifier, metadata name and published kid |
| JWT (`jwt`) | All five AAuth resource access modes; agent/auth/subscribe token purpose depends on the endpoint | Token issuer and matching cnf key; PS only for PS-asserted/federated flows |

### Role and trust

AAuth agents always use `jwt`. PS/AS server signers use `jwks_uri` with their
identifier and role metadata. A generic deployment can enable other schemes.
`jkt-jwt` provides durable-to-ephemeral delegation; it does not itself establish
hardware provenance or an external issuer identity. AP refresh binds the verified
durable key to enrollment. Platform attestation remains an application policy.

`self-jwt` requires an explicitly registered `ISignatureTokenVerifier` for the
expected token type. It forbids `cnf`; the discovered issuer key verifies both
signatures. Unknown token types are rejected, not reported as issuer-verified.

`SelfIssuing(...).As(...)` provisions an agent token using the `jwt` carrier.
It does not select `self-jwt`. Enrollment/refresh describes how a credential is
obtained; Signature-Key scheme describes how its verification key is conveyed;
resource access mode describes who authorizes the request.

## SDK Types

```csharp
using AAuth.Crypto;
using AAuth;

var key = AAuthKey.Generate();

// Builder API (recommended)
// Generic scheme selection does not enable a PS/AS authorization flow.
using var client = mode switch
{
    "hwk"      => new AAuthClientBuilder(key).UseHwk().Build(),
    "jwks_uri" => new AAuthClientBuilder(key).UseJwksUri(identifier, dwk, kid).Build(),
    "jwks"     => new AAuthClientBuilder(key).UseJwks(jwksUrl, kid).Build(),
    "jwt"      => new AAuthClientBuilder(key).UseJwt(heldToken).Build(),
    "jkt-jwt"  => new AAuthClientBuilder(ephemeralKey).UseJktJwt(() => namingJwt).Build(),
    "self-jwt" => new AAuthClientBuilder(key).UseSelfJwt(() => assertion).Build(),
    _ => throw new ArgumentException("Unknown signature scheme."),
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
    "jwks_uri" => new JwksUriSignatureKeyProvider(identifier, dwk, kid),
    "jwks"     => new JwksSignatureKeyProvider(jwksUrl, kid),
    "jwt"      => new JwtSignatureKeyProvider(() => agentToken),
    "jkt-jwt"  => new JktJwtSignatureKeyProvider(() => namingJwt),
    _ => throw new ArgumentException("Unknown signature scheme."),
};

var signingKey = mode == "jkt-jwt" ? ephemeralKey : key;
var handler = new AAuthSigningHandler(signingKey, provider);
```

</details>

## Capability Matrix

| Capability | Anonymous | Pseudonymous | Agent Identity | Agent Token |
|-----------|:---------:|:------------:|:--------------:|:-----------:|
| Proof of key possession | — | ✓ | ✓ | ✓ |
| Agent identifier disclosed | — | — | ✓ | ✓ |
| Per-request signature freshness | — | ✓ | ✓ | ✓ |
| Optional signature replay cache | — | ✓ | ✓ | ✓ |
| Remote key discovery (JWKS) | — | — | ✓ | ✓ (cached) |
| Person Server binding | — | — | — | ✓ |

Every signed request is subject to signature freshness checks, regardless of its
signing scheme. An optional replay cache rejects repeated verified signatures
within that window for all schemes. Token revocation is separate, keyed by the
issuer and `jti`; a valid, non-revoked token remains reusable with fresh request
signatures. See [Replay Detection and Revocation](../server/replay-detection.md).

Agent Token verification discovers the issuer's signing key through role metadata
and JWKS, with cached discovery. The embedded `cnf.jwk` supplies the request's
confirmation key; it does not replace issuer-key discovery or JWT verification.

## Valid Combinations per Access Mode

Signing modes and access modes are orthogonal concepts:
- **Signing mode** = what appears in `Signature-Key` (how the agent proves identity)
- **Access mode** = how the resource decides authorization (who grants access)

The access mode determines which signing modes are valid:

| Access Mode | Valid Signing Modes | Why |
|-------------|--------------------:|-----|
| **Identity-Based** | `jwt` | The resource authorizes the verified agent identity. |
| **Resource-Managed** (two-party) | `jwt` | The agent token authenticates; the resource manages its opaque authorization token. |
| **PS-Asserted** (three-party) | `jwt` only | The resource issues a `resource_token` with `aud=PS`. The PS must verify the agent's identity via the agent token (`aa-agent+jwt`), which requires `scheme=jwt` in `Signature-Key`. |
| **Federated** (four-party) | `jwt` only | Same as PS-Asserted — the PS federates with the AS, but the agent-side requirement is identical: present the agent token via `scheme=jwt`. |

The Profile sample's `/pseudonymous`, `/identified` and `/anchored` routes are
generic signing demonstrations. They do not implement the AAuth identity-based
access mode, which requires an agent token.

## Anatomy of a Signed Request

Every mode produces the same three headers:

```
Signature-Key: sig=<scheme>;...       ← keying material (mode-specific)
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1700000000
Signature: sig=:standard-base64-signature:
```

The `AAuthSigningHandler` handles construction automatically.

## Adaptive Signature Components

Every signed request always covers the four base AAuth components shown above
(`@method`, `@authority`, `@path`, `signature-key`), plus `authorization` when
that header is present.

A request with a body also covers `content-type` and `content-digest`. The spec
requires both on every body-bearing request to a PS or AS, and on revocation
requests. The signing handler can't tell a PS or AS from a resource, so it
covers them on every request with a body and computes `Content-Digest` itself.
The caller must set `Content-Type`; a body without `Content-Type` fails locally
before any signature is sent. PS and AS endpoints (`MapAAuthPersonServer`, `MapAAuthAccessServer`,
`MapAAuthGovernance`, `MapR3AccessTokenEndpoint`) answer an uncovered body with
`401` `invalid_input` before any policy or consent hook runs. Other hosts can opt
in with `AAuthVerificationOptions.RequireBodyCoverage`.

A resource MAY require further covered components through its
`additional_signature_components` metadata.
The agent discovers these in one of two ways:

1. **From resource metadata.** If you know a resource publishes
   `additional_signature_components`, seed them so the very first request
   already covers them:

   ```csharp
   using AAuth.Discovery;

   ResourceMetadata resource = await metadata.FetchResourceMetadataAsync("https://resource.example");

   using var client = new AAuthClientBuilder(key)
       .WithTokenRefresh(refresher)
       .WithChallengeHandling(ps, options => options.AddResourceMetadata(resource))
       .Build();
   ```

   The helper keys the seed by origin (`scheme://host:port`) and uses the typed
   `ResourceMetadata.AdditionalSignatureComponents` field.

2. **From a `401` response.** When a resource rejects a request with
  `Signature-Error: error=invalid_input, required_input=("content-digest")`, the
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

When many identical requests use the same signing key, method, authority and
path in one second, the signer sends one immediately and waits until the next
wall-clock second for the next identical tuple. It never future-dates
`created`; cancellation while waiting prevents the request from being sent.

See [Error Handling](../advanced/error-handling.md) for the
`Signature-Error` codes and `SignatureError.ParseRequiredInput`.

## Further Reading

- [Signing Mode Comparison](https://explorer.aauth.dev/signing/compare)
- [Signature-Key Schemes](https://explorer.aauth.dev/foundations/schemes)
- [HTTP Signatures Profile](https://explorer.aauth.dev/foundations/profile)
