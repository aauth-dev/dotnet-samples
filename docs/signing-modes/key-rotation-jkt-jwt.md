# Key Rotation (sig=jkt-jwt)

## Overview

A self-issued, two-key delegation where a durable (hardware-backed) key signs a
naming JWT that delegates HTTP-message signing to a short-lived ephemeral key.
The scheme is **self-anchored**: the durable public key travels in the naming
JWT's header, and the issuer is that key's own thumbprint — so a verifier needs
no external lookup. Access stays **pseudonymous**. Defined in
[`draft-hardt-httpbis-signature-key-04`](../../aauth-spec/v02/draft-hardt-httpbis-signature-key-04.txt)
§3.4; the AAuth protocol references this scheme normatively.

## When to Use

- Rotating the request-signing key without re-enrolling
- Hardware-backed durable keys that delegate to software ephemeral keys
- Two-key bootstrap refresh (agent ↔ AP) and pseudonymous resource access

### Why this scheme exists (enclave delegation)

`jkt-jwt` was designed for the **secure-enclave mobile** case: the durable key
lives in a hardware enclave that can prove it is genuine but is slow or
impractical to invoke on every HTTP request. The enclave therefore signs a
naming JWT **once per agent-token lifetime** to delegate signing to a fast
ephemeral software key, which signs the actual requests.

Trust is anchored at enrolment, not by pure trust-on-first-use: on first use the
Agent Provider drives a **platform attestation** (e.g. Apple App Attest or Google
Play Integrity) *alongside* the `jkt-jwt` to prove the durable key really is
enclave-resident material. After that, the durable-key signature on each naming
JWT is sufficient for every future agent token — the AP does not re-attest on
each refresh. See [Bootstrap & Enrollment](../workflows/bootstrap-enrollment.md)
for the attestation ceremony and the two-key refresh flow.

## Code Example

```csharp
using AAuth.Crypto;
using AAuth;

var durableKey = AAuthKey.Generate();    // long-lived, possibly hardware-backed
var ephemeralKey = AAuthKey.Generate();  // short-lived signing key

// The naming JWT is signed by the durable key, embeds the durable public key in
// its header, sets iss to the durable key's thumbprint URN, and names the
// ephemeral key via cnf.jwk.
var namingJwt = NamingJwtBuilder.Build(durableKey, ephemeralKey);

using var client = new AAuthClientBuilder(ephemeralKey)
    .UseJktJwt(() => namingJwt)
    .Build();
```

<details>
<summary>Manual Setup</summary>

```csharp
var provider = new JktJwtSignatureKeyProvider(() => namingJwt);
var handler = new AAuthSigningHandler(ephemeralKey, provider)
{
    InnerHandler = new HttpClientHandler()
};
using var client = new HttpClient(handler);
```

</details>

## The naming JWT (jkt-s256+jwt)

```text
header:  { "typ": "jkt-s256+jwt", "alg": "EdDSA", "jwk": { …durable public key… } }
payload: { "iss": "urn:jkt:sha-256:<durable-thumbprint>",
           "iat": …, "exp": …,
           "cnf": { "jwk": { …ephemeral public key… } } }
```

## What the Resource Sees

- `Signature-Key: sig=jkt-jwt;jwt="<jkt-s256+jwt>"` (a single `jwt` parameter)
- The reported pseudonym is the **durable** key's thumbprint — stable across
  ephemeral-key rotation.

## Verification (self-anchored TOFU, §3.4 steps 1–11)

1. Parse the naming JWT and check `typ` is `jkt-s256+jwt`.
2. Extract the durable public key from the header `jwk`.
3. Compute its RFC 7638 thumbprint and build `urn:jkt:sha-256:<thumbprint>`.
4. Verify that value equals the `iss` claim by string equality.
5. Verify the naming JWT signature using the header `jwk`.
6. Validate `exp` / `iat`.
7. Take the ephemeral key from `cnf.jwk` and verify the HTTP Message Signature
   with it.

Because the issuer is derived from the header key, an attacker cannot claim
another agent's pseudonym: a spoofed `iss` fails step 4, and supplying the
victim's `jwk` fails step 5 (no private key). The scheme provides pseudonymous
identity, not authority-vouched identity (§6.3).

## Further Reading

- [`draft-hardt-httpbis-signature-key-04`](../../aauth-spec/v02/draft-hardt-httpbis-signature-key-04.txt) §3.4
- [Bootstrap](../workflows/bootstrap-enrollment.md)
