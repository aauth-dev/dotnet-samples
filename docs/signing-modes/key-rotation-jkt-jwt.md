# AP Key Refresh with jkt-jwt

## Overview

A self-issued, two-key delegation where a durable key signs a
naming JWT that delegates HTTP-message signing to a short-lived ephemeral key.
The scheme is **self-anchored**: the durable public key travels in the naming
JWT's header, and the issuer is that key's own thumbprint — so a verifier needs
no external lookup. Access stays **pseudonymous**. Defined in
[`draft-hardt-httpbis-signature-key-09`](../../aauth-spec/v11/draft-hardt-httpbis-signature-key-09.txt)
section 3.5. Draft-11 AAuth uses this scheme only in the Agent Provider key-refresh
ceremony (#keying-material) or in explicitly generic Signature-Key
demonstrations. AAuth resource, PS and AS requests present the returned
`aa-agent+jwt`, `aa-person+jwt` or `aa-auth+jwt` under `sig=jwt`.

## When to Use

- Refreshing an AP-issued agent token while rotating the request-signing key
- Hardware-backed durable keys that delegate to software ephemeral keys
- Two-key bootstrap refresh (agent ↔ AP) and explicitly generic Signature-Key endpoints

### Why this scheme exists (enclave delegation)

`jkt-jwt` was designed for the **secure-enclave mobile** case: the durable key
lives in a hardware enclave that can prove it is genuine but is slow or
impractical to invoke on every HTTP request. The enclave therefore signs a
naming JWT **once per agent-token lifetime** to delegate signing to a fast
ephemeral software key, which signs the actual requests.

An AP can additionally validate platform attestation at enrollment if its
deployment supports that ceremony. This SDK's samples use software keys and
signed enrollment, not hardware attestation. The AP binds the durable key to its enrollment record and returns an agent JWT
bound to the ephemeral key. Resource-facing AAuth requests then use that JWT
with `sig=jwt`; old auth tokens bound to the previous key require
re-authorization after the key changes. Generic verification alone does not
establish provider or device trust. See [Bootstrap & Enrollment](../workflows/bootstrap-enrollment.md)
for the implemented two-key refresh and [platform limits](../advanced/platform-attestation.md).

## Code Example

**Implemented AP two-key refresh:**

```csharp
using AAuth.Agent;
using AAuth.Crypto;
using AAuth;

using var apHttp = AAuth.Discovery.AAuthHttpTransport.CreateClient();
var apClient = new AgentProviderClient(apHttp, keyStore);
var refreshed = await apClient.RefreshTwoKeyAsync(apRefreshEndpoint, localKeyHandle);

using var client = new AAuthClientBuilder(refreshed.EphemeralKey)
    .UseJwt(refreshed.AgentToken)
    .Build();
```

The SDK does not perform this rotation automatically. Call
`AgentProviderClient.RefreshTwoKeyAsync`, then rebuild the resource client with
the returned `EphemeralKey` and `AgentToken` together. `Enrolled(...).RefreshingFrom(...)`
and `AgentProviderTokenRefresher` use the single-key refresh path.

**Generic/manual `jkt-jwt` signing:**

```csharp
using AAuth.Agent;
using AAuth.Crypto;
using AAuth;

var durableKey = AAuthKey.Generate();    // long-lived software key in this example
var ephemeralKey = AAuthKey.Generate();  // short-lived signing key

// The naming JWT is signed by the durable key, embeds the durable public key in
// its header, sets iss to the durable key's thumbprint URN, and names the
// ephemeral key via cnf.jwk.
var namingJwt = await NamingJwtBuilder.BuildAsync(durableKey, ephemeralKey);

using var client = new AAuthClientBuilder(ephemeralKey)
    .UseJktJwt(() => namingJwt)
    .Build();
```

<details>
<summary>Manual Setup</summary>

```csharp
using AAuth.HttpSig;

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
header:  { "typ": "jkt-s256+jwt", "alg": "Ed25519", "jwk": { …durable public key… } }
payload: { "iss": "urn:jkt:sha-256:<durable-thumbprint>",
           "iat": …, "exp": …,
           "cnf": { "jwk": { …ephemeral public key… } } }
```

## What the AP or Generic Verifier Sees

- `Signature-Key: sig=jkt-jwt;jwt="<jkt-s256+jwt>"` (a single `jwt` parameter)
- The reported pseudonym is the **durable** key's thumbprint — stable across
  ephemeral-key rotation.

An AAuth resource does not see `sig=jkt-jwt` for normal AAuth access. It sees the
agent, person or auth JWT returned by the AP/PS/AS under `sig=jwt`.

## Verification (self-anchored, section 3.5)

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
identity, not authority-vouched identity (Signature Keys §8.1).

## Further Reading

- [`draft-hardt-httpbis-signature-key-09`](../../aauth-spec/v11/draft-hardt-httpbis-signature-key-09.txt) section 3.5
- [Bootstrap](../workflows/bootstrap-enrollment.md)
