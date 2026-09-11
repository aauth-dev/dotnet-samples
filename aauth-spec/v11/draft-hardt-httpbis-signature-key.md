%%%
title = "HTTP Signature Keys"
abbrev = "Signature-Keys"
ipr = "trust200902"
area = "Applications and Real-Time"
workgroup = "HTTP"
keyword = ["http", "signature", "key", "jwk", "jwt"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-hardt-httpbis-signature-key-latest"
stream = "IETF"

date = 2026-06-17T00:00:00Z

[[author]]
initials = "D."
surname = "Hardt"
fullname = "Dick Hardt"
organization = "Hellō"
  [author.address]
  email = "dick.hardt@gmail.com"

[[author]]
initials = "T."
surname = "Meunier"
fullname = "Thibault Meunier"
organization = "Cloudflare"
  [author.address]
  email = "ot-ietf@thibault.uk"

%%%

<reference anchor="IANA.JOSE.Algorithms" target="https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms">
  <front>
    <title>JSON Web Signature and Encryption Algorithms</title>
    <author>
      <organization>IANA</organization>
    </author>
  </front>
</reference>

<reference anchor="x402" target="https://docs.x402.org">
  <front>
    <title>x402: HTTP 402 Payment Protocol</title>
    <author>
      <organization>x402 Foundation</organization>
    </author>
    <date year="2025"/>
  </front>
</reference>

<reference anchor="OpenID.Discovery" target="https://openid.net/specs/openid-connect-discovery-1_0.html">
  <front>
    <title>OpenID Connect Discovery 1.0</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Michael B. Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="E." surname="Jay" fullname="Edmund Jay">
      <organization>Illumila</organization>
    </author>
    <date year="2014" month="November"/>
  </front>
</reference>

.# Abstract

This document defines five HTTP header fields for use with HTTP Message Signatures as defined in RFC 9421. The Signature-Key request header distributes public keys used to verify signatures, with eight initial key distribution schemes: pseudonymous inline keys (hwk), self-issued key delegation via JWK Thumbprint JWTs (jkt-jwt), identified signers with JWKS URI discovery (jwks_uri), direct JWKS fetch (jwks), JWT-based delegation (jwt), self-issued JWTs (self-jwt), X.509 certificate chains (x509), and references to previously cached assertions (cached). The Accept-Signature-Scheme and Accept-Signature-Alg response headers state the schemes and algorithms a server accepts, so a client can select both before it signs. The Signature-Error response header provides structured error information when signature verification fails, and the Signature-Key-Cache response header issues a cache identifier by which a caller can reference a previously presented assertion instead of resending it. Together, these mechanisms enable flexible trust models ranging from privacy-preserving pseudonymous verification to horizontally-scalable delegated authentication and PKI-based identity chains.

.# Discussion Venues

*Note: This section is to be removed before publishing as an RFC.*

Source for this draft and an issue tracker can be found at https://github.com/dickhardt/signature-key.

{mainmatter}

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Introduction

HTTP Message Signatures [@!RFC9421] provides a powerful mechanism for creating and verifying digital signatures over HTTP messages. To verify a signature, the verifier needs the signer's public key. While RFC 9421 defines signature creation and verification procedures, it intentionally leaves key distribution to application protocols, recognizing that different deployments have different trust requirements.

Where the signer and verifier have no prior relationship, that gap is usually filled by out-of-band pre-registration or by an application-specific token. This document addresses the cases those two options do not cover.

**A verifier may have no prior relationship with the signer.** Pre-registration assumes the signer is known before the request. Agents, first-contact clients, and cross-domain callers frequently are not. When the first request is also the first contact, there is no registration step in which to have exchanged a key. The key, or a means to obtain it, has to travel with the request.

**The key material and its trust model are separate questions.** "Which key signed this" and "why should the verifier trust that key" are distinct. A raw inline key answers the first and defers the second to the verifier's policy. A key discovered from an origin ties the key to that origin. A delegated key carries an assertion from a third party. A certificate chain carries a PKI trust path. These are different trust models over the same signature primitive, and a mechanism that hard-codes one of them cannot serve the others. This document treats the trust model as a scheme dimension rather than a fixed choice.

**Key conveyance must be covered by the signature it introduces.** If the keying material or its identifier travels alongside the signature but is not itself signed over, an intermediary can substitute a different key or identifier and the signature still verifies against the substituted key. Conveying the key in a covered component closes this. A design that carries the key outside the signature's covered components reopens it. (#signature-key-integrity) describes the scheme-substitution and identity-substitution attacks this prevents.

**The verifier must be able to state what it will accept.** A signer that guesses the wrong key distribution scheme, or the wrong algorithm, learns nothing useful from a bare verification failure. Without a way for the verifier to say what it requires and what it supports, the extension point cannot be exercised or negotiated, and it ossifies.

This document defines:

- **Signature-Key** ((#signature-key-http-request-header)) — a request header that distributes public keys for HTTP Message Signature verification. The header supports eight schemes, each designed for different trust models and operational requirements:

  1. **Header Web Key (hwk)** - Self-contained public keys for pseudonymous verification
  2. **JKT JWT (jkt-jwt)** - Self-issued key delegation via JWK Thumbprint JWTs ("jacket jot")
  3. **JWKS URI (jwks_uri)** - Identified signers with key discovery via metadata
  4. **Direct JWKS (jwks)** - Keys fetched directly from an HTTPS URL that is also the signer identity
  5. **JWT (jwt)** - Delegated keys embedded in signed JWTs for horizontal scale
  6. **Self-Issued JWT (self-jwt)** - Self-signed JWTs where the signer and issuer are the same party
  7. **X.509 (x509)** - Certificate-based verification with PKI trust chains
  8. **Cached Assertion (cached)** - A reference to an assertion the verifier has already cached

  Additional schemes may be defined through the IANA registry established by this document.

- **Accept-Signature-Scheme** and **Accept-Signature-Alg** ((#accept-signature-scheme-and-accept-signature-alg-response-headers)) — response headers stating the Signature-Key schemes and the signature algorithms the server accepts. Both are Lists, so a server states its full accepted set and a client selects a scheme and an algorithm before signing.

- **Signature-Error** ((#signature-error-http-response-header)) — a response header that provides structured error information when signature verification fails, enabling clients to diagnose and correct signing issues.

- **Signature-Key-Cache** ((#signature-key-cache-response-header)) — a response header by which a verifier issues the caller an opaque cache identifier for an assertion it has cached, so that later requests can reference the assertion instead of resending it.

Three properties follow from the gaps above and are held as invariants throughout this document:

1. Keying material or its identifier is conveyed in the Signature-Key header, which is a covered component ((#signature-key-integrity)). The signature protects the key or identifier that introduces it.

2. The trust model is a scheme, not a fixed choice. A single header ((#signature-key-http-request-header)) carries any of an inline key, an origin-discovered key, a delegated key, or a certificate chain, distinguished by a scheme token. The header is one namespace for key conveyance; the trust model varies within it.

3. Unknown schemes and algorithms have defined, mandatory feedback. A verifier that does not implement a presented scheme returns `unsupported_scheme` with the set it supports ((#unsupported-scheme)). A verifier requires fully-specified algorithms and rejects underspecified ones ((#algorithm-determination)). The extension point is exercised on ordinary traffic rather than only at the moment a new value is first deployed, per the guidance of [@?RFC9170].

The Signature-Key header works in conjunction with the Signature-Input and Signature headers defined in RFC 9421, using matching labels to correlate signature metadata with keying material.

The mechanisms in this document were designed as general-purpose building blocks and are used by other specifications. In the AAuth protocol [@?I-D.hardt-oauth-aauth-protocol], all parties communicate using Signature-Key to distribute the keys that verify their signed requests. Email Verification [@?I-D.hardt-email-verification] uses the `hwk` scheme to convey the browser's public key so the issuer can bind it into the verification token it issues. Additional protocols can adopt these mechanisms without further coordination.

# Signature-Key HTTP Request Header

The `Signature-Key` header provides the public key or key reference needed to verify an HTTP Message Signature. It is a Structured Field Dictionary [@!RFC8941] keyed by signature label, where each member describes how to obtain the verification key for the corresponding signature.

**Format:**

```
Signature-Key: <label>=<scheme>;<parameters>...
```

Where:
- `<label>` (dictionary key) matches the label in Signature-Input and Signature headers
- `<scheme>` (token) identifies the key distribution scheme
- `<parameters>` are semicolon-separated key-value pairs whose values are structured field strings or byte sequences, varying by scheme

Multiple keys are comma-separated per the dictionary format. See [@!RFC8941] for definitions of dictionary, token, string, and byte sequence.

**Unknown schemes:**

A verifier that selects a member whose scheme token it does not implement, including any unregistered value, MUST reject the request with a `Signature-Error` of `error=unsupported_scheme` ((#unsupported-scheme)) and MUST NOT fail in a scheme-specific or undefined manner. Verifiers SHOULD dispatch on the scheme token through a lookup over the HTTP Signature-Key Scheme registry ((#scheme-registry)) rather than a fixed set of branches, so that unknown schemes take this defined path.

This rule governs the member the verifier selected, and that member alone. A verifier MUST NOT reject a request because a member it did not select names a scheme the verifier does not implement; such members are ignored under (#label-consistency). Without this, a signer could not offer a signature under a new scheme without breaking every verifier that does not implement it, so no signer would offer one and the scheme registry would have no path into deployment.

**Example:**

```
Signature-Input: sig=("@method" "@authority" "@path" "signature-key"); created=1732210000
Signature: sig=:MEQCIA5...
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="JrQLj..."
```

**Label Correlation:**

Labels are correlated by equality of label names across Signature-Input, Signature, and Signature-Key. Signature-Key is a dictionary keyed by label; Signature-Input and Signature are the sources of what signatures are present; Signature-Key provides keying material for those labels.

Verifiers MUST:

1. Parse Signature-Input and Signature per RFC 9421 and obtain the set of signature labels present. The verifier determines which labels it is attempting to verify based on application context and RFC 9421 processing.

2. Parse Signature-Key as a Structured Fields Dictionary

3. For each label being verified, select the Signature-Key dictionary member with the same name

4. If the Signature-Key header is present and the verifier is attempting to verify a label using it, but the corresponding dictionary member is missing, verification for that signature MUST fail

> **Note:** A verifier might choose to verify only a subset of labels present (e.g., the application-required signature); labels not verified can be ignored.

Signatures whose keys are distributed through mechanisms outside this specification (e.g., pre-configured keys, out-of-band key exchange) are out of scope. A Signature-Key header is not required for such signatures, and verifiers MAY use application-specific means to obtain the verification key.

## Label Consistency

If a label appears in Signature or Signature-Input, and the verifier attempts to verify it using Signature-Key, the corresponding member MUST exist in Signature-Key. If Signature-Key contains members for labels not being verified, verifiers MAY ignore them.

## Multiple Signatures {#multiple-signatures}

The dictionary format supports multiple signatures per message. Each signature has its own dictionary member keyed by its unique label:

```
Signature-Input: sig1=(... "signature-key"), sig2=(... "signature-key")
Signature: sig1=:...:, sig2=:...:
Signature-Key: sig1=jwt;jwt="eyJ...", sig2=jwks_uri;id="https://example.com";dwk="eg-config";kid="k1"
```

Most deployments use a single signature. When multiple signatures are required, the complete Signature-Key header (containing all keys) MUST be populated before any signature is created, and each signature MUST cover `signature-key`. This ensures all signatures protect the integrity of all key material. See (#signature-key-integrity) in Security Considerations. Alternative key distribution mechanisms outside this specification may be used for scenarios requiring independent signature addition.

## Algorithm Determination {#algorithm-determination}

Several schemes in this document convey or reference a JSON Web Key [@!RFC7517]. For any such JWK, the signature algorithm MUST be fully determined by the key, meaning the JWK carries an `alg` member whose value is a fully-specified algorithm identifier: one that determines the signature operation completely, including curve and hash where applicable. A verifier MUST reject a JWK whose `alg` member is absent or whose `alg` is a polymorphic identifier, and MUST NOT select an algorithm for it by inspecting other key parameters. This requirement applies identically regardless of how the JWK was obtained.

Algorithm identifiers in this document are values from the IANA "JSON Web Signature and Encryption Algorithms" registry [@!IANA.JOSE.Algorithms], established by [@!RFC7518] and extended since. This document uses the JOSE signing algorithms of [@!RFC9421], Section 3.3.7: the signature base is the JWS Signing Input, no JOSE header is used, and the key signals the algorithm rather than the wire. That section states that JWA values are not registered in the HTTP Signature Algorithms registry ([@!RFC9421], Section 6.2), and that the `alg` signature parameter is not used at all with JOSE signing algorithms. This document therefore does not use that registry; see (#algorithm-selection).

In particular:

- The `none` algorithm MUST NOT be used, nor any algorithm whose JOSE Implementation Requirement is `Prohibited`. [@!RFC9421], Section 3.3.7 requires this of any JWS algorithm used for an HTTP Message Signature. A server MUST NOT list such an algorithm in `Accept-Signature-Alg` ((#accept-signature-alg)); listing `none` would advertise that the server takes an unsigned request for a signed one.

- The polymorphic `EdDSA` identifier MUST NOT be used. Use the fully-specified `Ed25519` or `Ed448` identifiers registered by [@!RFC9864] instead.

- For RSA keys, the `alg` MUST name both the padding scheme and the hash, for example `PS256` (RSASSA-PSS with SHA-256) or `RS256` (RSASSA-PKCS1-v1_5 with SHA-256). A key type of `RSA` alone is insufficient, since it determines neither the padding nor the hash.

- The JOSE ECDSA identifiers `ES256`, `ES384`, and `ES512` are already fully specified and are used as-is.

- Symmetric algorithms MUST NOT be used. The `oct` key type and the JOSE MAC identifiers `HS256`, `HS384`, and `HS512` name a shared secret rather than a public key. A verifier MUST reject a Signature-Key scheme that conveys or references such a key, and a server MUST NOT list a symmetric algorithm in `Accept-Signature-Alg` ((#accept-signature-alg)). See (#symmetric-algorithms).

[@!RFC9864] states the rule this rests on — that a key be used with only a single algorithm, unless using one key with several is proven secure — and from it RECOMMENDS that the `alg` member of a JWK be present, unless some other mechanism ensures the key is used as intended. It also deprecates the polymorphic identifiers in the JOSE registry, which is what the first bullet above applies.

This document raises that RECOMMENDED to a requirement, and does so uniformly rather than conditionally on key type.

For OKP and EC keys, `kty` and `crv` do determine the algorithm between them, and so are an instance of the "other mechanism" [@!RFC9864] permits. No registered JOSE signing algorithm pairs the `Ed25519` curve with anything but `Ed25519`, or `P-256` with anything but `ES256`. They do not determine it for an RSA key, which has no `crv` and whose padding scheme and hash are both free, nor for the `AKP` key type of [@!RFC9964], which covers several ML-DSA parameter sets. Requiring `alg` of every conveyed key, including those it would be possible to derive, is a deliberate choice; (#why-alg-is-required) gives the reasons. [@?I-D.richer-oauth-httpsig] arrives at the same requirement independently for the keys it binds as JWKs.

A verifier MUST reject a key whose `alg` names an algorithm it does not support, reporting `unsupported_algorithm` ((#unsupported_algorithm)). `Accept-Signature-Alg` ((#accept-signature-alg)) states exactly that set — the algorithms the verifier accepts, neither a subset nor a superset — so a client that selects an algorithm from that list, and presents a key carrying it, is assured of clearing this check.

Where the `alg` member comes from depends on the scheme. The hwk scheme carries it as a header parameter, the key itself being in the header. The jwt and jkt-jwt schemes carry it inside `cnf.jwk`, in an assertion the issuer mints. The jwks_uri, jwks, and self-jwt schemes carry no algorithm in the Signature-Key header at all: that header conveys `id`, `kid`, and `dwk`, which identify a key rather than describe it, so the `alg` member of the resolved JWKS entry is the only channel. A deployment adopting one of those schemes MUST publish a key that carries `alg`. Pointing at an existing key that omits it does not satisfy this document, even though such a key is valid under [@!RFC7517], where `alg` is OPTIONAL. Only the key the `kid` selects is subject to this requirement; other members of the same JWKS are never resolved, so an existing metadata document can be reused by adding a conforming key to it.

A JWK also carries key-structure members: `kty`, which [@!RFC7517] requires, and `crv` where the key type has one. Because a fully-specified `alg` determines the key type and the curve, these members are redundant with it. They remain present, since the schemes in this document convey ordinary JWKs, and the redundancy is used as a check rather than ignored: a verifier MUST verify that `kty` and, where present, `crv` are consistent with `alg`, and MUST reject the key if they are not. A JWK with an `alg` of `ES256` and a `kty` of `RSA` is inconsistent and MUST be rejected, as is one with an `alg` of `ES256` and a `crv` of `P-384`. Rejecting on disagreement prevents a key from being used under either of two conflicting interpretations.

Post-quantum signature algorithms are accommodated by this rule without special treatment. For example, the ML-DSA identifiers `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87` registered by [@!RFC9964] are fully specified and are used directly as the JWK `alg` value. The requirement is algorithm-agnostic and accommodates additional post-quantum and hybrid algorithms as they are registered.

A verifier that encounters a JWK whose `kty` it does not implement, including the `AKP` key type defined by [@!RFC9964] for post-quantum keys, MUST reject the key with defined error feedback and MUST NOT fail in an undefined manner. Unrecognized key material is handled on the same defined path as an unsupported algorithm, via `unsupported_algorithm` ((#unsupported_algorithm)). Absence of support for a key type is a reason to decline, not a parsing failure.

The rules above apply to the key a scheme resolves to and to that key alone. A JWKS may hold keys a verifier cannot use. A verifier MUST select the member matching `kid` without requiring any other member to be usable, and MUST NOT fail because an unselected member names a `kty` or `alg` it does not implement.

Without this rule no signer could introduce a new algorithm: an issuer adding a post-quantum key alongside a classical one would break every verifier that does not implement the new type, including those that were only ever going to use the classical key. The accommodation above would never be reached in deployment, because no issuer could afford to publish such a key.

Within a single JWK, a member a verifier does not understand is ignored, as [@!RFC7517], Section 4 requires. A member this document forbids, such as `kid` in the hwk scheme ((#header-web-key-hwk)), is different: it is understood and rejected, not unknown and ignored.

## Header Web Key (hwk)

The hwk scheme provides a self-contained public key inline in the header, enabling pseudonymous verification without key discovery. The parameter names and values correspond directly to the JWK parameters defined in [@!RFC7517].

**Parameters by key type:**

OKP (Octet Key Pair):

- `kty` (REQUIRED, String) - "OKP"

- `crv` (REQUIRED, String) - Curve name (e.g., "Ed25519")

- `x` (REQUIRED, String) - Public key value

- `alg` (REQUIRED, String) - Fully-specified algorithm identifier (e.g., "Ed25519")

```
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="JrQLj5P...";alg="Ed25519"
```

EC (Elliptic Curve):

- `kty` (REQUIRED, String) - "EC"

- `crv` (REQUIRED, String) - Curve name (e.g., "P-256", "P-384")

- `x` (REQUIRED, String) - X coordinate

- `y` (REQUIRED, String) - Y coordinate

- `alg` (REQUIRED, String) - Fully-specified algorithm identifier (e.g., "ES256")

```
Signature-Key: sig=hwk;kty="EC";crv="P-256";x="f83OJ3D...";y="x_FEzRu...";alg="ES256"
```

RSA:

- `kty` (REQUIRED, String) - "RSA"

- `n` (REQUIRED, String) - Modulus

- `e` (REQUIRED, String) - Exponent

- `alg` (REQUIRED, String) - Fully-specified algorithm identifier naming padding and hash (e.g., "PS256")

```
Signature-Key: sig=hwk;kty="RSA";n="0vx7agoebGcQ...";e="AQAB";alg="PS256"
```

**Constraints:**

- The `alg` parameter MUST be present and fully specified. The inline JWK is subject to Algorithm Determination ((#algorithm-determination)).

- The `kid` parameter MUST NOT be used. The key is carried inline, so there is nothing for an identifier to select, and a `kid` that disagrees with the inline key has no defined resolution.

**Use cases:**

- Privacy-preserving agents that avoid identity disclosure

- Experimental or temporary access without registration

- Rate limiting and reputation building on a per-key basis

## JKT JWT Self-Issued Key Delegation (jkt-jwt) {#jkt-jwt-scheme}

The jkt-jwt scheme (pronounced "jacket jot") provides self-issued key delegation using a JWT whose signing key is embedded in the JWT header. This enables devices with hardware-backed secure enclaves to delegate signing authority to ephemeral keys, avoiding the performance cost of repeated enclave operations while maintaining a cryptographic chain of trust rooted in the enclave key.

Many devices — mobile phones, laptops, IoT hardware — include secure enclaves or trusted execution environments (e.g., Apple Secure Enclave, Android StrongBox, TPM) that can generate and store private keys with strong protection guarantees. However, signing operations using these enclaves are comparatively slow and may require user interaction (biometric confirmation, PIN entry).

For HTTP Message Signatures, where every request requires a signature, this creates a tension between security and performance. The jkt-jwt scheme resolves this by allowing the enclave key to sign a JWT that delegates authority to a faster ephemeral key:

1. The enclave generates a long-lived key pair (the identity key)
2. The device generates an ephemeral key pair in software (the signing key)
3. The enclave signs a JWT binding the ephemeral key via the `cnf` claim
4. HTTP requests are signed with the fast ephemeral key
5. The JWT proves the ephemeral key was authorized by the enclave key

The enclave key's JWK Thumbprint URI (`urn:jkt:<hash-algorithm>:<thumbprint>`) serves as a stable, pseudonymous device identity. Verifiers build trust in this identity over time (TOFU — Trust On First Use [@?RFC7435]).

**Parameters:**

- `jwt` (REQUIRED, String) - Compact-serialized JWT

- `cache` (OPTIONAL, Boolean) - As for the jwt scheme ((#jwt-confirmation-key-jwt)): the caller indicates it can present a cache identifier on subsequent requests, using the cached scheme ((#cached-scheme)), and requests that the verifier issue one. A JWT presented with `cache` MUST contain a `jti` claim. See (#signature-key-cache-response-header).

**JWT requirements:**

Header:

- `typ` (REQUIRED) - Identifies the thumbprint hash algorithm. Defined values: `jkt-s256+jwt` (SHA-256), `jkt-s512+jwt` (SHA-512). Implementations MUST support `jkt-s256+jwt` and MAY support additional algorithms.

- `alg` (REQUIRED) - Signature algorithm used by the enclave key

- `jwk` (REQUIRED) - JWK public key of the enclave/identity key (the key that signed this JWT)

Payload:

- `iss` (REQUIRED) - JWK Thumbprint URI of the signing key, in the format `urn:jkt:<hash-algorithm>:<thumbprint>` where the thumbprint is computed per [@!RFC7638]. The hash algorithm in the URN MUST match the algorithm indicated by the JWT `typ`. The verifier knows the hash algorithm from the `typ` it accepted, computes the thumbprint of the header `jwk`, prepends the known `urn:jkt:<hash-algorithm>:` prefix, and compares to `iss` by string equality.

- `iat` (REQUIRED) - Issued-at timestamp

- `exp` (REQUIRED) - Expiration timestamp

- `cnf` (REQUIRED) - Confirmation claim [@!RFC7800] containing `jwk`: the ephemeral public key delegated for HTTP message signing

- `jti` (OPTIONAL) - Unique identifier for this delegation. REQUIRED when the JWT is presented with the `cache` parameter, since a cacheable assertion must be identifiable ((#signature-key-cache-response-header)). The `iss` thumbprint does not serve: it names the enclave key, so successive delegations from one enclave share it.

The `sub` claim is not used. The identity is the enclave key itself, fully represented by the `iss` thumbprint.

The header `jwk` and the delegated key in `cnf.jwk` are each subject to Algorithm Determination ((#algorithm-determination)).

**JWT Type Values:**

The `typ` value encodes both the purpose and the thumbprint hash algorithm:

| `typ` | Hash Algorithm | `iss` prefix |
|---|---|---|
| `jkt-s256+jwt` | SHA-256 | `urn:jkt:sha-256:` |
| `jkt-s512+jwt` | SHA-512 | `urn:jkt:sha-512:` |

The `jkt-` prefix indicates a self-issued delegation JWT: the signing key is embedded in the JWT header as a JWK, the issuer is identified by the key's thumbprint, and the JWT delegates signing authority to the key in the `cnf` claim. The suffix (`s256`, `s512`) identifies the hash algorithm used for the thumbprint. The `typ` and `iss` prefix MUST be consistent.

These types are independent of the Signature-Key header and MAY be used in other contexts where self-issued key delegation is needed. Additional hash algorithms can be supported by registering new `typ` values following the `jkt-<alg>+jwt` pattern.

**Example:**

```
Signature-Key: sig=jkt-jwt;jwt="eyJ..."
```

JWT header:

```json
{
  "typ": "jkt-s256+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
  }
}
```

JWT payload:

```json
{
  "iss": "urn:jkt:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "iat": 1732210000,
  "exp": 1732296400,
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    }
  }
}
```

In this example, the enclave holds a P-256 key (signed via hardware) and delegates to an Ed25519 ephemeral key (signed in software). The identity is `urn:jkt:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`.

The stable (enclave) key algorithm in the JWT `alg` header is determined by what the enclave hardware supports. This document's example uses `ES256` with a P-256 stable key delegating to an Ed25519 request key; deployments whose enclaves support Ed25519 (or other) stable-key algorithms should document this explicitly. The `cnf.jwk` request key algorithm is likewise enclave-determined.

**Verification procedure:**

1. Parse the JWT without verifying the signature

2. Check the `typ` header (e.g., `jkt-s256+jwt`). Reject if the type is not supported.

3. Determine the hash algorithm and `iss` prefix from the `typ` (e.g., `jkt-s256+jwt` → SHA-256, `urn:jkt:sha-256:`)

4. Extract the `jwk` from the JWT header

5. Compute the JWK Thumbprint ([@!RFC7638]) of the header `jwk` using the determined hash algorithm

6. Construct the expected `iss` value by prepending the known prefix to the computed thumbprint

7. Verify the `iss` claim matches the constructed value by string equality

8. Verify the JWT signature using the header `jwk`

9. Validate `exp` and `iat` claims per policy

10. Extract the ephemeral public key from `cnf.jwk`

11. Verify the HTTP Message Signature using the ephemeral key

**Caching:**

Caching — the cached scheme ((#cached-scheme)) together with the `Signature-Key-Cache` response header ((#signature-key-cache-response-header)) — keeps an assertion off the wire in the steady state, and the saving grows with the size of the keys and signatures the assertion carries ((#pqc-sizes)). This applies to any cacheable assertion, not only to jkt-jwt. What is specific to jkt-jwt is that the assertion carries a public key in its header and is signed by that key, so caching it also removes the thumbprint computation and the verification of that signature, which the jwt scheme does not perform. That part of the saving is small, since post-quantum verification is comparable to classical; the bytes are the reason to cache. The per-request signature continues to use the ephemeral `cnf.jwk` key.

**Use cases:**

- Devices with hardware-backed secure enclaves delegating to fast ephemeral keys

- Persistent pseudonymous identity without requiring registration or authority

- Mobile apps, laptops, and IoT devices with enclave-backed identity

## JWKS URI Discovery (jwks_uri) {#jwks-uri-scheme}

The jwks_uri scheme identifies the signer and enables key discovery via a metadata document containing a `jwks_uri` property.

**Parameters:**

- `id` (REQUIRED, String) - Signer identifier (HTTPS URL)

- `dwk` (REQUIRED, String) - Dot well-known metadata document name under `/.well-known/`

- `kid` (REQUIRED, String) - Key identifier

**Discovery procedure:**

1. Fetch `{id}/.well-known/{dwk}`

2. Parse as JSON metadata. The document MUST contain `issuer` and `jwks_uri` members. Reject with `issuer_missing` ((#issuer_missing)) if `issuer` is absent.

3. Verify `issuer` equals the `id` parameter, by byte equality as presented. Reject with `issuer_mismatch` ((#issuer_mismatch)) if they differ.

4. Extract `jwks_uri` property

5. Fetch JWKS from `jwks_uri`

6. Find key with matching `kid`

The `issuer` check binds the metadata document to the identity it was fetched under. Without it, a document served at `{id}/.well-known/{dwk}` — through misconfigured shared hosting, a subdomain takeover, or any other means — could point `jwks_uri` at keys that do not belong to `id`, and the verifier would attribute the request accordingly. This is the same check [@!RFC8414], Section 3.3 requires of authorization server metadata, and a document conforming to [@!RFC8414] or OpenID Connect Discovery already carries `issuer`.

The JWK selected from the retrieved JWKS is subject to Algorithm Determination ((#algorithm-determination)).

**Example:**

```
Signature-Key: sig=jwks_uri;id="https://client.example";dwk="example-configuration";kid="key-1"
```

**Use cases:**

- Identified services with stable HTTPS identity

- Search engine crawlers and monitoring services

- Services requiring explicit entity identification

## Direct JWKS (jwks) {#jwks-scheme}

The jwks scheme identifies the signer by an HTTPS URL that returns a JWKS directly. Unlike jwks_uri, there is no metadata document and no discovery hop: the URL is both the signer's identifier and the location of its keys.

**Parameters:**

- `url` (REQUIRED, String) - HTTPS URL of the signer's JWKS

- `kid` (REQUIRED, String) - Key identifier

**Discovery procedure:**

1. Apply egress admission ((#scheme-specific-risks)) to `url`

2. Fetch `url`

3. Parse as a JWKS ([@!RFC7517])

4. Find the key with matching `kid`

The JWK selected from the fetched JWKS is subject to Algorithm Determination ((#algorithm-determination)).

**Example:**

```
Signature-Key: sig=jwks;url="https://client.example/keys.jwks";kid="key-1"
```

**Identifier semantics:**

Under the jwks scheme the signer's identity is the JWKS URL itself. A verifier that allowlists or policies by identity is doing so against `url`. Because identity and key location are the same string, moving the JWKS to a different URL changes the signer's identity. Signers that need identity to remain stable while key location changes independently should use the jwks_uri scheme ((#jwks-uri-scheme)), whose indirection exists for that purpose (see (#why-jwks-uri)). The jwks scheme trades that decoupling for a single fetch and zero configuration.

The `url` is compared by byte equality, as presented: a verifier MUST NOT canonicalize or normalize it, and values that differ in any byte name different identities. A signer MUST present the same bytes wherever it intends the same identity.

**Use cases:**

- Signers that want a self-describing identifier with no metadata to host

- Deployments where the JWKS URL is an acceptable stable identity

## JWT Confirmation Key (jwt)

The jwt scheme embeds a public key inside a signed JWT using the `cnf` (confirmation) claim [@!RFC7800], enabling delegation and horizontal scale.

**Parameters:**

- `jwt` (REQUIRED, String) - Compact-serialized JWT

- `cache` (OPTIONAL, Boolean) - When true, the caller indicates it can present a cache identifier on subsequent requests, using the cached scheme ((#cached-scheme)), and requests that the verifier issue one. Absent means the caller does not want one. Boolean true is indicated by omitting the value ([@!RFC8941], Section 4.1.1.2), so the parameter is serialized as `cache` rather than `cache=?1`. Because it is carried in the Signature-Key header, this signal is covered by the per-request signature. A JWT presented with `cache` MUST contain a `jti` claim ([@!RFC7519], Section 4.1.7); a verifier MUST NOT issue a cache identifier for a JWT without one. See (#signature-key-cache-response-header).

```
Signature-Key: sig1=jwt;jwt="eyJhbGciOiJFZERTQSJ9...";cache
```

**JWT requirements:**

- MUST contain `cnf.jwk` claim with embedded JWK. The key conveyed in the assertion is subject to Algorithm Determination ((#algorithm-determination)).

- SHOULD contain `iss` claim (HTTPS URL of the issuer) — using SHOULD rather than MUST allows existing JWT infrastructure to be used without modification

- SHOULD contain `dwk` claim (dot well-known metadata document name) — the verifier constructs `{iss}/.well-known/{dwk}` to discover the issuer's `jwks_uri`. Using SHOULD allows deployments where the verifier already knows the issuer's keys.

- MUST contain `exp` claim. The assertion carries a confirmation key, and `exp` is what bounds how long that key is accepted; without it the key remains acceptable indefinitely. See (#layered-cryptographic-agility).

- SHOULD contain standard claims: `sub`, `iat`

- Verifiers SHOULD verify the JWT `typ` header parameter has an expected value per deployment policy, following the explicit-typing guidance of [@!RFC8725], Section 3.11. The check is a defence against token confusion — an assertion minted for one context being accepted in another — and also rejects a wrong token before any cryptographic work.

> **Note:** The mechanism by which the JWT is obtained is out of scope of this specification.

**Verification procedure:**

1. Parse the JWT parameter value per [@!RFC7519] Section 7.2. Reject if the value is not a well-formed JWT. This and subsequent pre-signature checks allow the verifier to fail early without expensive cryptographic operations or network fetches.

2. Verify the JWT `typ` header parameter has an expected value per policy. Reject if unexpected.

3. Validate `exp` claim if present. Reject if the token has expired.

4. Verify required claims are present (`cnf.jwk`, plus any claims required by deployment policy). Reject if a required claim is missing.

5. If `iss` and `dwk` claims are present, fetch `{iss}/.well-known/{dwk}`, parse as JSON metadata, and verify the document's `issuer` member equals the `iss` claim as for the jwks_uri scheme ((#jwks-uri-scheme)), rejecting with `issuer_missing` or `issuer_mismatch`. Extract `jwks_uri`, fetch the JWKS from it, and find the key matching `kid` in the JWT header. If `iss` or `dwk` is absent, the verifier MUST obtain the issuer's key through an application-specific mechanism.

6. Verify JWT signature using the discovered key

7. Validate remaining JWT claims per policy (`iss`, `sub`, etc.)

8. Extract JWK from `cnf.jwk`

9. Verify HTTP Message Signature using extracted key

**Example:**

```
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFUzI1NiI..."
```

**JWT payload example:**

```json
{
  "iss": "https://issuer.example",
  "dwk": "example-configuration",
  "sub": "instance-123",
  "exp": 1732210000,
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    }
  }
}
```

**Use cases:**

- Distributed services with ephemeral instance keys

- Delegation scenarios where instances act on behalf of an authority

- Short-lived credentials for horizontal scaling

## Self-Issued JWT (self-jwt)

The self-jwt scheme carries a signed JWT where the JWT issuer and the HTTP request signer are the same party. The signing key is discoverable from the issuer's JWKS, and that same key verifies both the JWT and the HTTP Message Signature. Unlike the jwt scheme, no `cnf` claim is present — the signing key is the confirmation key.

**Parameters:**

- `jwt` (REQUIRED, String) - Compact-serialized JWT

**JWT requirements:**

- MUST contain `iss` claim (HTTPS URL of the issuer)

- MUST contain `dwk` claim (dot well-known metadata document name) — the verifier constructs `{iss}/.well-known/{dwk}` to discover the issuer's `jwks_uri`

- MUST have `kid` in the JWT header identifying the signing key in the issuer's JWKS. The JWK selected from the issuer's JWKS is subject to Algorithm Determination ((#algorithm-determination)).

- MUST NOT contain `cnf` claim

- MUST contain `exp` claim, bounding how long the assertion is accepted

- SHOULD contain standard claims: `sub`, `aud`, `iat`

The self-jwt scheme does not support the `cache` parameter, and a verifier MUST NOT issue a cache identifier for a self-jwt. A self-jwt embeds no key: its signing key is the confirmation key and is discovered from the issuer's JWKS by `iss` and `kid`. That key is already cacheable on those two values ((#caching-and-performance)), so caching the assertion in addition would save only the assertion's own bytes, of which there are few. A self-jwt also typically carries claims specific to the request it accompanies, so a cached copy would be stale for the next request rather than reusable.

- Verifiers SHOULD verify the JWT `typ` header parameter has an expected value per deployment policy, following the explicit-typing guidance of [@!RFC8725], Section 3.11. The check is a defence against token confusion — an assertion minted for one context being accepted in another — and also rejects a wrong token before any cryptographic work.

> **Note:** The mechanism by which the JWT is obtained is out of scope of this specification.

**Verification procedure:**

1. Parse the JWT parameter value per [@!RFC7519] Section 7.2. Verifiers MUST reject if the value is not a well-formed JWT. Performing this and the subsequent pre-signature checks first lets the verifier fail early, without expensive cryptographic operations or network fetches.

2. Verify the JWT `typ` header parameter has an expected value per policy. Reject if unexpected.

3. Validate `exp` claim if present. Reject if the token has expired.

4. Verify `iss`, `dwk` claims and `kid` JWT header parameter are present. Reject if any is absent.

5. Verify `cnf` claim is absent. Reject if present.

6. Construct `{iss}/.well-known/{dwk}`, parse as JSON metadata, and verify the document's `issuer` member equals the `iss` claim as for the jwks_uri scheme ((#jwks-uri-scheme)), rejecting with `issuer_missing` or `issuer_mismatch`. Extract `jwks_uri`, fetch the JWKS from it, and find the key matching `kid` from the JWT header. Reject if the key is not found (error: `unknown_key`).

7. Verify JWT signature using the discovered key.

8. Validate remaining JWT claims per policy (`sub`, `aud`, etc.)

9. Verify HTTP Message Signature using the same key from step 6.

**Example:**

```
Signature-Key: sig=self-jwt;jwt="eyJhbGciOiJFUzI1NiIsImtpZCI6InIxIn0..."
```

JWT header:

```json
{
  "alg": "ES256",
  "kid": "r1",
  "typ": "aauth-resource+jwt"
}
```

JWT payload:

```json
{
  "iss": "https://resource.example",
  "dwk": "aauth-resource",
  "aud": "https://agent.example",
  "eid": "evt-abc123",
  "exp": 1732210000
}
```

The verifier fetches `https://resource.example/.well-known/aauth-resource`, retrieves the JWKS, finds the key with `kid="r1"`, verifies the JWT signature with it, then uses that same key to verify the HTTP Message Signature.

**Use cases:**

- Resources delivering events with application-layer claims that the verifier needs alongside key verification

- Clients presenting themselves directly without delegating to a separate authority

## X.509 Certificates (x509)

The x509 scheme provides certificate-based verification using PKI trust chains.

**Parameters:**

- `x5u` (REQUIRED, String) - URL to X.509 certificate chain (PEM format, [@!RFC7517] Section 4.6)

- `x5t` (REQUIRED, Byte Sequence) - Certificate thumbprint: SHA-256 hash of DER-encoded end-entity certificate

**Verification procedure:**

1. Check cache for certificate with matching `x5t`

2. If not cached or expired, fetch PEM from `x5u`

3. Validate certificate chain to trusted root CA

4. Check certificate validity and revocation status

5. Verify `x5t` matches end-entity certificate

6. Extract public key from end-entity certificate

7. Verify signature using extracted key

8. Cache certificate indexed by `x5t`

For x509, the verifier determines the signature algorithm from the certificate's SubjectPublicKeyInfo together with the signing algorithm it will apply for HTTP Message Signature verification. The verifier MUST select a fully-specified algorithm and MUST NOT make a polymorphic selection.

**Example:**

```
Signature-Key: sig=x509;x5u="https://client.example/.well-known/cert.pem";x5t=:bWcoon4QTVn8Q6xiY0ekMD6L8bNLMkuDV2KtvsFc1nM=:
```

**Use cases:**

- Enterprise environments with PKI infrastructure

- Integration with existing certificate management systems

- Scenarios requiring certificate revocation checking

- Regulated industries requiring certificate-based authentication

## Cached Assertion (cached) {#cached-scheme}

> **Editor's Note:** Assertion caching, comprising this scheme, the `cache` signal on the jwt and jkt-jwt schemes, the `Signature-Key-Cache` response header ((#signature-key-cache-response-header)), and the `cache_miss` error ((#cache_miss)), is a straw man offered as a starting point for discussion, not a settled design. Caching is hard, and this may not be the right layer for it. Mechanisms that already exist lower down may fit better: HPACK ([@?RFC7541]) and QPACK ([@?RFC9204]) header compression already avoid retransmitting a repeated header field value, entity tags ([@!RFC9110], Section 8.8.3) already express "I hold this, do you" at the HTTP layer, and HTTP/2 and HTTP/3 session resumption already carry state across connections. The problem is real and grows with post-quantum assertion sizes ((#pqc-sizes)); the shape of the answer is open. Feedback on whether this belongs in this document, and at this layer, is specifically sought.

The cached scheme references an assertion the verifier has previously cached and issued a cache identifier for ((#signature-key-cache-response-header)), in place of presenting the assertion in full.

**Parameters:**

- `cid` (REQUIRED, String) - The cache identifier previously issued by the verifier for this assertion. It is opaque to the caller, which MUST present it exactly as received and MUST NOT parse or construct it.

**Example:**

```
Signature-Key: sig1=cached;cid="2f9c8a1e-a7b3"
```

A request using the cached scheme MUST carry the per-request HTTP Message Signature as usual. The cache identifier stands in for the assertion, not for the signature. The verifier resolves it to the cached assertion ((#presenting-and-resolving-a-cached-assertion)), obtains the assertion's confirmation key, and verifies the per-request signature against that key. The `signature-key` component is covered by the signature ((#signature-key-integrity)), so the cache identifier is signed over and cannot be substituted by an intermediary.

A caller MUST NOT present a cache identifier unless a verifier has issued one for that assertion via Signature-Key-Cache ((#signature-key-cache-response-header)). A verifier that does not implement assertion caching treats cached as an unimplemented scheme and returns `unsupported_scheme` ((#unsupported-scheme)); the caller then retries with the full assertion.

# Accept-Signature-Scheme and Accept-Signature-Alg Response Headers {#accept-signature-scheme-and-accept-signature-alg-response-headers}

[@!RFC9421] Section 5 defines the `Accept-Signature` response header for requesting HTTP Message Signatures. Its signature metadata parameters are Item parameters, whose values are bare Items ([@!RFC8941], Section 3.1.2) and cannot be lists. A server therefore cannot use `Accept-Signature` to state that it accepts any of several Signature-Key schemes, nor any of several algorithms: its `alg` parameter names one algorithm.

This document defines two response header fields that carry those sets. Both are List Structured Fields ([@!RFC8941], Section 3.1) of Tokens, so a server states everything it accepts in one response, and a client selects a scheme and an algorithm before it signs rather than discovering them through a rejection.

Both headers are advisory capability statements, not directives. A server that omits them is not asserting that it accepts everything; a client that cannot satisfy them learns the outcome from `Signature-Error` ((#error-codes)) as before.

## Accept-Signature-Scheme {#accept-signature-scheme}

`Accept-Signature-Scheme` is a List ([@!RFC8941], Section 3.1) of Tokens, each naming a scheme registered in the HTTP Signature-Key Scheme registry ((#scheme-registry)). It states the Signature-Key schemes the server accepts.

```http
Accept-Signature-Scheme: hwk, jwks_uri, jwt
```

Order carries the server's preference: a server SHOULD list schemes in descending order of preference. A client MAY choose any listed scheme it can satisfy, and the order does not bind it. The preference is an operational convenience for the server, while the choice of scheme decides whether the signer stays pseudonymous or is identified ((#pseudonymity-vs-identity)). A client that would be identified under the server's first preference and pseudonymous under its second is entitled to take the second.

A client MUST ignore tokens it does not recognize, so that a server may list schemes registered after the client was written without breaking it. A client that recognizes no listed scheme SHOULD NOT sign the request, since no scheme it can produce will be accepted.

Listing the `cached` scheme ((#cached-scheme)) states that the server implements assertion caching. A client that sees it can set the `cache` signal ((#jwt-confirmation-key-jwt), (#jkt-jwt-scheme)) on its first request rather than probing. `cached` is a capability announcement rather than a scheme a client can choose to present: a client MUST NOT present it until a verifier has issued it a cache identifier, whatever the list order. A server that lists `cached` first is stating a preference for the steady state, not for the first request, and the client selects any scheme it can satisfy from the remainder.

## Accept-Signature-Alg {#accept-signature-alg}

`Accept-Signature-Alg` is a List ([@!RFC8941], Section 3.1) of Tokens, each a fully-specified identifier from the IANA "JSON Web Signature and Encryption Algorithms" registry [@!IANA.JOSE.Algorithms] — the same identifiers a conveyed key carries in its `alg` member ((#algorithm-determination)), and not those of the HTTP Signature Algorithms registry, which this document does not use ((#algorithm-selection)). It states the signature algorithms the server accepts. Using the registry the key uses is what lets a client compare what a server accepts against the keys it holds.

```http
Accept-Signature-Alg: Ed25519, ES256
```

Each Token is the registered identifier verbatim, including its case: `ES256`, not `es256`. Structured Field parsing preserves the case of a Token ([@!RFC8941], Section 4.2.6), and the comparison a client performs is against the `alg` member of a JWK, a case-sensitive JSON string. A case-folded token names no registered algorithm and matches no key.

Order, unknown-token handling, and the no-recognized-value case are as for `Accept-Signature-Scheme`.

Because a fully-specified algorithm identifier determines the key type and curve ((#algorithm-determination)), this list also tells the client which keys are usable, and so which key to generate or select when it holds more than one.

`Accept-Signature-Alg` states what the server accepts. The `alg` parameter of `Accept-Signature` ([@!RFC9421], Section 5.1) requests one specific algorithm for a specific signature label, naming it in the HTTP Signature Algorithms registry, which this document does not use ((#algorithm-selection)): under the JOSE signing algorithms the algorithm is signaled by the key, not requested on the wire. A server that sends `Accept-Signature-Alg` SHOULD NOT send the `alg` parameter, and a client MAY ignore an `alg` received alongside `Accept-Signature-Alg`; the algorithm the client uses is the one its key carries ((#algorithm-determination)).

## Relationship to Accept-Signature

`Accept-Signature` continues to carry what is to be signed: the covered components, and the per-label parameters of [@!RFC9421] Section 5.1. The two headers defined here carry what the server will accept in the `Signature-Key` header and in the signature itself. They are independent fields; a response MAY include any combination.

Neither header is keyed by signature label. Both state a server-wide capability, which does not vary per signature. A deployment that genuinely requires different schemes for different labels in one multi-signature message is outside what these headers express, and states the requirement in its own protocol.

`Accept-Signature` also defines a `keyid` parameter ([@!RFC9421], Section 5.1), which asks the signer to use key material the two parties already hold. Where the client is to identify its key through `Signature-Key`, `keyid` has nothing left to name: a server SHOULD NOT send it, and a client MAY ignore it. If a signer includes `keyid` in `Signature-Input` for a label it also lists in `Signature-Key`, the two MUST identify the same key, and a verifier verifying that label MUST take the key from `Signature-Key`.

```http
HTTP/1.1 401 Unauthorized
Accept-Signature: sig1=("@method" "@path" "@authority");created
Accept-Signature-Scheme: jwks_uri, jwt
Accept-Signature-Alg: Ed25519
```

The client responds with matching labels:

```
Signature-Key: sig1=jwks_uri;id="https://client.example";dwk="example-configuration";kid="key-1"
Signature-Input: sig1=("@method" "@path" "@authority" "signature-key");
    created=1732210000
Signature: sig1=:MEQCIA5...:
```

The `signature-key` covered component is added by the client per this specification's requirement that `signature-key` appear in covered components. The server does not need to list it in `Accept-Signature`.

## Sending on Errors and on Challenges

Both headers MAY be sent on any response. They are useful on two occasions in particular.

On a challenge, before the client has signed anything, they let the client choose correctly the first time.

On a `Signature-Error` response, they say what would have worked. A server returning `unsupported_scheme` ((#unsupported-scheme)) SHOULD include `Accept-Signature-Scheme`, and a server returning `unsupported_algorithm` ((#unsupported_algorithm)) SHOULD include `Accept-Signature-Alg`. The error names what went wrong; the header names what would succeed. A server MAY omit the header where enumerating its accepted schemes or algorithms to an unauthenticated caller is judged a disclosure risk, accepting that a client then has to discover them by trial or out of band; the same consideration applies to `Signature-Error` itself.

```http
HTTP/1.1 401 Unauthorized
Signature-Error: error=unsupported_scheme
Accept-Signature-Scheme: jwks_uri, jwt
```

## Response Status Codes

These headers can be set on any response. Below is a list of what they MAY mean on responses with the following status codes:

| Status | Meaning | Legacy client behavior | Signature-aware client behavior |
|--------|---------|----------------------|-------------------------------|
| `401` | Authentication required | Falls back to WWW-Authenticate | Signs request with an accepted Signature-Key scheme |
| `402` | Payment + authentication required | Processes payment mechanism | Signs request AND processes payment |
| `429` | Rate limited | Respects Retry-After, slows down | Signs request, gets higher per-key rate limit |

The `429` case is particularly important for incremental adoption: a server can add these headers to its existing 429 responses with zero risk. Legacy clients ignore the unknown header fields and respect `Retry-After`. Signature-aware clients sign with a pseudonymous key, giving the server a stable key thumbprint for per-client rate limiting, and the client gets a higher rate limit in return.

## Incremental Adoption

These headers are designed for zero-coordination deployment. They are unknown to legacy clients, and an unknown header field is ignored, so servers can add them to existing responses without breaking anything.

**Stage 1 - Rate limiting (429):** A server adds `Accept-Signature-Scheme: hwk` to its 429 responses. Legacy clients slow down as before. Signature-aware clients sign requests and get higher per-key rate limits. The server gains per-client rate limiting without requiring registration or API keys.

**Stage 2 - Authentication (401):** The server starts requiring signatures on some paths, returning 401 with `Accept-Signature-Scheme: hwk`. It can include `WWW-Authenticate` alongside for legacy clients that have other auth mechanisms. Signature-aware clients sign; legacy clients fall back to bearer tokens or other schemes.

**Stage 3 - Identity (401):** The server advertises `Accept-Signature-Scheme: jwks_uri, jwt, x509` on sensitive paths, requiring verifiable client identity. The server can now make identity-based policy decisions without pre-registration.

Each stage is independently deployable. A server can use stage 1 on all endpoints while using stage 3 on admin endpoints. No bilateral agreements or client coordination required.

## Coexistence with WWW-Authenticate

These headers and `WWW-Authenticate` ([@!RFC9110], Section 11.6.1) are independent header fields; a response MAY include both. A client that understands Signature-Key processes the `Accept-Signature-*` headers; a legacy client processes `WWW-Authenticate`. Neither header's presence invalidates the other.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api"
Accept-Signature-Scheme: jwks_uri, jwt
Accept-Signature-Alg: ES256
```

What a client that understands both mechanisms does depends on what the `WWW-Authenticate` auth-scheme does. Nothing on the wire says which, and this document defines no signal for it, but a client only faces the choice for a scheme it already understands.

- Where the challenge is an authentication or authorization challenge, such as `Basic` or `Bearer`, the two are alternatives. The client SHOULD sign the request rather than present the credential: a signature demonstrates possession of a private key over this request, whereas a bearer credential authenticates whoever holds it, and signing puts no credential on the wire that the exchange did not require. A response carrying both does not assert that the two grant the same access, so a client that needs what only the credential grants MAY present it instead, and a server that is not satisfied by the choice challenges again.

- Where the challenge is not an authentication or authorization challenge, such as the payment challenge defined by the Micropayment Protocol ([@?I-D.ryan-httpauth-payment]), the two are complements: satisfying one does not satisfy the other, and a client that wants the resource satisfies both.

A `402` response MAY include a payment mechanism such as x402 [@?x402] or the Micropayment Protocol ([@?I-D.ryan-httpauth-payment]) alongside a signature challenge. Payment is not authentication, so this is the complementary case and a client satisfies both:

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="x7Tg2pLq", method="example",
    request="eyJhbW91bnQiOiIxMDAw..."
Accept-Signature-Scheme: hwk
```

## Examples

Pseudonymous access:

```http
HTTP/1.1 401 Unauthorized
Accept-Signature-Scheme: hwk
```

Identity with algorithm restriction:

```http
HTTP/1.1 401 Unauthorized
Accept-Signature-Scheme: jwks_uri, jwt
Accept-Signature-Alg: ES256
```

Rate limiting with pseudonymous upgrade:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30
Accept-Signature-Scheme: hwk
```

Payment with pseudonymous authentication:

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="x7Tg2pLq", method="example",
    request="eyJhbW91bnQiOiIxMDAw..."
Accept-Signature-Scheme: hwk
```

## Client Processing {#client-processing}

When a client receives a response containing `Accept-Signature-Scheme` ((#accept-signature-scheme)), it MAY retry the request with an HTTP Message Signature using any listed Signature-Key scheme it can satisfy.

[@!RFC9421] Section 5.2 defines the processing of `Accept-Signature` by the client. A client MAY ignore `Accept-Signature-Scheme` and `Accept-Signature-Alg`, and MUST ignore tokens within them that it does not recognize.

If a client already knows which schemes and algorithms the server accepts (from a previous interaction or metadata), it MAY sign the initial request directly without waiting for a challenge response.

A conforming verifier, when presented with a well-formed request bearing an unknown or unregistered scheme, returns `unsupported_scheme` and an `Accept-Signature-Scheme` header naming what it accepts. This exercises the unknown-scheme path as a matter of defined behavior.

When a `429` response includes both `Retry-After` and `Accept-Signature-Scheme`, the client MAY retry one time with a signed request without waiting for the `Retry-After` interval. Signing the request provides a key thumbprint that enables per-client rate limiting, which may result in a higher rate limit for the client.

A server MAY return a `429` response without `Accept-Signature-Scheme` to a signed request when it wants to rate-limit the client regardless of signing. In this case, the client MUST respect `Retry-After` as usual.

> **Open Issue:** Should this specification define a baseline HTTP Message Signatures profile (minimum covered components, timestamp requirements, verification steps), or is that always the responsibility of the protocol using these headers? See [GitHub issue #7](https://github.com/dickhardt/signature-key/issues/7).

# Signature-Error HTTP Response Header

When a server rejects a signed request due to a signature-related error, the response SHOULD include the `Signature-Error` header. A server MAY omit it where returning diagnostic detail to an unauthenticated caller is itself judged a disclosure risk, accepting that clients then cannot self-diagnose. The response status code is typically `400 Bad Request`, since the signature or keying material is malformed or invalid. A server MAY use `401 Unauthorized` for recoverable errors (e.g., `unsupported_algorithm`, `unsupported_scheme`, `invalid_input`) where the client can retry with corrected parameters.

## Header Structure

The `Signature-Error` header is a Dictionary ([@!RFC8941], Section 3.2) with the following member:

- `error` (REQUIRED): A Token ([@!RFC8941], Section 3.3.4) indicating the error code.

Additional members are defined per error code. Recipients MUST ignore unknown members.

```http
Signature-Error: error=unsupported_algorithm
```

The `Signature-Error` header is the authoritative source for machine-readable error information. The client MUST NOT depend on the response body for error handling.

## Response Body

Servers SHOULD use Problem Details [@!RFC9457] (`application/problem+json`) for the response body when returning `Signature-Error`, and MAY use another representation where content negotiation or an existing error format requires it. The header, not the body, is the interoperable carrier. Where a Problem Details body is returned, its `type` member MUST be a URN of the form `urn:ietf:params:sig-error:<error-code>`, where `<error-code>` matches the `error` value in the header; a `type` of any other form cannot be interpreted against this document's registry.

```json
{
  "type": "urn:ietf:params:sig-error:unsupported_algorithm",
  "title": "Unsupported signature algorithm",
  "status": 400,
  "detail": "The server does not support RS256"
}
```

Extension members in the Problem Details object MAY duplicate information from the `Signature-Error` header for convenience. When the header and body conflict, the header takes precedence.

## Access Denied

When the server successfully verifies the client's signature and identity but denies access based on policy (e.g., the client is not authorized for this resource), the server returns `403 Forbidden`. This is not a signature error — the authentication succeeded but authorization was denied. The response MUST NOT include an `Accept-Signature-Scheme` header, an `Accept-Signature-Alg` header, or a `Signature-Error` header.

## Error Codes {#error-codes}

### unsupported_algorithm {#unsupported_algorithm}

The signing algorithm used by the client is not supported by the server.

The response SHOULD include an `Accept-Signature-Alg` header ((#accept-signature-alg)) naming the algorithms the server accepts.

```http
Signature-Error: error=unsupported_algorithm
Accept-Signature-Alg: Ed25519, ES256
```

This error also covers a JWK whose key type the server does not implement ((#algorithm-determination)). Because a fully-specified algorithm identifier determines the key type, the accompanying `Accept-Signature-Alg` tells the client which key types are usable without a separate list: a client offered `Ed25519` learns that an OKP key on the Ed25519 curve is accepted.

### unsupported_scheme {#unsupported-scheme}

The Signature-Key scheme presented by the client is not supported by the server.

The response SHOULD include an `Accept-Signature-Scheme` header ((#accept-signature-scheme)) naming the schemes the server accepts.

```http
Signature-Error: error=unsupported_scheme
Accept-Signature-Scheme: jwks_uri, jwt
```

This error is recoverable. A server MAY return it with `401 Unauthorized` so the client can retry with an accepted scheme.

### cache_miss {#cache_miss}

A cache identifier presented with the cached scheme ((#cached-scheme)) could not be resolved to a cached assertion. It is unknown, has been evicted, or failed integrity or decryption.

```http
Signature-Error: error=cache_miss
```

This error is recoverable and carries no additional members. The caller retries the request presenting the assertion in full (for example via the jwt scheme). A verifier MAY return it with `401 Unauthorized`. A verifier MUST NOT treat an unresolved cache identifier as an authorization failure, and MUST NOT return `cache_miss` for an assertion that resolved but failed validation.

### invalid_signature

The HTTP Message Signature is missing, malformed, or cryptographic verification failed. This includes missing `Signature`, `Signature-Input`, or `Signature-Key` headers, an expired `created` timestamp, or a signature that does not verify.

```http
Signature-Error: error=invalid_signature
```

### invalid_input

The Signature-Input is missing required covered components.

- `required_input` (RECOMMENDED): An Inner List of String ([@!RFC8941], Section 3.1.1) listing the covered components the server requires. A server SHOULD include this member, and MAY omit it where enumerating its requirements to an unauthenticated caller is judged a disclosure risk; a client then has to discover the required components by other means.

```http
Signature-Error: error=invalid_input,
    required_input=("@method" "@authority" "@path"
    "signature-key" "content-digest")
```

### invalid_request

The request is malformed or missing required information unrelated to signature verification — such as missing query parameters or an unsupported content type.

```http
Signature-Error: error=invalid_request
```

### invalid_key

The public key in `Signature-Key` could not be parsed, is expired, or does not meet the server's trust requirements.

```http
Signature-Error: error=invalid_key
```

### unknown_key

The public key from `Signature-Key` does not match any key at the client's `jwks_uri` (applicable when the client uses `scheme=jwks_uri`). The server SHOULD re-fetch the JWKS once before returning this error, to handle key rotation.

```http
Signature-Error: error=unknown_key
```

### issuer_missing {#issuer_missing}

The metadata document fetched during discovery does not contain an `issuer` member. Applicable to the jwks_uri scheme ((#jwks-uri-scheme)), and to the jwt and self-jwt schemes when they discover the issuer's keys through a metadata document.

```http
Signature-Error: error=issuer_missing
```

### issuer_mismatch {#issuer_mismatch}

The `issuer` member of the metadata document fetched during discovery does not match the identity the document was fetched under: the `id` parameter for the jwks_uri scheme, or the `iss` claim for the jwt and self-jwt schemes.

```http
Signature-Error: error=issuer_mismatch
```

### invalid_jwt

The JWT in the `Signature-Key` header (when using `scheme=jwt` or `scheme=jkt-jwt`) is malformed or its signature verification failed.

```http
Signature-Error: error=invalid_jwt
```

### expired_jwt

The JWT in the `Signature-Key` header (when using `scheme=jwt` or `scheme=jkt-jwt`) has expired (`exp` claim is in the past).

```http
Signature-Error: error=expired_jwt
```

# Signature-Key-Cache Response Header {#signature-key-cache-response-header}

A verifier that has cached an assertion presented in a signed request, and that was asked to do so by the `cache` signal on the presented scheme ((#jwt-confirmation-key-jwt), (#jkt-jwt-scheme)), MAY return the `Signature-Key-Cache` response header to issue the caller a cache identifier for later reference.

`Signature-Key-Cache` is a Dictionary ([@!RFC8941], Section 3.2) keyed by the signature label whose assertion was cached.

The member value is the cache identifier itself, a String. It is not a named parameter. The caller presents this same String back to the verifier as the `cid` parameter of the cached scheme ((#cached-scheme)).

The cache identifier is opaque to the caller. A verifier chooses its own form: a random value indexed in a cache, or a self-contained, integrity-protected, encrypted value that any node in a verifier fleet can resolve without shared cache state. A verifier using the self-contained form SHOULD choose a compact textual encoding, since the identifier is carried on every request that uses it. See (#why-the-verifier-issues-the-cache-identifier).

The member's parameters describe the cached assertion:

- `jti` (String, OPTIONAL): The `jti` claim of the cached assertion ([@!RFC7519], Section 4.1.7), echoed so the caller can associate the cache identifier with the assertion's own identity rather than with the per-request signature label. A JWT is cacheable only if it carries a `jti` ((#jwt-confirmation-key-jwt), (#jkt-jwt-scheme)), so this value always exists; a verifier SHOULD include it when a caller may have more than one assertion in flight.

- `expires` (Integer, OPTIONAL): An advisory time, in seconds since the Unix epoch, after which the verifier may no longer honor the cache identifier. When present it MUST NOT be later than the assertion's own expiry. This is advisory; the caller MUST be prepared for a cache miss ((#cache_miss)) at any time regardless of `expires`.

**Example:**

```
Signature-Key-Cache: sig1="2f9c8a1e-a7b3";jti="2f9c8a1e";expires=1730000000
```

**Round trip:**

The caller presents the assertion in full and asks for a cache identifier. The JWT carries a `jti`, without which it is not cacheable:

```http
Signature-Key: sig1=jwt;jwt="eyJhbGciOiJFZERTQSJ9...";cache
```

The verifier caches the assertion and issues a cache identifier for it:

```http
Signature-Key-Cache: sig1="2f9c8a1e-a7b3";jti="2f9c8a1e";expires=1730000000
```

On subsequent requests the caller presents the cache identifier in place of the assertion, as the `cid` parameter of the cached scheme. The String is the one the verifier issued, unchanged:

```http
Signature-Key: sig1=cached;cid="2f9c8a1e-a7b3"
```

Each request is signed as usual, and `signature-key` remains a covered component, so the cache identifier is signed over on every request that carries it.

The cache identifier's validity never exceeds the cached assertion's expiry. Two expiries are therefore in play and MUST NOT be confused. The cache entry's expiry is the verifier's own retention decision; the assertion's expiry is a property of the assertion. A verifier that still holds the entry MUST resolve it and let the assertion fail validation ((#presenting-and-resolving-a-cached-assertion)), exactly as an expired assertion presented in full would, rather than reporting `cache_miss`. A verifier that has already evicted the entry returns `cache_miss`, which is correct: it no longer holds the assertion and cannot say why the assertion would have been rejected. The caller resends in full and receives the validation error.

## Presenting and Resolving a Cached Assertion {#presenting-and-resolving-a-cached-assertion}

A receiver processes a request bearing the cached scheme in two stages, which MUST remain distinct:

1. Resolution. The signature-verification layer resolves the cache identifier to the cached assertion. If it is unknown, has been evicted, including at the cache entry's own expiry, or (for a self-contained identifier) fails integrity or decryption, resolution fails and the verifier returns `cache_miss` ((#cache_miss)). On success, the verifier obtains the assertion and its confirmation key and verifies the per-request signature against that key. This stage answers cache hit or cache miss.

2. Validation. The resolved assertion is validated by the consuming authorization layer identically to an assertion presented in full, including expiry and any other claim checks. Resolution by cache identifier does not move, replace, or defer this validation. This stage answers valid or invalid, and an expired assertion here produces the same error as an expired assertion presented in full.

These two outcomes MUST NOT be conflated. A cache miss (stage 1) means the assertion could not be reconstructed and is recovered by resending it in full. An invalid assertion (stage 2) means the assertion was reconstructed and failed validation and is not recovered by resending it. A verifier MUST NOT report a validation failure as a cache miss, nor a cache miss as an authorization failure.

Because assertions are short-lived, expiry at stage 2 is the freshness check and no separate revocation state is required; the short lifetime is the revocation window. A deployment that issues long-lived assertions MUST either perform a revocation check at stage 2 or disallow caching for those assertions.

## Degradation and Interoperability

Implementation of assertion caching is OPTIONAL. The degradation behavior in this subsection is not.

A verifier that does not implement assertion caching MUST NOT emit `Signature-Key-Cache`, and MUST reject a request using the cached scheme with `unsupported_scheme` ((#unsupported-scheme)). A caller MUST NOT present the cached scheme unless a verifier has issued a cache identifier for that assertion. A verifier that implements caching MUST implement the `cache_miss` path ((#cache_miss)). These rules allow a caching caller and a non-caching verifier, and the reverse, to interoperate without prior negotiation: a caller always falls back to presenting the assertion in full.

# Security Considerations

## Key Validation

Verifiers MUST validate all cryptographic material before use:

- **hwk**: Validate JWK structure and key parameters per [@!RFC7517]

- **jwks_uri**: Verify HTTPS transport and validate fetched JWKS per [@!RFC7517]

- **jwks**: Verify HTTPS transport and validate fetched JWKS per [@!RFC7517]

- **x509**: Validate complete certificate chain per [@!RFC5280], check revocation status

- **jwt**: Verify JWT signature per [@!RFC7519] and validate embedded JWK per [@!RFC7517]

- **self-jwt**: Verify JWT signature per [@!RFC7519] using the key discovered from `{iss}/.well-known/{dwk}`; reuse that key as the HTTP signing key

- **jkt-jwt**: Verify JWT signature per [@!RFC7519] using header `jwk`, validate thumbprint matches `iss` per [@!RFC7638], validate embedded ephemeral JWK per [@!RFC7517]

## Caching and Performance {#caching-and-performance}

Verifiers MAY cache keys to improve performance but MUST implement appropriate cache expiration:

- **jwks_uri**: Respect cache-control headers, implement reasonable TTLs. Verifiers MUST NOT refetch a given issuer's JWKS more frequently than once per minute to prevent abuse.

- **jwks**: Cache by `url`; the same cache-control handling and once-per-minute refetch floor as `jwks_uri` apply.

- **x509**: Cache by `x5t`, invalidate on certificate expiry

- **jwt**: Cache embedded keys until JWT expiration

- **self-jwt**: Cache discovered keys until JWT expiration; cache by `iss` + `kid`

- **jkt-jwt**: Cache embedded keys until JWT expiration; cache by `iss` thumbprint URI

Verifiers MUST implement cache limits. Cache entries are created by unauthenticated callers, so an unbounded cache is a resource exhaustion attack with no work factor for the attacker.

When the `Signature-Key` scheme is `jwks_uri` and a cached key matching the JWT `kid` fails signature verification, the verifier SHOULD refresh the issuer's JWKS once and retry verification before returning `unknown_key` (if the key is then absent) or `invalid_jwt` (if verification still fails), subject to the once-per-minute fetch floor and egress admission ((#scheme-specific-risks)) that apply to unknown-`kid` refreshes. This covers silent re-keying where the issuer replaces key material under the same `kid` without changing the identifier.

## Scheme-Specific Risks {#scheme-specific-risks}

**hwk**: No identity verification - suitable only for scenarios where pseudonymous access is acceptable.

**jkt-jwt**: The security of this scheme depends on the enclave key's private key remaining protected in hardware. If the enclave key is compromised, all delegated ephemeral keys are compromised. Verifiers should be aware that the jkt-jwt scheme implies but does not prove hardware protection — there is no attestation mechanism in this scheme. Unlike the `jwt` scheme where trust is rooted in a discoverable issuer, jkt-jwt trust is rooted in the key itself. Verifiers MUST understand that any party can create a jkt-jwt — the scheme provides pseudonymous identity, not verified identity. The `exp` claim on the JWT controls how long the ephemeral key is valid. Shorter lifetimes limit the exposure window if an ephemeral key is compromised, and the lifetime should be no longer than the deployment's re-delegation interval allows. The `iss` value is a JWK Thumbprint URI — a globally unique, collision-resistant identifier. The verifier MUST always compute the expected `iss` from the header `jwk` and compare by string equality — never trust the `iss` value alone.

**jwks_uri**: Relies on HTTPS security — vulnerable to DNS/CA compromise. Beyond HTTPS validation, nothing prevents an attacker from copying a client's public keys and serving them from a different domain. Verifiers SHOULD verify that the `id` parameter in the Signature-Key header matches an expected or authorized origin. A general-purpose verifier that accepts signers it has no prior relationship with has no such list to match against, and cannot apply this check; such a verifier obtains an origin-bound pseudonym rather than an authorized identity, and MUST NOT treat a well-formed `id` as evidence that the origin authorized the request.

Because the JWKS location (and, for `jwks_uri`, the metadata document that yields it) is controlled by the asserted signer, an unconstrained verifier can be induced to fetch attacker-chosen internal URLs (SSRF). Verifiers MUST apply egress admission before fetching issuer metadata, a `jwks_uri`, or a `jwks` `url`:

- Require HTTPS for all outbound fetches.
- Enforce response-size and timeout limits.
- Refuse or constrain redirects (at minimum, do not follow redirects to a different host).
- Reject private, loopback, and link-local destination addresses unless explicitly allowed by deployment configuration.
- Defend against DNS rebinding by pinning the resolved IP address for the duration of the connection.
- Treat cross-origin `jwks_uri` URLs (where the JWKS host differs from the metadata host) as requiring explicit deployment admission.

**jwks**: The jwks scheme carries the same server-side request forgery exposure as jwks_uri, and arguably more directly, since the verifier fetches a client-supplied URL with no metadata step to anchor it. The egress-admission requirements above apply to jwks without exception. Because the signer's identity is the JWKS URL itself, a verifier that policies by identity is policying against a value the presenter chooses; verifiers SHOULD verify that `url` matches an expected or authorized origin.

**jwt**: Delegation trust depends on JWT issuer verification. Verifiers MUST validate JWT signatures and claims before trusting embedded keys.

**self-jwt**: Trust is rooted entirely in the issuer's JWKS. The same SSRF egress admission requirements that apply to `jwks_uri` and `jwt` apply here — the `iss` and `dwk` values are asserted by the presenter. Verifiers MUST validate that `cnf` is absent before treating the scheme as self-issued; a JWT containing `cnf` MUST be rejected. Short JWT lifetimes are especially important because the signing key also authenticates the HTTP request — compromise of the key is immediately exploitable at both layers.

**x509**: Requires robust certificate validation including revocation checking. Verifiers MUST NOT skip certificate chain validation.

## Algorithm Selection

The signature algorithm is determined by the key material in Signature-Key. For JWK-based schemes (hwk, jkt-jwt, jwks_uri, jwks, jwt, self-jwt), the algorithm is the fully-specified identifier carried in the JWK `alg` member, per Algorithm Determination ((#algorithm-determination)); verifiers MUST NOT derive it from the key type and curve. For the x509 scheme, the algorithm is determined by the certificate's public key type.

[@!RFC9421], Section 1.4 offers three ways for an application to establish the algorithm: state it in the `alg` signature parameter, derive it from the key material, or agree it out of band. This document takes the second, which [@!RFC9421], Section 3.3.7 develops for JOSE signing algorithms: the algorithm is signaled by the key, and "the explicit `alg` signature parameter is not used at all when using JOSE signing algorithms".

Signers therefore MUST NOT include the `alg` parameter in Signature-Input ([@!RFC9421], Section 2.3), and verifiers MUST ignore it if present and MUST NOT use it to select or validate the algorithm. One source of truth is the point. The two identifier spaces do not correspond — [@!RFC9421], Section 3.3.7 notes that JWA values are not registered in the HTTP Signature Algorithms registry — so a rule requiring the parameter to agree with the key would have no defined meaning to test against. Ignoring the parameter also forecloses the confused-verifier condition in which one verifier takes the algorithm from the parameter and another from the key.

Algorithm agility depends on the verifier selecting exactly one signature algorithm for a given key. A key whose algorithm is not fully determined by its identifier invites downgrade and confused-verifier conditions, where two verifiers disagree on the operation a signature represents. For this reason this document requires a present, fully-specified `alg` for conveyed JWKs ((#algorithm-determination)). This aligns with [@!RFC9864], which states that a key is to be used with only a single algorithm unless the use of that key with multiple algorithms has been proven secure, and recommends that the algorithm parameter of a JWK be present.

Verifiers MUST:

- Take the algorithm from the key's `alg` member, and reject a key that has none ((#algorithm-determination))

- Reject a key whose `kty` or `crv` is inconsistent with its `alg`

- Reject an `alg` naming an algorithm the verifier does not support, or that its policy declines, reporting `unsupported_algorithm` ((#unsupported_algorithm)) and stating what it does accept in `Accept-Signature-Alg` ((#accept-signature-alg))

## Symmetric Algorithms {#symmetric-algorithms}

Every scheme in this document distributes a public key or a reference to one, and every verification it describes is a public-key operation. A symmetric algorithm has no public key: verifying a MAC requires the same secret used to produce it. Distributing that secret in a request header would hand the verifying party the ability to forge the signature it is checking, and any intermediary that saw the header the same ability. The proof of possession this document relies on would then prove nothing, since possession would no longer be exclusive to the signer.

For this reason symmetric algorithms MUST NOT be used with Signature-Key ((#algorithm-determination)). A verifier MUST reject a JWK whose `kty` is `oct` or whose `alg` is a MAC identifier such as `HS256`. A shared-secret MAC remains available to deployments that have a pre-shared key and use `keyid` as [@!RFC9421] describes; it is out of scope here precisely because it needs no key distribution.

## Cache Identifiers {#cache-identifiers}

Cache identifiers inherit the request's proof of possession. A cache identifier is presented in the Signature-Key header, which is a covered component, and the request is signed by the agent's confirmation key, so a captured identifier is useless without the corresponding private key, the same property as a captured token. It is covered by the per-request signature and cannot be substituted by an intermediary.

A verifier MUST NOT treat successful resolution as authentication. Resolution answers only which assertion was referenced. The caller is authenticated by the per-request signature, which the verifier MUST verify against the confirmation key carried in the resolved assertion, exactly as it would had the assertion been presented in full. A caller presenting a cache identifier it did not receive therefore fails signature verification, because it does not hold the corresponding private key. No separate check that the assertion belongs to the caller is required, or possible: possession of the confirmation key is that proof.

Cache identifiers MUST be unpredictable to any party other than the verifier. A guessable identifier does not by itself permit impersonation, since the request signature must still verify against the resolved assertion's confirmation key. It does allow an unrelated party to distinguish a cache miss from a signature failure and so learn whether a verifier currently holds a given assertion, and it removes the second line of defence against a verifier that resolves without verifying. An identifier is a lookup key supplied by a remote party and is untrusted input to the cache.

A cache identifier is a stable reference to one assertion and is therefore a correlator across the requests that use it, for the life of the assertion, in the same way that a repeated `ETag` or session ticket is. It is a fingerprinting surface, but not a new one: it replaces an assertion that carries the confirmation key itself, and a repeated key is at least as strong a correlator as a repeated identifier. Any party that can observe the identifier could have observed the assertion it stands in for. The exposure is therefore bounded above by what the assertion already discloses, and it is bounded below only by the identifier's lifetime: a verifier concerned with correlation by intermediaries MAY issue and rotate distinct identifiers for the same assertion, which the caller cannot detect and need not act on, since it presents whatever it was last issued.

Assertion caching lets a caller create verifier-side state at will. Nothing bounds how many distinct assertions it presents with `cache`, and a self-issued scheme such as jkt-jwt can mint a fresh `jti`, and so a fresh cache entry, on every request. The cache limits required by (#caching-and-performance) apply to assertion caching, and a verifier SHOULD bound entries per confirmation key rather than only in aggregate, so that one caller cannot evict every other caller's entries. A verifier is never obliged to issue a cache identifier: `cache` is a request, not an instruction.

A self-contained cache identifier carries verifier state to itself across a fleet. Such an identifier MUST be integrity-protected and encrypted under keys known only to the verifier fleet, so that it cannot be forged or read by any other party, and one that fails integrity or decryption MUST be treated as a cache miss ((#cache_miss)).

## Post-Quantum Key and Signature Sizes {#pqc-sizes}

Post-quantum keys and signatures are substantially larger than classical ones. ML-DSA public keys are 1312, 1952, and 2592 octets for the three parameter sets, and signatures are larger still, and other post-quantum schemes are larger again. The cost that matters here is size rather than verification time: ML-DSA verification is comparable to Ed25519, so what a deployment must plan for is bytes on the wire. Two consequences follow. First, an inline key conveyed with the hwk scheme, together with the signature, can approach or exceed HTTP header size limits imposed by servers, proxies, and intermediaries. Deployments conveying large keys SHOULD prefer a discovery scheme (jwks_uri or jwks), which conveys a reference rather than the key itself, so that the key material does not traverse a header. A deployment MAY keep an inline scheme where it controls the whole request path and has confirmed the headers fit, trading the discovery fetch for header size. Second, the HTTP Message Signature itself is carried in a header regardless of scheme and is large for post-quantum algorithms; discovery does not mitigate this, and operators should size header buffers to accommodate post-quantum signatures where such algorithms are in use.

## Signature-Key Integrity

The Signature-Key header MUST be included as a covered component in Signature-Input:

```
Signature-Input: sig=("@method" "@authority" "@path" "signature-key"); created=1732210000
```

If `signature-key` is not covered, an attacker can modify the header without invalidating the signature. Attacks include:

**Scheme substitution**: An attacker extracts the public key from an `hwk` scheme and republishes it via `jwks_uri` under their own identity, causing verifiers to attribute the request to the attacker.

**Identity substitution**: An attacker modifies the `id` parameter in a `jwks_uri` scheme to point to their own metadata endpoint that returns the same public key, impersonating a different signer.

Verifiers MUST reject requests where `signature-key` is not a covered component. There is no deployment in which accepting an uncovered `Signature-Key` is safe: both attacks above succeed against any verifier that does so, and neither is detectable after the fact.

# Privacy Considerations

## Pseudonymity vs. Identity {#pseudonymity-vs-identity}

The hwk and jkt-jwt schemes enable pseudonymous operation where the signer's identity is not disclosed. Verifiers should be aware that:

- A server can track a client across requests by JWK Thumbprint ([@!RFC7638]). If a client uses the same key across multiple servers, those servers could correlate the client's activity. Clients MUST use distinct keys for distinct servers to prevent cross-server correlation of pseudonymous identity.

- The jkt-jwt thumbprint is stable across sessions (tied to the enclave key), enabling long-term tracking even when ephemeral keys rotate.

- Verifiers should not log or retain pseudonymous keys beyond operational necessity.

The jwks_uri, jwks, x509, jwt, and self-jwt schemes reveal signer identity. When a client presents its identity via these schemes, the server learns the client's HTTPS URL or certificate subject, revealing which software is making the request. Servers SHOULD NOT disclose client identity information to third parties without the client operator's consent.

## Key Discovery Tracking

The jwks_uri, jwks, jwt, self-jwt, and x509 schemes require verifiers to fetch resources from signer-controlled URLs. This creates tracking vectors:

- Signers can observe when and from where keys are fetched. In particular, when a server fetches a client's JWKS from `jwks_uri` at verification time, the fetch reveals to the JWKS host that someone is verifying signatures for that client.

- Verifiers should cache keys to minimize fetches.

- Verifiers may wish to use shared caching infrastructure to reduce fingerprinting.

## JWT Contents

JWTs in the jwt scheme may contain additional claims beyond `cnf`. Verifiers should:

- Only process claims necessary for verification

- Not log or retain unnecessary JWT claims

- Be aware that JWT contents are visible to network observers unless using TLS

# IANA Considerations

## HTTP Field Name Registration

This document registers the following header fields in the "Hypertext Transfer Protocol (HTTP) Field Name Registry" defined in [@!RFC9110].

Header field name: Signature-Key

Applicable protocol: http

Status: standard

Author/Change controller: IETF

Specification document(s): [this document]

Header field name: Signature-Error

Applicable protocol: http

Status: standard

Author/Change controller: IETF

Specification document(s): [this document]

Header field name: Signature-Key-Cache

Applicable protocol: http

Status: standard

Author/Change controller: IETF

Specification document(s): [this document]

Header field name: Accept-Signature-Scheme

Applicable protocol: http

Status: standard

Author/Change controller: IETF

Specification document(s): [this document]

Header field name: Accept-Signature-Alg

Applicable protocol: http

Status: standard

Author/Change controller: IETF

Specification document(s): [this document]

## Signature-Key Scheme Registry {#scheme-registry}

This document establishes the "HTTP Signature-Key Scheme" registry. This registry allows for the definition of additional key distribution schemes beyond those defined in this document.

### Registration Procedure

New scheme registrations follow the Specification Required policy ([@!RFC8126], Section 4.6). See (#designated-expert-instructions) for instructions to the designated expert.

### Initial Registry Contents

| Scheme | Description | Reference |
|--------|-------------|-----------|
| hwk | Header Web Key - inline public key | [this document] |
| jkt-jwt | JKT JWT Self-Issued Key Delegation - enclave-backed delegation | [this document] |
| jwks_uri | JWKS URI Discovery - key discovery via metadata | [this document] |
| jwks | Direct JWKS - JWKS fetched directly from an HTTPS URL that is also the signer identity | [this document] |
| jwt | JWT Confirmation Key - delegated key in JWT | [this document] |
| self-jwt | Self-Issued JWT - signer and issuer are the same party | [this document] |
| x509 | X.509 Certificate - PKI certificate chain | [this document] |
| cached | Cached Assertion - reference to an assertion the verifier has cached | [this document] |

### Registration Template

Scheme Name:
: The token value used in the Signature-Key header

Description:
: A brief description of the scheme

Specification:
: Reference to the specification defining the scheme

Parameters:
: List of parameters defined for this scheme

## URN Sub-namespace Registration

This document registers the following URN sub-namespace in the "IETF URN Sub-namespace for Registered Protocol Parameter Identifiers" registry defined in [@!RFC3553].

Registry name: sig-error

Specification: [this document]

Repository: [this document], Section on Error Codes

Index value: Values are registered in the "Signature Error Code" registry defined in this document.

The URN pattern is `urn:ietf:params:sig-error:<error-code>`, where `<error-code>` corresponds to a value in the Signature Error Code registry. These URNs are used as Problem Details `type` values ([@!RFC9457]) in response bodies accompanying `Signature-Error` headers.

## Signature Error Code Registry

This document establishes the "Signature Error Code" registry. New values may be registered following the Expert Review policy ([@!RFC8126], Section 4.5). See (#designated-expert-instructions) for instructions to the designated expert.

### Initial Registry Contents

| Value | Description | Reference |
|-------|-------------|-----------|
| `unsupported_algorithm` | Signing algorithm not supported | [this document] |
| `unsupported_scheme` | Signature-Key scheme not supported | [this document] |
| `cache_miss` | Cache identifier could not be resolved | [this document] |
| `invalid_signature` | Signature missing, malformed, or verification failed | [this document] |
| `invalid_input` | Missing required covered components | [this document] |
| `invalid_request` | Missing required info unrelated to signature | [this document] |
| `invalid_key` | Key cannot be parsed or doesn't meet trust requirements | [this document] |
| `unknown_key` | Key not found at jwks_uri | [this document] |
| `issuer_missing` | Metadata document lacks an issuer member | [this document] |
| `issuer_mismatch` | Metadata document issuer does not match the discovery identity | [this document] |
| `invalid_jwt` | JWT malformed or signature verification failed | [this document] |
| `expired_jwt` | JWT expired | [this document] |

### Registration Template

Value:
: The error code token used in the `Signature-Error` header and the `urn:ietf:params:sig-error:` URN

Description:
: A brief description of the error condition and when a verifier generates it

Reference:
: Reference to the document or specification defining the error code

## Designated Expert Instructions {#designated-expert-instructions}

Registration requests for the registries established by this document are evaluated by a designated expert appointed by the IESG. The HTTP Signature-Key Scheme registry uses the Specification Required policy ([@!RFC8126], Section 4.6); the Signature Error Code registry uses the Expert Review policy ([@!RFC8126], Section 4.5).

Registration requests should be sent to IANA, which will forward them to the designated expert. The expert is expected to respond within two weeks. Denials should include an explanation and, if applicable, suggestions for how the request could be revised to be successful.

For all registrations, the designated expert should verify that:

- The proposed value conforms to the registry's syntax and is not confusingly similar to an existing entry.
- The registration does not duplicate the semantics of an existing entry without clear justification.

For the HTTP Signature-Key Scheme registry, the expert should additionally verify that the referenced specification is stable and freely available, describes the scheme in sufficient detail that interoperable, independent implementations are possible, and defines:

- How the verifier obtains the public key and establishes its authenticity.
- All parameters used by the scheme, including which are required and which are optional.
- The security and privacy properties of the scheme, including the trust model (e.g., pseudonymous, URI-bound, or PKI-anchored) and any risks introduced by network fetches during verification.

For the Signature Error Code registry, the expert should additionally verify that:

- The error code is a lowercase token using only lowercase letters and underscore, consistent with the registry's existing entries.
- The error condition is broadly applicable to signed HTTP message exchanges rather than specific to a single application. The condition need not be a signature verification failure; it may concern any part of the exchange the verifier rejects, as `invalid_request` does.
- The description makes clear when a verifier generates the error, and the error does not leak sensitive information to unauthenticated callers.

# Document History

*Note: This section is to be removed before publishing as an RFC.*

- draft-hardt-httpbis-signature-key-08

  Not backward compatible with -07. Breaking changes are listed first.

  Breaking changes:

  - Removed the `sigkey` Accept-Signature parameter and its registry entry. A parameter value is a bare Item and cannot be a list, so `sigkey` could name only one scheme. Use `Accept-Signature-Scheme` and `Accept-Signature-Alg`, which are Lists of Tokens and let a client select before it signs rather than after a rejection.
  - Removed the `supported_algorithms` member of `Signature-Error`, added in -04. Use `Accept-Signature-Alg`, which works on a challenge and on an error alike.
  - Made the hwk `alg` parameter REQUIRED and fully specified. It was forbidden in -06 and -07, so an hwk key serialized per -07 is rejected by a -08 verifier, and one serialized per -08 is rejected by a -07 verifier. There is nothing to negotiate over, so both ends of a deployment move together.
  - Forbade the polymorphic `EdDSA` identifier, deprecated by [@!RFC9864]. Use `Ed25519` or `Ed448`.
  - Required verifiers to take the algorithm from the JWK `alg` rather than derive it from `kty` and `crv`, and to reject a JWK whose `kty` or `crv` disagrees with its `alg`.
  - Required RSA `alg` to name both padding and hash, for example `PS256` or `RS256`. A key type of `RSA` alone is no longer sufficient.
  - Forbade symmetric algorithms: the `oct` key type and the JOSE MAC identifiers. Every scheme here distributes a public key, and a shared secret handed to the verifier proves nothing.
  - Forbade the `none` algorithm and any algorithm whose JOSE Implementation Requirement is `Prohibited`, as [@!RFC9421], Section 3.3.7 requires of a JWS algorithm used for an HTTP Message Signature. Gave the rule its response-side half: a server MUST NOT list such an algorithm in `Accept-Signature-Alg`, which would otherwise advertise that it accepts unsigned requests as signed.
  - Named the registry these identifiers come from, citing the IANA "JSON Web Signature and Encryption Algorithms" registry itself rather than [@!RFC7518], which established it but no longer holds all of it. This document uses the JOSE signing algorithms of [@!RFC9421], Section 3.3.7 and does not use the HTTP Signature Algorithms registry.
  - Corrected `Accept-Signature-Alg` to carry identifiers from that same JOSE registry rather than from the HTTP Signature Algorithms registry. A server has to advertise algorithms in the namespace a conveyed key uses, or a client cannot compare what the server accepts against the keys it holds.
  - Replaced the requirement that a Signature-Input `alg` parameter be "consistent with the key material" with the rule of [@!RFC9421], Section 3.3.7: signers MUST NOT send it and verifiers MUST ignore it. The consistency rule had no testable meaning, since Section 3.3.7 states that JWA values are not registered in the HTTP Signature Algorithms registry and so no mapping between the two namespaces exists. Cited Section 1.4, which names deriving the algorithm from the key material as one of the three approaches an application may take.
  - Removed the Editor's Note that made the post-quantum paragraph contingent on ML-DSA being registered for HTTP Message Signatures. Under [@!RFC9421], Section 3.3.7 the JOSE path never consults that registry, so the pending registration does not gate ML-DSA here: [@!RFC9964] registers ML-DSA in the JOSE registry, which is the one that applies.
  - Raised `signature-key` coverage from SHOULD to MUST on both sides: signers MUST include it as a covered component and verifiers MUST reject requests where it is not covered. The scheme-substitution and identity-substitution attacks in (#signature-key-integrity) succeed against any verifier that accepts an uncovered header, so no valid reason to ignore the requirement exists. This also removes an internal contradiction, since (#accept-signature-scheme) already described coverage as a requirement of this specification.
  - Raised `exp` from a member of the "standard claims" SHOULD list to MUST in the jwt and self-jwt schemes. For jwt, `exp` is what bounds acceptance of the confirmation key the assertion carries.
  - Raised the hwk `kid` prohibition from SHOULD NOT to MUST NOT. The key is inline, so a `kid` selects nothing and a disagreeing `kid` has no defined resolution.
  - Raised rejection of a malformed JWT from SHOULD to MUST. A value that does not parse as a JWT cannot be verified, so the SHOULD had no exception case; the early-rejection rationale was the point being made and is retained as such.
  - Raised cache limits from SHOULD to MUST. Cache entries are created by unauthenticated callers.
  - Required the Problem Details `type` member, where a Problem Details body is returned, to be the `urn:ietf:params:sig-error:` URN form. Whether to return that body remains a SHOULD; the format of the member, once present, is not optional, since another form cannot be resolved against the registry.

  Other changes:

  - Required a verifier resolving a key from a JWKS to select the member matching `kid` without requiring any other member to be usable, and forbade failing because an unselected member names an unimplemented `kty` or `alg`. Without it no issuer could add a post-quantum key alongside a classical one, since doing so would break every verifier that does not implement the new type, including those that were only ever going to use the classical key. Noted that an unknown member within a single JWK is ignored per [@!RFC7517], Section 4, which is distinct from a member this document forbids.
  - Stated that an `Accept-Signature-Alg` Token is the registered identifier verbatim, case included: `ES256`, not `es256`. Structured Field parsing preserves a Token's case, and the value is compared against the `alg` member of a JWK, a case-sensitive JSON string, so a case-folded token matches no key.
  - Corrected the claim that `kty` and `crv` underdetermine the algorithm for EC keys. Within JOSE they do not: `ES256`, `ES384`, and `ES512` correspond one to one with `P-256`, `P-384`, and `P-521`, and no registered signing algorithm pairs a curve with another hash. Genuine underdetermination is limited to RSA, which has no `crv`, and to the `AKP` key type of [@!RFC9964].
  - Stated that requiring `alg` of every conveyed key is therefore a choice rather than a necessity, and gave the reasons in a new Design Rationale section, (#why-alg-is-required): the set of underdetermined key types grows as algorithms are registered, `Accept-Signature-Alg` comparison has to be total, a verifier keeps one code path, and the signer bears no cost. Said plainly that this tightens [@!RFC9864], which RECOMMENDS rather than requires the member.
  - Required a verifier to reject an `alg` it does not support with `unsupported_algorithm`, and stated that `Accept-Signature-Alg` names exactly that set, neither a subset nor a superset. Replaced the vague "validate the algorithm against policy" verifier obligations with the specific checks.
  - Stated where `alg` comes from in each scheme, and that jwks_uri, jwks, and self-jwt have no in-band channel for it: the resolved JWKS entry is the only source, so adopting those schemes means publishing a key that carries `alg` rather than pointing at one that omits it. Only the key the `kid` selects is subject to the requirement, so an existing metadata document can be reused by adding a conforming key.
  - Corrected the `Accept-Signature-Alg` examples, which still used HTTP Signature Algorithms registry identifiers (`ed25519`, `ecdsa-p256-sha256`, `rsa-v1_5-sha256`) after the header was defined to carry JOSE identifiers.
  - Rewrote the justification in Algorithm Determination. [@!RFC9864] RECOMMENDS rather than requires the JWK `alg` member, and allows a deployment to rely on some other mechanism for ensuring a key is used as intended, so citing it as the basis for a MUST overstated it. The requirement now says what it is — a tightening — and gives the reason: keys conveyed in band come from a party the verifier has no prior relationship with, so no such other mechanism exists, and `kty` and `crv` underdetermine the algorithm for RSA, EC, and `AKP` keys alike. Noted that [@?I-D.richer-oauth-httpsig] reaches the same requirement independently for JWK-bound keys.
  - Audited every BCP 14 SHOULD against RFC 2119 Section 6. Each retained SHOULD now names the circumstance under which it may be ignored: omitting `Signature-Error` or `required_input` where diagnostics to an unauthenticated caller are a disclosure risk, returning a non-Problem-Details body under content negotiation, the general-purpose verifier that has no authorized-origin list to check `id` against, and the deployment that keeps an inline scheme because it has confirmed its headers fit.
  - Downgraded to lowercase the statements that were not interoperability requirements, per RFC 2119 Section 6 and the RFC 8174 convention that only uppercase is normative: single-signature deployment advice, the recommendation to document enclave stable-key algorithms, the "shortest practical lifetime" guidance, which was unmeasurable as written, and header buffer sizing.
  - Grounded the `typ` header check of the jwt and self-jwt schemes in the JWT BCP: verifiers SHOULD require an expected `typ`, per the explicit-typing guidance of [@!RFC8725], Section 3.11. The check is a token-confusion defence, not the optimization the text previously called it.
  - Corrected the layered cryptographic agility rationale: post-quantum verification is not the expensive part, since ML-DSA verification is comparable to Ed25519. What caching saves the verifier is the assertion's bytes on the wire and the repeated resolution, not verification time. The signer's per-request cost is time and the verifier's is size.
  - Corrected the basis of the classical hot path: what bounds exposure is the lifetime of the confirmation key, not the expiry of the assertion carrying it. A signer that rebinds one long-lived key into successive assertions leaves that key acceptable indefinitely whatever each `exp` says, and gains nothing from short assertion lifetimes. jkt-jwt has the intended shape by construction.
  - Removed the archived IETF 125 presentation from the repository.

  - Added the `jwks` scheme: a direct JWKS fetch whose HTTPS `url` is both the signer identity and the key location, under the same egress-admission rules as `jwks_uri`.
  - Stated that the jwks `url` is compared by byte equality as presented, with no canonicalization.
  - Required the discovery metadata document to contain `issuer` and `jwks_uri`, and required verifiers to reject a document whose `issuer` does not match the identity it was fetched under — the check of [@!RFC8414], Section 3.3 — with the new `issuer_missing` and `issuer_mismatch` error codes. Applies to jwks_uri, jwt, and self-jwt discovery. Addresses issue #12.
  - Added the `unsupported_scheme` error code and made unknown-scheme rejection mandatory and conformance-testable, scoped to the `Signature-Key` member the verifier selected. A member the verifier did not select is ignored, so a signer can offer a signature under a new scheme without breaking verifiers that lack it.
  - Added an Algorithm Determination section as the single home for the fully-specified algorithm rules, referenced from every scheme that conveys or references a JWK.
  - Required defined rejection of unimplemented JWK key types, including `AKP` [@!RFC9964], reported as `unsupported_algorithm`.
  - Noted that the ML-DSA identifiers of [@!RFC9964] satisfy the rule without special treatment. Added a deployment consideration on post-quantum key and signature sizes.
  - Added assertion caching as a strawman for discussion: the `cached` scheme, the `cache` signal on jwt and jkt-jwt, the `Signature-Key-Cache` response header, the `cache_miss` error, and the resolution and validation model. A JWT is cacheable only if it carries a `jti`; self-jwt is excluded, its key being already cacheable on `iss` and `kid` and its claims request-specific. Implementation is optional; the degradation behavior is not. Whether this is the right layer for caching is an open question.
  - Distinguished the cache entry's expiry from the assertion's: a verifier still holding the entry resolves it and lets validation reject an expired assertion, while one that has evicted it returns `cache_miss` and the caller resends in full.
  - Made `cached` in `Accept-Signature-Scheme` a capability announcement: a client cannot present it until a verifier has issued it a cache identifier.
  - Bounded verifier-side cache state: a caller can mint an assertion, and so a cache entry, per request, so the cache limits apply to assertion caching and a verifier should bound entries per confirmation key.
  - Specified client behaviour when a response carries both `WWW-Authenticate` and a signature challenge: alternatives where the auth-scheme authenticates, in which case the client signs rather than presenting the credential, and complements where it does not, such as a payment challenge, in which case the client satisfies both. Addresses issue #17.
  - Stated what `keyid` ([@!RFC9421], Section 5.1) means alongside `Signature-Key`: a server SHOULD NOT send it, a `keyid` in `Signature-Input` MUST identify the same key as the `Signature-Key` member for that label, and the verifier takes the key from `Signature-Key`.
  - Made the scheme preference order in `Accept-Signature-Scheme` non-binding on the client. The order is the server's preference, while the choice of scheme decides whether the signer is identified, which is the client's to make.
  - Had a server that sends `Accept-Signature-Alg` not send the `alg` parameter of `Accept-Signature`, which names algorithms in the HTTP Signature Algorithms registry this document does not use; a client MAY ignore an `alg` received alongside `Accept-Signature-Alg`.
  - Expanded the Introduction to state the gaps this document addresses and the invariants that follow.
  - Added rationale for a scheme token rather than a header per scheme, for carrying the accepted sets in header fields rather than in parameters or error members, for layered cryptographic agility, for the verifier issuing the cache identifier rather than deriving it from the assertion as an entity tag would be, and for not reserving grease values.
  - Gave the SHOULD for sending `Accept-Signature-Scheme` and `Accept-Signature-Alg` on an error response its exception case, per RFC 2119 Section 6: a server may withhold the header where enumerating what it accepts to an unauthenticated caller is a disclosure risk.
  - Corrected the Accept-Signature parameter name from `algs` to `alg`, per [@!RFC9421], Section 5.1.
  - Converted internal cross-references to mmark xref syntax so they render as section numbers.
  - IANA review feedback: added Designated Expert Instructions for the HTTP Signature-Key Scheme and Signature Error Code registries per RFC 8126 Section 4.5.
  - Changed the Signature Error Code registry policy from Specification Required to Expert Review.
  - Added a registration template to the Signature Error Code registry.

- draft-hardt-httpbis-signature-key-07
  - Editorial. Noted in the Introduction that the mechanisms defined here are used by other specifications, citing the AAuth protocol [@?I-D.hardt-oauth-aauth-protocol] and Email Verification [@?I-D.hardt-email-verification]. No normative change.

- draft-hardt-httpbis-signature-key-06
  - Added the `self-jwt` scheme for self-issued JWTs where the signer and the JWT issuer are the same party. The JWT signing key, discovered via `{iss}/.well-known/{dwk}`, is reused as the HTTP signing key, and no `cnf` claim is present.

- draft-hardt-httpbis-signature-key-05
  - Incorporated implementer feedback from Joshua Gay (sidecat), and added him to the acknowledgments.
  - Added a mandatory egress-admission checklist to the `jwks_uri` SSRF risk bullet: HTTPS, size and timeout limits, redirect policy, private and loopback address rejection, DNS rebinding defense, and cross-origin JWKS admission.
  - Added a once-per-minute JWKS fetch floor, and a same-`kid` refresh rule allowing one refresh and retry before returning `unknown_key` or `invalid_jwt`, subject to that floor and to egress-admission policy.
  - Noted that the stable (enclave) key algorithm in `jkt-jwt` is enclave-determined, and that deployments supporting Ed25519 or other stable-key algorithms SHOULD document this.

- draft-hardt-httpbis-signature-key-04
  - Renamed the specification from "HTTP Signature-Key Header" to "HTTP Signature Keys".
  - Added the `sigkey` parameter to Accept-Signature ([@!RFC9421], Section 5) with three values: `jkt` (pseudonymous), `uri` (URI-identified), and `x509` (PKI certificate), and registered it in the HTTP Signature Metadata Parameters registry.
  - Added the Signature-Error response header and established the Signature Error Code registry.
  - Added an incremental adoption section describing zero-coordination deployment via 429, 401, and 402 responses.
  - Added privacy considerations for key thumbprint tracking, agent identity disclosure, and the JWKS fetch side channel.

- draft-hardt-httpbis-signature-key-03
  - Added the `jkt-jwt` scheme for self-issued key delegation, with a TOFU reference to [@?RFC7435].
  - Renamed the `well-known` parameter to `dwk` (dot well-known).
  - Added `iss` and `dwk` claims to the jwt scheme (SHOULD) for issuer key discovery.
  - Added an early validation step to jwt verification: format, `typ`, and `exp` checks before any network fetch.
  - Added design rationale for `jwks_uri` rather than an inline JWKS, and moved the hwk string versus byte sequence note to the rationale appendix.
  - Reordered the schemes and added acknowledgments.

- draft-hardt-httpbis-signature-key-02
  - Changed the `x5t` parameter to a byte sequence, per reviewer feedback.
  - Added structured field types to all parameters.
  - Added a design note on the string versus byte sequence choice for hwk.

- draft-hardt-httpbis-signature-key-01
  - Initial public draft, with four schemes: hwk, jwks_uri, x509, and jwt.

# Acknowledgments

The author would like to thank Joshua Gay, Ted Hardie, Thibault Meunier, Mikkel Albrechtsen, Yaron Sheffer, and Martin Thomson for their feedback on this specification. Ted Hardie raised the question of client behaviour when `WWW-Authenticate` and a signature challenge coexist, which (#coexistence-with-www-authenticate) answers. Thibault Meunier's review shaped much of -08: citing the JOSE registry itself rather than [@!RFC7518], closing the `none` case on the response side, scoping the unknown-scheme rejection to the selected member, restoring what `keyid` means alongside `Signature-Key`, and untangling the key cache expiry from the assertion cache expiry. Mikkel Albrechtsen raised the question of adding signatures independently of one another. Martin Thomson suggested the guidance of [@?RFC9170], which shaped the extensibility design, and this document's repository is built on his i-d-template.

{backmatter}

# Design Rationale

## Why jwks_uri Instead of Inline JWKS? {#why-jwks-uri}

The `jwks_uri` and `jwt` schemes reference a `jwks_uri` property in the `.well-known` metadata document rather than embedding the JWKS directly in the metadata. This separation of concerns is deliberate:

1. **Independent key rotation**: Keys can be rotated by updating the JWKS endpoint without modifying the `.well-known` metadata document. This decouples key lifecycle management from configuration management, allowing operations teams to rotate keys on their own schedule without redeploying metadata.

2. **Independent management**: The `.well-known` metadata document and the JWKS can be hosted, managed, and secured by different systems or teams. For example, an identity team may manage keys while a platform team manages service metadata.

3. **Caching semantics**: The JWKS endpoint can have its own cache-control headers tuned for key rotation frequency (e.g., short TTLs during a rotation event), independent of the `.well-known` document's caching policy.

4. **Consistency with existing standards**: This approach mirrors the pattern established by OpenID Connect Discovery [@?OpenID.Discovery] and OAuth Authorization Server Metadata [@?RFC8414], which both use `jwks_uri` in metadata documents for the same reasons.

## Why Both jwks and jwks_uri?

The `jwks` and `jwks_uri` schemes occupy adjacent points on a simplicity/decoupling axis. `jwks_uri` fetches a `.well-known` metadata document and follows its `jwks_uri` property to the keys, so identity (the `id` origin) is separate from key location (the discovered JWKS URL); the two can be managed and rotated independently, as (#why-jwks-uri) describes. `jwks` collapses this to a single HTTPS fetch whose URL is both identity and key location. Neither dominates: `jwks` removes a hop and all metadata hosting at the cost of tying identity to the JWKS URL, while `jwks_uri` keeps identity stable across key-location changes at the cost of a discovery step. Offering both lets a signer choose the tradeoff rather than having it imposed.

## Why a Separate Header?

An alternative design would extend Signature-Input with additional parameters to carry key material. This was considered and rejected for several reasons:

1. **Parameter complexity**: Each scheme has a different set of parameters (e.g., `hwk` needs `kty`, `crv`, `x`, `y`; `jwks_uri` needs `id`, `dwk`, `kid`; `jwt` needs a full JWT string). Overloading Signature-Input with all possible key parameters across all schemes would make the Signature-Input grammar unwieldy and harder to parse.

2. **Separation of concerns**: Signature-Input describes *what* is signed and *how* (covered components, algorithm, timestamps). Signature-Key describes *who* signed it and *where to find the key*. These are distinct concerns, and separating them into distinct headers makes each easier to understand and process independently.

3. **Extensibility**: A separate header with a scheme registry allows new key distribution mechanisms to be added without modifying the Signature-Input grammar. New schemes can define arbitrary parameters without coordination with RFC 9421.

4. **Multiple signatures**: With a dictionary structure keyed by label, each signature can use a different scheme. This is natural in a separate header but would create complex nesting if embedded in Signature-Input.

## Why Schemes Instead of Just a Key and Key ID?

A simpler design would define Signature-Key as carrying only a public key (or key reference) and a key identifier, without the scheme abstraction. This was considered insufficient because:

1. **Trust model varies**: A bare key tells the verifier nothing about the trust model. Is this a pseudonymous key to be evaluated on its own merits (hwk)? A key bound to a discoverable identity (jwks_uri)? A delegated key from an authority (jwt)? A certificate-backed key (x509)? The scheme token tells the verifier which verification procedure to follow and what trust properties the key carries.

2. **Verification procedure differs**: Each scheme has a fundamentally different verification path. `hwk` requires no external fetches. `jwks_uri` requires metadata discovery. `x509` requires certificate chain validation. `jwt` requires JWT signature verification before the HTTP signature can be verified. A key-and-ID-only design would push scheme detection to heuristics or out-of-band agreement.

3. **Security properties differ**: Without an explicit scheme, a verifier cannot distinguish between a self-asserted key and a CA-certified key. The scheme makes the trust model explicit, allowing verifiers to enforce policy (e.g., "only accept `jwt` or `x509` schemes").

4. **Interoperability**: Explicit schemes create clear interoperability targets. Two implementations that support the `jwt` scheme know exactly what to expect from each other. Without schemes, the same key material could be interpreted differently by different implementations.

## Why a Scheme Token Instead of a Header per Scheme?

An alternative design would define a distinct header field per key distribution mechanism (for example `Signature-Key-Hwk`, `Signature-Key-Jwt`) rather than one `Signature-Key` header carrying a scheme token. HTTP field names are the most heavily exercised extension point on the web, and [@?RFC9170] identifies header fields in email and HTTP as the canonical case of an extension point that stays usable because recipients routinely ignore fields they do not understand. A per-mechanism header would ride that established tolerance rather than a scheme registry with little traffic. This document nonetheless uses a single header with a scheme token, for four reasons.

1. **Ignorability is the wrong property for keying material.** Header-name extensibility works because an unknown header can be safely ignored. `Signature-Key` carries mandatory keying material. A verifier that ignores an unknown `Signature-Key-X` header fails verification exactly as if no key were present, and cannot tell the client why. With a scheme token, the verifier knows a key was offered under a scheme it does not implement and returns `unsupported_scheme` with an `Accept-Signature-Scheme` header naming what it accepts. [@?RFC9170] Section 4.4 notes that effective feedback is what keeps the surrounding extension machinery working.

2. **The covered-component invariant stays fixed.** The scheme substitution and identity substitution attacks in (#signature-key-integrity) depend on `signature-key` being a covered component. With one header, `signature-key` is a single stable identifier in the signature base across every scheme. Per-scheme headers would make the covered component name mechanism-dependent and would require a rule for a request that covers one key header while leaving another uncovered.

3. **Label correlation stays simple.** The dictionary is keyed by signature label so that each signature in a multi-signature message carries its own keying material ((#multiple-signatures)). Resolving a label's key is one dictionary lookup. Across N per-scheme headers it becomes a scan with a cross-header collision policy.

4. **Fewer namespaces.** [@?RFC9170] Section 4.1 observes that a smaller number of widely applicable extension points is exercised more, and ossifies less, than many specialized ones. The scheme is the single namespace for key distribution mechanisms, referenced from both this header and the `Accept-Signature-Scheme` response header. Per-scheme header names would add a second namespace for the same axis.

To keep the scheme registry usable despite its narrow traffic, this document relies on defined behavior rather than on greasing [@?RFC8701]. Unknown and unregistered schemes have a single mandatory outcome ((#unsupported-scheme)), verifiers dispatch through the registry rather than a fixed branch set, and conformance testing exercises the unknown-scheme path directly ((#client-processing)). Reserving grease values was considered and not adopted: a mandatory, conformance-tested reject path exercises the same handling that grease would provoke, whereas a reserved grease token tends to become a filterable synonym for "unknown" that implementations special-case, the outcome [@?RFC9170] Section 3.3 cautions against.

## Why Accept-Signature-Scheme and Accept-Signature-Alg Are Separate Headers

Earlier versions of this document carried the server's scheme requirement in a `sigkey` parameter on `Accept-Signature`, and the accepted sets in `supported_schemes` and `supported_algorithms` members of `Signature-Error`. Both were replaced by two response header fields. The reasons are worth recording, because at first reading a new header field looks like the more invasive choice.

1. **A set cannot be expressed in a parameter.** A Structured Fields parameter value is a bare Item ([@!RFC8941], Section 3.1.2) and cannot be an Inner List. A parameter can therefore name one scheme, never a set. This is not a limitation of `sigkey`: the `alg` parameter of `Accept-Signature` ([@!RFC9421], Section 5.1) is singular for the same structural reason. Any design that puts the accepted set in a parameter slot is constrained to a single value, whatever it is named.

2. **The Accept-Signature member value is already spoken for.** The alternative to a parameter is a Dictionary member value, which may be an Inner List. In `Accept-Signature` that position holds the covered components, so it is unavailable. Carrying the accepted sets there would mean overloading one list with two unrelated kinds of token.

3. **Capability does not vary by signature label.** A new Dictionary keyed by label could carry a list per label, but the schemes and algorithms a verifier accepts are a property of the verifier, not of a particular signature in a particular message. Keying by label would invite the question of what a client should do when two labels disagree, and would create a per-label negotiation surface with no deployment behind it. `Accept-Signature` retains label granularity for what it is for: which components are to be covered, and the per-label parameters of [@!RFC9421] Section 5.1.

4. **One dimension per field is the established HTTP pattern.** HTTP negotiates with `Accept`, `Accept-Encoding`, `Accept-Language`, and `Accept-Charset`: one field per dimension, each a list, each independently ignorable. A single field carrying both dimensions as Dictionary members would be equally valid Structured Fields, but it would depart from that pattern, and it would couple the two: a server with no algorithm constraint could not simply omit the algorithm field.

5. **The same syntax serves the challenge and the error.** This is the property the previous design could not have. `supported_schemes` and `supported_algorithms` lived inside `Signature-Error`, so a client could reach them only by first being rejected. A header field can be sent on an ordinary challenge, before the client has signed anything, and on an error response, and means the same thing in both places. A client selects a scheme and an algorithm before it signs rather than after a failure. [@?RFC9170] Section 4.4 observes that an extension point stays usable when it is exercised routinely; a set that can be learned only through failure is exercised only when something goes wrong.

6. **Removing the error members avoids two ways to say one thing.** Once the headers exist, retaining the members would leave two encodings of the same information, differing only in when they may appear. [@?RFC9170] Section 4.1 notes that redundant, partially-used mechanisms ossify. `Signature-Error` now states what went wrong, and the `Accept-Signature-*` fields state what would succeed.

Adding header fields here does not contradict the argument against per-scheme key headers in (#why-a-scheme-token-instead-of-a-header-per-scheme). That argument turns on ignorability being the wrong property for mandatory keying material: a verifier that silently ignores an unknown `Signature-Key-X` cannot tell the client why verification failed. These fields carry advisory capability rather than keying material, and ignorability is exactly the property wanted. A client that does not understand `Accept-Signature-Scheme` ignores it and behaves as it did before, which is also what a client that cannot satisfy any listed scheme does. Nothing is lost by ignoring a hint, whereas ignoring a key is a silent failure. The two conclusions differ because the requirements differ.

## Layered Cryptographic Agility

Post-quantum protection is applied to artifacts whose authenticity must survive into the quantum era: durable, consequential, or retained assertions. The per-request HTTP Message Signature is ephemeral, replay-bounded proof of possession that no verifier accepts outside its short window; it MAY continue to use a classical algorithm such as Ed25519 in a post-quantum deployment. Ed25519 is not itself post-quantum, and the claim here concerns the threat model for short-lived authentication signatures rather than the algorithm's quantum resistance. Caching ((#signature-key-cache-response-header)) makes the post-quantum assertion, whose signature is large ((#pqc-sizes)), affordable to reference on each request without retransmitting it.

What makes the classical hot path acceptable is the lifetime of the key, not the lifetime of the assertion carrying it. A confirmation key's public value travels in the assertion and can be collected by any observer today, so the exposure is bounded by how long a verifier will still accept that key, not by how long ago it was seen. A classical key is safe against an attacker who later recovers private keys from harvested public keys for as long as it is replaced — a freshly generated key bound in a newly issued assertion — faster than that recovery is possible. Expiring the assertion does not achieve this on its own: a signer that rebinds one long-lived key into each successive assertion leaves that key acceptable for as long as it keeps doing so, whatever `exp` any individual assertion carries. The jkt-jwt scheme ((#jkt-jwt-scheme)) has the intended shape by construction, the stable enclave key establishing identity while the request key in `cnf` is generated per delegation. A deployment that instead reuses a confirmation key across assertions gains nothing from short assertion lifetimes, and should choose that key's algorithm against its true acceptance window.

The saving is on both sides, though for a different reason on each. The jkt-jwt scheme exists because signing in a secure enclave is slow, so the enclave key signs once and delegates to a fast ephemeral key: the signer's per-request cost is time. The verifier's is size. Post-quantum verification is not the expensive part — ML-DSA verification is comparable to Ed25519 — and the burden is the assertion ((#pqc-sizes)) that would otherwise be retransmitted and reparsed on every request. A verifier that caches the delegation resolves it once, fetching, parsing, computing the thumbprint, and verifying the signature, and references the result thereafter, while the caller stops paying the assertion's bytes on each request. Delegation on the signer's side and caching on the verifier's answer the same shape of problem from opposite ends.

Long-term non-repudiation is out of scope for this layer and is provided above it. The per-request signature is not the durable evidentiary record. Where long-term, tamper-evident proof of what an agent did is required, it is provided by a transparency ledger that records actions and is itself protected for the long term, not by retaining and later trusting individual per-request signatures. Because durable evidence lives in the ledger, the per-request signature has no long-term evidentiary value to protect, and the classical hot path needs no post-quantum sealing at this layer. The ledger, being the durable artifact, is where post-quantum protection is applied for audit. The ledger itself is outside the scope of this document.

## Why the Verifier Issues the Cache Identifier {#why-the-verifier-issues-the-cache-identifier}

The cache identifier is issued by the verifier, not chosen by the caller. The caller already has an identifier for the assertion, its `jti`, so it is worth stating why that one is not used and why the naming is the verifier's.

1. **The cache is the verifier's.** The identifier is a lookup key into storage the verifier owns and evicts from. Only the verifier knows its namespace, its eviction policy, and whether an entry survives. A caller-chosen key would name something the caller cannot observe.

2. **A `jti` is unique per issuer, not per verifier.** The `jti` claim is unique within the scope of its issuer ([@!RFC7519], Section 4.1.7). A verifier accepting assertions from many issuers can be presented with the same `jti` by unrelated callers, so `jti` alone is not a key. A verifier could key on issuer and `jti` together, but that is a compound the caller would have to reconstruct exactly, and it fixes the key's form for every verifier rather than letting each choose.

3. **A caller-chosen identifier is attacker-chosen input to a lookup.** If callers named their own entries, one caller could name an entry another caller had created, and cache lookup would become a probe for whether a given assertion is held. Verifier-issued identifiers keep the namespace under the verifier's control, which is what allows the unpredictability requirement in Security Considerations to mean anything.

4. **Only the verifier can make the identifier self-contained.** A verifier that encodes the assertion's state into the identifier, encrypted to itself, can resolve it on any node without shared cache state. That is possible only if the verifier constructs it. TLS session tickets take the same approach for the same reason ((#precedents-for-assertion-caching)).

The `jti` is still useful to the caller, and is echoed in `Signature-Key-Cache` so that a caller with several assertions in flight can associate the identifier it receives with the assertion it sent. It identifies the assertion; the cache identifier identifies the verifier's cached copy of it.

## Precedents for Assertion Caching {#precedents-for-assertion-caching}

The reference-and-fallback shape of the cached scheme follows established practice.

The TLS Cached Information Extension [@?RFC7924] lets a client tell the server it already holds an object and reference it, with a defined fallback when the server's copy does not match. The cached scheme has the same shape: a reference in place of the object, and a defined miss path back to sending it in full.

TLS session tickets ([@?RFC5077]; [@?RFC8446], Section 4.6.1) are server-minted, optionally self-contained encrypted references that any node in a fleet can honor without shared state. This is the precedent for permitting a self-contained cache identifier ((#signature-key-cache-response-header)) and for the fleet case in which an identifier minted by one node is presented to another that cannot resolve it ((#cache_miss)).

Entity tags ([@!RFC9110], Section 8.8.3) are the closest HTTP precedent and the source of three properties adopted here. An entity tag is opaque to the recipient, which echoes it back unmodified; it is issued by the party that holds the thing it names; and a recipient that does not recognize one falls back to the full representation rather than failing. A cache identifier behaves the same way: opaque, verifier-issued, and recoverable by resending the assertion ((#cache_miss)).

One property of entity tags is deliberately not adopted. A strong entity tag is commonly derived from the representation, so two parties holding the same bytes compute the same tag. Applying that to assertions, by using a thumbprint of the assertion as the cache identifier, would make the identifier computable by anyone who has seen the assertion, including any intermediary it passed through. Cache lookup would then become a probe any such party could run to learn whether a verifier currently holds a given assertion, and the identifier would no longer be unpredictable ((#cache-identifiers)). A content-derived identifier also fixes one construction for every verifier, foreclosing the self-contained encrypted form that the session-ticket precedent supports. The cache identifier is therefore verifier-minted and unpredictable rather than derived from the assertion, and the assertion's own identity is carried separately by the `jti` echoed in `Signature-Key-Cache` ((#why-the-verifier-issues-the-cache-identifier)).

The TLS mechanisms above are cited as context for the design, not as normative dependencies.

## Why Strings Instead of Byte Sequences for hwk?

The hwk parameters use structured field strings rather than byte sequences. JWK key values are base64url-encoded per [@!RFC7517], while structured field byte sequences use base64 encoding per [@!RFC8941]. Using strings allows implementations to pass JWK values directly without converting between base64url and base64, avoiding a potential source of encoding bugs.

## Why alg Is Required on Every Conveyed Key {#why-alg-is-required}

The alternative considered was deriving the algorithm from the key's structure, as JOSE implementations commonly do today.

That derivation works, for two of the four key types this document can convey. No registered JOSE signing algorithm pairs the `Ed25519` curve with anything but `Ed25519`, or `P-256` with anything but `ES256`; for OKP and EC keys, `kty` and `crv` between them name exactly one algorithm. Stating otherwise would be wrong, and the requirement here is not justified by an ambiguity that does not exist in those cases.

It fails for the other two. An RSA key has no `crv`, and `kty` of `RSA` determines neither the padding scheme nor the hash, so the same key admits `RS256`, `PS256`, `RS512`, and more. The `AKP` key type of [@!RFC9964] covers several ML-DSA parameter sets, none of them recoverable from `kty`. In both cases the key does not say what it is for, and nothing else in these schemes does either.

The requirement is uniform rather than restricted to those two cases, for four reasons.

**The set of underdetermined types grows.** A conditional rule needs a table of which key types are self-determining, maintained in this document, revised whenever an algorithm is registered. Post-quantum and hybrid algorithms are arriving now, and `AKP` is already an entry in that table. A uniform requirement accommodates a new algorithm with no change here at all.

**Negotiation must be a total comparison.** `Accept-Signature-Alg` ((#accept-signature-alg)) advertises algorithm identifiers with no key attached, because the server has no key to attach. A client decides which of its keys to present by comparing them against that list. Were keys permitted to omit `alg`, every client would have to implement the derivation table purely to perform that comparison, and would have to implement it identically to every server, or the two would disagree about what the client holds. Requiring `alg` makes the comparison a string match over one vocabulary on both sides.

**One code path in the verifier.** Determination becomes a single lookup followed by a single consistency check, with no branch on whether this key type happens to be self-determining, and no second path that a test suite must cover and an implementer may get wrong. The redundancy between `alg` and `kty`/`crv` is then available as a check rather than as an alternative ((#algorithm-determination)).

**The cost to the signer is nil.** A signer constructs the key it conveys inline, mints the assertion that carries its confirmation key, and publishes the JWKS its identity resolves to. There is no third party to persuade and no existing artifact that must change, because a deployment adopting this document is publishing keys for a purpose that did not previously exist.

[@!RFC9864] RECOMMENDS rather than requires that a JWK carry `alg`, permitting a deployment to rely instead on "some other mechanism for ensuring that the key is used as intended". This document tightens that RECOMMENDED to a requirement. It does so as a matter of choice, on the grounds above, and not because the exception [@!RFC9864] allows is unavailable — for OKP and EC keys it plainly is available.
