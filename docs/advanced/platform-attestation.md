# Platform Attestation

> [Signing Modes](https://explorer.aauth.dev/foundations/schemes)

## Overview

Platform attestation can establish device/key properties when a platform verifier
and relying-party policy validate its evidence. The SDK exposes `IPlatformAttestor`;
it does not ship WebAuthn/App Attest verification or prove hardware custody.
The software-key samples establish cryptographic possession, not device assurance.

## IPlatformAttestor Interface

```csharp
namespace AAuth.Agent;

public interface IPlatformAttestor
{
    /// Produce an attestation statement for the given challenge.
    Task<string> AttestAsync(string challenge, CancellationToken ct = default);
}
```

## NoopAttestor (Default)

When no attestation is required, the SDK-provided `NoopAttestor` returns an empty attestation. `NoopAttestor` is part of the SDK (`AAuth.Agent.NoopAttestor`) and is the default `IPlatformAttestor` used by `AgentProviderClient` when no attestor is supplied:

```csharp
// Part of the SDK: AAuth.Agent.NoopAttestor — shown here for reference.
public sealed class NoopAttestor : IPlatformAttestor
{
    public Task<string> AttestAsync(string challenge, CancellationToken ct)
        => Task.FromResult(string.Empty);
}
```

This is the default behavior — attestation is opt-in.

## Custom Attestation

Implement `IPlatformAttestor` to integrate with platform-specific attestation. The examples below are illustrative — `WebAuthnAttestor`, `AppAttestAttestor`, the `IWebAuthnService` interface, and the `DeviceCheck` helper are **not** part of the AAuth SDK; only `IPlatformAttestor` (in `AAuth.Agent`) is.

### WebAuthn Example

```csharp
// Sample implementation of AAuth.Agent.IPlatformAttestor — not part of the SDK.
// IWebAuthnService is also illustrative; supply your own WebAuthn integration.
public sealed class WebAuthnAttestor : IPlatformAttestor
{
    private readonly IWebAuthnService _webauthn;

    public WebAuthnAttestor(IWebAuthnService webauthn) => _webauthn = webauthn;

    public async Task<string> AttestAsync(string challenge, CancellationToken ct)
    {
        var assertion = await _webauthn.CreateAssertionAsync(
            Convert.FromBase64String(challenge), ct);
        return Convert.ToBase64String(assertion);
    }
}
```

### Apple App Attest Example

```csharp
// Sample implementation of AAuth.Agent.IPlatformAttestor — not part of the SDK.
// `DeviceCheck` here is a placeholder for your platform-specific binding to
// Apple's DCAppAttestService; it is not provided by the AAuth SDK.
public sealed class AppAttestAttestor : IPlatformAttestor
{
    public async Task<string> AttestAsync(string challenge, CancellationToken ct)
    {
        // Platform-specific: call DCAppAttestService
        var attestation = await DeviceCheck.AttestKeyAsync(challenge);
        return Convert.ToBase64String(attestation);
    }
}
```

## Wiring Into the SDK

The following illustrative wiring is not compiled or run against a platform.
Your provider integration must implement challenge acquisition, freshness,
evidence validation and retry. The current `AgentProviderClient` constructor
accepts the hook but does not implement an attestation challenge/retry ceremony:

```csharp
var attestor = new WebAuthnAttestor(webauthnService);

// Platform-specific provider integration supplies the ceremony.
using var apHttp = AAuth.Discovery.AAuthHttpTransport.CreateClient();
var apClient = new AgentProviderClient(
    apHttp, keyStore, attestor);
```

## When Is Attestation Required?

Attestation is a provider/platform choice. The sample AP has no attestation
challenge endpoint, and no standardized `attestation_challenge` response member
is implemented by this SDK. The adapter classes above intentionally stand for
external platform code and are not complete deployable implementations.

Typical scenarios:

- High-security enrollment (Agent Provider requires device attestation)
- Premium resource access (resource requires platform verification)
- Regulated environments (compliance mandates hardware binding)

## Attestation and the `jkt-jwt` signing mode

Attestation is what makes the [`jkt-jwt`](../signing-modes/key-rotation-jkt-jwt.md)
key-rotation scheme trustworthy in the enclave-backed mobile case it was designed
for. The pattern, in the scheme designer's words — *"on first use, the AP drives a
platform attestation in addition to the jkt-jwt, and then the jkt-jwt is all that
is needed for future agent tokens"*:

1. **At enrolment (once):** the agent's durable key is generated inside a secure
   enclave. The AP sends an `attestation_challenge`; the agent returns an App
   Attest / Play Integrity / WebAuthn statement proving the durable key is genuine
   enclave-resident material. This is the strong, one-time trust anchor.
2. **At every refresh thereafter:** the enclave signs a short-lived **naming JWT**
   (`jkt-s256+jwt`) delegating to a fast ephemeral software key (the `jkt-jwt`
   scheme). The AP verifies the durable-key signature on the naming JWT against
   its enrolment record — **no re-attestation is needed**, because the same enclave
   key is demonstrably making the request.

So the enclave key signs rarely (once per agent-token lifetime), while the
ephemeral key signs every HTTP request. Attestation anchors the durable key at
enrolment; `jkt-jwt` carries that established trust forward cheaply. This is why
the AP-side `jkt-jwt` verification is **not** pure trust-on-first-use even though
the wire format is self-anchored — see
[Bootstrap & Enrollment § Two-Key Refresh](../workflows/bootstrap-enrollment.md).

## Further Reading

- [Bootstrap & Enrollment](../workflows/bootstrap-enrollment.md)
- [Key Rotation (`jkt-jwt`)](../signing-modes/key-rotation-jkt-jwt.md) — the enclave delegation scheme
- [Key Management](key-management.md) — hardware-backed key storage
