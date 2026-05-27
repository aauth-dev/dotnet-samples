# Platform Attestation

> [Signing Modes](https://explorer.aauth.dev/foundations/schemes)

## Overview

Platform attestation allows a resource or Person Server to verify that the agent is running on genuine hardware (e.g., WebAuthn, Apple App Attest). The SDK provides an `IPlatformAttestor` seam that can be plugged into enrollment and token exchange flows.

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

Attestation is provided during enrollment or token operations where the server sends an attestation challenge:

```csharp
var attestor = new WebAuthnAttestor(webauthnService);

// The attestor is called automatically when a server
// includes an attestation challenge in its response
var apClient = new AgentProviderClient(
    new HttpClient(), keyStore, attestor);
```

## When Is Attestation Required?

Attestation is **optional** in the protocol. A server signals it requires attestation by including an `attestation_challenge` in its response. If the agent doesn't provide a valid attestation, the server rejects the request.

Typical scenarios:

- High-security enrollment (Agent Provider requires device attestation)
- Premium resource access (resource requires platform verification)
- Regulated environments (compliance mandates hardware binding)

## Further Reading

- [Bootstrap & Enrollment](../workflows/bootstrap-enrollment.md)
- [Key Management](key-management.md) — hardware-backed key storage
