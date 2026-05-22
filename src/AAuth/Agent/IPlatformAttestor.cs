using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Agent;

/// <summary>
/// Abstraction for platform attestation during agent bootstrap (§7).
/// Allows plugging in WebAuthn, App Attest, Play Integrity, etc.
/// </summary>
public interface IPlatformAttestor
{
    /// <summary>
    /// Generate an attestation payload for the given challenge.
    /// Returns a base64url-encoded attestation statement.
    /// </summary>
    Task<string> AttestAsync(string challenge, CancellationToken ct = default);
}

/// <summary>
/// No-op attestor for development/testing. Returns an empty attestation.
/// </summary>
public sealed class NoopAttestor : IPlatformAttestor
{
    /// <inheritdoc/>
    public Task<string> AttestAsync(string challenge, CancellationToken ct = default)
    {
        return Task.FromResult(string.Empty);
    }
}
