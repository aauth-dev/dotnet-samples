using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Server;

/// <summary>
/// Abstraction for resource-managed opaque access tokens (§1.1, 2-party flow).
/// The resource issues short opaque tokens directly (without a PS/AS) for
/// simple agent↔resource interactions.
/// </summary>
public interface IOpaqueTokenStore
{
    /// <summary>Issue a new opaque token. Returns the token string.</summary>
    Task<string> IssueAsync(OpaqueTokenInfo info, CancellationToken ct = default);

    /// <summary>Validate and retrieve info for an opaque token. Returns null if invalid/expired.</summary>
    Task<OpaqueTokenInfo?> ValidateAsync(string token, CancellationToken ct = default);

    /// <summary>Revoke an opaque token.</summary>
    Task RevokeAsync(string token, CancellationToken ct = default);
}

/// <summary>Metadata associated with an opaque access token.</summary>
public sealed class OpaqueTokenInfo
{
    /// <summary>The agent's JWK thumbprint (binding).</summary>
    public required string AgentJkt { get; init; }

    /// <summary>Granted scope.</summary>
    public string? Scope { get; init; }

    /// <summary>When the token expires.</summary>
    public required DateTimeOffset Expiration { get; init; }

    /// <summary>Optional subject identifier.</summary>
    public string? Subject { get; init; }
}

/// <summary>
/// In-memory opaque token store for development and testing.
/// </summary>
public sealed class InMemoryOpaqueTokenStore : IOpaqueTokenStore
{
    private readonly ConcurrentDictionary<string, OpaqueTokenInfo> _tokens = new();

    /// <inheritdoc/>
    public Task<string> IssueAsync(OpaqueTokenInfo info, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(info);
        var token = Guid.NewGuid().ToString("N");
        _tokens[token] = info;
        return Task.FromResult(token);
    }

    /// <inheritdoc/>
    public Task<OpaqueTokenInfo?> ValidateAsync(string token, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        if (!_tokens.TryGetValue(token, out var info))
            return Task.FromResult<OpaqueTokenInfo?>(null);
        if (info.Expiration < DateTimeOffset.UtcNow)
        {
            _tokens.TryRemove(token, out _);
            return Task.FromResult<OpaqueTokenInfo?>(null);
        }
        return Task.FromResult<OpaqueTokenInfo?>(info);
    }

    /// <inheritdoc/>
    public Task RevokeAsync(string token, CancellationToken ct = default)
    {
        _tokens.TryRemove(token, out _);
        return Task.CompletedTask;
    }
}
