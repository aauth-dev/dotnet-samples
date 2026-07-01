using System;
using System.Collections.Concurrent;

namespace AAuth.Agent;

/// <summary>
/// Agent-side store for the latest opaque <c>AAuth-Access</c> token per resource
/// origin (§AAuth-Access Response Header). The agent treats the token as an
/// opaque string keyed by origin (<c>scheme://authority</c>) and replays it as
/// <c>Authorization: AAuth &lt;token68&gt;</c> on subsequent requests.
/// </summary>
/// <remarks>
/// This is deliberately <b>distinct</b> from the resource-side
/// <see cref="AAuth.Server.IOpaqueTokenStore"/>: the resource mints and validates
/// tokens (and owns <c>OpaqueTokenInfo</c>), whereas the agent only needs the
/// latest opaque string for an origin so it can present it again. Implementations
/// MUST be safe for concurrent use.
/// </remarks>
public interface IAAuthAccessStore
{
    /// <summary>Get the latest token for <paramref name="origin"/>, if any.</summary>
    bool TryGet(string origin, out string token);

    /// <summary>
    /// Store the latest token for <paramref name="origin"/>, replacing any
    /// previous value (rolling refresh, last-writer-wins).
    /// </summary>
    void Set(string origin, string token);

    /// <summary>Remove any stored token for <paramref name="origin"/>.</summary>
    void Remove(string origin);
}

/// <summary>
/// In-memory <see cref="IAAuthAccessStore"/> for single-process agents and tests.
/// A distributed agent (multiple instances) should supply its own shared store.
/// </summary>
public sealed class InMemoryAAuthAccessStore : IAAuthAccessStore
{
    private readonly ConcurrentDictionary<string, string> _tokens = new(StringComparer.Ordinal);

    /// <inheritdoc/>
    public bool TryGet(string origin, out string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(origin);
        if (_tokens.TryGetValue(origin, out var value))
        {
            token = value;
            return true;
        }

        token = string.Empty;
        return false;
    }

    /// <inheritdoc/>
    public void Set(string origin, string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(origin);
        ArgumentException.ThrowIfNullOrEmpty(token);
        // Last-writer-wins: concurrent in-flight responses may each carry a new
        // value; the most recently observed one simply replaces the prior one.
        _tokens[origin] = token;
    }

    /// <inheritdoc/>
    public void Remove(string origin)
    {
        ArgumentException.ThrowIfNullOrEmpty(origin);
        _tokens.TryRemove(origin, out _);
    }
}
