using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Server.Governance;

/// <summary>
/// In-memory <see cref="IDeferredConsentStore"/> for development and samples
/// (§Deferred Consent). Pending consents live only in process memory; a
/// production PS swaps in durable, expiring storage.
/// </summary>
public sealed class InMemoryDeferredConsentStore : IDeferredConsentStore
{
    private readonly ConcurrentDictionary<string, DeferredConsent> _entries =
        new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<DeferredConsent> ParkAsync(DeferredConsent consent, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(consent);
        if (string.IsNullOrEmpty(consent.Id))
        {
            consent.Id = Guid.NewGuid().ToString("N");
        }
        _entries[consent.Id] = consent;
        return Task.FromResult(consent);
    }

    /// <inheritdoc />
    public Task<DeferredConsent?> GetAsync(string id, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        return Task.FromResult(_entries.TryGetValue(id, out var entry) ? entry : null);
    }

    /// <inheritdoc />
    public Task ResolveAsync(string id, bool approved, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        if (_entries.TryGetValue(id, out var entry))
        {
            entry.Decision = approved;
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RemoveAsync(string id, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        _entries.TryRemove(id, out _);
        return Task.CompletedTask;
    }
}
