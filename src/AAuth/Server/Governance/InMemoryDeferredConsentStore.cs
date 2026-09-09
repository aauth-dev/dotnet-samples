using System;
using System.Collections.Concurrent;
using System.Linq;
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
        Sweep();
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
        Sweep();
        return Task.FromResult(_entries.TryGetValue(id, out var entry) ? entry : null);
    }

    public Task<DeferredConsent?> GetByCodeAsync(string code, CancellationToken ct = default)
    {
        Sweep();
        var normalized = AAuth.Headers.InteractionCode.Normalize(code);
        return Task.FromResult(_entries.Values.FirstOrDefault(entry => entry.Code == normalized));
    }

    private void Sweep()
    {
        foreach (var pair in _entries)
            if (pair.Value.ExpiresAt.AddHours(1) <= DateTimeOffset.UtcNow) _entries.TryRemove(pair.Key, out _);
    }

    /// <inheritdoc />
    public async Task ResolveAsync(string id, bool approved, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        if (_entries.TryGetValue(id, out var entry))
        {
            await entry.Lifecycle.Gate.WaitAsync(ct);
            try
            {
                if (!entry.Lifecycle.Delivered && !entry.Lifecycle.Cancelled && entry.ExpiresAt > DateTimeOffset.UtcNow)
                    entry.Decision ??= approved;
            }
            finally { entry.Lifecycle.Gate.Release(); }
        }
    }

    /// <inheritdoc />
    public Task RemoveAsync(string id, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        _entries.TryRemove(id, out _);
        return Task.CompletedTask;
    }
}
