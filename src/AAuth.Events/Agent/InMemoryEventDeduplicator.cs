using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Events.Agent;

/// <summary>
/// A bounded, expiring, thread-safe in-memory event deduplicator.
/// </summary>
/// <remarks>
/// This is a convenience implementation for a single process. It is not
/// durable and must not be used as the sole replay defense for a distributed
/// or restart-sensitive agent. Expired entries are removed before every
/// operation, and the oldest entry is deterministically evicted at capacity.
/// </remarks>
public sealed class InMemoryEventDeduplicator : IEventDeduplicator
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly int _capacity;
    private readonly TimeSpan _retention;
    private readonly Func<DateTimeOffset> _clock;
    private long _sequence;

    /// <summary>Creates a bounded in-memory deduplicator.</summary>
    public InMemoryEventDeduplicator(
        int capacity = 10_000,
        TimeSpan? retention = null,
        Func<DateTimeOffset>? clock = null)
    {
        if (capacity <= 0)
            throw new ArgumentOutOfRangeException(nameof(capacity));
        _retention = retention ?? TimeSpan.FromHours(1);
        if (_retention <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(retention));
        _capacity = capacity;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Maximum number of live keys retained.</summary>
    public int Capacity => _capacity;

    /// <summary>How long a successful key is retained.</summary>
    public TimeSpan Retention => _retention;

    /// <summary>Current number of live keys, after deterministic expiry cleanup.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                RemoveExpired(_clock());
                return _entries.Count;
            }
        }
    }

    /// <inheritdoc />
    public ValueTask<bool> TryRecordAsync(
        string idempotencyKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(idempotencyKey);
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var now = _clock();
            RemoveExpired(now);
            if (_entries.ContainsKey(idempotencyKey))
                return ValueTask.FromResult(false);

            while (_entries.Count >= _capacity)
                RemoveOldest();

            _entries.Add(
                idempotencyKey,
                new Entry(now + _retention, _sequence++));
            return ValueTask.FromResult(true);
        }
    }

    private void RemoveExpired(DateTimeOffset now)
    {
        List<string>? expired = null;
        foreach (var pair in _entries)
        {
            if (pair.Value.ExpiresAt <= now)
                (expired ??= new List<string>()).Add(pair.Key);
        }
        if (expired is not null)
            foreach (var key in expired)
                _entries.Remove(key);
    }

    private void RemoveOldest()
    {
        string? oldestKey = null;
        Entry oldest = default;
        foreach (var pair in _entries)
        {
            if (oldestKey is null ||
                pair.Value.Sequence < oldest.Sequence ||
                (pair.Value.Sequence == oldest.Sequence &&
                 string.CompareOrdinal(pair.Key, oldestKey) < 0))
            {
                oldestKey = pair.Key;
                oldest = pair.Value;
            }
        }

        if (oldestKey is not null)
            _entries.Remove(oldestKey);
    }

    private readonly record struct Entry(DateTimeOffset ExpiresAt, long Sequence);
}
