using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Discovery;

internal sealed record DiscoveryResponse<T>(T Value, TimeSpan Freshness, bool AllowStale, bool Store);

internal sealed class DiscoveryCache<T> where T : class
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Attempt> _issuerAttempts = new(StringComparer.Ordinal);
    private readonly TimeSpan _ttl;
    private readonly TimeSpan _floor;
    private readonly TimeSpan _maxAge;
    private readonly int _capacity;
    private readonly TimeProvider _time;

    public DiscoveryCache(TimeSpan ttl, TimeSpan floor, TimeProvider timeProvider,
        int capacity = 1024, TimeSpan? maxAge = null)
    {
        if (ttl < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ttl));
        if (floor < TimeSpan.FromMinutes(1)) throw new ArgumentOutOfRangeException(nameof(floor));
        if (capacity < 1) throw new ArgumentOutOfRangeException(nameof(capacity));
        _maxAge = maxAge ?? TimeSpan.FromHours(24);
        if (_maxAge <= TimeSpan.Zero || _maxAge > TimeSpan.FromHours(24))
            throw new ArgumentOutOfRangeException(nameof(maxAge));
        _ttl = ttl < _maxAge ? ttl : _maxAge;
        _floor = floor;
        _capacity = capacity;
        _time = timeProvider;
    }

    public DiscoveryResponse<T> Response(T value, HttpResponseMessage response)
    {
        var now = _time.GetUtcNow();
        var control = response.Headers.CacheControl;
        var date = response.Headers.Date ?? now;
        var apparentAge = now > date ? now - date : TimeSpan.Zero;
        var age = response.Headers.Age ?? TimeSpan.Zero;
        if (apparentAge > age) age = apparentAge;
        var lifetime = control?.MaxAge ?? (response.Content.Headers.Expires is { } expires ? expires - date : _ttl);
        var freshness = lifetime > age ? lifetime - age : TimeSpan.Zero;
        if (freshness > _maxAge) freshness = _maxAge;
        var revalidate = control?.NoCache == true || control?.MustRevalidate == true;
        if (control?.NoCache == true) freshness = TimeSpan.Zero;
        return new(value, freshness, !revalidate && control?.NoStore != true, control?.NoStore != true);
    }

    public Task<T> GetAsync(string key, Func<T, bool> refresh, Func<Task<DiscoveryResponse<T>>> load,
        CancellationToken cancellationToken, string? issuer = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            if (!_entries.TryGetValue(key, out var entry))
            {
                if (_entries.Count >= _capacity)
                {
                    var victim = _entries.FirstOrDefault(pair => pair.Value.Pending is null
                        && now >= pair.Value.NextAttempt);
                    if (victim.Key is null) throw new HttpRequestException("Discovery cache capacity reached.");
                    _entries.Remove(victim.Key);
                }
                entry = new Entry();
                _entries.Add(key, entry);
            }
            if (entry.Pending is not null) return entry.Pending.WaitAsync(cancellationToken);
            if (entry.Value is not null && now - entry.FetchedAt >= _maxAge) entry.Value = null;
            if (entry.Value is not null && now < entry.FreshUntil && !refresh(entry.Value))
                return Task.FromResult(entry.Value);
            if (now < entry.NextAttempt)
            {
                if (entry.Value is not null && (entry.AllowStale || now < entry.FreshUntil)) return Task.FromResult(entry.Value);
                entry.Failure?.Throw();
                throw new HttpRequestException("Discovery fetch is rate limited.");
            }
            Attempt? attempt = null;
            if (issuer is not null)
            {
                if (!_issuerAttempts.TryGetValue(issuer, out attempt))
                {
                    if (_issuerAttempts.Count >= _capacity)
                    {
                        var victim = _issuerAttempts.FirstOrDefault(pair => !pair.Value.Pending && now >= pair.Value.NextAttempt);
                        if (victim.Key is null) throw new HttpRequestException("Issuer attempt cache capacity reached.");
                        _issuerAttempts.Remove(victim.Key);
                    }
                    attempt = new();
                    _issuerAttempts.Add(issuer, attempt);
                }
                if (attempt.Pending || now < attempt.NextAttempt)
                {
                    if (entry.Value is not null && (entry.AllowStale || now < entry.FreshUntil)) return Task.FromResult(entry.Value);
                    throw new HttpRequestException("Issuer JWKS fetch is rate limited.");
                }
                attempt.NextAttempt = now + _floor;
                attempt.Pending = true;
            }
            entry.NextAttempt = now + _floor;
            entry.Pending = LoadAsync(entry, attempt, load);
            return entry.Pending.WaitAsync(cancellationToken);
        }
    }

    private async Task<T> LoadAsync(Entry entry, Attempt? attempt, Func<Task<DiscoveryResponse<T>>> load)
    {
        await Task.Yield();
        try
        {
            var value = await load().ConfigureAwait(false);
            lock (_gate)
            {
                entry.Value = value.Store ? value.Value : null;
                entry.FetchedAt = _time.GetUtcNow();
                entry.FreshUntil = entry.FetchedAt + value.Freshness;
                entry.AllowStale = value.AllowStale;
                entry.Failure = null;
                entry.Failures = 0;
                if (attempt is not null) attempt.Failures = 0;
            }
            return value.Value;
        }
        catch (Exception exception)
        {
            lock (_gate)
            {
                entry.Failure = ExceptionDispatchInfo.Capture(exception);
                entry.Failures = Math.Min(entry.Failures + 1, 7);
                if (attempt is not null) attempt.Failures = Math.Min(attempt.Failures + 1, 7);
                var backoff = TimeSpan.FromTicks((long)Math.Min(
                    _floor.Ticks * Math.Pow(2, Math.Max(entry.Failures, attempt?.Failures ?? 0) - 1), TimeSpan.FromHours(1).Ticks));
                var now = _time.GetUtcNow();
                entry.NextAttempt = now + (backoff > _floor ? backoff : _floor);
                if (attempt is not null) attempt.NextAttempt = entry.NextAttempt;
                if (entry.Value is not null && now - entry.FetchedAt < _maxAge
                    && (entry.AllowStale || now < entry.FreshUntil)) return entry.Value;
                entry.Value = null;
            }
            throw;
        }
        finally
        {
            lock (_gate)
            {
                entry.Pending = null;
                if (attempt is not null) attempt.Pending = false;
            }
        }
    }

    public void Invalidate(string? key = null)
    {
        lock (_gate)
        {
            foreach (var pair in _entries)
                if (key is null || pair.Key == key) pair.Value.Value = null;
        }
    }

    private sealed class Attempt
    {
        public DateTimeOffset NextAttempt;
        public bool Pending;
        public int Failures;
    }

    private sealed class Entry
    {
        public T? Value;
        public DateTimeOffset FetchedAt;
        public DateTimeOffset FreshUntil;
        public bool AllowStale;
        public DateTimeOffset NextAttempt;
        public Task<T>? Pending;
        public ExceptionDispatchInfo? Failure;
        public int Failures;
    }
}