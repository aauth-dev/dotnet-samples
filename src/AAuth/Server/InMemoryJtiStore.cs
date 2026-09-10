using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Server;

/// <summary>
/// In-memory <see cref="IJtiStore"/> for development and testing.
/// NOT production-grade — state is lost on restart, no distributed support.
/// </summary>
public sealed class InMemoryJtiStore : IJtiStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _requests = new(StringComparer.Ordinal);
    private readonly Dictionary<TokenKey, Entry> _tokens = new();
    private readonly TimeProvider _clock;
    private readonly int _capacity;
    private readonly TimeSpan _retention;
    private DateTimeOffset _nextCleanup;

    public InMemoryJtiStore(TimeProvider? timeProvider = null, int capacity = 100_000, TimeSpan? retention = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        _clock = timeProvider ?? TimeProvider.System;
        _capacity = capacity;
        _retention = retention ?? TimeSpan.FromHours(1);
        if (_retention < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(retention));
    }

    public Task<bool> TryRecordRequestAsync(string requestKey, DateTimeOffset expiration, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestKey);
        ct.ThrowIfCancellationRequested();
        lock (_gate)
        {
            MaybeCleanup();
            if (expiration <= _clock.GetUtcNow() || _requests.ContainsKey(requestKey)) return Task.FromResult(false);
            EnsureCapacity(_requests.Count);
            _requests.Add(requestKey, expiration);
            return Task.FromResult(true);
        }
    }

    public Task<bool> RegisterAsync(TokenKey token, DateTimeOffset expiration, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ct.ThrowIfCancellationRequested();
        lock (_gate)
        {
            MaybeCleanup();
            if (expiration <= _clock.GetUtcNow()) return Task.FromResult(false);
            if (_tokens.TryGetValue(token, out var entry))
                return Task.FromResult(!HasRevokedAncestor(token) && entry.Expiration == expiration);
            EnsureCapacity(_tokens.Count);
            _tokens.Add(token, new Entry(expiration));
            return Task.FromResult(true);
        }
    }

    public Task<bool> RevokeAsync(TokenKey token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ct.ThrowIfCancellationRequested();
        lock (_gate)
        {
            MaybeCleanup();
            if (!_tokens.TryGetValue(token, out var entry)) return Task.FromResult(false);
            entry.Revoked = true;
            return Task.FromResult(true);
        }
    }

    public Task<bool> IsRevokedAsync(TokenKey token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ct.ThrowIfCancellationRequested();
        lock (_gate)
        {
            MaybeCleanup();
            return Task.FromResult(HasRevokedAncestor(token));
        }
    }

    public void Cleanup()
    {
        lock (_gate)
        {
            var now = _clock.GetUtcNow();
            foreach (var request in _requests.Where(pair => pair.Value <= now).Select(pair => pair.Key).ToArray())
                _requests.Remove(request);
            foreach (var token in _tokens.Where(pair => pair.Value.Expiration + _retention <= now).Select(pair => pair.Key).ToArray())
                _tokens.Remove(token);
            _nextCleanup = now.AddMinutes(1);
        }
    }

    public Task<bool> RegisterGrantAsync(IReadOnlyCollection<TokenKey> sources, TokenGrant grant, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(sources);
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(grant.Token);
        ArgumentException.ThrowIfNullOrWhiteSpace(grant.Resource);
        ct.ThrowIfCancellationRequested();
        lock (_gate)
        {
            MaybeCleanup();
            var now = _clock.GetUtcNow();
            if (sources.Count == 0 || grant.ExpiresAt <= now || sources.Any(source =>
                !_tokens.TryGetValue(source, out var entry) || HasRevokedAncestor(source) || entry.Expiration <= now
                || grant.ExpiresAt > entry.Expiration || Ancestry(source).Contains(grant.Token))) return Task.FromResult(false);
            if (_tokens.TryGetValue(grant.Token, out var existing))
            {
                if (HasRevokedAncestor(grant.Token) || existing.Expiration != grant.ExpiresAt
                    || (existing.Grant is not null && (existing.Grant != grant || !existing.Sources.SetEquals(sources))))
                    return Task.FromResult(false);
            }
            else
            {
                EnsureCapacity(_tokens.Count);
                _tokens.Add(grant.Token, existing = new Entry(grant.ExpiresAt));
            }
            existing.Grant = grant;
            existing.Sources.UnionWith(sources);
            return Task.FromResult(true);
        }
    }

    public Task<IReadOnlyList<TokenGrant>> GetGrantsAsync(TokenKey source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ct.ThrowIfCancellationRequested();
        lock (_gate)
        {
            MaybeCleanup();
            IReadOnlyList<TokenGrant> grants = _tokens.Values
                .Where(entry => entry.Grant is not null && entry.Sources.Contains(source) && entry.Expiration > _clock.GetUtcNow())
                .Select(entry => entry.Grant!).ToArray();
            return Task.FromResult(grants);
        }
    }

    private bool HasRevokedAncestor(TokenKey token) => Ancestry(token).Any(ancestor =>
        _tokens.TryGetValue(ancestor, out var entry) && entry.Revoked);

    private IEnumerable<TokenKey> Ancestry(TokenKey token)
    {
        var visited = new HashSet<TokenKey>();
        var remaining = new Stack<TokenKey>();
        remaining.Push(token);
        while (remaining.TryPop(out var current))
        {
            if (!visited.Add(current)) continue;
            yield return current;
            if (_tokens.TryGetValue(current, out var entry))
                foreach (var source in entry.Sources) remaining.Push(source);
        }
    }

    private void MaybeCleanup()
    {
        if (_clock.GetUtcNow() >= _nextCleanup) Cleanup();
    }

    private void EnsureCapacity(int count)
    {
        if (count >= _capacity) throw new InvalidOperationException("Token or request inventory capacity exceeded.");
    }

    private sealed class Entry(DateTimeOffset expiration)
    {
        public DateTimeOffset Expiration { get; } = expiration;
        public bool Revoked { get; set; }
        public TokenGrant? Grant { get; set; }
        public HashSet<TokenKey> Sources { get; } = new();
    }
}
