using System;
using System.Collections.Generic;
using System.Linq;

namespace AAuth.Server;

/// <summary>
/// Per-issuer bounds on what a revocation recipient accepts (#token-revocation): a caller beyond
/// either is answered <c>429 rate_limited</c> with <c>Retry-After</c>.
/// </summary>
public sealed class RevocationLimits
{
    /// <summary>Unexpired revocation entries one issuer may hold. Default 10,000.</summary>
    public int MaxEntriesPerIssuer { get; set; } = 10_000;

    /// <summary>Revocation requests one issuer may send per <see cref="Window"/>. Default 600.</summary>
    public int MaxRequestsPerIssuer { get; set; } = 600;

    /// <summary>The rate window. Default one minute.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
}

internal sealed class RevocationIssuerLimiter(RevocationLimits limits, TimeProvider clock)
{
    private readonly object _gate = new();
    private readonly Dictionary<string, IssuerState> _issuers = new(StringComparer.Ordinal);

    /// <summary>Admit one request; returns the seconds to wait when the issuer is over a bound.</summary>
    public int? TryAdmit(string issuer, string jti, DateTimeOffset expiresAt)
    {
        var now = clock.GetUtcNow();
        lock (_gate)
        {
            if (!_issuers.TryGetValue(issuer, out var state)) _issuers[issuer] = state = new();
            while (state.Requests.TryPeek(out var oldest) && oldest + limits.Window <= now) state.Requests.Dequeue();
            foreach (var expired in state.Entries.Where(entry => entry.Value <= now).Select(entry => entry.Key).ToArray())
                state.Entries.Remove(expired);
            if (state.Requests.Count >= limits.MaxRequestsPerIssuer)
                return Seconds(state.Requests.Peek() + limits.Window - now);
            if (!state.Entries.ContainsKey(jti) && state.Entries.Count >= limits.MaxEntriesPerIssuer)
                return Seconds(state.Entries.Values.Min() - now);
            state.Requests.Enqueue(now);
            state.Entries[jti] = expiresAt;
            return null;
        }
    }

    private static int Seconds(TimeSpan wait) => Math.Max(1, (int)Math.Ceiling(wait.TotalSeconds));

    private sealed class IssuerState
    {
        public Queue<DateTimeOffset> Requests { get; } = new();
        public Dictionary<string, DateTimeOffset> Entries { get; } = new(StringComparer.Ordinal);
    }
}
