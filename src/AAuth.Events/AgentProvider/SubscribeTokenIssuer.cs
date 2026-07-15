using AAuth.Crypto;
using AAuth.Events.Tokens;

namespace AAuth.Events.AgentProvider;

/// <summary>Configuration for AP subscribe-token issuance.</summary>
public sealed class SubscribeTokenIssuerOptions
{
    /// <summary>AP issuer URL.</summary>
    public string Issuer { get; set; } = string.Empty;
    /// <summary>Agent identifier in the token subject.</summary>
    public string Agent { get; set; } = string.Empty;
    /// <summary>Resource URL in the token audience.</summary>
    public string Resource { get; set; } = string.Empty;
    /// <summary>AP signing key identifier.</summary>
    public string KeyId { get; set; } = string.Empty;
    /// <summary>AP private signing key.</summary>
    public IAAuthKey Key { get; set; } = null!;
    /// <summary>Agent HTTP-signature confirmation key.</summary>
    public IAAuthKey ConfirmationKey { get; set; } = null!;
    /// <summary>JWT lifetime.</summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromHours(1);
    /// <summary>Optional finite event-use limit.</summary>
    public long? MaxUses { get; set; }
    /// <summary>Clock used for token and subscription timestamps.</summary>
    public Func<DateTimeOffset> Clock { get; set; } = static () => DateTimeOffset.UtcNow;
    /// <summary>Fresh opaque eid generator. It must never return an earlier id.</summary>
    public Func<string> EidGenerator { get; set; } = DefaultEidGenerator;
    /// <summary>Maximum number of collision retries, including the first attempt.</summary>
    public int MaxCollisionRetries { get; set; } = 8;

    private static string DefaultEidGenerator() =>
        Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
}

/// <summary>Issues AP subscribe tokens only after durable subscription creation.</summary>
public sealed class SubscribeTokenIssuer
{
    private readonly IAAuthAgentProviderEventStore _store;
    private readonly SubscribeTokenIssuerOptions _options;
    private readonly object _idGate = new();
    private readonly HashSet<string> _everGeneratedIds = new(StringComparer.Ordinal);

    /// <summary>Creates an issuer backed by the required durable AP store.</summary>
    public SubscribeTokenIssuer(
        IAAuthAgentProviderEventStore store,
        SubscribeTokenIssuerOptions options)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        if (_options.MaxCollisionRetries <= 0)
            throw new ArgumentOutOfRangeException(nameof(options), "MaxCollisionRetries must be positive.");
    }

    /// <summary>Issues one token and atomically reserves its eid.</summary>
    public Task<SubscribeTokenArtifact> IssueAsync(CancellationToken cancellationToken = default) =>
        IssueCoreAsync(cancellationToken);

    /// <summary>Alias for <see cref="IssueAsync(CancellationToken)"/>.</summary>
    public Task<SubscribeTokenArtifact> CreateAsync(CancellationToken cancellationToken = default) =>
        IssueAsync(cancellationToken);

    private async Task<SubscribeTokenArtifact> IssueCoreAsync(CancellationToken cancellationToken)
    {
        var issuedAt = _options.Clock();
        var expiresAt = issuedAt + _options.Lifetime;
        for (var attempt = 0; attempt < _options.MaxCollisionRetries; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var eid = _options.EidGenerator();
            if (string.IsNullOrWhiteSpace(eid))
                throw new InvalidOperationException("The eid generator returned an empty or previously used identifier.");
            lock (_idGate)
            {
                if (!_everGeneratedIds.Add(eid))
                    throw new InvalidOperationException(
                        "The eid generator returned an empty or previously used identifier.");
            }

            var artifact = new SubscribeTokenBuilder
            {
                Issuer = _options.Issuer,
                Subject = _options.Agent,
                Audience = _options.Resource,
                KeyId = _options.KeyId,
                Key = _options.Key,
                ConfirmationKey = _options.ConfirmationKey,
                Lifetime = _options.Lifetime,
                IssuedAt = issuedAt,
                EventId = eid,
                MaxUses = _options.MaxUses,
            }.Build();

            var subscription = new AgentProviderSubscription(
                artifact.Eid,
                _options.Agent,
                _options.Resource,
                _options.MaxUses,
                expiresAt);
            if (await _store.TryCreateSubscriptionAsync(subscription, cancellationToken).ConfigureAwait(false))
                return artifact;
        }

        throw new InvalidOperationException(
            $"Unable to reserve a unique Events subscription eid after {_options.MaxCollisionRetries} attempts.");
    }
}
