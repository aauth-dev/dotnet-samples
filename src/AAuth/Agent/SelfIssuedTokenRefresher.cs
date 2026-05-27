using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Tokens;

namespace AAuth.Agent;

/// <summary>
/// Built-in <see cref="ITokenRefresher"/> for hosted services that self-issue
/// agent tokens. Builds a fresh JWT on each refresh using <see cref="AgentTokenBuilder"/>.
/// </summary>
/// <remarks>
/// Use this for services with a stable URL that act as their own issuer —
/// no Agent Provider enrollment is needed. Each call to <see cref="RefreshAsync"/>
/// mints a new short-lived agent token signed with the provided key.
/// </remarks>
public sealed class SelfIssuedTokenRefresher : ITokenRefresher
{
    private readonly AAuthKey _key;
    private readonly string _issuer;
    private readonly string _subject;
    private readonly string _keyId;
    private readonly string? _personServer;
    private readonly TimeSpan? _lifetime;

    /// <summary>Create a self-issued token refresher.</summary>
    /// <param name="key">The agent's signing key.</param>
    /// <param name="issuer">Issuer URL (the service's own HTTPS URL).</param>
    /// <param name="subject">Agent identifier (e.g. <c>aauth:my-service@my-service.example</c>).</param>
    /// <param name="kid">JWT <c>kid</c> header value (resources match this against your JWKS to find the verification key).</param>
    /// <param name="personServer">Optional Person Server URL to embed in the token.</param>
    /// <param name="lifetime">Optional token lifetime (defaults to <see cref="AgentTokenBuilder"/> default of 1 hour).</param>
    public SelfIssuedTokenRefresher(
        AAuthKey key,
        string issuer,
        string subject,
        string kid,
        string? personServer = null,
        TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(subject);
        ArgumentException.ThrowIfNullOrEmpty(kid);
        _key = key;
        _issuer = issuer;
        _subject = subject;
        _keyId = kid;
        _personServer = personServer;
        _lifetime = lifetime;
    }

    /// <inheritdoc/>
    public Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
    {
        var builder = new AgentTokenBuilder
        {
            Issuer = _issuer,
            Subject = _subject,
            KeyId = _keyId,
            Key = _key,
            PersonServer = _personServer,
            Lifetime = _lifetime ?? TimeSpan.FromHours(1),
        };

        return Task.FromResult(builder.Build());
    }

    /// <summary>Start building a self-issued refresher with required parameters.</summary>
    /// <param name="key">The agent's signing key.</param>
    /// <param name="issuer">Issuer URL (the service's own HTTPS URL).</param>
    /// <param name="subject">Agent identifier (e.g. <c>aauth:my-service@my-service.example</c>).</param>
    public static RefresherBuilder Create(AAuthKey key, string issuer, string subject) => new(key, issuer, subject);

    /// <summary>Fluent builder for <see cref="SelfIssuedTokenRefresher"/>.</summary>
    public sealed class RefresherBuilder
    {
        private readonly AAuthKey _key;
        private readonly string _issuer;
        private readonly string _subject;
        private string? _keyId;
        private string? _personServer;
        private TimeSpan? _lifetime;

        internal RefresherBuilder(AAuthKey key, string issuer, string subject)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentException.ThrowIfNullOrEmpty(issuer);
            ArgumentException.ThrowIfNullOrEmpty(subject);
            _key = key;
            _issuer = issuer;
            _subject = subject;
        }

        /// <summary>Set a custom JWT <c>kid</c> header value. Defaults to the key's JWK thumbprint.</summary>
        public RefresherBuilder WithKid(string kid) { _keyId = kid; return this; }

        /// <summary>Embed a Person Server URL in the token.</summary>
        public RefresherBuilder WithPersonServer(string personServer) { _personServer = personServer; return this; }

        /// <summary>Set a custom token lifetime. Defaults to 1 hour.</summary>
        public RefresherBuilder WithLifetime(TimeSpan lifetime) { _lifetime = lifetime; return this; }

        /// <summary>Build the refresher.</summary>
        public SelfIssuedTokenRefresher Build()
            => new(_key, _issuer, _subject, _keyId ?? _key.ComputeJwkThumbprint(), _personServer, _lifetime);

        /// <summary>Implicit conversion so the builder can be passed directly where <see cref="ITokenRefresher"/> is expected.</summary>
        public static implicit operator SelfIssuedTokenRefresher(RefresherBuilder b) => b.Build();
    }
}
