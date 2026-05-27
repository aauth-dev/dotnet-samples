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
    /// <param name="key">The agent's signing key (must include private component).</param>
    /// <param name="issuer">Issuer URL (the service's own HTTPS URL).</param>
    /// <param name="subject">Agent identifier (e.g. <c>aauth:my-service@my-service.example</c>).</param>
    /// <param name="keyId">Key ID for the JWT header.</param>
    /// <param name="personServer">Optional Person Server URL to embed in the token.</param>
    /// <param name="lifetime">Optional token lifetime (defaults to <see cref="AgentTokenBuilder"/> default of 1 hour).</param>
    public SelfIssuedTokenRefresher(
        IAAuthKey key,
        string issuer,
        string subject,
        string keyId,
        string? personServer = null,
        TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(subject);
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        _key = key is AAuthKey concrete ? concrete : throw new ArgumentException("Key must be an AAuthKey instance.", nameof(key));
        _issuer = issuer;
        _subject = subject;
        _keyId = keyId;
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
}
