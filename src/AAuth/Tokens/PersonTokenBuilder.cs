using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;

namespace AAuth.Tokens;

/// <summary>
/// Builds and signs an <c>aa-person+jwt</c> (§Person Token Structure): the PS's
/// statement of which person an agent acts for, addressed to one resource.
/// </summary>
public sealed class PersonTokenBuilder
{
    /// <summary>The JWT <c>typ</c> value for a person token.</summary>
    public const string TokenType = "aa-person+jwt";

    /// <summary>The fixed <c>dwk</c> value: person tokens are issued by a PS.</summary>
    public const string PersonDwk = "aauth-person.json";

    public AAuth.Discovery.AAuthEgressPolicy EgressPolicy { get; init; } = AAuth.Discovery.AAuthEgressPolicy.Production;

    /// <summary>HTTPS URL of the issuing PS (<c>iss</c>).</summary>
    public required string Issuer { get; init; }

    /// <summary>The resource the token is for (<c>aud</c>).</summary>
    public required string Audience { get; init; }

    /// <summary>The directed identifier this PS minted for the person at <see cref="Audience"/> (<c>sub</c>).</summary>
    public required string Subject { get; init; }

    /// <summary>The key the agent signs with (<c>cnf.jwk</c>); the sub-agent's key for a sub-agent.</summary>
    public required IAAuthKey ConfirmationKey { get; init; }

    /// <summary>The <c>exp</c> of the agent token presented with the request; the token never outlives it.</summary>
    public required DateTimeOffset AgentTokenExpiresAt { get; init; }

    /// <summary>A further ceiling: the <c>upstream_token</c> <c>exp</c> or the mission's <c>expires_at</c>.</summary>
    public DateTimeOffset? AuthorizationExpiresAt { get; init; }

    /// <summary>The PS signing key.</summary>
    public required IAAuthSigner Key { get; init; }

    /// <summary>The PS key id (<c>kid</c>).</summary>
    public required string KeyId { get; init; }

    /// <summary>Optional mission the request is under (<c>mission_s256</c>).</summary>
    public string? MissionS256 { get; init; }

    /// <summary>Optional organization context (<c>tenant</c>).</summary>
    public string? Tenant { get; init; }

    /// <summary>Lifetime; capped at 1 hour and at the ceilings. Default 1 hour.</summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromHours(1);

    public DateTimeOffset? IssuedAt { get; init; }
    public string? TokenId { get; init; }
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>Build and sign the person token.</summary>
    public async ValueTask<string> BuildAsync(CancellationToken cancellationToken = default)
    {
        TokenClaims.Require(Issuer, nameof(Issuer));
        TokenClaims.Require(Audience, nameof(Audience));
        TokenClaims.Require(Subject, nameof(Subject));
        TokenClaims.Require(KeyId, nameof(KeyId));
        TokenClaims.RequireSigningKey(Key);
        ArgumentNullException.ThrowIfNull(ConfirmationKey);
        TokenClaims.RequireServer(Issuer, nameof(Issuer), EgressPolicy);
        TokenClaims.RequireServer(Audience, nameof(Audience), EgressPolicy);
        if (MissionS256 is not null && !MissionReference.IsValid(MissionS256))
            throw new InvalidOperationException("MissionS256 must be an unpadded base64url SHA-256 digest.");
        var (iat, exp) = TokenClaims.Lifetime(IssuedAt, Lifetime, AgentTokenExpiresAt, AuthorizationExpiresAt, TimeProvider);

        var payload = new JsonObject
        {
            ["iss"] = Issuer,
            ["dwk"] = PersonDwk,
            ["aud"] = Audience,
            ["sub"] = Subject,
            ["jti"] = TokenId ?? Guid.NewGuid().ToString("N"),
            ["cnf"] = new JsonObject { ["jwk"] = ConfirmationKey.ToPublicJwk() },
            ["iat"] = iat.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
        };
        if (MissionS256 is not null) payload[MissionReference.ClaimName] = MissionS256;
        if (!string.IsNullOrEmpty(Tenant)) payload["tenant"] = Tenant;
        return await JwtWriter.SignCompactAsync(new JsonObject { ["alg"] = Key.Algorithm, ["typ"] = TokenType, ["kid"] = KeyId }, payload, Key,
            cancellationToken).ConfigureAwait(false);
    }
}

internal static class TokenClaims
{
    public static void Require(string? value, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException($"{name} must be a non-empty string.");
    }

    public static void RequireSigningKey(IAAuthKey? key)
    {
        if (key is null) throw new InvalidOperationException("Key must be set.");
        if (!key.HasPrivateKey) throw new InvalidOperationException("Signing key must include a private component.");
    }

    public static void RequireServer(string value, string name, AAuth.Discovery.AAuthEgressPolicy policy)
    {
        if (!AAuthUrl.IsHttpsOrLoopback(value, policy))
            throw new InvalidOperationException($"{name} must be an absolute https:// URL (or http://localhost).");
    }

    // Person and auth tokens: exp - iat at most 1 hour, never past any ceiling.
    public static (DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt) Lifetime(DateTimeOffset? issuedAt, TimeSpan lifetime,
        DateTimeOffset agentTokenExpiresAt, DateTimeOffset? authorizationExpiresAt, TimeProvider clock)
    {
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromHours(1))
            throw new InvalidOperationException("Lifetime must be positive and must not exceed 1 hour.");
        var now = clock.GetUtcNow();
        var iat = issuedAt ?? now;
        var ceiling = authorizationExpiresAt is { } other && other < agentTokenExpiresAt ? other : agentTokenExpiresAt;
        var exp = iat + lifetime < ceiling ? iat + lifetime : ceiling;
        if (exp.ToUnixTimeSeconds() <= iat.ToUnixTimeSeconds() || exp.ToUnixTimeSeconds() <= now.ToUnixTimeSeconds())
            throw new AuthTokenExpiredException();
        return (iat, exp);
    }
}
