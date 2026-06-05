using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Tokens;

/// <summary>
/// Builds and signs an <c>aa-resource+jwt</c> per the AAuth protocol spec
/// (§Resource Token Structure).
/// </summary>
/// <remarks>
/// Symmetric with <see cref="AgentTokenBuilder"/>: hand-rolls a minimal JWT
/// writer using BouncyCastle. Resource tokens have audience equal to the
/// PS (three-party) or AS (four-party); the current code paths exercise
/// only the three-party path.
/// </remarks>
public sealed class ResourceTokenBuilder
{
    /// <summary>The JWT <c>typ</c> value for a resource token.</summary>
    public const string TokenType = "aa-resource+jwt";

    /// <summary>The fixed <c>dwk</c> value mandated by the spec.</summary>
    public const string ResourceDwk = "aauth-resource.json";

    /// <summary>HTTPS URL of the resource issuing the token (<c>iss</c>).</summary>
    public required string Issuer { get; init; }

    /// <summary>Audience — the PS URL (three-party) or AS URL (four-party).</summary>
    public required string Audience { get; init; }

    /// <summary>Agent identifier from the agent token (<c>agent</c>).</summary>
    public required string Agent { get; init; }

    /// <summary>JWK thumbprint of the agent's signing key (<c>agent_jkt</c>).</summary>
    public required string AgentJkt { get; init; }

    /// <summary>Resource's signing key.</summary>
    public required AAuthKey Key { get; init; }

    /// <summary>Resource's key identifier (<c>kid</c>).</summary>
    public required string KeyId { get; init; }

    /// <summary>Requested scopes, space-separated (<c>scope</c>).</summary>
    public string? Scope { get; init; }

    /// <summary>
    /// Mission claim (<c>mission</c>) — present when the resource is mission-aware
    /// and the agent sent an <c>AAuth-Mission</c> header (§Resource Token Structure).
    /// Carries only <c>approver</c> and <c>s256</c>; the mission content stays at the PS.
    /// </summary>
    public MissionClaim? Mission { get; init; }

    /// <summary>Lifetime; spec says SHOULD NOT exceed 5 minutes. Default 5 minutes.</summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Issued-at time. Defaults to current UTC.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>Token id. Defaults to a fresh GUID.</summary>
    public string? TokenId { get; init; }

    /// <summary>Build and sign the resource token.</summary>
    public string Build()
    {
        Require(Issuer, nameof(Issuer));
        Require(Audience, nameof(Audience));
        Require(Agent, nameof(Agent));
        Require(AgentJkt, nameof(AgentJkt));
        Require(KeyId, nameof(KeyId));
        // `required` is a compile-time hint; reflection / default! callers
        // can still pass null. Fail explicitly so the diagnostic points at
        // the configuration rather than surfacing as a NullReferenceException
        // deep inside the JWT writer.
        if (Key is null)
        {
            throw new InvalidOperationException("Key must be set.");
        }
        if (!Key.HasPrivateKey)
        {
            throw new InvalidOperationException("Signing key must include a private component.");
        }
        if (!AAuthUrl.IsHttpsOrLoopback(Issuer))
        {
            throw new InvalidOperationException("Issuer must be an absolute https:// URL (or http://localhost).");
        }
        if (!AAuthUrl.IsHttpsOrLoopback(Audience))
        {
            throw new InvalidOperationException("Audience must be an absolute https:// URL (or http://localhost).");
        }
        if (Lifetime > TimeSpan.FromMinutes(5))
        {
            // Spec §Resource Token: "SHOULD NOT have a lifetime exceeding 5
            // minutes". Treat anything larger as a configuration error in
            // these samples rather than emit a non-conformant token.
            throw new InvalidOperationException("Resource token Lifetime must not exceed 5 minutes.");
        }

        var iat = IssuedAt ?? DateTimeOffset.UtcNow;
        var exp = iat + Lifetime;
        var jti = TokenId ?? Guid.NewGuid().ToString("N");

        var header = new JsonObject
        {
            ["alg"] = AAuthKey.Algorithm,
            ["typ"] = TokenType,
            ["kid"] = KeyId,
        };

        var payload = new JsonObject
        {
            ["iss"] = Issuer,
            ["dwk"] = ResourceDwk,
            ["aud"] = Audience,
            ["jti"] = jti,
            ["agent"] = Agent,
            ["agent_jkt"] = AgentJkt,
            ["iat"] = iat.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
        };

        if (!string.IsNullOrEmpty(Scope))
        {
            payload["scope"] = Scope;
        }

        if (Mission is not null)
        {
            payload["mission"] = Mission.ToJsonObject();
        }

        return JwtWriter.SignCompact(header, payload, Key);
    }

    private static void Require(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"{name} must be a non-empty string.");
        }
    }

}
