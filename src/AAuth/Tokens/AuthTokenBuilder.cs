using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;

namespace AAuth.Tokens;

/// <summary>
/// Builds and signs an <c>aa-auth+jwt</c> per the AAuth protocol spec
/// (§Auth Token Structure). Used by Person Servers (three-party) and Access
/// Servers (four-party). Phase 2 ships this for the in-process mock PS in
/// the integration tests and the future <c>samples/MockPersonServer/</c>.
/// </summary>
public sealed class AuthTokenBuilder
{
    /// <summary>The JWT <c>typ</c> value for an auth token.</summary>
    public const string TokenType = "aa-auth+jwt";

    /// <summary>The <c>dwk</c> value when issued by a PS asserting identity.</summary>
    public const string PersonDwk = "aauth-person.json";

    /// <summary>The <c>dwk</c> value when issued by an AS.</summary>
    public const string AccessDwk = "aauth-access.json";

    /// <summary>HTTPS URL of the PS/AS that issues this token (<c>iss</c>).</summary>
    public required string Issuer { get; init; }

    /// <summary>Audience — the resource URL (<c>aud</c>).</summary>
    public required string Audience { get; init; }

    /// <summary>Agent identifier (<c>agent</c>).</summary>
    public required string Agent { get; init; }

    /// <summary>The agent's public confirmation key (<c>cnf.jwk</c>).</summary>
    public required AAuthKey AgentConfirmationKey { get; init; }

    /// <summary>The issuer's signing key.</summary>
    public required AAuthKey Key { get; init; }

    /// <summary>The issuer's key id (<c>kid</c>).</summary>
    public required string KeyId { get; init; }

    /// <summary>
    /// <c>dwk</c> — defaults to <see cref="PersonDwk"/>. Set to
    /// <see cref="AccessDwk"/> when issued by an Access Server.
    /// </summary>
    public string Dwk { get; init; } = PersonDwk;

    /// <summary>Granted scopes, space-separated.</summary>
    public string? Scope { get; init; }

    /// <summary>Pairwise pseudonymous user identifier.</summary>
    public string? Subject { get; init; }

    /// <summary>Lifetime; spec caps at 1 hour. Default 1 hour.</summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Issued-at time. Defaults to current UTC.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>Token id. Defaults to a fresh GUID.</summary>
    public string? TokenId { get; init; }

    /// <summary>Build and sign the auth token.</summary>
    public string Build()
    {
        Require(Issuer, nameof(Issuer));
        Require(Audience, nameof(Audience));
        Require(Agent, nameof(Agent));
        Require(KeyId, nameof(KeyId));
        if (!Key.HasPrivateKey)
        {
            throw new InvalidOperationException("Signing key must include a private component.");
        }
        if (!IsHttpsUrl(Issuer))
        {
            throw new InvalidOperationException("Issuer must be an absolute https:// URL.");
        }
        if (!IsHttpsUrl(Audience))
        {
            throw new InvalidOperationException("Audience must be an absolute https:// URL.");
        }
        if (Lifetime > TimeSpan.FromHours(1))
        {
            throw new InvalidOperationException("Auth token Lifetime must not exceed 1 hour.");
        }
        if (Subject is null && string.IsNullOrEmpty(Scope))
        {
            // Spec: at least one of `sub` or `scope` MUST be present.
            throw new InvalidOperationException("At least one of Subject or Scope must be set.");
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
            ["dwk"] = Dwk,
            ["aud"] = Audience,
            ["jti"] = jti,
            ["agent"] = Agent,
            ["cnf"] = new JsonObject { ["jwk"] = AgentConfirmationKey.ToPublicJwk() },
            ["act"] = new JsonObject { ["sub"] = Agent },
            ["iat"] = iat.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
        };

        if (Subject is not null)
        {
            payload["sub"] = Subject;
        }
        if (!string.IsNullOrEmpty(Scope))
        {
            payload["scope"] = Scope;
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

    private static bool IsHttpsUrl(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == "https";
}
