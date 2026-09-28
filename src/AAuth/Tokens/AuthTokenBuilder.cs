using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using AAuth.Crypto;

namespace AAuth.Tokens;

/// <summary>
/// Builds and signs an <c>aa-auth+jwt</c> per the AAuth protocol spec
/// (§Auth Token Structure). Used by Person Servers (three-party) and Access
/// Servers (four-party). The token names the person (<c>ps</c>, <c>sub</c>) and
/// the agent's key (<c>cnf</c>), never an agent identifier.
/// </summary>
public sealed class AuthTokenBuilder
{
    public AAuth.Discovery.AAuthEgressPolicy EgressPolicy { get; init; } = AAuth.Discovery.AAuthEgressPolicy.Production;
    /// <summary>The JWT <c>typ</c> value for an auth token.</summary>
    public const string TokenType = "aa-auth+jwt";

    /// <summary>The <c>dwk</c> value when issued by a PS asserting identity.</summary>
    public const string PersonDwk = "aauth-person.json";

    /// <summary>The <c>dwk</c> value when issued by an AS.</summary>
    public const string AccessDwk = "aauth-access.json";

    private static readonly HashSet<string> ReservedClaims = new(StringComparer.Ordinal)
    {
        "iss", "dwk", "aud", "jti", "ps", "cnf", "iat", "exp", "nbf",
        "sub", "scope", "mission_s256", "account", "tenant", "roles", "groups",
        // An auth token carries no agent identifier or delegation chain.
        "agent", "act", "mission",
    };

    public static bool IsReservedClaim(string name) => ReservedClaims.Contains(name);

    public static bool IsIdentityClaimAllowed(string name) => !IsReservedClaim(name)
        || name is "tenant" or "roles" or "groups";

    /// <summary>HTTPS URL of the PS/AS that issues this token (<c>iss</c>).</summary>
    public required string Issuer { get; init; }

    /// <summary>Audience — the resource URL (<c>aud</c>).</summary>
    public required string Audience { get; init; }

    /// <summary>The person's PS (<c>ps</c>): the issuer in three-party, the federating PS in four-party.</summary>
    public required string PersonServer { get; init; }

    /// <summary>The directed subject copied from the resource token (<c>sub</c>).</summary>
    public required string Subject { get; init; }

    /// <summary>The agent's public confirmation key (<c>cnf.jwk</c>); the sub-agent's for a sub-agent.</summary>
    public required IAAuthKey AgentConfirmationKey { get; init; }

    public required DateTimeOffset AgentTokenExpiresAt { get; init; }

    public DateTimeOffset? AuthorizationExpiresAt { get; init; }

    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>The issuer's signing key.</summary>
    public required IAAuthKey Key { get; init; }

    /// <summary>The issuer's key id (<c>kid</c>).</summary>
    public required string KeyId { get; init; }

    /// <summary>
    /// <c>dwk</c> — defaults to <see cref="PersonDwk"/>. Set to
    /// <see cref="AccessDwk"/> when issued by an Access Server.
    /// </summary>
    public string Dwk { get; init; } = PersonDwk;

    /// <summary>Granted scopes, space-separated.</summary>
    public string? Scope { get; init; }
    public string? Account { get; init; }

    /// <summary>
    /// Enterprise <c>roles</c> claim ([@!RFC9068]) — the user's roles asserted
    /// by the PS/AS. Emitted as a JSON string array when non-empty.
    /// </summary>
    public IReadOnlyList<string>? Roles { get; init; }

    /// <summary>
    /// Enterprise <c>groups</c> claim ([@!RFC9068]) — the user's groups asserted
    /// by the PS/AS. Emitted as a JSON string array when non-empty.
    /// </summary>
    public IReadOnlyList<string>? Groups { get; init; }

    /// <summary><c>mission_s256</c> copied from the resource token, when present.</summary>
    public string? MissionS256 { get; init; }

    /// <summary>
    /// Enterprise <c>tenant</c> claim copied from the resource token: organization
    /// context, not part of the person identifier <c>(iss, sub)</c>.
    /// </summary>
    public string? Tenant { get; init; }

    /// <summary>Lifetime; spec caps at 1 hour. Default 1 hour.</summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Issued-at time. Defaults to current UTC.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>Token id. Defaults to a fresh GUID.</summary>
    public string? TokenId { get; init; }

    /// <summary>
    /// Additional identity claims to merge into the payload — used by an
    /// Access Server to assert claims it received from a Person Server via the
    /// §Claims Required push (e.g. <c>email</c>). May not
    /// collide with a required/reserved claim (case-sensitive per RFC 7519 §4).
    /// </summary>
    public IReadOnlyDictionary<string, JsonNode?>? AdditionalClaims { get; init; }

    /// <summary>Build and sign the auth token.</summary>
    public string Build()
    {
        Require(Issuer, nameof(Issuer));
        Require(Audience, nameof(Audience));
        Require(PersonServer, nameof(PersonServer));
        Require(Subject, nameof(Subject));
        Require(KeyId, nameof(KeyId));
        AccountBinding.Validate(Account);
        if (MissionS256 is not null && !MissionReference.IsValid(MissionS256))
            throw new InvalidOperationException("MissionS256 must be an unpadded base64url SHA-256 digest.");
        // `required` is a compile-time hint; reflection / default! callers
        // can still pass null. Fail explicitly so the diagnostic points at
        // the configuration rather than surfacing as a NullReferenceException
        // deep inside the JWT writer.
        if (Key is null)
        {
            throw new InvalidOperationException("Key must be set.");
        }
        if (AgentConfirmationKey is null)
        {
            throw new InvalidOperationException("AgentConfirmationKey must be set.");
        }
        if (!Key.HasPrivateKey)
        {
            throw new InvalidOperationException("Signing key must include a private component.");
        }
        if (!AAuthUrl.IsHttpsOrLoopback(Issuer, EgressPolicy))
        {
            throw new InvalidOperationException("Issuer must be an absolute https:// URL (or http://localhost).");
        }
        if (!AAuthUrl.IsHttpsOrLoopback(Audience, EgressPolicy))
        {
            throw new InvalidOperationException("Audience must be an absolute https:// URL (or http://localhost).");
        }
        if (!AAuthUrl.IsHttpsOrLoopback(PersonServer, EgressPolicy))
        {
            throw new InvalidOperationException("PersonServer must be an absolute https:// URL (or http://localhost).");
        }
        var (iat, exp) = TokenClaims.Lifetime(IssuedAt, Lifetime, AgentTokenExpiresAt, AuthorizationExpiresAt, TimeProvider);
        var jti = TokenId ?? Guid.NewGuid().ToString("N");

        var header = new JsonObject
        {
            ["alg"] = Key.Algorithm,
            ["typ"] = TokenType,
            ["kid"] = KeyId,
        };

        var payload = new JsonObject
        {
            ["iss"] = Issuer,
            ["dwk"] = Dwk,
            ["aud"] = Audience,
            ["jti"] = jti,
            ["ps"] = PersonServer,
            ["sub"] = Subject,
            ["cnf"] = new JsonObject { ["jwk"] = AgentConfirmationKey.ToPublicJwk() },
            ["iat"] = iat.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
        };

        if (Account is not null) payload["account"] = Account;
        if (!string.IsNullOrEmpty(Tenant))
        {
            payload["tenant"] = Tenant;
        }
        if (!string.IsNullOrEmpty(Scope))
        {
            payload["scope"] = Scope;
        }
        if (Roles is { Count: > 0 })
        {
            payload["roles"] = ToJsonArray(Roles);
        }
        if (Groups is { Count: > 0 })
        {
            payload["groups"] = ToJsonArray(Groups);
        }
        if (MissionS256 is not null)
        {
            payload[MissionReference.ClaimName] = MissionS256;
        }
        if (AdditionalClaims is not null)
        {
            foreach (var (k, v) in AdditionalClaims)
            {
                if (IsReservedClaim(k))
                {
                    throw new InvalidOperationException($"Additional claim '{k}' is reserved.");
                }
                payload[k] = v?.DeepClone();
            }
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

    private static JsonArray ToJsonArray(IReadOnlyList<string> values)
    {
        var array = new JsonArray();
        foreach (var value in values)
        {
            array.Add(value);
        }
        return array;
    }

}
