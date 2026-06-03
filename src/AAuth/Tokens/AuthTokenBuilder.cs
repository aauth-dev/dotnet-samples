using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using AAuth.Crypto;

namespace AAuth.Tokens;

/// <summary>
/// Builds and signs an <c>aa-auth+jwt</c> per the AAuth protocol spec
/// (§Auth Token Structure). Used by Person Servers (three-party) and Access
/// Servers (four-party). The current consumers are the in-process mock PS
/// in the integration tests and the future <c>samples/MockPersonServer/</c>.
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
    public required IAAuthKey AgentConfirmationKey { get; init; }

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

    /// <summary>Pairwise pseudonymous user identifier.</summary>
    public string? Subject { get; init; }

    /// <summary>
    /// Enterprise <c>tenant</c> claim (§Auth Token, OpenID Connect for
    /// Enterprise) — identifies the principal's tenant/organization within the
    /// issuer. Combined with <c>iss</c> and <c>sub</c> it forms the globally
    /// unique <c>(iss, tenant, sub)</c> identity. Emitted when non-empty.
    /// </summary>
    public string? Tenant { get; init; }

    /// <summary>Lifetime; spec caps at 1 hour. Default 1 hour.</summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Issued-at time. Defaults to current UTC.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>Token id. Defaults to a fresh GUID.</summary>
    public string? TokenId { get; init; }

    /// <summary>
    /// Optional upstream <c>act</c> object for call-chaining scenarios.
    /// When set, nested inside the token's <c>act</c> claim to preserve
    /// the full delegation chain (caller → resource → downstream).
    /// </summary>
    public JsonObject? UpstreamAct { get; init; }

    /// <summary>
    /// Additional identity claims to merge into the payload — used by an
    /// Access Server to assert claims it received from a Person Server via the
    /// §Claims Required push (e.g. <c>email</c>, <c>tenant</c>). May not
    /// collide with a required/reserved claim (case-sensitive per RFC 7519 §4).
    /// </summary>
    public IReadOnlyDictionary<string, JsonNode?>? AdditionalClaims { get; init; }

    /// <summary>Build and sign the auth token.</summary>
    public string Build()
    {
        Require(Issuer, nameof(Issuer));
        Require(Audience, nameof(Audience));
        Require(Agent, nameof(Agent));
        Require(KeyId, nameof(KeyId));
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
        if (!AAuthUrl.IsHttpsOrLoopback(Issuer))
        {
            throw new InvalidOperationException("Issuer must be an absolute https:// URL (or http://localhost).");
        }
        if (!AAuthUrl.IsHttpsOrLoopback(Audience))
        {
            throw new InvalidOperationException("Audience must be an absolute https:// URL (or http://localhost).");
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
            ["alg"] = Key.Algorithm,
            ["typ"] = TokenType,
            ["kid"] = KeyId,
        };

        // Build the act claim. In call-chaining, nest the upstream act
        // inside the current agent's act to preserve the delegation chain.
        // UpstreamAct is the RAW act from the upstream token; the builder
        // performs the single nesting per §Upstream Token Verification step 4.
        var act = new JsonObject { ["sub"] = Agent };
        if (UpstreamAct is not null)
        {
            act["act"] = UpstreamAct.DeepClone();
        }

        var payload = new JsonObject
        {
            ["iss"] = Issuer,
            ["dwk"] = Dwk,
            ["aud"] = Audience,
            ["jti"] = jti,
            ["agent"] = Agent,
            ["cnf"] = new JsonObject { ["jwk"] = AgentConfirmationKey.ToPublicJwk() },
            ["act"] = act,
            ["iat"] = iat.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
        };

        if (Subject is not null)
        {
            payload["sub"] = Subject;
        }
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
        if (AdditionalClaims is not null)
        {
            foreach (var (k, v) in AdditionalClaims)
            {
                if (payload.ContainsKey(k))
                {
                    throw new InvalidOperationException($"Additional claim '{k}' collides with a required claim.");
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
