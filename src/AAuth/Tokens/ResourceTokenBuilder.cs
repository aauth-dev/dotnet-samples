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
/// (§Resource Token Structure). A resource issues one only after verifying a
/// person token or auth token on the request; <c>ps</c>, <c>sub</c>,
/// <c>presented_jti</c>, <c>mission_s256</c> and <c>tenant</c> are copied from it.
/// </summary>
public sealed class ResourceTokenBuilder
{
    public AAuth.Discovery.AAuthEgressPolicy EgressPolicy { get; init; } = AAuth.Discovery.AAuthEgressPolicy.Production;
    /// <summary>The JWT <c>typ</c> value for a resource token.</summary>
    public const string TokenType = "aa-resource+jwt";

    /// <summary>The fixed <c>dwk</c> value mandated by the spec.</summary>
    public const string ResourceDwk = "aauth-resource.json";

    /// <summary>HTTPS URL of the resource issuing the token (<c>iss</c>).</summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// Audience — the PS that issued the presented token (three-party) or the
    /// resource's own AS (four-party).
    /// </summary>
    public required string Audience { get; init; }

    /// <summary>The person's PS (<c>ps</c>): the person token's <c>iss</c>, or the auth token's <c>ps</c>.</summary>
    public required string PersonServer { get; init; }

    /// <summary>The directed subject copied from the presented token (<c>sub</c>).</summary>
    public required string Subject { get; init; }

    /// <summary>The <c>jti</c> of the person or auth token the request presented (<c>presented_jti</c>).</summary>
    public required string PresentedJti { get; init; }

    /// <summary>JWK thumbprint of the agent's signing key (<c>agent_jkt</c>).</summary>
    public required string AgentJkt { get; init; }

    /// <summary>Resource's signing key.</summary>
    public required IAAuthKey Key { get; init; }

    /// <summary>Resource's key identifier (<c>kid</c>).</summary>
    public required string KeyId { get; init; }

    /// <summary>Requested scopes, space-separated (<c>scope</c>).</summary>
    public string? Scope { get; init; }
    public string? Account { get; init; }
    public IReadOnlyDictionary<string, string>? ScopeDescriptions { get; init; }
    public IReadOnlyCollection<string>? PersonServerScopesSupported { get; init; }

    /// <summary><c>mission_s256</c> copied unchanged from the presented token, when it carried one.</summary>
    public string? MissionS256 { get; init; }

    /// <summary><c>tenant</c> copied from the presented token.</summary>
    public string? Tenant { get; init; }

    /// <summary>Optional hint about who the authorization is for (<c>login_hint</c>).</summary>
    public string? LoginHint { get; init; }
    public AAuth.Headers.Interaction? Interaction { get; init; }

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
        Require(PersonServer, nameof(PersonServer));
        Require(Subject, nameof(Subject));
        Require(PresentedJti, nameof(PresentedJti));
        Require(AgentJkt, nameof(AgentJkt));
        Require(KeyId, nameof(KeyId));
        AccountBinding.Validate(Account);
        ValidateScopes(Scope, ScopeDescriptions, PersonServerScopesSupported);
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
            ["alg"] = Key.Algorithm,
            ["typ"] = TokenType,
            ["kid"] = KeyId,
        };

        var payload = new JsonObject
        {
            ["iss"] = Issuer,
            ["dwk"] = ResourceDwk,
            ["aud"] = Audience,
            ["jti"] = jti,
            ["ps"] = PersonServer,
            ["sub"] = Subject,
            ["presented_jti"] = PresentedJti,
            ["agent_jkt"] = AgentJkt,
            ["iat"] = iat.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
            ["scope"] = Scope ?? string.Empty,
        };

        if (Account is not null) payload["account"] = Account;
        if (MissionS256 is not null) payload[MissionReference.ClaimName] = MissionS256;
        if (!string.IsNullOrEmpty(Tenant)) payload["tenant"] = Tenant;
        if (!string.IsNullOrEmpty(LoginHint)) payload["login_hint"] = LoginHint;

        if (Interaction is not null)
        {
            AAuth.Headers.Interaction.Format(Interaction.Url, Interaction.Code, EgressPolicy);
            payload["interaction"] = new JsonObject { ["url"] = Interaction.Url, ["code"] = Interaction.Code };
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

    public static void ValidateScopes(string? scope, IReadOnlyDictionary<string, string>? resourceScopes,
        IReadOnlyCollection<string>? personServerScopes)
    {
        if (string.IsNullOrEmpty(scope)) return;
        var identityScopes = new HashSet<string>(personServerScopes ?? Array.Empty<string>(), StringComparer.Ordinal);
        foreach (var value in scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var declaredResource = resourceScopes is not null && resourceScopes.TryGetValue(value, out var description)
                && !string.IsNullOrWhiteSpace(description);
            if (!declaredResource && !identityScopes.Contains(value))
                throw new InvalidOperationException($"Scope '{value}' is not declared in resource scope_descriptions or PS scopes_supported.");
        }
    }

}
