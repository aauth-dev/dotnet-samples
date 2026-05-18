using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Tokens;

/// <summary>
/// Builds and signs an <c>aa-agent+jwt</c> per the AAuth protocol spec
/// (draft-hardt-oauth-aauth-protocol §Agent Token Structure).
/// </summary>
/// <remarks>
/// Phase 1 hand-rolls JWT signing because <c>Microsoft.IdentityModel.Tokens</c>
/// does not ship a built-in EdDSA <c>SignatureProvider</c>, and native
/// <c>System.Security.Cryptography.EdDSA</c> is not available on .NET 10 in
/// this runtime. The format is small enough that an external JWT stack is
/// unwarranted at this stage.
/// </remarks>
public sealed class AgentTokenBuilder
{
    /// <summary>The JWT <c>typ</c> value for an agent token.</summary>
    public const string TokenType = "aa-agent+jwt";

    /// <summary>The fixed <c>dwk</c> value mandated by the spec.</summary>
    public const string AgentDwk = "aauth-agent.json";

    /// <summary>HTTPS URL of the agent provider that issues this token (<c>iss</c>).</summary>
    public required string Issuer { get; init; }

    /// <summary>Stable agent identifier in the form <c>aauth:local@domain</c> (<c>sub</c>).</summary>
    public required string Subject { get; init; }

    /// <summary>Key identifier for the JWT header (<c>kid</c>).</summary>
    public required string KeyId { get; init; }

    /// <summary>The agent's signing key. Its public half is embedded as <c>cnf.jwk</c>.</summary>
    public required AAuthKey Key { get; init; }

    /// <summary>Optional Person Server URL (<c>ps</c>).</summary>
    public string? PersonServer { get; init; }

    /// <summary>Token lifetime. Spec recommends &le; 24 hours; default is 1 hour.</summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Issue time. Defaults to current UTC.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>Unique token identifier (<c>jti</c>). Defaults to a fresh GUID.</summary>
    public string? TokenId { get; init; }

    /// <summary>Additional claims to merge into the payload. May not collide with required claims.</summary>
    public IReadOnlyDictionary<string, JsonNode?>? AdditionalClaims { get; init; }

    /// <summary>Build and sign the agent token. Returns the compact JWT serialization.</summary>
    public string Build()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
        {
            throw new InvalidOperationException("Issuer must be a non-empty string.");
        }
        if (string.IsNullOrWhiteSpace(Subject))
        {
            throw new InvalidOperationException("Subject must be a non-empty string.");
        }
        if (string.IsNullOrWhiteSpace(KeyId))
        {
            throw new InvalidOperationException("KeyId must be a non-empty string.");
        }
        if (!Key.HasPrivateKey)
        {
            throw new InvalidOperationException("Signing key must include a private component.");
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
            ["dwk"] = AgentDwk,
            ["sub"] = Subject,
            ["jti"] = jti,
            ["cnf"] = new JsonObject { ["jwk"] = Key.ToPublicJwk() },
            ["iat"] = iat.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
        };

        if (PersonServer is not null)
        {
            payload["ps"] = PersonServer;
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

        var headerBytes = Encoding.UTF8.GetBytes(header.ToJsonString());
        var payloadBytes = Encoding.UTF8.GetBytes(payload.ToJsonString());

        var headerSegment = Base64UrlEncoder.Encode(headerBytes);
        var payloadSegment = Base64UrlEncoder.Encode(payloadBytes);
        var signingInput = headerSegment + "." + payloadSegment;
        var signature = Key.Sign(Encoding.ASCII.GetBytes(signingInput));
        var signatureSegment = Base64UrlEncoder.Encode(signature);

        return signingInput + "." + signatureSegment;
    }
}
