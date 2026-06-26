using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Headers;
using AAuth.R3.Model;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.R3;

/// <summary>Writes R3 auth-token challenges with resource tokens carrying R3 claims.</summary>
public sealed class R3Challenge
{
    public required string ResourceIssuer { get; init; }
    public required string Audience { get; init; }
    public required IAAuthKey Key { get; init; }
    public required string KeyId { get; init; }
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromMinutes(5);
    public Func<DateTimeOffset> Clock { get; init; } = () => DateTimeOffset.UtcNow;

    public string BuildResourceToken(
        string agent,
        string agentJkt,
        string r3Uri,
        string r3S256,
        string? scope = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(agent);
        ArgumentException.ThrowIfNullOrEmpty(agentJkt);
        R3AuthClaims.ResourceDocument(r3Uri, r3S256);

        if (Key is null)
        {
            throw new InvalidOperationException("Key must be set.");
        }
        if (!Key.HasPrivateKey)
        {
            throw new InvalidOperationException("Signing key must include a private component.");
        }
        if (Lifetime > TimeSpan.FromMinutes(5))
        {
            throw new InvalidOperationException("Resource token Lifetime must not exceed 5 minutes.");
        }

        var iat = Clock();
        var header = new JsonObject
        {
            ["alg"] = Key.Algorithm,
            ["typ"] = ResourceTokenBuilder.TokenType,
            ["kid"] = KeyId,
        };
        var payload = new JsonObject
        {
            ["iss"] = ResourceIssuer,
            ["dwk"] = ResourceTokenBuilder.ResourceDwk,
            ["aud"] = Audience,
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["agent"] = agent,
            ["agent_jkt"] = agentJkt,
            ["iat"] = iat.ToUnixTimeSeconds(),
            ["exp"] = iat.Add(Lifetime).ToUnixTimeSeconds(),
            [R3AuthClaims.UriClaim] = r3Uri,
            [R3AuthClaims.S256Claim] = r3S256,
        };
        if (!string.IsNullOrWhiteSpace(scope))
        {
            payload["scope"] = scope;
        }
        return SignCompact(header, payload, Key);
    }

    public IResult Challenge(HttpContext context, string agent, string agentJkt, string r3Uri, string r3S256, string? scope = null)
    {
        var token = BuildResourceToken(agent, agentJkt, r3Uri, r3S256, scope);
        context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatAuthToken(token);
        return Results.Json(new { error = "auth_token_required" }, statusCode: StatusCodes.Status401Unauthorized);
    }

    internal static string SignCompact(JsonObject header, JsonObject payload, IAAuthKey key)
    {
        var headerBytes = Encoding.UTF8.GetBytes(header.ToJsonString());
        var payloadBytes = Encoding.UTF8.GetBytes(payload.ToJsonString());
        var signingInput = Base64UrlEncoder.Encode(headerBytes) + "." + Base64UrlEncoder.Encode(payloadBytes);
        var signature = key.Sign(Encoding.ASCII.GetBytes(signingInput));
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }

}
