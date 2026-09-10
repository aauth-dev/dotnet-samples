using AAuth.Crypto;
using AAuth.Tokens;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Testing;

public static class TestTokens
{
    public static readonly string Resource = BuildResource();
    public static readonly string UpdatedResource = BuildResource();

    public static IEnumerable<object[]> InvalidCredentials =>
        from credentialField in new[] { "agent_token", "resource_token", "subagent_token", "upstream_token" }
        from variant in new[] { "object", "array", "number", "boolean", "empty", "blank", "base64",
            "missing-claim", "signature-base64", "signature-length", "signature", "expired", "recently-expired", "duplicate-header", "duplicate-payload" }
        where credentialField != "resource_token" || variant != "recently-expired"
        select new object[] { credentialField, variant, CredentialError(credentialField, variant) };

    public static string CredentialError(string field, string variant) => variant switch
    {
        "object" or "array" or "number" or "boolean" => "invalid_request",
        _ when field == "upstream_token" => "invalid_upstream_token",
        _ => (variant is "expired" or "recently-expired" ? "expired_" : "invalid_")
            + (field == "resource_token" ? "resource_token" : "agent_token"),
    };

    public static JsonNode MalformedCredential(string jwt, IAAuthKey key, string variant)
    {
        switch (variant)
        {
            case "object": return new JsonObject();
            case "array": return new JsonArray();
            case "number": return JsonValue.Create(123)!;
            case "boolean": return JsonValue.Create(false)!;
            case "empty": return JsonValue.Create("")!;
            case "blank": return JsonValue.Create(" ")!;
            case "base64": return JsonValue.Create("x.%.x")!;
        }
        var segments = jwt.Split('.');
        var header = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(segments[0]))!.AsObject();
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(segments[1]))!.AsObject();
        if (variant == "missing-claim") payload.Remove("iat");
        if (variant is "expired" or "recently-expired")
        {
            payload["iat"] = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds();
            payload["exp"] = DateTimeOffset.UtcNow.AddSeconds(variant == "expired" ? -120 : -1).ToUnixTimeSeconds();
        }
        var headerJson = header.ToJsonString();
        var payloadJson = payload.ToJsonString();
        if (variant == "duplicate-header") headerJson = headerJson[..^1] + ",\"alg\":\"" + key.Algorithm + "\"}";
        if (variant == "duplicate-payload") payloadJson = payloadJson[..^1] + ",\"iss\":" + payload["iss"]!.ToJsonString() + "}";
        var input = Base64UrlEncoder.Encode(headerJson) + "." + Base64UrlEncoder.Encode(payloadJson);
        var signature = key.Sign(Encoding.ASCII.GetBytes(input));
        if (variant == "signature") signature[0] ^= 1;
        if (variant == "signature-length") signature = signature[..1];
        return JsonValue.Create(input + "." + (variant == "signature-base64" ? "%" : Base64UrlEncoder.Encode(signature)))!;
    }

    public static IEnumerable<object[]> InvalidRequiredClaims =>
        new[] { AgentTokenBuilder.TokenType, ResourceTokenBuilder.TokenType, AuthTokenBuilder.TokenType }
        .SelectMany(type => new[] { "header.alg", "header.typ", "header.kid", "iss", "dwk", "jti", "iat", "exp" }
            .Concat(type == AgentTokenBuilder.TokenType ? ["sub", "cnf"]
                : type == ResourceTokenBuilder.TokenType ? ["aud", "agent", "agent_jkt", "scope"] : ["aud", "agent", "cnf"])
            .SelectMany(claim => new[] { "absent", "null", "blank", "number", "array", "boolean" }
                .Where(mutation => mutation != "number" || claim is not ("iat" or "exp"))
                .Where(mutation => mutation != "blank" || claim != "scope")
                .Select(mutation => new object[] { type, claim, mutation })));

    public static string Raw(IAAuthKey key, string type, Action<JsonObject, JsonObject>? mutate = null)
    {
        var header = new JsonObject { ["alg"] = key.Algorithm, ["typ"] = type, ["kid"] = "issuer" };
        var payload = new JsonObject
        {
            ["iss"] = "https://issuer.example", ["dwk"] = type == AgentTokenBuilder.TokenType ? AgentTokenBuilder.AgentDwk
                : type == ResourceTokenBuilder.TokenType ? ResourceTokenBuilder.ResourceDwk : AuthTokenBuilder.PersonDwk,
            ["jti"] = "token-id", ["iat"] = 1800000000L, ["exp"] = 1800000300L,
        };
        if (type == AgentTokenBuilder.TokenType) payload["sub"] = "aauth:wire@issuer.example";
        else
        {
            payload["aud"] = "https://resource.example";
            payload["agent"] = "aauth:wire@issuer.example";
            payload["scope"] = "read";
        }
        if (type == ResourceTokenBuilder.TokenType) payload["agent_jkt"] = key.ComputeJwkThumbprint();
        else payload["cnf"] = new JsonObject { ["jwk"] = key.ToPublicJwk() };
        mutate?.Invoke(header, payload);
        var input = Base64UrlEncoder.Encode(header.ToJsonString()) + "." + Base64UrlEncoder.Encode(payload.ToJsonString());
        return input + "." + Base64UrlEncoder.Encode(key.Sign(Encoding.ASCII.GetBytes(input)));
    }

    public static void Mutate(JsonObject header, JsonObject payload, string claim, string mutation)
    {
        var target = claim.StartsWith("header.", StringComparison.Ordinal) ? header : payload;
        var name = claim.StartsWith("header.", StringComparison.Ordinal) ? claim[7..] : claim;
        if (mutation == "absent") target.Remove(name);
        else target[name] = mutation switch
        {
            "null" => null, "blank" => JsonValue.Create(""), "number" => JsonValue.Create(123),
            "boolean" => JsonValue.Create(false), _ => new JsonArray(),
        };
    }

    private static string BuildResource() => new ResourceTokenBuilder
    {
        Issuer = "https://resource.test", Audience = "https://ps.test",
        Agent = "aauth:demo@ap.test", AgentJkt = "fixture-key",
        Key = AAuthKey.Generate(), KeyId = "resource-1",
    }.Build();
}