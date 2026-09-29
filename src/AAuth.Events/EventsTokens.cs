using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Identifiers;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Events;

public static class EventsTokens
{
    public const string SubscribeType = "aa-subscribe+jwt";
    public const string EventType = "aa-event+jwt";
    public const string AgentDwk = "aauth-agent.json";
    public const string ResourceDwk = "aauth-resource.json";

    public static string Create(IAAuthKey key, string keyId, JsonObject payload, bool subscribe,
        TokenVerifier? verifier = null)
    {
        var header = new JsonObject { ["alg"] = key.Algorithm, ["kid"] = keyId,
            ["typ"] = subscribe ? SubscribeType : EventType };
        var input = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString())) + "."
            + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var jwt = input + "." + Base64UrlEncoder.Encode(key.Sign(Encoding.ASCII.GetBytes(input)));
        Verify(jwt, key, subscribe, verifier ?? new TokenVerifier());
        return jwt;
    }

    public static TokenVerifier.VerifiedToken Verify(string jwt, IAAuthKey issuerKey, bool subscribe,
        TokenVerifier verifier, string? audience = null)
    {
        var token = verifier.Verify(jwt, issuerKey, subscribe ? SubscribeType : EventType,
            subscribe ? AgentDwk : ResourceDwk);
        var payload = token.Payload;
        RequireText(token.Header, "kid");
        RequireText(payload, "eid");
        var actualAudience = RequireText(payload, "aud");
        if (audience is not null && actualAudience != audience)
            throw new TokenVerificationException("Event audience mismatch.");
        var now = verifier.TimeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (payload["iat"] is not JsonValue issued || !issued.TryGetValue<long>(out var iat) || iat > now
            || token.ExpiresAt.ToUnixTimeSeconds() <= now || token.ExpiresAt.ToUnixTimeSeconds() <= iat)
            throw new TokenVerificationException("Events require a current iat and a future exp.");
        if (subscribe)
        {
            if (!AgentId.TryParse(RequireText(payload, "sub"), out var agent, out _, verifier.EgressPolicy)
                || !verifier.EgressPolicy.IsValidIdentifier(actualAudience))
                throw new TokenVerificationException("Invalid subscribe identity or resource audience.");
            if (!verifier.EgressPolicy.IsValidIdentifier(token.Issuer)
                || (token.Issuer != "https://" + agent.Domain
                    && !(new Uri(token.Issuer).IsLoopback && new Uri(token.Issuer).IdnHost == agent.Domain)))
                throw new TokenVerificationException("Subscribe issuer does not own the agent domain.");
            if (payload["cnf"] is not JsonObject confirmation || confirmation["jwk"] is not JsonObject)
                throw new TokenVerificationException("Subscribe token requires cnf.jwk.");
            try { KeyFactory.FromPublicJwk(confirmation["jwk"]!.AsObject()); }
            catch (JwkValidationException exception)
            { throw new TokenVerificationException(exception.Code, exception.Message, exception); }
            if (payload.ContainsKey("max_uses") && (payload["max_uses"] is not JsonValue maximum
                || !maximum.TryGetValue<long>(out var uses) || uses <= 0))
                throw new TokenVerificationException("max_uses must be a positive integer when present.");
        }
        else if (payload.ContainsKey("cnf") || !AgentId.TryParse(actualAudience, out _, out _, verifier.EgressPolicy))
            throw new TokenVerificationException("Event tokens forbid cnf and require an agent audience.");
        else RequireText(payload, "jti");
        return token;
    }

    public static string RequireText(JsonObject value, string name) =>
        value[name] is JsonValue member && member.TryGetValue<string>(out var text)
            && !string.IsNullOrWhiteSpace(text) ? text
            : throw new TokenVerificationException($"Events require a non-empty {name}.");
}