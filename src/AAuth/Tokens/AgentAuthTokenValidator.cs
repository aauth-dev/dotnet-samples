using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.HttpSig;

namespace AAuth.Tokens;

public static class AgentAuthTokenValidator
{
    public static void Validate(string authToken, string resourceToken, IAAuthKey signingKey,
        string agentToken, string? subagentToken = null, string? upstreamToken = null,
        AAuth.Discovery.AAuthEgressPolicy? policy = null)
    {
        var resource = Payload(resourceToken);
        var parent = Payload(agentToken);
        var bound = subagentToken is null ? parent : Payload(subagentToken);
        var expectedKey = subagentToken is null ? signingKey : SignatureKeyParser.Confirmation(bound);
        var expectedAgent = (string?)bound["sub"];
        JsonObject? expectedAct = null;
        if (upstreamToken is not null)
        {
            var upstream = Payload(upstreamToken);
            expectedAct = ActChainBuilder.BuildNestedAct((string?)upstream["agent"]
                ?? throw new TokenVerificationException("Upstream agent missing."), upstream["act"] as JsonObject, policy);
        }
        if (subagentToken is not null)
        {
            if ((string?)bound["parent_agent"] != (string?)parent["sub"])
                throw new TokenVerificationException("Child token does not name the requesting parent.");
            expectedAct = ActChainBuilder.BuildNestedAct((string?)parent["sub"]
                ?? throw new TokenVerificationException("Parent identity missing."), expectedAct, policy);
        }
        var auth = Payload(authToken);
        if (!AccountBinding.TryRead(resource, out var resourceAccount)
            || !AccountBinding.TryRead(auth, out var authAccount)
            || !AccountBinding.Matches(resourceAccount, authAccount))
            throw new TokenVerificationException("Auth token response account differs from the resource request.");
        if (!JsonNode.DeepEquals(auth["mission"], resource["mission"]))
            throw new TokenVerificationException("Auth token response mission differs from the verified request.");
        if ((string?)auth["iss"] != (string?)resource["aud"] || (string?)auth["aud"] != (string?)resource["iss"]
            || (string?)auth["agent"] != expectedAgent || (string?)resource["agent"] != expectedAgent
            || SignatureKeyParser.Confirmation(auth).ComputeJwkThumbprint() != expectedKey.ComputeJwkThumbprint()
            || (string?)resource["agent_jkt"] != expectedKey.ComputeJwkThumbprint()
            || !AuthTokenResponseValidator.ActChainsMatch(auth["act"] as JsonObject, expectedAct, policy)
            || (auth.ContainsKey("act") && auth["act"] is not JsonObject))
            throw new TokenVerificationException("Auth token response issuer, audience, agent, key or actor context mismatch.");
        var requested = new System.Collections.Generic.HashSet<string>(((string?)resource["scope"] ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries));
        foreach (var scope in ((string?)auth["scope"] ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries))
            if (!requested.Contains(scope)) throw new TokenVerificationException("Auth token response broadens requested scope.");
        if ((long?)auth["exp"] is not { } expiry || expiry <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            || expiry > (long?)parent["exp"] || expiry > (long?)bound["exp"]
            || (upstreamToken is not null && expiry > (long?)Payload(upstreamToken)["exp"]))
            throw new TokenVerificationException("Auth token response exceeds authorization lifetime.");
    }

    private static JsonObject Payload(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) throw new TokenVerificationException("Token must be a compact JWS.");
        return TokenVerifier.DecodeJsonSegment(parts[1], "payload");
    }
}