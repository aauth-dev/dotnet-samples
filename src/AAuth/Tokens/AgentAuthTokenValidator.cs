using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.HttpSig;

namespace AAuth.Tokens;

/// <summary>
/// The agent's check of an auth token returned by its PS (§Auth Token Response
/// Verification): issued by the resource token's <c>aud</c>, for the resource,
/// bound to the agent's (or sub-agent's) key, naming the person the presented
/// token named, and never outliving the agent, presented or upstream token.
/// </summary>
public static class AgentAuthTokenValidator
{
    public static void Validate(string authToken, string resourceToken, IAAuthKey signingKey,
        string agentToken, string presentedToken, string? subagentToken = null, string? upstreamToken = null,
        string? expectedDwk = null)
    {
        var resource = Payload(resourceToken);
        var presented = Payload(presentedToken);
        var parent = Payload(agentToken);
        var bound = subagentToken is null ? parent : Payload(subagentToken);
        var expectedKey = subagentToken is null ? signingKey : SignatureKeyParser.Confirmation(bound);
        if (subagentToken is not null && (string?)bound["parent_agent"] != (string?)parent["sub"])
            throw new TokenVerificationException("Child token does not name the requesting parent.");
        var authSegments = authToken.Split('.');
        if (authSegments.Length != 3) throw new TokenVerificationException("Auth token must be a compact JWS.");
        var authHeader = TokenVerifier.DecodeJsonSegment(authSegments[0], "header");
        if ((string?)authHeader["typ"] != AuthTokenBuilder.TokenType)
            throw new TokenVerificationException("Auth token response has an unexpected 'typ'.");
        var auth = Payload(authToken);
        var authDwk = (string?)auth["dwk"];
        if (expectedDwk is not null && authDwk != expectedDwk)
            throw new TokenVerificationException("Auth token response has an unexpected 'dwk'.");
        if (expectedDwk is null && authDwk is not (AuthTokenBuilder.PersonDwk or AuthTokenBuilder.AccessDwk))
            throw new TokenVerificationException("Auth token response has an unexpected 'dwk'.");
        if (!AccountBinding.TryRead(resource, out var resourceAccount)
            || !AccountBinding.TryRead(auth, out var authAccount)
            || !AccountBinding.Matches(resourceAccount, authAccount))
            throw new TokenVerificationException("Auth token response account differs from the resource request.");
        if ((string?)auth[MissionReference.ClaimName] != (string?)resource[MissionReference.ClaimName])
            throw new TokenVerificationException("Auth token response mission differs from the verified request.");
        if ((string?)auth["iss"] != (string?)resource["aud"] || (string?)auth["aud"] != (string?)resource["iss"]
            || (string?)auth["sub"] != (string?)presented["sub"] || (string?)auth["ps"] != (string?)resource["ps"]
            || SignatureKeyParser.Confirmation(auth).ComputeJwkThumbprint() != expectedKey.ComputeJwkThumbprint()
            || (string?)resource["agent_jkt"] != expectedKey.ComputeJwkThumbprint())
            throw new TokenVerificationException("Auth token response issuer, audience, person or key mismatch.");
        var requested = new System.Collections.Generic.HashSet<string>(((string?)resource["scope"] ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries));
        foreach (var scope in ((string?)auth["scope"] ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries))
            if (!requested.Contains(scope)) throw new TokenVerificationException("Auth token response broadens requested scope.");
        if ((long?)auth["exp"] is not { } expiry || expiry <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            || expiry > (long?)parent["exp"] || expiry > (long?)bound["exp"] || expiry > (long?)presented["exp"]
            || (upstreamToken is not null && expiry > (long?)Payload(upstreamToken)["exp"]))
            throw new TokenVerificationException("Auth token response exceeds authorization lifetime.");
    }

    internal static JsonObject Payload(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) throw new TokenVerificationException("Token must be a compact JWS.");
        return TokenVerifier.DecodeJsonSegment(parts[1], "payload");
    }
}
