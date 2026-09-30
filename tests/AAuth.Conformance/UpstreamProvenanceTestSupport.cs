using AAuth.Person;
using AAuth.Server;
using AAuth.Tokens;

namespace AAuth.Conformance;

internal static class UpstreamProvenanceTestSupport
{
    private static readonly DateTimeOffset BindingExpiresAt = new(9000, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static async Task RecordAsync(IJtiStore inventory, string token, string personServer, string? callerAgentId = null)
    {
        var header = TokenVerifier.DecodeJsonSegment(token.Split('.')[0], "header");
        var payload = TokenVerifier.DecodeJsonSegment(token.Split('.')[1], "payload");
        var tokenKey = new TokenKey(payload["iss"]!.GetValue<string>(), payload["jti"]!.GetValue<string>());
        var expires = DateTimeOffset.FromUnixTimeSeconds(payload["exp"]!.GetValue<long>());
        var audience = payload["aud"]!.GetValue<string>();
        var subject = payload["sub"]!.GetValue<string>();
        var agentIssuer = audience;
        var agentId = callerAgentId ?? "aauth:caller@origin.test";
        var callerToken = new TokenKey(agentIssuer, "caller-agent " + agentId);
        var binding = AgentPersonBinding.Key(personServer, agentIssuer, agentId);
        await inventory.RegisterAsync(callerToken, BindingExpiresAt);
        await inventory.RegisterAsync(binding, BindingExpiresAt);
        var caller = new UpstreamCallerRecord(agentIssuer, agentId, callerToken, binding);
        await inventory.RegisterGrantAsync([callerToken, binding], new TokenGrant(tokenKey, audience, expires)
        {
            Provenance = new AAuthTokenProvenance(
                header["typ"]?.GetValue<string>() ?? AAuthConstants.TokenTypes.AuthToken,
                audience, subject, personServer, caller)
            {
                PresentedToken = tokenKey.Issuer == personServer ? null : new TokenKey(personServer, "presented " + tokenKey.TokenId),
            },
        });
    }
}
