using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Server.Governance;

/// <summary>Mission approval helpers for PS hosts that map their own mission endpoint.</summary>
public static class MissionPersonTokenExtensions
{
    /// <summary>
    /// Issue the approval's <c>person_tokens</c> (§Mission Approval) for the verified agent token that
    /// signed this request, using the registered <see cref="IMissionPersonTokenIssuer"/>. Returns
    /// <see langword="null"/> when there is nothing to issue: no resources, no issuer, or a signer that is
    /// not a verified top-level agent. Pass the result to <see cref="MissionApprovalBuilder.Response"/>.
    /// </summary>
    public static async Task<IReadOnlyDictionary<string, string>?> IssueMissionPersonTokensAsync(this HttpContext context,
        string personServer, string missionS256, IReadOnlyList<string> resources, DateTimeOffset? expiresAt = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(resources);
        if (resources.Count == 0 || context.RequestServices.GetService<IMissionPersonTokenIssuer>() is not { } issuer
            || context.GetAAuthVerification() is not { TokenType: AAuthTokenType.AgentToken, IssuerVerified: true, Agent: { } agent }
            || context.GetAAuthParsedKey()?.Payload is not { } payload
            // A sub-agent obtains person tokens only through its parent (§Sub-Agents).
            || payload["parent_agent"] is not null
            || payload["cnf"]?["jwk"] is not JsonObject jwk)
            return null;
        TokenRegistration registration;
        try { registration = TokenRegistration.FromPayload(payload); }
        catch (Tokens.TokenVerificationException) { return null; }
        return await issuer.IssueAsync(new MissionPersonTokenRequest
        {
            PersonServer = personServer,
            AgentId = agent,
            ConfirmationKey = Crypto.KeyFactory.FromPublicJwk(jwk),
            AgentTokenExpiresAt = registration.ExpiresAt,
            SourceTokens = [registration],
            MissionS256 = missionS256,
            MissionExpiresAt = expiresAt,
            Resources = resources,
        }, context.RequestAborted).ConfigureAwait(false);
    }
}
