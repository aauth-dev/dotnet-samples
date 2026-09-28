using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Server;

namespace AAuth.Tokens;

/// <summary>
/// The verified agent context of a PS or AS token request: the signing agent's
/// token, an optional <c>subagent_token</c> (whose key the issued token is bound
/// to) and an optional <c>upstream_token</c> (call chaining), with the combined
/// lifetime ceiling.
/// </summary>
public sealed record AgentIssuanceContext
{
    /// <summary>The signing agent's identifier (the parent for a sub-agent request).</summary>
    public required string AgentId { get; init; }

    /// <summary>The key the issued token is bound to: the sub-agent's when present.</summary>
    public required IAAuthKey ConfirmationKey { get; init; }
    public required DateTimeOffset AgentTokenExpiresAt { get; init; }

    /// <summary>The earliest of the agent, sub-agent and upstream token expiries.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>The intermediary's agent-token <c>iss</c> when chaining; the upstream <c>aud</c> equals it.</summary>
    public required string AgentIssuer { get; init; }

    /// <summary><see langword="true"/> when a <c>subagent_token</c> binds the issued token.</summary>
    public bool SubAgent { get; init; }
    public UpstreamTokenValidationResult? Upstream { get; init; }
    public IReadOnlyList<TokenRegistration> SourceTokens { get; init; } = [];

    /// <summary>A downstream request under an upstream token carries its <c>mission_s256</c> unchanged.</summary>
    public void ValidateResourceContext(JsonObject resource)
    {
        if (Upstream is not null && MissionReference.Read(resource) != Upstream.MissionS256)
            throw new TokenVerificationException("Downstream resource request must retain the upstream mission.")
            { Credential = TokenCredential.Resource };
    }

    public static async Task<AgentIssuanceContext> VerifyAsync(
        string agentToken, string? subagentToken, string? upstreamToken, string personServer,
        TokenVerifier verifier, MetadataClient metadata, JwksClient jwks,
        Func<string, bool> isTrustedAuthTokenIssuer, CancellationToken cancellationToken = default,
        TokenCredential? agentTokenCredential = null)
    {
        async Task<TokenVerifier.VerifiedToken> VerifyAgentAsync(string token, TokenCredential credential)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(token)) throw new TokenVerificationException("Agent token is empty.");
                return await verifier.VerifyWithJwksAsync(token, metadata, jwks,
                    AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk, expectedAudience: null,
                    cancellationToken: cancellationToken);
            }
            catch (TokenVerificationException exception)
            { throw new TokenVerificationException(exception.Message, exception) { Credential = credential }; }
        }

        var parent = await VerifyAgentAsync(agentToken, TokenCredential.Agent);
        if (parent.Payload["parent_agent"] is not null)
            throw new TokenVerificationException("A sub-agent cannot request authorization directly.");
        var parentId = (string?)parent.Payload["sub"]
            ?? throw new TokenVerificationException("agent_token missing sub");
        var bound = parent;
        // Null when the agent token signed the request; TokenCredential.Agent at an AS, where it is a body parameter.
        var sources = new List<TokenRegistration> { TokenRegistration.FromVerified(parent, agentTokenCredential) };
        var ceiling = parent.ExpiresAt;
        UpstreamTokenValidationResult? upstreamContext = null;
        if (upstreamToken is not null)
        {
            // The upstream aud must equal the iss of the intermediary's agent token:
            // the intermediary is its own agent provider (§Intermediary Agent Identity).
            var upstream = await new UpstreamTokenValidator(metadata, jwks, verifier).ValidateAsync(
                upstreamToken, parent.Issuer, personServer, isTrustedAuthTokenIssuer, cancellationToken);
            if (!upstream.IsValid || upstream.ExpiresAt is not { } upstreamExpiry)
                throw new TokenVerificationException(upstream.FailureCode, upstream.Error ?? "Invalid upstream token.")
                { Credential = TokenCredential.Upstream };
            if (upstreamExpiry < ceiling) ceiling = upstreamExpiry;
            upstreamContext = upstream;
            sources.Add(TokenRegistration.FromVerified(upstream.Verified!, TokenCredential.Upstream));
        }
        if (subagentToken is not null)
        {
            bound = await VerifyAgentAsync(subagentToken, TokenCredential.Subagent);
            if (!string.Equals((string?)bound.Payload["parent_agent"], parentId, StringComparison.Ordinal)
                || !string.Equals(bound.Issuer, parent.Issuer, StringComparison.Ordinal))
                throw new TokenVerificationException("subagent_token must name the requesting parent and share its issuer.")
                { Credential = TokenCredential.Subagent };
            sources.Add(TokenRegistration.FromVerified(bound, TokenCredential.Subagent));
        }
        if (bound.ExpiresAt < ceiling) ceiling = bound.ExpiresAt;
        if (ceiling.ToUnixTimeSeconds() <= verifier.Clock().ToUnixTimeSeconds())
            throw new TokenVerificationException(AAuth.Errors.SignatureErrorCode.ExpiredJwt, "The verified authorization context has expired.");
        var confirmation = bound.Payload["cnf"]?["jwk"] as JsonObject
            ?? throw new TokenVerificationException("agent_token missing cnf.jwk");
        return new AgentIssuanceContext
        {
            AgentId = parentId,
            ConfirmationKey = KeyFactory.FromPublicJwk(confirmation),
            AgentTokenExpiresAt = bound.ExpiresAt,
            ExpiresAt = ceiling,
            AgentIssuer = parent.Issuer,
            SubAgent = subagentToken is not null,
            Upstream = upstreamContext,
            SourceTokens = sources,
        };
    }
}
