using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Server;

namespace AAuth.Tokens;

public sealed record AgentIssuanceContext
{
    public required string AgentId { get; init; }
    public required IAAuthKey ConfirmationKey { get; init; }
    public required DateTimeOffset AgentTokenExpiresAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public JsonObject? Act { get; init; }
    public UpstreamTokenValidationResult? Upstream { get; init; }
    public IReadOnlyList<TokenRegistration> SourceTokens { get; init; } = [];

    public void ValidateResourceContext(JsonObject resource, string? governingPersonServer = null)
    {
        if (Upstream is null) return;
        if (governingPersonServer is not null && Upstream.IssuerDwk == AuthTokenBuilder.AccessDwk && Upstream.Mission is null)
            throw new TokenVerificationException("AS-issued upstream authorization requires a mission for PS call chaining.");
        if (Upstream.Mission is not { } upstreamMission) return;
        var mission = resource["mission"] as JsonObject;
        if ((governingPersonServer is not null && upstreamMission.Approver != governingPersonServer)
            || (string?)mission?["approver"] != upstreamMission.Approver
            || (string?)mission?["s256"] != upstreamMission.S256)
            throw new TokenVerificationException("Downstream resource request must retain the upstream mission and governing PS.");
    }

    public static async Task<AgentIssuanceContext> VerifyAsync(
        string agentToken, string? subagentToken, string? upstreamToken,
        TokenVerifier verifier, MetadataClient metadata, JwksClient jwks,
        Func<string, bool> isTrustedUpstreamIssuer, CancellationToken cancellationToken = default)
    {
        async Task<TokenVerifier.VerifiedToken> VerifyAgentAsync(string token, TokenCredential credential)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(token)) throw new TokenVerificationException("Agent token is empty.");
                var verified = await verifier.VerifyWithJwksAsync(token, metadata, jwks,
                    AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk, expectedAudience: null,
                    cancellationToken: cancellationToken);
                if (verified.ExpiresAt.ToUnixTimeSeconds() <= verifier.Clock().ToUnixTimeSeconds())
                    throw new TokenVerificationException(AAuth.Errors.SignatureErrorCode.ExpiredJwt, "Agent token has expired.");
                return verified;
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
        var sources = new List<TokenRegistration> { TokenRegistration.FromVerified(parent) };
        var ceiling = parent.ExpiresAt;
        JsonObject? act = null;
        UpstreamTokenValidationResult? upstreamContext = null;
        if (upstreamToken is not null)
        {
            if (string.IsNullOrWhiteSpace(upstreamToken))
                throw new TokenVerificationException("Upstream token is empty.") { Credential = TokenCredential.Upstream };
            var upstream = await new UpstreamTokenValidator(metadata, jwks, verifier).ValidateAsync(
                upstreamToken, parent.Issuer, isTrustedUpstreamIssuer, cancellationToken);
            if (!upstream.IsValid || upstream.ExpiresAt is not { } upstreamExpiry)
                throw new TokenVerificationException(upstream.FailureCode, upstream.Error ?? "Invalid upstream token.")
                { Credential = TokenCredential.Upstream };
            if (upstreamExpiry.ToUnixTimeSeconds() <= verifier.Clock().ToUnixTimeSeconds())
                throw new TokenVerificationException(AAuth.Errors.SignatureErrorCode.ExpiredJwt, "Upstream token has expired.")
                { Credential = TokenCredential.Upstream };
            if (upstreamExpiry < ceiling) ceiling = upstreamExpiry;
            upstreamContext = upstream;
            sources.Add(TokenRegistration.FromVerified(upstream.Verified!));
            act = ActChainBuilder.BuildNestedAct(upstream.Agent!, upstream.UpstreamAct, verifier.EgressPolicy);
        }
        if (subagentToken is not null)
        {
            bound = await VerifyAgentAsync(subagentToken, TokenCredential.Subagent);
            if (!string.Equals((string?)bound.Payload["parent_agent"], parentId, StringComparison.Ordinal))
                throw new TokenVerificationException("subagent_token.parent_agent does not name the requesting parent.")
                { Credential = TokenCredential.Subagent };
            sources.Add(TokenRegistration.FromVerified(bound));
            act = ActChainBuilder.BuildNestedAct(parentId, act, verifier.EgressPolicy);
        }
        if (bound.ExpiresAt < ceiling) ceiling = bound.ExpiresAt;
        if (ceiling.ToUnixTimeSeconds() <= verifier.Clock().ToUnixTimeSeconds())
            throw new TokenVerificationException(AAuth.Errors.SignatureErrorCode.ExpiredJwt, "The verified authorization context has expired.");
        var confirmation = bound.Payload["cnf"]?["jwk"] as JsonObject
            ?? throw new TokenVerificationException("agent_token missing cnf.jwk");
        return new AgentIssuanceContext
        {
            AgentId = (string?)bound.Payload["sub"] ?? throw new TokenVerificationException("agent_token missing sub"),
            ConfirmationKey = KeyFactory.FromJwk(confirmation),
            AgentTokenExpiresAt = bound.ExpiresAt,
            ExpiresAt = ceiling,
            Act = act,
            Upstream = upstreamContext,
            SourceTokens = sources,
        };
    }
}