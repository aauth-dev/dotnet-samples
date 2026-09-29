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
    public AAuth.Discovery.AAuthEgressPolicy EgressPolicy { get; init; } = AAuth.Discovery.AAuthEgressPolicy.Production;
    public required string ResourceIssuer { get; init; }
    public required string Audience { get; init; }
    public required IAAuthKey Key { get; init; }
    public required string KeyId { get; init; }
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromMinutes(5);
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>
    /// Build an R3 resource token naming <paramref name="presented"/> — the verified
    /// person or auth token the request carried — bound to <paramref name="agentJkt"/>,
    /// the thumbprint of the key that signed the request (§Resource Token Structure).
    /// </summary>
    public string BuildResourceToken(
        TokenVerifier.VerifiedToken presented,
        string agentJkt,
        string r3Uri,
        string r3S256,
        string? scope = null,
        string? account = null)
    {
        ArgumentNullException.ThrowIfNull(presented);
        AccountBinding.Validate(account);
        ArgumentException.ThrowIfNullOrEmpty(agentJkt);
        EgressPolicy.ValidateIdentifier(ResourceIssuer);
        EgressPolicy.ValidateIdentifier(Audience);
        R3AuthClaims.ResourceDocument(r3Uri, r3S256);
        var personServer = presented.TokenType switch
        {
            PersonTokenBuilder.TokenType => presented.Issuer,
            AuthTokenBuilder.TokenType => (string?)presented.Payload["ps"]
                ?? throw new InvalidOperationException("Presented auth token is missing 'ps'."),
            _ => throw new InvalidOperationException("A resource token must name a presented person token or auth token."),
        };
        var subject = presented.Subject
            ?? throw new InvalidOperationException("Presented token is missing 'sub'.");

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

        var iat = TimeProvider.GetUtcNow();
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
            ["ps"] = personServer,
            ["sub"] = subject,
            ["presented_jti"] = presented.Jti,
            ["agent_jkt"] = agentJkt,
            ["iat"] = iat.ToUnixTimeSeconds(),
            ["exp"] = iat.Add(Lifetime).ToUnixTimeSeconds(),
            [R3AuthClaims.UriClaim] = r3Uri,
            [R3AuthClaims.S256Claim] = r3S256,
        };
        if (presented.MissionS256 is { } mission) payload[MissionReference.ClaimName] = mission;
        if (presented.Tenant is { } tenant) payload["tenant"] = tenant;
        if (!string.IsNullOrWhiteSpace(scope))
        {
            payload["scope"] = scope;
        }
        if (account is not null) payload["account"] = account;
        return SignCompact(header, payload, Key);
    }

    /// <summary>Build an R3 resource token for a presented auth token, bound to its <c>cnf</c> key and account.</summary>
    public string BuildResourceToken(
        TokenVerifier.VerifiedToken verifiedAuthToken,
        string r3Uri,
        string r3S256,
        string? scope = null)
    {
        ArgumentNullException.ThrowIfNull(verifiedAuthToken);
        var cnf = verifiedAuthToken.Payload["cnf"]?["jwk"] as JsonObject
            ?? throw new InvalidOperationException("auth token missing cnf.jwk");
        var agentJkt = KeyFactory.FromJwk(cnf).ComputeJwkThumbprint();
        return BuildResourceToken(verifiedAuthToken, agentJkt, r3Uri, r3S256, scope, verifiedAuthToken.Account);
    }

    /// <summary>
    /// Challenge the current request: an agent token gets <c>requirement=person-token</c>;
    /// a person or auth token gets <c>requirement=auth-token</c> with an R3 resource token
    /// naming it (§Resource Access Modes).
    /// </summary>
    public IResult Challenge(HttpContext context, string r3Uri, string r3S256, string? scope = null, string? account = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        var presented = AAuth.Server.Verification.AAuthHttpContextExtensions.GetAAuthVerifiedAssertion(context)
            ?? throw new InvalidOperationException("R3 challenges require verified AAuth request context.");
        if (presented.Token.TokenType == AgentTokenBuilder.TokenType)
        {
            context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatPersonToken();
            return AAuth.Server.AAuthProblemDetails.Create("person_token_required", statusCode: StatusCodes.Status401Unauthorized);
        }
        var token = BuildResourceToken(presented.Token, presented.HttpSigningKey.ComputeJwkThumbprint(), r3Uri, r3S256, scope, account);
        context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatAuthToken(token);
        return AAuth.Server.AAuthProblemDetails.Create("auth_token_required", statusCode: StatusCodes.Status401Unauthorized);
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
