using System;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server.Challenge;

/// <summary>
/// ASP.NET Core middleware that automatically issues 401 challenges with
/// <c>aa-resource+jwt</c> resource tokens when the resource requires an auth
/// token but only an agent token is presented.
/// </summary>
/// <remarks>
/// Must run AFTER <see cref="AAuthVerificationMiddleware"/> so that parsed token info is
/// available in <c>HttpContext.Items</c>.
/// <list type="bullet">
/// <item>If <see cref="ChallengeOptions.AccessMode"/> is <see cref="AAuthAccessMode.IdentityOnly"/>,
///   passes through regardless of token type.</item>
/// <item>If <see cref="ChallengeOptions.AccessMode"/> is <see cref="AAuthAccessMode.RequireAuthToken"/>
///   and the token is <c>aa-agent+jwt</c>, mints a resource token and returns 401 with
///   <c>AAuth-Requirement: requirement=auth-token; resource-token="…"</c>.</item>
/// <item>If <see cref="ChallengeOptions.AccessMode"/> is <see cref="AAuthAccessMode.AgentTokenRequired"/>,
///   passes through when an AAuth agent or auth token is present, otherwise returns 401 with
///   a bare <c>AAuth-Requirement: requirement=agent-token</c> (§Agent Token Required).</item>
/// <item>If the token is <c>aa-auth+jwt</c> (or non-JWT schemes in identity-only mode),
///   passes through to the next middleware.</item>
/// </list>
/// </remarks>
public sealed class AAuthChallengeMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ChallengeOptions _options;

    /// <summary>Create the challenge middleware.</summary>
    public AAuthChallengeMiddleware(RequestDelegate next, ChallengeOptions options)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(options);
        _next = next;
        _options = options;
    }

    /// <inheritdoc cref="RequestDelegate"/>
    public async Task InvokeAsync(HttpContext context)
    {
        // Identity-only and resource-managed modes always pass through: in both
        // the resource decides access itself, with no PS/AS resource-token
        // challenge. Resource-managed endpoints drive their own
        // 202-interaction / AAuth-Access flow (§Resource-Managed Authorization).
        if (_options.AccessMode is AAuthAccessMode.IdentityOnly or AAuthAccessMode.ResourceManaged)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Read the verification result from the upstream verification middleware.
        VerificationResult? result = null;
        if (context.Items.TryGetValue(AAuthVerificationMiddleware.ContextItemKey, out var obj))
        {
            result = obj as VerificationResult;
        }

        // Also read the parsed info for scheme/token type if needed.
        SignatureKeyParser.ParsedSignatureKeyInfo? parsedInfo = null;
        if (context.Items.TryGetValue(AAuthVerificationMiddleware.ParsedInfoItemKey, out var parsedObj))
        {
            parsedInfo = parsedObj as SignatureKeyParser.ParsedSignatureKeyInfo;
        }

        // Determine the scheme and token type.
        var scheme = result?.Scheme ?? parsedInfo?.Scheme;
        var tokenType = AAuthTokenTypeExtensions.ParseTokenType(
            result?.TokenType ?? (string?)parsedInfo?.Header?["typ"]);

        // Scheme filtering.
        if (scheme is not null && _options.AllowedSignatureKeySchemes is { } allowed && !allowed.Contains(scheme))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers[AAuthConstants.Headers.AAuthError] = $"Scheme '{scheme}' is not allowed by this resource.";
            return;
        }

        // §Agent Token Required: this resource specifically wants an AAuth agent
        // token, distinct from any other URI-identified key. Pass through when an
        // AAuth token (agent or auth) is present — identity is established;
        // otherwise challenge with a bare requirement=agent-token (no PS/AS, no
        // resource token — the agent need only present the token it already holds).
        if (_options.AccessMode == AAuthAccessMode.AgentTokenRequired)
        {
            if (tokenType is AAuthTokenType.AgentToken or AAuthTokenType.AuthToken)
            {
                await _next(context).ConfigureAwait(false);
                return;
            }

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers[AAuthRequirementHeader.Name] =
                AAuthRequirementHeader.FormatAgentToken();
            return;
        }

        // Non-JWT schemes (hwk, jwks_uri) pass through — they have no token upgrade path.
        if (scheme is AAuthConstants.Schemes.Hwk or AAuthConstants.Schemes.JwksUri)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Auth token already present → pass through.
        if (tokenType == AAuthTokenType.AuthToken)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Agent token → challenge.
        if (tokenType == AAuthTokenType.AgentToken)
        {
            await IssueChallenge(context, result, parsedInfo).ConfigureAwait(false);
            return;
        }

        // Unknown token type — pass through (let downstream handle).
        await _next(context).ConfigureAwait(false);
    }

    private Task IssueChallenge(
        HttpContext context,
        VerificationResult? result,
        SignatureKeyParser.ParsedSignatureKeyInfo? parsedInfo)
    {
        // Resolve agent ID and agent_jkt from verification result or parsed info.
        var agent = result?.Agent
            ?? (string?)parsedInfo?.Payload?["sub"]
            ?? (string?)parsedInfo?.Payload?["agent"]
            ?? "unknown";

        var agentJkt = parsedInfo?.ConfirmationKey?.ComputeJwkThumbprint()
            ?? result?.Subject  // fallback, though not ideal
            ?? throw new InvalidOperationException(
                "Cannot issue challenge: unable to determine agent key thumbprint.");

        // Resolve audience:
        // 1. Explicit PersonServerAudience (covers four-party where resource has own AS).
        // 2. Agent token's `ps` claim (three-party standard path).
        // 3. If neither → cannot challenge (resource must handle auth itself).
        var audience = _options.PersonServerAudience;
        if (string.IsNullOrEmpty(audience))
        {
            audience = (string?)parsedInfo?.Payload?["ps"];
        }

        if (string.IsNullOrEmpty(audience))
        {
            // No PS available and no explicit audience configured.
            // Return 401 without resource token — the resource cannot issue a valid challenge.
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers[AAuthConstants.Headers.AAuthError] =
                "Auth token required but no Person Server audience could be resolved.";
            return Task.CompletedTask;
        }

        // Validate that required options are present for challenge issuance.
        if (_options.ResourceSigningKey is null || !_options.ResourceSigningKey.HasPrivateKey)
        {
            throw new InvalidOperationException(
                "ChallengeOptions.ResourceSigningKey must be set with a private key for RequireAuthToken mode.");
        }
        if (string.IsNullOrEmpty(_options.ResourceKeyId))
        {
            throw new InvalidOperationException(
                "ChallengeOptions.ResourceKeyId must be set for RequireAuthToken mode.");
        }
        if (string.IsNullOrEmpty(_options.ResourceIdentifier))
        {
            throw new InvalidOperationException(
                "ChallengeOptions.ResourceIdentifier must be set for RequireAuthToken mode.");
        }

        // §Terminology / §Mission Request Header: a mission-aware resource copies
        // the mission object from a valid AAuth-Mission header (verified as a
        // signed component upstream) into the resource token it issues, so the
        // mission context (approver + s256) reaches the PS.
        MissionClaim? mission = null;
        if (_options.MissionAware
            && AAuthMissionHeader.TryParseStructured(
                context.Request.Headers[AAuthMissionHeader.Name],
                out var missionApprover, out var missionS256))
        {
            mission = new MissionClaim(missionApprover!, missionS256!);
        }

        var resourceToken = new ResourceTokenBuilder
        {
            Issuer = _options.ResourceIdentifier,
            Audience = audience,
            Agent = agent,
            AgentJkt = agentJkt,
            Key = _options.ResourceSigningKey,
            KeyId = _options.ResourceKeyId,
            Scope = _options.DefaultScopes,
            Mission = mission,
        }.Build();

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers[AAuthRequirementHeader.Name] =
            AAuthRequirementHeader.FormatAuthToken(resourceToken);
        return Task.CompletedTask;
    }
}
