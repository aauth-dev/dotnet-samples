using System;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

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
        // If identity-only mode, always pass through.
        if (_options.AccessMode == AAuthAccessMode.IdentityOnly)
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
        var tokenType = result?.TokenType ?? (string?)parsedInfo?.Header?["typ"];

        // Scheme filtering.
        if (scheme is not null && _options.AllowedSignatureKeySchemes is { } allowed && !allowed.Contains(scheme))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers["AAuth-Error"] = $"Scheme '{scheme}' is not allowed by this resource.";
            return;
        }

        // Non-JWT schemes (hwk, jwks_uri) pass through — they have no token upgrade path.
        if (scheme is "hwk" or "jwks_uri")
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Auth token already present → pass through.
        if (tokenType == AuthTokenBuilder.TokenType)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Agent token → challenge.
        if (tokenType == AgentTokenBuilder.TokenType)
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
            context.Response.Headers["AAuth-Error"] =
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

        var resourceToken = new ResourceTokenBuilder
        {
            Issuer = _options.ResourceIdentifier,
            Audience = audience,
            Agent = agent,
            AgentJkt = agentJkt,
            Key = _options.ResourceSigningKey,
            KeyId = _options.ResourceKeyId,
            Scope = _options.DefaultScopes,
        }.Build();

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers[AAuthRequirementHeader.Name] =
            AAuthRequirementHeader.FormatAuthToken(resourceToken);
        return Task.CompletedTask;
    }
}
