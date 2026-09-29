using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server.Verification;
using AAuth.Server.Metadata;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

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

        // §Agent Token Required: this resource specifically wants AAuth identity,
        // distinct from any other URI-identified key. Pass through when an AAuth
        // token (agent, person or auth) is present; otherwise challenge with a
        // bare requirement=agent-token.
        if (_options.AccessMode == AAuthAccessMode.AgentTokenRequired)
        {
            if (tokenType is AAuthTokenType.AgentToken or AAuthTokenType.PersonToken or AAuthTokenType.AuthToken)
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

        // §Person Token Required: a resource issues a resource token only after it
        // verifies a person token (or an auth token) on the request.
        if (tokenType == AAuthTokenType.AgentToken)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatPersonToken();
            return;
        }

        if (tokenType == AAuthTokenType.PersonToken
            && context.Features.Get<AAuthVerifiedAssertion>() is { } presented)
        {
            await IssueChallenge(context, presented, parsedInfo).ConfigureAwait(false);
            return;
        }

        // Unknown token type — pass through (let downstream handle).
        await _next(context).ConfigureAwait(false);
    }

    /// <summary>
    /// Build a resource token from a verified person or auth token: <c>ps</c>,
    /// <c>sub</c>, <c>presented_jti</c>, <c>mission_s256</c> and <c>tenant</c> come
    /// from it; <c>aud</c> is the resource's AS (four-party) or the person's PS.
    /// </summary>
    public static async ValueTask<string> BuildResourceTokenAsync(ChallengeOptions options, AAuthVerifiedAssertion presented,
        string? scope, string? account = null, IReadOnlyDictionary<string, string>? scopeDescriptions = null,
        IReadOnlyCollection<string>? personServerScopes = null, Interaction? interaction = null, string? loginHint = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(presented);
        if (options.ResourceSigningKeys is not { Count: > 0 } signingKeys)
            throw new InvalidOperationException("ChallengeOptions.ResourceSigningKeys must be set for RequireAuthToken mode.");
        var (keyId, signer) = signingKeys.Active;
        if (!signer.HasPrivateKey)
            throw new InvalidOperationException("ChallengeOptions.ResourceSigningKeys' active key must be able to sign.");
        if (string.IsNullOrEmpty(options.ResourceIdentifier))
            throw new InvalidOperationException("ChallengeOptions.ResourceIdentifier must be set for RequireAuthToken mode.");
        var token = presented.Token;
        var personServer = PersonServerOf(token);
        return await new ResourceTokenBuilder
        {
            EgressPolicy = options.EgressPolicy,
            Issuer = options.ResourceIdentifier,
            Audience = options.AccessServer ?? personServer,
            PersonServer = personServer,
            Subject = token.Subject ?? throw new TokenVerificationException("Presented token is missing 'sub'."),
            PresentedJti = token.Jti,
            AgentJkt = presented.HttpSigningKey.ComputeJwkThumbprint(),
            MissionS256 = token.MissionS256,
            Tenant = token.Tenant,
            Key = signer,
            KeyId = keyId,
            Scope = scope,
            Account = account,
            ScopeDescriptions = scopeDescriptions,
            PersonServerScopesSupported = personServerScopes,
            Interaction = interaction,
            LoginHint = loginHint,
        }.BuildAsync(cancellationToken).ConfigureAwait(false);
    }

    // The PS the presented token names: a person token's iss, an auth token's ps.
    private static string PersonServerOf(TokenVerifier.VerifiedToken token)
        => token.TokenType == AuthTokenBuilder.TokenType
            ? (string?)token.Payload["ps"] ?? throw new TokenVerificationException("Auth token is missing 'ps'.")
            : token.Issuer;

    private async Task IssueChallenge(
        HttpContext context,
        AAuthVerifiedAssertion presented,
        SignatureKeyParser.ParsedSignatureKeyInfo? parsedInfo)
    {
        var definitions = _options.ScopeDescriptions
            ?? context.RequestServices?.GetService<AAuthResourceMetadataOptions>()?.ScopeDescriptions;
        IReadOnlyCollection<string>? identityScopes = null;
        var requestedScopes = (_options.DefaultScopes ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (requestedScopes.Any(scope => definitions?.ContainsKey(scope) != true))
        {
            var metadata = context.RequestServices!.GetRequiredService<MetadataClient>();
            var person = await metadata.FetchAsync(metadata.GetUrl(PersonServerOf(presented.Token), AAuthConstants.DwkFiles.Person), context.RequestAborted);
            identityScopes = (person["scopes_supported"] as System.Text.Json.Nodes.JsonArray)?
                .Select(scope => scope?.GetValue<string>() ?? "").ToArray();
        }
        var resourceToken = await BuildResourceTokenAsync(_options, presented, _options.DefaultScopes,
            _options.RequestedAccount?.Invoke(context), definitions, identityScopes,
            cancellationToken: context.RequestAborted);

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers[AAuthRequirementHeader.Name] =
            AAuthRequirementHeader.FormatAuthToken(resourceToken);
    }
}
