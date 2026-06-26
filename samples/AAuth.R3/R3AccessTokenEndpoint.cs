using System.Net;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.R3.Model;
using AAuth.Server.Metadata;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.R3;

/// <summary>Self-contained R3 Access Server metadata, JWKS, and token endpoint.</summary>
public static class R3AccessTokenEndpoint
{
    public static WebApplication MapR3AccessTokenEndpoint(this WebApplication app, R3AccessTokenEndpointOptions options)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        var (signingKid, signingKey) = options.FirstSigningKey();
        var issuer = options.Issuer.TrimEnd('/');
        var tokenPath = "/" + options.TokenPath.Trim('/');

        WellKnownEndpoints.MapAAuthAccessServerWellKnown(app, new AAuthAccessServerMetadataOptions
        {
            Issuer = issuer,
            TokenEndpoint = $"{issuer}{tokenPath}",
            SigningKeys = options.SigningKeys,
        });

        app.MapPost(tokenPath, async (HttpContext context) =>
        {
            R3VerifiedFetcher caller;
            try
            {
                caller = await R3DocumentEndpoint.VerifyFetcherAsync(context);
            }
            catch (Exception ex) when (ex is R3FetchVerificationException or AAuth.HttpSig.AAuthVerificationException)
            {
                return Results.Json(new { error = "invalid_signature", detail = ex.Message }, statusCode: StatusCodes.Status401Unauthorized);
            }

            if (!options.IsTrustedPersonServer(caller))
            {
                return Results.Json(new { error = "untrusted_person_server" }, statusCode: StatusCodes.Status403Forbidden);
            }

            JsonObject? body;
            try
            {
                body = await context.Request.ReadFromJsonAsync<JsonObject>();
            }
            catch (System.Text.Json.JsonException)
            {
                return Results.Json(new { error = "invalid_request", detail = "body is not valid JSON" }, statusCode: StatusCodes.Status400BadRequest);
            }

            var agentToken = (string?)body?["agent_token"];
            var resourceToken = (string?)body?["resource_token"];
            if (string.IsNullOrWhiteSpace(agentToken) || string.IsNullOrWhiteSpace(resourceToken))
            {
                return Results.Json(new { error = "invalid_request", detail = "missing agent_token or resource_token" }, statusCode: StatusCodes.Status400BadRequest);
            }

            var tokenVerifier = GetServiceOrDefault(context, new TokenVerifier());
            var metadata = GetRequired<MetadataClient>(context);
            var jwks = GetRequired<JwksClient>(context);

            string agentId;
            IAAuthKey agentConfirmationKey;
            try
            {
                var verifiedAgent = await tokenVerifier.VerifyWithJwksAsync(
                    agentToken,
                    metadata,
                    jwks,
                    AgentTokenBuilder.TokenType,
                    AgentTokenBuilder.AgentDwk,
                    expectedAudience: null,
                    cancellationToken: context.RequestAborted);
                agentId = (string?)verifiedAgent.Payload["sub"]
                    ?? throw new TokenVerificationException("agent_token missing sub");
                var cnfJwk = verifiedAgent.Payload["cnf"]?["jwk"] as JsonObject
                    ?? throw new TokenVerificationException("agent_token missing cnf.jwk");
                agentConfirmationKey = KeyFactory.FromJwk(cnfJwk);
            }
            catch (TokenVerificationException ex)
            {
                return Results.Json(new { error = "invalid_agent_token", detail = ex.Message }, statusCode: StatusCodes.Status401Unauthorized);
            }

            TokenVerifier.VerifiedToken verifiedResource;
            R3ClaimReader.ResourceDocumentClaims r3DocumentClaims;
            try
            {
                verifiedResource = await tokenVerifier.VerifyResourceTokenAsync(
                    resourceToken,
                    expectedAudience: issuer,
                    expectedAgentId: agentId,
                    expectedAgentJkt: agentConfirmationKey.ComputeJwkThumbprint(),
                    metadata,
                    jwks,
                    cancellationToken: context.RequestAborted);
                r3DocumentClaims = R3ClaimReader.ReadResourceDocument(verifiedResource.Payload)
                    ?? throw new TokenVerificationException("resource_token missing r3_uri/r3_s256");
            }
            catch (Exception ex) when (ex is TokenVerificationException or InvalidOperationException)
            {
                return Results.Json(new { error = "invalid_resource_token", detail = ex.Message }, statusCode: StatusCodes.Status400BadRequest);
            }

            var resourceAudience = (string?)verifiedResource.Payload["iss"];
            if (string.IsNullOrWhiteSpace(resourceAudience))
            {
                return Results.Json(new { error = "invalid_resource_token", detail = "resource_token missing iss" }, statusCode: StatusCodes.Status400BadRequest);
            }

            try
            {
                var proposalUri = (string?)body?["proposal_uri"];
                var proposalS256 = (string?)body?["proposal_s256"];
                AuthMintParts mintParts = string.IsNullOrWhiteSpace(proposalUri) && string.IsNullOrWhiteSpace(proposalS256)
                    ? await EvaluateDocumentAsync(context, options, r3DocumentClaims, context.RequestAborted)
                    : await EvaluateProposalAsync(context, options, proposalUri, proposalS256, context.RequestAborted);

                var claims = R3AuthClaims.AuthToken(
                    mintParts.Uri,
                    mintParts.S256,
                    mintParts.Granted,
                    mintParts.Conditional);

                var authToken = new AuthTokenBuilder
                {
                    Issuer = issuer,
                    Audience = resourceAudience,
                    Agent = agentId,
                    AgentConfirmationKey = agentConfirmationKey,
                    Key = signingKey,
                    KeyId = signingKid,
                    Dwk = AuthTokenBuilder.AccessDwk,
                    Subject = options.Subject,
                    AdditionalClaims = claims,
                }.Build();

                return Results.Ok(new { auth_token = authToken, expires_in = 3600 });
            }
            catch (Exception ex) when (ex is R3HashMismatchException or InvalidOperationException or HttpRequestException or TaskCanceledException)
            {
                return Results.Json(new { error = "r3_evaluation_failed", detail = ex.Message }, statusCode: StatusCodes.Status400BadRequest);
            }
        });

        return app;
    }

    private static async Task<AuthMintParts> EvaluateDocumentAsync(
        HttpContext context,
        R3AccessTokenEndpointOptions options,
        R3ClaimReader.ResourceDocumentClaims r3,
        CancellationToken cancellationToken)
    {
        var bytes = await FetchAsync(context, options, r3.Uri, r3.S256, cancellationToken);
        var document = R3Document.FromUtf8Bytes(bytes);
        var granted = new List<McpOperation>();
        var conditional = new List<McpOperation>();
        foreach (var operation in document.Operations)
        {
            if (options.ConditionalTools.Contains(operation.Tool))
            {
                conditional.Add(operation);
            }
            else
            {
                granted.Add(operation);
            }
        }
        return new AuthMintParts(
            r3.Uri,
            r3.S256,
            new R3Grant { Vocabulary = document.Vocabulary, Operations = granted },
            conditional.Count == 0 ? null : new R3Grant { Vocabulary = document.Vocabulary, Operations = conditional });
    }

    private static async Task<AuthMintParts> EvaluateProposalAsync(
        HttpContext context,
        R3AccessTokenEndpointOptions options,
        string? proposalUri,
        string? proposalS256,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(proposalUri) || string.IsNullOrWhiteSpace(proposalS256))
        {
            throw new InvalidOperationException("proposal_uri and proposal_s256 must be present together.");
        }
        var bytes = await FetchAsync(context, options, proposalUri, proposalS256, cancellationToken);
        var proposal = R3ProposalDocument.FromUtf8Bytes(bytes);
        return new AuthMintParts(
            proposalUri,
            proposalS256,
            new R3Grant { Vocabulary = proposal.Vocabulary, Operations = proposal.Operations },
            null);
    }

    private static async Task<byte[]> FetchAsync(
        HttpContext context,
        R3AccessTokenEndpointOptions options,
        string uri,
        string s256,
        CancellationToken cancellationToken)
    {
        if (options.FetchAndVerifyAsync is not null)
        {
            return await options.FetchAndVerifyAsync(context, uri, s256, cancellationToken).ConfigureAwait(false);
        }

        var (kid, key) = options.FirstSigningKey();
        var client = R3FetchClient.Create(key, $"{options.Issuer.TrimEnd('/')}/.well-known/jwks.json", kid);
        return await client.FetchAndVerifyAsync(uri, s256, cancellationToken).ConfigureAwait(false);
    }

    private static T GetRequired<T>(HttpContext context) where T : notnull =>
        context.RequestServices.GetRequiredService<T>();

    private static T GetServiceOrDefault<T>(HttpContext context, T fallback) where T : class =>
        context.RequestServices.GetService<T>() ?? fallback;

    private sealed record AuthMintParts(string Uri, string S256, R3Grant Granted, R3Grant? Conditional);
}

public sealed class R3AccessTokenEndpointOptions
{
    public required string Issuer { get; init; }
    public required IReadOnlyDictionary<string, AAuthKey> SigningKeys { get; init; }
    public string TokenPath { get; init; } = "/token";
    public string Subject { get; init; } = "pairwise-sub";
    public IReadOnlyCollection<string>? TrustedPersonServers { get; init; }
    public ISet<string> ConditionalTools { get; init; } = new HashSet<string>(StringComparer.Ordinal);
    public Func<HttpContext, string, string, CancellationToken, Task<byte[]>>? FetchAndVerifyAsync { get; init; }

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
        {
            throw new InvalidOperationException("Issuer must be set.");
        }
        if (SigningKeys is null || SigningKeys.Count == 0)
        {
            throw new InvalidOperationException("At least one AS signing key is required.");
        }
        if (string.IsNullOrWhiteSpace(TokenPath))
        {
            throw new InvalidOperationException("TokenPath must be set.");
        }
        if (string.IsNullOrWhiteSpace(Subject))
        {
            throw new InvalidOperationException("Subject must be set.");
        }
    }

    internal (string Kid, AAuthKey Key) FirstSigningKey()
    {
        foreach (var pair in SigningKeys)
        {
            return (pair.Key, pair.Value);
        }
        throw new InvalidOperationException("At least one AS signing key is required.");
    }

    internal bool IsTrustedPersonServer(R3VerifiedFetcher fetcher)
    {
        if (fetcher.Scheme != AAuthConstants.Schemes.JwksUri || fetcher.JwksUri is null)
        {
            return false;
        }
        if (TrustedPersonServers is null || TrustedPersonServers.Count == 0)
        {
            return true;
        }
        var allowed = TrustedPersonServers
            .Select(ps => Uri.TryCreate(ps, UriKind.Absolute, out var uri) ? uri.Authority : ps)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return allowed.Contains(fetcher.JwksUri.Authority);
    }
}
