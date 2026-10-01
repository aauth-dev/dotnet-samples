using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;

namespace AAuth.Agent;

/// <summary>
/// Exchanges a resource token at the agent's Person Server for an auth
/// token (three-party autonomous flow). Returns the auth-token JWT on
/// success, or surfaces the PS response body / status to the caller.
/// </summary>
/// <remarks>
/// The HTTP POST to the PS's <c>auth_token_endpoint</c> MUST be signed with the
/// agent's key (RFC 9421) and carry the agent's agent token in
/// <c>Signature-Key</c>. The caller is expected to supply an
/// <see cref="HttpClient"/> wrapped in an
/// <see cref="HttpSig.AAuthSigningHandler"/> configured with the agent
/// token, just like any other outbound AAuth request.
/// </remarks>
public sealed class TokenExchangeClient
{
    private readonly DeferredExchange _exchange;

    /// <summary>Create the exchange client.</summary>
    /// <param name="signedClient">HttpClient already wired with an <see cref="HttpSig.AAuthSigningHandler"/>.</param>
    /// <param name="metadata">Metadata client for resolving the PS <c>auth_token_endpoint</c>.</param>
    public TokenExchangeClient(HttpClient signedClient, MetadataClient metadata)
    {
        _exchange = new DeferredExchange(signedClient, metadata);
        EgressPolicy = metadata.Policy;
    }

    public AAuthEgressPolicy EgressPolicy { get; }

    /// <summary>
    /// Submit <paramref name="resourceToken"/> and the <paramref name="presentedToken"/>
    /// it names to the PS at <paramref name="personServer"/> and return the auth token.
    /// </summary>
    /// <returns>The compact <c>aa-auth+jwt</c>.</returns>
    public Task<string> ExchangeAsync(
        string personServer,
        string resourceToken,
        string presentedToken,
        CancellationToken cancellationToken = default)
        => ExchangeAsync(personServer, resourceToken, new TokenExchangeRequest { PresentedToken = presentedToken }, cancellationToken);

    /// <summary>
    /// Submit <paramref name="resourceToken"/> to the PS at
    /// <paramref name="personServer"/> and return the auth token, with
    /// support for the deferred / user-consent path (PS returns
    /// <c>202 Accepted</c> + <c>AAuth-Requirement: requirement=interaction</c>),
    /// call chaining, and capability/prompt declaration.
    /// </summary>
    /// <param name="personServer">PS issuer URL (used to fetch <c>aauth-person.json</c>).</param>
    /// <param name="resourceToken">Compact <c>aa-resource+jwt</c> from the resource's challenge.</param>
    /// <param name="options">
    /// Optional exchange parameters (interaction callback, poller options,
    /// upstream token, capabilities, prompt). Pass a default-constructed
    /// instance for the plain exchange.
    /// </param>
    /// <param name="cancellationToken">Caller cancellation.</param>
    public async Task<string> ExchangeAsync(
        string personServer,
        string resourceToken,
        TokenExchangeRequest options,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        ArgumentException.ThrowIfNullOrEmpty(resourceToken);
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.PresentedToken))
            throw new ArgumentException("TokenExchangeRequest.PresentedToken is required: send the person or auth token presented to the resource.", nameof(options));
        AccountBinding.Validate(options.Account);
        void ValidateResourceAccount(string token)
        {
            var segments = token.Split('.');
            if (segments.Length != 3) throw new TokenVerificationException("Resource token must be a compact JWS.");
            var payload = TokenVerifier.DecodeJsonSegment(segments[1], "payload");
            if (!AccountBinding.Matches(options.Account, AccountBinding.Read(payload)))
                throw new TokenVerificationException("Resource token account differs from the requested account.");
        }
        IAAuthSigner? signingKey = null;
        string? signedAgentToken = null;
        void ValidateClarificationUpdate(ClarificationResponse answer)
        {
            if (answer.Action != ClarificationResponse.Kind.Update)
            {
                return;
            }

            ValidateUpdatedRequestPair(resourceToken, answer.ResourceToken!, answer.PresentedToken!, signingKey);
            ValidateResourceAccount(answer.ResourceToken!);
        }
        ValidateResourceAccount(resourceToken);

        var onInteractionRequired = options.OnInteractionRequired;
        var pollerOptions = options.PollerOptions;
        var upstreamToken = options.UpstreamToken;
        var effectiveResourceToken = resourceToken;
        var effectivePresentedToken = options.PresentedToken;

        using var activity = AAuthDiagnostics.Source.StartActivity("AAuth.TokenExchange");

        var tokenEndpointUri = await _exchange.ResolveEndpointAsync(
            personServer, "auth_token_endpoint", cancellationToken).ConfigureAwait(false);

        var body = new JsonObject { ["resource_token"] = resourceToken, ["presented_token"] = options.PresentedToken };
        AddRequestParameters(body, options);

        var exchangeOptions = new DeferredExchangeOptions
        {
            OnInteractionRequired = onInteractionRequired,
            OnClarificationRequired = options.OnClarificationRequired is { } clarify ? async (question, ct) =>
            {
                var answer = await clarify(question, ct);
                if (answer.Action == ClarificationResponse.Kind.Update)
                {
                    ValidateClarificationUpdate(answer);
                    effectiveResourceToken = answer.ResourceToken!;
                    effectivePresentedToken = answer.PresentedToken!;
                }
                return answer;
            } : null,
            MaxClarificationRounds = options.MaxClarificationRounds,
            PollerOptions = pollerOptions,
            RequireInteractionCallback = true,
            // §Polling Error Codes: a user denial surfaces as 403 `denied` on
            // the poll. Classify it only after an interaction poll (matching the
            // original placement) so a direct/clarification 403 stays a token error.
            OnPolledResponse = async (resp, ct) =>
            {
                if (resp.StatusCode == HttpStatusCode.Forbidden
                    && await IsDeniedAsync(resp, ct).ConfigureAwait(false))
                {
                    throw new AAuthInteractionDeniedException(
                        "The user denied the AAuth interaction request.");
                }
            },
        };

        var response = await _exchange.PostAsync(
            tokenEndpointUri, body, exchangeOptions, cancellationToken, request =>
            {
                request.Options.TryGetValue(AAuthSigningHandler.SigningKeyContext, out signingKey);
                if (request.Headers.TryGetValues(AAuthConstants.Headers.SignatureKey, out var values))
                    foreach (var value in values)
                        signedAgentToken = SignatureKeyParser.Parse(value).Jwt;
            }).ConfigureAwait(false);
        try
        {
            var authToken = await ReadTokenAsync(response, "auth_token", cancellationToken).ConfigureAwait(false);
            if (signingKey is null || signedAgentToken is null)
                throw new TokenVerificationException("Token exchange requires a locally signed agent-token request context.");
            AgentAuthTokenValidator.Validate(authToken, effectiveResourceToken, signingKey, signedAgentToken,
                effectivePresentedToken!, options.SubagentToken, upstreamToken);
            return authToken;
        }
        finally
        {
            response.Dispose();
        }
    }

    /// <summary>Request a person token for <paramref name="resource"/> with default options.</summary>
    /// <returns>The compact <c>aa-person+jwt</c>.</returns>
    public Task<string> RequestPersonTokenAsync(
        string personServer,
        string resource,
        CancellationToken cancellationToken = default)
        => RequestPersonTokenAsync(personServer, resource, new TokenExchangeRequest(), cancellationToken);

    /// <summary>
    /// Request a person token for <paramref name="resource"/> at the PS's
    /// <c>person_token_endpoint</c> (§Person Token Request), with the same
    /// deferred-consent handling as an auth token request. Set
    /// <see cref="TokenExchangeRequest.MissionS256"/> to act under a mission,
    /// <see cref="TokenExchangeRequest.UpstreamToken"/> when chaining, and
    /// <see cref="TokenExchangeRequest.SubagentToken"/> for a sub-agent.
    /// </summary>
    /// <returns>The compact <c>aa-person+jwt</c>.</returns>
    public async Task<string> RequestPersonTokenAsync(
        string personServer,
        string resource,
        TokenExchangeRequest options,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        ArgumentException.ThrowIfNullOrEmpty(resource);
        ArgumentNullException.ThrowIfNull(options);
        if (!Identifiers.ServerId.TryParse(resource, out _, out _, EgressPolicy))
            throw new ArgumentException("resource must be a server identifier.", nameof(resource));
        if (options.MissionS256 is not null && !MissionReference.IsValid(options.MissionS256))
            throw new ArgumentException("MissionS256 must be an unpadded base64url SHA-256 digest.", nameof(options));

        using var activity = AAuthDiagnostics.Source.StartActivity("AAuth.PersonTokenRequest");
        var endpoint = await _exchange.ResolveEndpointAsync(
            personServer, "person_token_endpoint", cancellationToken).ConfigureAwait(false);
        var body = new JsonObject { ["resource"] = resource };
        DeferredExchange.AddIfPresent(body, MissionReference.ClaimName, options.MissionS256);
        AddRequestParameters(body, options);

        IAAuthSigner? signingKey = null;
        string? signedAgentToken = null;
        var response = await _exchange.PostAsync(endpoint, body, new DeferredExchangeOptions
        {
            OnInteractionRequired = options.OnInteractionRequired,
            PollerOptions = options.PollerOptions,
            RequireInteractionCallback = true,
            OnPolledResponse = async (resp, ct) =>
            {
                if (resp.StatusCode == HttpStatusCode.Forbidden && await IsDeniedAsync(resp, ct).ConfigureAwait(false))
                    throw new AAuthInteractionDeniedException("The user denied the AAuth interaction request.");
            },
        }, cancellationToken, request =>
        {
            request.Options.TryGetValue(AAuthSigningHandler.SigningKeyContext, out signingKey);
            if (request.Headers.TryGetValues(AAuthConstants.Headers.SignatureKey, out var values))
                foreach (var value in values)
                    signedAgentToken = SignatureKeyParser.Parse(value).Jwt;
        }).ConfigureAwait(false);
        try
        {
            var personToken = await ReadTokenAsync(response, "person_token", cancellationToken).ConfigureAwait(false);
            if (signingKey is null || signedAgentToken is null)
                throw new TokenVerificationException("Person token request requires a locally signed agent-token request context.");
            var agent = AgentAuthTokenValidator.Payload(signedAgentToken);
            var bound = options.SubagentToken is null ? agent : AgentAuthTokenValidator.Payload(options.SubagentToken);
            var expectedKey = options.SubagentToken is null ? signingKey : SignatureKeyParser.Confirmation(bound);
            var payload = AgentAuthTokenValidator.Payload(personToken);
            var header = TokenVerifier.DecodeJsonSegment(personToken.Split('.')[0], "header");
            if ((string?)header["typ"] != PersonTokenBuilder.TokenType || (string?)payload["iss"] != personServer
                || (string?)payload["aud"] != resource
                || SignatureKeyParser.Confirmation(payload).ComputeJwkThumbprint() != expectedKey.ComputeJwkThumbprint()
                || (options.UpstreamToken is null && (string?)payload[MissionReference.ClaimName] != options.MissionS256)
                || (long?)payload["exp"] is not { } expiry || expiry > (long?)agent["exp"] || expiry > (long?)bound["exp"]
                || expiry <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                || (options.UpstreamToken is not null && expiry > (long?)AgentAuthTokenValidator.Payload(options.UpstreamToken)["exp"]))
                throw new TokenVerificationException("Person token response issuer, audience, key, mission or lifetime mismatch.");
            return personToken;
        }
        finally
        {
            response.Dispose();
        }
    }

    // Parameters shared by the person token and auth token requests (§Person Token Request).
    private static void AddRequestParameters(JsonObject body, TokenExchangeRequest options)
    {
        DeferredExchange.AddIfPresent(body, "upstream_token", options.UpstreamToken);
        DeferredExchange.AddIfPresent(body, "subagent_token", options.SubagentToken);
        var capabilities = options.Capabilities ?? InferCapabilities(options.OnInteractionRequired, options.OnClarificationRequired);
        if (options.Capabilities is not null || capabilities.Count > 0)
        {
            var caps = new JsonArray();
            foreach (var capability in capabilities)
            {
                caps.Add(capability);
            }
            body["capabilities"] = caps;
        }
        DeferredExchange.AddIfPresent(body, "prompt", options.Prompt);
        DeferredExchange.AddIfPresent(body, "justification", options.Justification);
        DeferredExchange.AddIfPresent(body, "login_hint", options.LoginHint);
        DeferredExchange.AddIfPresent(body, "tenant", options.Tenant);
        DeferredExchange.AddIfPresent(body, "domain_hint", options.DomainHint);
        DeferredExchange.AddIfPresent(body, "platform", options.Platform);
        DeferredExchange.AddIfPresent(body, "device", options.Device);
    }

    // Default capability inference: declare "interaction" when the caller can
    // handle a 202 + user-facing consent redirect, and "clarification" when the
    // caller can answer clarification questions. An explicit capabilities list
    // passed to ExchangeAsync overrides this.
    private static IReadOnlyList<string> InferCapabilities(
        Func<Interaction, CancellationToken, Task>? onInteractionRequired,
        Delegate? onClarificationRequired)
    {
        var capabilities = new List<string>();
        if (onInteractionRequired is not null)
        {
            capabilities.Add(AAuthConstants.Capabilities.Interaction);
        }
        if (onClarificationRequired is not null)
        {
            capabilities.Add(AAuthConstants.Capabilities.Clarification);
        }
        return capabilities;
    }

    private static void ValidateUpdatedRequestPair(
        string originalResourceToken,
        string replacementResourceToken,
        string replacementPresentedToken,
        IAAuthKey? signingKey)
    {
        var original = Payload(originalResourceToken);
        var replacement = Payload(replacementResourceToken);
        var presented = Payload(replacementPresentedToken);
        TokenVerifier.RequireSameResourceRequest(original, replacement);

        if (!string.Equals((string?)replacement["presented_jti"], (string?)presented["jti"], StringComparison.Ordinal))
        {
            throw new TokenVerificationException("Replacement resource token 'presented_jti' does not match the replacement presented token.");
        }

        foreach (var claim in new[] { "sub", "mission_s256", "tenant" })
        {
            if (!JsonNode.DeepEquals(replacement[claim], presented[claim]))
            {
                throw new TokenVerificationException($"Replacement presented token changes '{claim}'.");
            }
        }

        if (signingKey is not null
            && !string.Equals((string?)replacement["agent_jkt"], signingKey.ComputeJwkThumbprint(), StringComparison.Ordinal))
        {
            throw new TokenVerificationException("Replacement resource token 'agent_jkt' does not match the signing key.");
        }

        static JsonObject Payload(string jwt)
        {
            var segments = jwt.Split('.');
            if (segments.Length != 3)
            {
                throw new TokenVerificationException("Replacement tokens must be compact JWS values.");
            }

            return TokenVerifier.DecodeJsonSegment(segments[1], "payload");
        }
    }

    private static async Task<bool> IsDeniedAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        // Buffer the body so the subsequent ReadAuthTokenAsync (if we
        // decide it isn't a denial) still sees it.
        var body = await DeferredExchange.BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
        try
        {
            var json = JsonNode.Parse(body) as JsonObject;
            return json?["error"] is JsonValue value
                && value.TryGetValue<string>(out var error) && error == "denied";
        }
        catch (System.Text.Json.JsonException)
        {
            return false;
        }
    }

    private static async Task<string> ReadTokenAsync(
        HttpResponseMessage response, string member, CancellationToken cancellationToken)
    {
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            // The token endpoint signals failure with a JSON body carrying a
            // required 'error' code and optional 'detail'
            // (§Token Endpoint Error Response Format). Surface those as a
            // typed exception so callers can branch on the code. Bodies that
            // are not parseable AAuth error objects fall back to a plain
            // HttpRequestException.
            var errorCode = TryReadErrorCode(responseBody, out var detail);
            if (errorCode is not null)
            {
                throw new Errors.AAuthTokenExchangeException(
                    errorCode, detail, (int)response.StatusCode,
                    Errors.AAuthTokenExchangeException.IsTerminalCode(errorCode));
            }

            throw new HttpRequestException(
                $"Token exchange failed: {(int)response.StatusCode} {response.ReasonPhrase}\n{responseBody}");
        }

        var json = JsonNode.Parse(responseBody) as JsonObject
            ?? throw new InvalidOperationException("Token exchange response was not a JSON object.");
        return (string?)json[member]
            ?? throw new InvalidOperationException($"Token response did not include '{member}'.");
    }

    // Parse a token-endpoint error body into its 'error' code (and optional
    // 'detail'). Returns null when the body is not a JSON object
    // with a non-empty string 'error' member, signalling the caller to fall
    // back to a generic transport exception.
    private static string? TryReadErrorCode(string body, out string? detail)
    {
        detail = null;
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }
        JsonObject? json;
        try { json = JsonNode.Parse(body) as JsonObject; }
        catch (System.Text.Json.JsonException) { return null; }
        if (json is null)
        {
            return null;
        }
        if (json["error"] is not JsonValue errorValue
            || !errorValue.TryGetValue<string>(out var error)
            || string.IsNullOrWhiteSpace(error))
        {
            return null;
        }
        if (json["detail"] is JsonValue detailValue)
            detailValue.TryGetValue<string>(out detail);
        return error;
    }
}
