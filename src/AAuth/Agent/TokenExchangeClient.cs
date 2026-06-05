using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;
using AAuth.Headers;

namespace AAuth.Agent;

/// <summary>
/// Exchanges a resource token at the agent's Person Server for an auth
/// token (three-party autonomous flow). Returns the auth-token JWT on
/// success, or surfaces the PS response body / status to the caller.
/// </summary>
/// <remarks>
/// The HTTP POST to the PS's <c>token_endpoint</c> MUST be signed with the
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
    /// <param name="metadata">Metadata client for resolving the PS <c>token_endpoint</c>.</param>
    public TokenExchangeClient(HttpClient signedClient, MetadataClient metadata)
        => _exchange = new DeferredExchange(signedClient, metadata);

    /// <summary>
    /// Submit <paramref name="resourceToken"/> to the PS at
    /// <paramref name="personServer"/> and return the auth token.
    /// </summary>
    /// <returns>The compact <c>aa-auth+jwt</c>.</returns>
    public Task<string> ExchangeAsync(
        string personServer,
        string resourceToken,
        CancellationToken cancellationToken = default)
        => ExchangeAsync(personServer, resourceToken, new TokenExchangeRequest(), cancellationToken);

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

        var onInteractionRequired = options.OnInteractionRequired;
        var pollerOptions = options.PollerOptions;
        var upstreamToken = options.UpstreamToken;
        var capabilities = options.Capabilities;
        var prompt = options.Prompt;

        using var activity = AAuthDiagnostics.Source.StartActivity("AAuth.TokenExchange");

        var tokenEndpointUri = await _exchange.ResolveEndpointAsync(
            personServer, "token_endpoint", cancellationToken).ConfigureAwait(false);

        var body = new JsonObject { ["resource_token"] = resourceToken };
        if (!string.IsNullOrEmpty(upstreamToken))
        {
            body["upstream_token"] = upstreamToken;
        }
        // Declare capabilities so the PS knows what the agent can do (e.g.
        // handle a 202 + user-facing consent redirect). Spec §AAuth-Capabilities
        // plus -02 token endpoint parameter. null = infer from flow; an explicit
        // (possibly empty) list overrides.
        var resolvedCapabilities = capabilities ?? InferCapabilities(onInteractionRequired, options.OnClarificationRequired);
        if (resolvedCapabilities.Count > 0)
        {
            var caps = new JsonArray();
            foreach (var capability in resolvedCapabilities)
            {
                caps.Add(capability);
            }
            body["capabilities"] = caps;
        }
        // Optional OIDC prompt hint (e.g. "consent" to force a fresh consent
        // screen). Spec -02 §7.1.3. Omitted when null.
        if (!string.IsNullOrEmpty(prompt))
        {
            body["prompt"] = prompt;
        }
        // Optional consent/display parameters (§Agent Token Request). Each is
        // emitted only when set.
        DeferredExchange.AddIfPresent(body, "justification", options.Justification);
        DeferredExchange.AddIfPresent(body, "login_hint", options.LoginHint);
        DeferredExchange.AddIfPresent(body, "tenant", options.Tenant);
        DeferredExchange.AddIfPresent(body, "domain_hint", options.DomainHint);
        DeferredExchange.AddIfPresent(body, "platform", options.Platform);
        DeferredExchange.AddIfPresent(body, "device", options.Device);

        var exchangeOptions = new DeferredExchangeOptions
        {
            OnInteractionRequired = onInteractionRequired,
            OnClarificationRequired = options.OnClarificationRequired,
            MaxClarificationRounds = options.MaxClarificationRounds,
            PollerOptions = pollerOptions,
            // Token exchange cannot complete consent without an interaction
            // callback, so any deferred 202 with no callback fails fast.
            RequireInteractionCallback = true,
            // §User Interaction: a user denial surfaces as 403 access_denied on
            // the poll. Classify it only after an interaction poll (matching the
            // original placement) so a direct/clarification 403 stays a token error.
            OnPolledResponse = async (resp, ct) =>
            {
                if (resp.StatusCode == HttpStatusCode.Forbidden
                    && await IsAccessDeniedAsync(resp, ct).ConfigureAwait(false))
                {
                    throw new AAuthInteractionDeniedException(
                        "The user denied the AAuth interaction request.");
                }
            },
        };

        var response = await _exchange.PostAsync(
            tokenEndpointUri, body, exchangeOptions, cancellationToken).ConfigureAwait(false);
        try
        {
            return await ReadAuthTokenAsync(response, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            response.Dispose();
        }
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
            capabilities.Add("interaction");
        }
        if (onClarificationRequired is not null)
        {
            capabilities.Add("clarification");
        }
        return capabilities;
    }

    private static async Task<bool> IsAccessDeniedAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        // Buffer the body so the subsequent ReadAuthTokenAsync (if we
        // decide it isn't access_denied) still sees it.
        var body = await DeferredExchange.BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
        try
        {
            var json = JsonNode.Parse(body) as JsonObject;
            return (string?)json?["error"] == "access_denied";
        }
        catch (System.Text.Json.JsonException)
        {
            return false;
        }
    }

    private static async Task<string> ReadAuthTokenAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            // The token endpoint signals failure with a JSON body carrying a
            // required 'error' code and optional 'error_description'
            // (§Token Endpoint Error Response Format). Surface those as a
            // typed exception so callers can branch on the code. Bodies that
            // are not parseable AAuth error objects fall back to a plain
            // HttpRequestException.
            var errorCode = TryReadErrorCode(responseBody, out var errorDescription);
            if (errorCode is not null)
            {
                throw new Errors.AAuthTokenExchangeException(
                    errorCode, errorDescription, (int)response.StatusCode,
                    Errors.AAuthTokenExchangeException.IsTerminalCode(errorCode));
            }

            throw new HttpRequestException(
                $"Token exchange failed: {(int)response.StatusCode} {response.ReasonPhrase}\n{responseBody}");
        }

        var json = JsonNode.Parse(responseBody) as JsonObject
            ?? throw new InvalidOperationException("Token exchange response was not a JSON object.");
        return (string?)json["auth_token"]
            ?? throw new InvalidOperationException("Token exchange response did not include 'auth_token'.");
    }

    // Parse a token-endpoint error body into its 'error' code (and optional
    // 'error_description'). Returns null when the body is not a JSON object
    // with a non-empty string 'error' member, signalling the caller to fall
    // back to a generic transport exception.
    private static string? TryReadErrorCode(string body, out string? errorDescription)
    {
        errorDescription = null;
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
        var error = (string?)json["error"];
        if (string.IsNullOrEmpty(error))
        {
            return null;
        }
        errorDescription = (string?)json["error_description"];
        return error;
    }
}
