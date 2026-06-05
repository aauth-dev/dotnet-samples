using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
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
    private readonly HttpClient _signedClient;
    private readonly MetadataClient _metadata;

    /// <summary>Create the exchange client.</summary>
    /// <param name="signedClient">HttpClient already wired with an <see cref="HttpSig.AAuthSigningHandler"/>.</param>
    /// <param name="metadata">Metadata client for resolving the PS <c>token_endpoint</c>.</param>
    public TokenExchangeClient(HttpClient signedClient, MetadataClient metadata)
    {
        ArgumentNullException.ThrowIfNull(signedClient);
        ArgumentNullException.ThrowIfNull(metadata);
        _signedClient = signedClient;
        _metadata = metadata;
    }

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

        var metadataUrl = MetadataClient.BuildUrl(personServer, "aauth-person.json");
        var doc = await _metadata.FetchAsync(metadataUrl, cancellationToken).ConfigureAwait(false);
        var tokenEndpoint = (string?)doc["token_endpoint"]
            ?? throw new InvalidOperationException(
                $"Person Server metadata at {metadataUrl} is missing 'token_endpoint'.");

        // A malicious or compromised PS metadata document could otherwise
        // redirect the signed exchange request to an arbitrary URL (SSRF
        // pivot for the agent) or downgrade it to plain http. Require the
        // same https-or-loopback policy used elsewhere, and pin the
        // endpoint to the same origin as the configured PS so a metadata
        // compromise can't divert the signed exchange off-host.
        if (!AAuthUrl.IsHttpsOrLoopback(tokenEndpoint)
            || !Uri.TryCreate(tokenEndpoint, UriKind.Absolute, out var tokenEndpointUri))
        {
            throw new InvalidOperationException(
                $"Person Server 'token_endpoint' must be an absolute https:// URL (or http://localhost): {tokenEndpoint}");
        }
        if (!Uri.TryCreate(personServer, UriKind.Absolute, out var psUri)
            || !string.Equals(
                tokenEndpointUri.GetLeftPart(UriPartial.Authority),
                psUri.GetLeftPart(UriPartial.Authority),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Person Server 'token_endpoint' must share an origin with {personServer}: {tokenEndpoint}");
        }

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
        AddIfPresent(body, "justification", options.Justification);
        AddIfPresent(body, "login_hint", options.LoginHint);
        AddIfPresent(body, "tenant", options.Tenant);
        AddIfPresent(body, "domain_hint", options.DomainHint);
        AddIfPresent(body, "platform", options.Platform);
        AddIfPresent(body, "device", options.Device);
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpointUri)
        {
            Content = JsonContent.Create(body),
        };

        // Signal willingness to long-poll on the initial exchange request
        // per spec: "agent signals its willingness to wait using the Prefer header".
        if (pollerOptions?.PreferWaitSeconds is { } preferWait)
        {
            request.Headers.TryAddWithoutValidation("Prefer", $"wait={preferWait}");
        }

        var response = await _signedClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        ClarificationExchange? clarificationExchange = null;

        try
        {
            // Resolve any deferred (202) requirements — user interaction and/or
            // clarification chat — looping until the PS returns a terminal
            // response (§User Interaction, §Clarification Chat).
            while (response.StatusCode == HttpStatusCode.Accepted)
            {
                var pendingUrl = ResolveLocation(response, tokenEndpointUri);
                var requirement = ExtractRequirement(response);

                // §Clarification Chat: the PS is asking the agent a question
                // during consent. Surface it via the callback, apply the agent's
                // chosen action against the pending URL, then resume polling.
                if (requirement?.Requirement == Headers.ClarificationRequirement.RequirementType)
                {
                    var clarificationBody = await ReadJsonBodyAsync(response, cancellationToken).ConfigureAwait(false);
                    var clarification = Headers.ClarificationRequirement.FromResponse(requirement, clarificationBody);
                    response.Dispose();

                    if (options.OnClarificationRequired is null)
                    {
                        throw new HttpRequestException(
                            "PS returned requirement=clarification but no OnClarificationRequired callback was provided.");
                    }

                    clarificationExchange ??= new ClarificationExchange(
                        _signedClient, pendingUrl, options.MaxClarificationRounds);
                    var decision = await options.OnClarificationRequired(clarification!, cancellationToken)
                        .ConfigureAwait(false);
                    await clarificationExchange.ApplyAsync(decision, cancellationToken).ConfigureAwait(false);

                    response = await PollPendingAsync(pendingUrl, pollerOptions, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                // §User Interaction: out-of-band consent. The agent relays the
                // URL+code to the user and then polls for completion.
                if (onInteractionRequired is null)
                {
                    throw new HttpRequestException(
                        $"PS returned {(int)response.StatusCode} (deferred response) but no onInteractionRequired callback was provided.");
                }

                var interaction = requirement is null ? null : Interaction.FromRequirement(requirement);
                response.Dispose();
                if (interaction is not null)
                {
                    await onInteractionRequired(interaction, cancellationToken).ConfigureAwait(false);
                }

                response = await PollPendingAsync(pendingUrl, pollerOptions, cancellationToken).ConfigureAwait(false);

                // 403 access_denied → user explicitly denied. Surface a distinct
                // typed exception so UIs / retry policies can treat denial
                // differently from "unknown id" (404) or transport failure.
                if (response.StatusCode == HttpStatusCode.Forbidden
                    && await IsAccessDeniedAsync(response, cancellationToken).ConfigureAwait(false))
                {
                    response.Dispose();
                    throw new AAuthInteractionDeniedException(
                        "The user denied the AAuth interaction request.");
                }
            }

            // §Mission Status Errors: a 403 mission_terminated means the request
            // referenced a mission that is no longer active. Terminal — the
            // agent must stop acting on the mission.
            if (response.StatusCode == HttpStatusCode.Forbidden
                && await TryReadMissionTerminatedAsync(response, cancellationToken).ConfigureAwait(false)
                    is var (terminated, missionStatus) && terminated)
            {
                response.Dispose();
                throw new Errors.AAuthMissionTerminatedException(missionStatus);
            }

            return await ReadAuthTokenAsync(response, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            response.Dispose();
        }
    }

    // Poll the pending URL, translating a poll-budget timeout into the typed
    // interaction-timeout exception and stopping early on a clarification 202 so
    // the exchange loop can handle it (composing with any caller predicate).
    private async Task<HttpResponseMessage> PollPendingAsync(
        Uri pendingUrl, DeferredPollerOptions? pollerOptions, CancellationToken cancellationToken)
    {
        var composed = ComposePollerOptions(pollerOptions);
        try
        {
            using var pollActivity = AAuthDiagnostics.Source.StartActivity("AAuth.DeferredPoll");
            return await new DeferredPoller(_signedClient, composed)
                .PollAsync(pendingUrl, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            throw new AAuthInteractionTimeoutException(
                $"PS deferred interaction did not complete within the polling budget: {ex.Message}",
                ex);
        }
    }

    // Compose poller options so polling stops on a clarification 202 (returning
    // it to the exchange loop), preserving any caller-supplied StopWhenAccepted.
    private static DeferredPollerOptions ComposePollerOptions(DeferredPollerOptions? baseOptions)
    {
        var userStop = baseOptions?.StopWhenAccepted;
        bool Stop(HttpResponseMessage resp)
        {
            if (userStop is not null && userStop(resp)) { return true; }
            var requirement = ExtractRequirement(resp);
            return requirement?.Requirement == Headers.ClarificationRequirement.RequirementType;
        }

        return baseOptions is null
            ? new DeferredPollerOptions { StopWhenAccepted = Stop }
            : baseOptions with { StopWhenAccepted = Stop };
    }

    private static void AddIfPresent(JsonObject body, string name, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            body[name] = value;
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
        var body = await BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
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

    // §Mission Status Errors: detect a 403 mission_terminated body. Buffers the
    // body so a non-matching response still flows to ReadAuthTokenAsync.
    // Returns (terminated, mission_status).
    private static async Task<(bool Terminated, string? MissionStatus)> TryReadMissionTerminatedAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var body = await BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
        try
        {
            var json = JsonNode.Parse(body) as JsonObject;
            if ((string?)json?["error"] == Errors.AAuthMissionTerminatedException.ErrorCode)
            {
                return (true, (string?)json?["mission_status"]);
            }
            return (false, null);
        }
        catch (System.Text.Json.JsonException)
        {
            return (false, null);
        }
    }

    // Read a response body to a string and replace the Content with a buffered
    // copy (preserving media type / charset) so it can be read again — e.g. by
    // a subsequent error classifier or ReadAuthTokenAsync.
    private static async Task<string> BufferBodyAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var originalMediaType = response.Content.Headers.ContentType?.MediaType ?? "application/json";
        var originalCharset = response.Content.Headers.ContentType?.CharSet;
        // Fall back to UTF-8 for unknown / malformed charset values rather
        // than surfacing an ArgumentException from Encoding.GetEncoding,
        // which would mask the real exchange failure the caller is trying
        // to diagnose.
        System.Text.Encoding encoding;
        if (string.IsNullOrEmpty(originalCharset))
        {
            encoding = System.Text.Encoding.UTF8;
        }
        else
        {
            try { encoding = System.Text.Encoding.GetEncoding(originalCharset); }
            catch (ArgumentException) { encoding = System.Text.Encoding.UTF8; }
        }
        response.Content.Dispose();
        response.Content = new StringContent(body, encoding, originalMediaType);
        return body;
    }

    private static async Task<JsonObject?> ReadJsonBodyAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }
        try { return JsonNode.Parse(body) as JsonObject; }
        catch (System.Text.Json.JsonException) { return null; }
    }

    private static AAuthRequirementHeader.ParsedRequirement? ExtractRequirement(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(AAuthRequirementHeader.Name, out var values))
        {
            return null;
        }
        foreach (var raw in values)
        {
            if (string.IsNullOrWhiteSpace(raw)) { continue; }
            try { return AAuthRequirementHeader.Parse(raw); }
            catch (FormatException) { continue; }
        }
        return null;
    }

    private static Uri ResolveLocation(HttpResponseMessage response, Uri @base)
    {
        var location = response.Headers.Location
            ?? throw new HttpRequestException(
                "Deferred PS response is missing the Location header — cannot poll.");
        return location.IsAbsoluteUri ? location : new Uri(@base, location);
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
