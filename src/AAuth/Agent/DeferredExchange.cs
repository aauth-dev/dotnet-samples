using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;

namespace AAuth.Agent;

/// <summary>
/// Transport-level options for <see cref="DeferredExchange"/>: the deferred
/// (<c>202</c>) callbacks shared by token exchange and the PS governance clients,
/// plus two seams that let the token-exchange path preserve its specific
/// behaviour.
/// </summary>
internal sealed class DeferredExchangeOptions
{
    /// <summary>Relay an interaction (URL/code) to the user (§User Interaction).</summary>
    public Func<Interaction, CancellationToken, Task>? OnInteractionRequired { get; init; }

    /// <summary>Answer a clarification question during review (§Clarification Chat).</summary>
    public Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>>? OnClarificationRequired { get; init; }

    /// <summary>Maximum clarification rounds before the exchange aborts (default 5).</summary>
    public int MaxClarificationRounds { get; init; } = ClarificationExchange.DefaultMaxRounds;

    /// <summary>Optional polling tuning for deferred responses.</summary>
    public DeferredPollerOptions? PollerOptions { get; init; }

    /// <summary>
    /// When <see langword="true"/>, any non-clarification <c>202</c> requires an
    /// interaction callback (token exchange cannot complete consent without one).
    /// When <see langword="false"/>, the callback is only required if the PS
    /// returns an explicit interaction requirement (governance default).
    /// </summary>
    public bool RequireInteractionCallback { get; init; }

    /// <summary>
    /// Invoked after each poll in the interaction branch, before the loop
    /// re-checks for a <c>202</c>. Token exchange uses this to classify a polled
    /// <c>403 denied</c>; the callback may throw. <see langword="null"/> =
    /// no-op.
    /// </summary>
    public Func<HttpResponseMessage, CancellationToken, Task>? OnPolledResponse { get; init; }
}

/// <summary>
/// Shared transport for signed AAuth POSTs that may defer (token exchange and the
/// PS governance endpoints): resolves an endpoint from PS metadata (origin-pinned),
/// POSTs a signed JSON body, drives the deferred <c>202</c> loop (interaction +
/// clarification), and surfaces <c>403 mission_terminated</c>
/// (#mission-status-errors) as a typed exception. The caller owns parsing the
/// terminal response and MUST dispose it.
/// </summary>
internal sealed class DeferredExchange
{
    private readonly HttpClient _signedClient;
    private readonly MetadataClient _metadata;

    internal DeferredExchange(HttpClient signedClient, MetadataClient metadata)
    {
        ArgumentNullException.ThrowIfNull(signedClient);
        ArgumentNullException.ThrowIfNull(metadata);
        _signedClient = signedClient;
        _metadata = metadata;
    }

    /// <summary>
    /// Fetch PS metadata and resolve the endpoint named <paramref name="field"/>,
    /// pinned to the same origin as <paramref name="personServer"/> and required
    /// to be https-or-loopback.
    /// </summary>
    internal async Task<Uri> ResolveEndpointAsync(
        string personServer, string field, CancellationToken cancellationToken)
    {
        var metadataUrl = MetadataClient.BuildUrl(personServer, AAuthConstants.DwkFiles.Person);
        var doc = await _metadata.FetchAsync(metadataUrl, cancellationToken).ConfigureAwait(false);
        var endpoint = (string?)doc[field]
            ?? throw new InvalidOperationException(
                $"Person Server metadata at {metadataUrl} is missing '{field}'.");

        // Pin the endpoint to the configured PS origin and require https (or
        // loopback) so a compromised metadata document can't divert the signed
        // request off-host (SSRF) or downgrade it to plain http.
        if (!AAuthUrl.IsHttpsOrLoopback(endpoint)
            || !Uri.TryCreate(endpoint, UriKind.Absolute, out var endpointUri))
        {
            throw new InvalidOperationException(
                $"Person Server '{field}' must be an absolute https:// URL (or http://localhost): {endpoint}");
        }
        if (!Uri.TryCreate(personServer, UriKind.Absolute, out var psUri)
            || !string.Equals(
                endpointUri.GetLeftPart(UriPartial.Authority),
                psUri.GetLeftPart(UriPartial.Authority),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Person Server '{field}' must share an origin with {personServer}: {endpoint}");
        }

        return endpointUri;
    }

    /// <summary>
    /// POST <paramref name="body"/> to <paramref name="endpoint"/> and resolve any
    /// deferred (<c>202</c>) responses to a terminal response. The caller owns
    /// parsing the terminal response and MUST dispose it.
    /// </summary>
    internal async Task<HttpResponseMessage> PostAsync(
        Uri endpoint, JsonObject body, DeferredExchangeOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = JsonContent.Create(body),
        };
        if (options.PollerOptions?.PreferWaitSeconds is { } preferWait)
        {
            request.Headers.TryAddWithoutValidation("Prefer", $"wait={preferWait}");
        }

        var response = await _signedClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        ClarificationExchange? clarificationExchange = null;
        var ownsResponse = true;
        Uri? lastPendingUrl = null;
        try
        {
            while (response.StatusCode == HttpStatusCode.Accepted)
            {
                // A polled 202 (e.g. an interaction gate that follows a
                // clarification round) may omit the Location header; the pending
                // URL is unchanged, so fall back to the last one we resolved.
                var pendingUrl = ResolveLocation(response, endpoint, lastPendingUrl);
                lastPendingUrl = pendingUrl;
                var requirement = ExtractRequirement(response);

                // §Clarification Chat: the PS is asking the agent a question
                // during review. Surface it, apply the decision, resume polling.
                if (requirement?.Requirement == ClarificationRequirement.RequirementType)
                {
                    var clarificationBody = await ReadJsonBodyAsync(response, cancellationToken).ConfigureAwait(false);
                    var clarification = ClarificationRequirement.FromResponse(requirement, clarificationBody);
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

                    // After answering, the PS may escalate to a user-interaction
                    // gate (§Clarification Chat then §User Interaction). Stop the
                    // poll on that interaction so the loop below surfaces it via
                    // OnInteractionRequired; otherwise a bare poll would wait it
                    // out silently and never prompt the user.
                    response = await PollAsync(
                        pendingUrl, options.PollerOptions, cancellationToken, stopOnInteraction: true)
                        .ConfigureAwait(false);
                    continue;
                }

                // §User Interaction: token exchange requires an interaction
                // callback for any deferred response; governance only when an
                // interaction requirement is present.
                if (options.RequireInteractionCallback && options.OnInteractionRequired is null)
                {
                    var status = (int)response.StatusCode;
                    response.Dispose();
                    // The PS deferred for user interaction but the agent supplied no
                    // interaction callback and did not declare the `interaction`
                    // capability — there is no channel to the user. Surface the
                    // terminal `user_unreachable` error (draft-02 §Token Endpoint
                    // Error Codes) so callers can branch on it, instead of a generic
                    // transport failure.
                    throw new AAuthTokenExchangeException(
                        new TokenErrorResponse(TokenErrorCode.UserUnreachable).ErrorCode,
                        $"PS returned {status} (deferred response) but no onInteractionRequired callback was provided.",
                        statusCode: 403,
                        isTerminal: true);
                }

                var interaction = requirement is null ? null : Interaction.FromRequirement(requirement);
                response.Dispose();
                if (interaction is not null)
                {
                    if (options.OnInteractionRequired is null)
                    {
                        throw new HttpRequestException(
                            "PS returned requirement=interaction but no OnInteractionRequired callback was provided.");
                    }
                    await options.OnInteractionRequired(interaction, cancellationToken).ConfigureAwait(false);
                }

                response = await PollAsync(pendingUrl, options.PollerOptions, cancellationToken).ConfigureAwait(false);

                // Token exchange classifies a polled 403 denied here (only
                // after an interaction poll, matching the original placement).
                if (options.OnPolledResponse is not null)
                {
                    await options.OnPolledResponse(response, cancellationToken).ConfigureAwait(false);
                }
            }

            // §Mission Status Errors: a 403 mission_terminated is terminal — the
            // mission referenced by the request is no longer active.
            if (response.StatusCode == HttpStatusCode.Forbidden
                && await TryReadMissionTerminatedAsync(response, cancellationToken).ConfigureAwait(false)
                    is var (terminated, missionStatus) && terminated)
            {
                response.Dispose();
                throw new AAuthMissionTerminatedException(missionStatus);
            }

            ownsResponse = false;
            return response;
        }
        finally
        {
            if (ownsResponse)
            {
                response.Dispose();
            }
        }
    }

    private async Task<HttpResponseMessage> PollAsync(
        Uri pendingUrl, DeferredPollerOptions? pollerOptions, CancellationToken cancellationToken,
        bool stopOnInteraction = false)
    {
        var composed = ComposePollerOptions(pollerOptions, stopOnInteraction);
        try
        {
            using var pollActivity = AAuthDiagnostics.Source.StartActivity("AAuth.DeferredPoll");
            return await new DeferredPoller(_signedClient, composed)
                .PollAsync(pendingUrl, cancellationToken).ConfigureAwait(false);
        }
        catch (PollingErrorException ex) when (ex.ErrorCode == PollingErrorCode.Denied)
        {
            // §Polling Error Codes: `denied` (403) is an explicit user/approver
            // denial. Surface the semantic interaction-denied exception so callers
            // can distinguish it from a transport-level polling failure.
            throw new AAuthInteractionDeniedException(
                "The user denied the AAuth interaction request.", ex);
        }
        catch (TimeoutException ex)
        {
            throw new AAuthInteractionTimeoutException(
                $"PS deferred request did not complete within the polling budget: {ex.Message}",
                ex);
        }
    }

    // Stop polling on a clarification 202 so the exchange loop can handle it,
    // preserving any caller-supplied StopWhenAccepted predicate. When
    // <paramref name="stopOnInteraction"/> is set (immediately after a
    // clarification round) the poll also stops on an interaction 202 so the loop
    // can surface it via OnInteractionRequired.
    private static DeferredPollerOptions ComposePollerOptions(
        DeferredPollerOptions? baseOptions, bool stopOnInteraction = false)
    {
        var userStop = baseOptions?.StopWhenAccepted;
        bool Stop(HttpResponseMessage resp)
        {
            if (userStop is not null && userStop(resp)) { return true; }
            var requirement = ExtractRequirement(resp);
            if (requirement?.Requirement == ClarificationRequirement.RequirementType) { return true; }
            return stopOnInteraction
                && requirement?.Requirement == Interaction.RequirementType;
        }

        return baseOptions is null
            ? new DeferredPollerOptions { StopWhenAccepted = Stop }
            : baseOptions with { StopWhenAccepted = Stop };
    }

    private static (bool Terminated, string? MissionStatus) ReadMissionTerminated(string body)
    {
        try
        {
            var json = JsonNode.Parse(body) as JsonObject;
            if ((string?)json?["error"] == AAuthMissionTerminatedException.ErrorCode)
            {
                return (true, (string?)json?["mission_status"]);
            }
        }
        catch (JsonException)
        {
            // Not a mission-terminated body.
        }
        return (false, null);
    }

    private static async Task<(bool Terminated, string? MissionStatus)> TryReadMissionTerminatedAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var body = await BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
        return ReadMissionTerminated(body);
    }

    // Read the body to a string and replace Content with a buffered copy so a
    // non-matching response still flows to the caller's parser.
    internal static async Task<string> BufferBodyAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var mediaType = response.Content.Headers.ContentType?.MediaType ?? "application/json";
        var charset = response.Content.Headers.ContentType?.CharSet;
        Encoding encoding;
        if (string.IsNullOrEmpty(charset))
        {
            encoding = Encoding.UTF8;
        }
        else
        {
            try { encoding = Encoding.GetEncoding(charset); }
            catch (ArgumentException) { encoding = Encoding.UTF8; }
        }
        response.Content.Dispose();
        response.Content = new StringContent(body, encoding, mediaType);
        return body;
    }

    private static async Task<JsonObject?> ReadJsonBodyAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(body)) { return null; }
        try { return JsonNode.Parse(body) as JsonObject; }
        catch (JsonException) { return null; }
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

    private static Uri ResolveLocation(HttpResponseMessage response, Uri @base, Uri? fallback = null)
    {
        var location = response.Headers.Location;
        if (location is null)
        {
            return fallback
                ?? throw new HttpRequestException(
                    "Deferred PS response is missing the Location header — cannot poll.");
        }
        return location.IsAbsoluteUri ? location : new Uri(@base, location);
    }

    internal static void AddIfPresent(JsonObject body, string name, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            body[name] = value;
        }
    }
}
