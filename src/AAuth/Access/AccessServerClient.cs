using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;

namespace AAuth.Access;

/// <summary>
/// Performs the signed Person Server → Access Server token request and the
/// deferred loop (four-party / federated flow). Returns the AS-issued auth
/// token (<c>aa-auth+jwt</c>) after verifying it per §Auth Token Delivery.
/// </summary>
/// <remarks>
/// <para>The HTTP POST to the AS's <c>auth_token_endpoint</c> MUST be signed with
/// the PS's key (RFC 9421) and carry the PS's <c>jwks_uri</c> in
/// <c>Signature-Key</c>. The caller supplies an <see cref="HttpClient"/>
/// wrapped in an <see cref="HttpSig.AAuthSigningHandler"/> configured for the
/// <c>jwks_uri</c> scheme, just like any other outbound AAuth request.</para>
/// <para>This client recognises a <c>402 Payment Required</c> response,
/// dispatches <see cref="AccessServerRequest.OnPaymentRequired"/>, then polls
/// the AS pending <c>Location</c> after settlement. A <c>202 requirement=claims</c>
/// response (§Claims Required) drives the identity-claims push: the requested
/// claim names are handed to <see cref="AccessServerRequest.OnClaimsRequired"/>,
/// the returned claims (never <c>sub</c>) are POSTed — signed —
/// to the AS's pending <c>Location</c> URL, and the client then resumes polling
/// for the issued auth token. When the AS asks for claims but no
/// <see cref="AccessServerRequest.OnClaimsRequired"/> handler is configured the
/// call surfaces a <see cref="NotSupportedException"/>.</para>
/// </remarks>
public sealed class AccessServerClient
{
    private readonly HttpClient _signedClient;
    private readonly MetadataClient _metadata;
    private readonly AuthTokenResponseValidator _validator;

    /// <summary>Create the federation client.</summary>
    /// <param name="signedClient">HttpClient already wired with the PS's <see cref="HttpSig.AAuthSigningHandler"/> (jwks_uri scheme).</param>
    /// <param name="metadata">Metadata client for resolving the AS <c>auth_token_endpoint</c>.</param>
    /// <param name="validator">Validator for the §Auth Token Delivery checks on the AS response.</param>
    public AccessServerClient(
        HttpClient signedClient,
        MetadataClient metadata,
        AuthTokenResponseValidator validator)
    {
        ArgumentNullException.ThrowIfNull(signedClient);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(validator);
        _signedClient = signedClient;
        _metadata = metadata;
        _validator = validator;
    }

    /// <summary>
    /// Submit the resource + agent tokens to the Access Server at
    /// <paramref name="accessServer"/> and return the verified auth token.
    /// </summary>
    /// <param name="accessServer">AS issuer URL (the resource token's <c>aud</c>; used to fetch <c>aauth-access.json</c>).</param>
    /// <param name="request">Federation parameters and delivery-verification context.</param>
    /// <param name="cancellationToken">Caller cancellation.</param>
    /// <returns>The verified compact <c>aa-auth+jwt</c> from the AS.</returns>
    public async Task<string> FederateAsync(
        string accessServer,
        AccessServerRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(accessServer);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrEmpty(request.ResourceToken);
        ArgumentException.ThrowIfNullOrEmpty(request.AgentToken);
        ArgumentException.ThrowIfNullOrEmpty(request.PresentedToken);
        ArgumentException.ThrowIfNullOrEmpty(request.ExpectedAudience);
        ArgumentException.ThrowIfNullOrEmpty(request.ExpectedSubject);
        ArgumentException.ThrowIfNullOrEmpty(request.ExpectedPersonServer);
        ArgumentNullException.ThrowIfNull(request.AgentKey);

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(TimeSpan.FromMinutes(10));
        cancellationToken = budget.Token;
        Uri? activePendingUrl = null;
        if (request.AuthorizationExpiresAt.ToUnixTimeSeconds() <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            throw new TokenVerificationException("The verified authorization context has expired.");

        using var activity = AAuthDiagnostics.Source.StartActivity("AAuth.AccessServerFederation");

        var metadataUrl = _metadata.GetUrl(accessServer, AAuthConstants.DwkFiles.Access);
        var doc = await _metadata.FetchAsync(metadataUrl, cancellationToken).ConfigureAwait(false);
        var tokenEndpoint = (string?)doc["auth_token_endpoint"]
            ?? throw new InvalidOperationException(
                $"Access Server metadata at {metadataUrl} is missing 'auth_token_endpoint'.");

        // A malicious or compromised AS metadata document could otherwise
        // redirect the signed federation request to an arbitrary URL (SSRF
        // pivot for the PS) or downgrade it to plain http. Require the same
        // https-or-loopback policy used elsewhere, and pin the endpoint to the
        // same origin as the configured AS so a metadata compromise can't
        // divert the signed request off-host.
        var tokenEndpointUri = _metadata.Policy.ValidateUrl(tokenEndpoint, endpoint: true);
        if (!Uri.TryCreate(accessServer, UriKind.Absolute, out var asUri)
            || !string.Equals(
                tokenEndpointUri.GetLeftPart(UriPartial.Authority),
                asUri.GetLeftPart(UriPartial.Authority),
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Access Server 'auth_token_endpoint' must share an origin with {accessServer}: {tokenEndpoint}");
        }

        var body = new JsonObject
        {
            ["resource_token"] = request.ResourceToken,
            ["agent_token"] = request.AgentToken,
            ["presented_token"] = request.PresentedToken,
        };
        if (!string.IsNullOrEmpty(request.UpstreamToken))
        {
            body["upstream_token"] = request.UpstreamToken;
        }
        if (!string.IsNullOrEmpty(request.SubagentToken))
        {
            body["subagent_token"] = request.SubagentToken;
        }

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, tokenEndpointUri)
        {
            Content = JsonContent.Create(body),
        };
        if (request.PollerOptions?.PreferWaitSeconds is { } preferWait)
        {
            httpRequest.Headers.TryAddWithoutValidation("Prefer", $"wait={preferWait}");
        }

        var response = await AAuthHttpTransport.SendAsync(_signedClient, httpRequest, cancellationToken).ConfigureAwait(false);

        try
        {
            // Deferred response: the AS needs interaction (consent) and/or
            // identity claims before it can issue an auth token. Per spec
            // §Trust Establishment these mechanisms COMPOSE onto a single
            // Location (e.g. 402 → interaction → claims), so loop until the
            // response is terminal, dispatching each requirement in turn.
            // Bounded to guard against a misbehaving AS that never resolves.
            const int maxCompositionSteps = 16;
            var compositionSteps = 0;
            Interaction? deliveredInteraction = null;
            while (response.StatusCode is HttpStatusCode.Accepted or HttpStatusCode.PaymentRequired)
            {
                if (++compositionSteps > maxCompositionSteps)
                {
                    response.Dispose();
                    throw new HttpRequestException(
                        $"Access Server exceeded {maxCompositionSteps} composed deferred-requirement steps without issuing an auth token.");
                }

                if (response.StatusCode == HttpStatusCode.PaymentRequired)
                {
                    activePendingUrl = ResolveSameOriginLocation(response, tokenEndpointUri, asUri);
                    var challenge = await AAuthPaymentChallenge.FromResponseAsync(response, cancellationToken)
                        .ConfigureAwait(false);
                    response.Dispose();
                    if (request.OnPaymentRequired is null)
                    {
                        throw new NotSupportedException(
                            "Access Server returned 402 Payment Required, but no OnPaymentRequired handler is configured.");
                    }
                    var settlement = await request.OnPaymentRequired(new AAuthPaymentSettlementContext
                    {
                        Challenge = challenge,
                        AccessServerOrigin = asUri.GetLeftPart(UriPartial.Authority),
                        PendingUrl = activePendingUrl,
                    }, cancellationToken).ConfigureAwait(false)
                        ?? throw new InvalidOperationException(
                            "AccessServerRequest.OnPaymentRequired returned null; expected a settlement result.");
                    if (!settlement.Settled)
                    {
                        throw new AAuthTokenExchangeException(
                            "denied", "payment settlement is unavailable", StatusCodes.Status403Forbidden, true);
                    }
                    response = await PollDeferredAsync(activePendingUrl, request.PollerOptions, deliveredInteraction, cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }

                var requirement = ExtractRequirementType(response);
                activePendingUrl = ResolveSameOriginLocation(response, tokenEndpointUri, asUri);

                // requirement=claims (§Claims Required) is a spec-mandated
                // active identity-claims PUSH: read the requested claim names,
                // ask the caller to supply them (never `sub`), POST them signed
                // to the Location, then resume polling the same URL.
                if (requirement == ClarificationRequirement.RequirementType)
                {
                    if (request.OnClarificationRequired is null)
                        throw new NotSupportedException("AS clarification requires OnClarificationRequired.");
                    var clarificationBody = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken);
                    var clarification = ClarificationRequirement.FromResponse(
                        AAuthRequirementHeader.Parse("requirement=clarification"), clarificationBody)!;
                    response.Dispose();
                    using var roundBudget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    roundBudget.CancelAfter(TimeSpan.FromSeconds(clarification.TimeoutSeconds ?? 300));
                    var answer = await request.OnClarificationRequired(clarification, roundBudget.Token)
                        .WaitAsync(roundBudget.Token).ConfigureAwait(false);
                    await new ClarificationExchange(_signedClient, activePendingUrl).ApplyAsync(answer, roundBudget.Token);
                    response = await PollDeferredAsync(activePendingUrl, request.PollerOptions, deliveredInteraction, cancellationToken);
                }
                else if (string.Equals(requirement, ClaimsRequirement.RequirementType, StringComparison.Ordinal))
                {
                    if (request.OnClaimsRequired is null)
                    {
                        response.Dispose();
                        throw new NotSupportedException(
                            "Access Server returned 202 requirement=claims, but no OnClaimsRequired handler is configured. "
                            + "Set AccessServerRequest.OnClaimsRequired to supply directed identity claims.");
                    }

                    var claimsRequirement = await ExtractClaimsRequirementAsync(response, cancellationToken).ConfigureAwait(false);
                    if (ClaimsRequirement.ContainsForbiddenClaimName(claimsRequirement.RequiredClaims))
                        throw new TokenVerificationException("Requested identity claims contain protocol-owned names.");
                    var claimsPendingUrl = ResolveSameOriginLocation(response, tokenEndpointUri, asUri);
                    response.Dispose();

                    var claimsResponse = await request.OnClaimsRequired(claimsRequirement, cancellationToken).ConfigureAwait(false)
                        ?? throw new InvalidOperationException(
                            "AccessServerRequest.OnClaimsRequired returned null; expected a ClaimsResponse.");

                    var pushResponse = await PushClaimsAsync(claimsPendingUrl, claimsResponse.ToJson(), cancellationToken).ConfigureAwait(false);
                    if (pushResponse.StatusCode == HttpStatusCode.Accepted && !IsActionable(pushResponse, deliveredInteraction))
                    {
                        // Still pending after the push — poll the same URL.
                        // Mechanisms compose, so stop polling if the next 202
                        // is itself a requirement=claims (handled next loop).
                        pushResponse.Dispose();
                        response = await PollDeferredAsync(claimsPendingUrl, request.PollerOptions, deliveredInteraction, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        // The push response itself carries the verdict (200
                        // auth_token, 403 `denied`, or a structured error).
                        response = pushResponse;
                    }

                    if (response.StatusCode == HttpStatusCode.Forbidden
                        && await IsDeniedAsync(response, cancellationToken).ConfigureAwait(false))
                    {
                        var detail = await AAuth.Agent.InteractionDenial.ReadDetailAsync(response, cancellationToken).ConfigureAwait(false);
                        response.Dispose();
                        throw new AAuthInteractionDeniedException(string.IsNullOrWhiteSpace(detail)
                            ? "The Access Server denied the request after the claims push." : detail);
                    }
                }
                else
                {
                    var interaction = ExtractInteraction(response);
                    if (interaction is not null)
                    {
                        if (request.OnInteractionRequired is null)
                            throw new HttpRequestException("AS interaction requires OnInteractionRequired.");
                        await AAuthHttpTransport.AdmitInteractionAsync(_signedClient, interaction.Url, cancellationToken).ConfigureAwait(false);
                        await request.OnInteractionRequired(interaction, cancellationToken).ConfigureAwait(false);
                        deliveredInteraction = interaction;
                    }

                    var pendingUrl = ResolveLocation(response, tokenEndpointUri);
                    response.Dispose();
                    // Poll the same Location; stop early if the AS escalates to
                    // requirement=claims so the next loop can push the claims.
                    response = await PollDeferredAsync(pendingUrl, request.PollerOptions, deliveredInteraction, cancellationToken).ConfigureAwait(false);

                    if (response.StatusCode == HttpStatusCode.Forbidden
                        && await IsDeniedAsync(response, cancellationToken).ConfigureAwait(false))
                    {
                        var detail = await AAuth.Agent.InteractionDenial.ReadDetailAsync(response, cancellationToken).ConfigureAwait(false);
                        response.Dispose();
                        // The PS relays this message to the agent as the `denied` detail.
                        throw new AAuthInteractionDeniedException(
                            string.IsNullOrWhiteSpace(detail) ? AAuth.Agent.InteractionDenial.DefaultMessage : detail);
                    }
                }
            }

            var authToken = await ReadAuthTokenAsync(response, cancellationToken).ConfigureAwait(false);

            // §Auth Token Delivery (steps 1–7): the PS MUST verify the AS auth
            // token before returning it to the agent.
            var delivery = await _validator.ValidateAsync(
                authToken,
                expectedIssuer: accessServer,
                expectedAudience: request.ExpectedAudience,
                expectedSubject: request.ExpectedSubject,
                expectedPersonServer: request.ExpectedPersonServer,
                agentKey: request.AgentKey,
                presentedTokenExpiresAt: request.PresentedTokenExpiresAt,
                requestedScope: request.RequestedScope,
                ct: cancellationToken,
                expectedAccount: request.Account).ConfigureAwait(false);

            if (!delivery.IsValid)
            {
                throw new TokenVerificationException(
                    $"Auth token delivery verification failed: {delivery.Error}");
            }

            if (delivery.Verified!.MissionS256 != request.ExpectedMissionS256)
                throw new TokenVerificationException("Auth token delivery mission differs from the resource request.");

            if (delivery.Verified!.ExpiresAt > request.AuthorizationExpiresAt
                || delivery.Verified.ExpiresAt.ToUnixTimeSeconds() <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            {
                throw new TokenVerificationException("Auth token delivery exceeds the verified authorization lifetime.");
            }

            return authToken;
        }
        catch (Exception ex) when (ex is OperationCanceledException or TimeoutException or AAuthInteractionTimeoutException)
        {
            if (activePendingUrl is not null)
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try { await new ClarificationExchange(_signedClient, activePendingUrl).CancelAsync(cleanup.Token); }
                catch (Exception cleanupError) when (cleanupError is HttpRequestException or OperationCanceledException) { }
            }
            throw;
        }
        finally
        {
            response.Dispose();
        }
    }

    private static string? ExtractRequirementType(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(AAuthRequirementHeader.Name, out var values))
        {
            return null;
        }
        foreach (var raw in values)
        {
            if (string.IsNullOrWhiteSpace(raw)) { continue; }
            try { return AAuthRequirementHeader.Parse(raw).Requirement; }
            catch (FormatException) { continue; }
        }
        return null;
    }

    private Interaction? ExtractInteraction(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(AAuthRequirementHeader.Name, out var values))
        {
            return null;
        }
        foreach (var raw in values)
        {
            if (string.IsNullOrWhiteSpace(raw)) { continue; }
            AAuthRequirementHeader.ParsedRequirement parsed;
            try { parsed = AAuthRequirementHeader.Parse(raw); }
            catch (FormatException) { continue; }
            var interaction = Interaction.FromRequirement(parsed, _metadata.Policy);
            if (interaction is not null) { return interaction; }
        }
        return null;
    }

    /// <summary>
    /// Read a <c>202 requirement=claims</c> response's requested claim names
    /// from the body's <c>required_claims</c> array (§Claims Required puts the
    /// claim names only in the body, never the <c>AAuth-Requirement</c> header).
    /// </summary>
    private static async Task<ClaimsRequirement> ExtractClaimsRequirementAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        JsonObject? body = null;
        if (response.Content is not null)
        {
            var raw = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(raw))
            {
                try { body = JsonNode.Parse(raw) as JsonObject; }
                catch (System.Text.Json.JsonException) { body = null; }
            }
        }

        if (response.Headers.TryGetValues(AAuthRequirementHeader.Name, out var values))
        {
            foreach (var raw in values)
            {
                if (string.IsNullOrWhiteSpace(raw)) { continue; }
                AAuthRequirementHeader.ParsedRequirement parsed;
                try { parsed = AAuthRequirementHeader.Parse(raw); }
                catch (FormatException) { continue; }
                ClaimsRequirement? requirement;
                try { requirement = ClaimsRequirement.FromResponse(parsed, body); }
                catch (FormatException ex)
                {
                    throw new HttpRequestException(
                        $"Access Server returned 202 requirement=claims but the claim names were malformed: {ex.Message}");
                }
                if (requirement is not null) { return requirement; }
            }
        }

        throw new HttpRequestException(
            "Access Server returned 202 requirement=claims but no claim names could be resolved.");
    }

    /// <summary>
    /// POST the supplied identity claims (signed via the PS's HTTP-Sig client)
    /// to the AS's pending <c>Location</c> URL per §Claims Required.
    /// </summary>
    private async Task<HttpResponseMessage> PushClaimsAsync(
        Uri pendingUrl, JsonObject claims, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, pendingUrl)
        {
            Content = JsonContent.Create(claims),
        };
        return await AAuthHttpTransport.SendAsync(_signedClient, request, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Poll a pending <c>Location</c> to its terminal verdict, but stop early
    /// and return a <c>202</c> carrying claims, clarification, or a new
    /// interaction. The caller dispatches that requirement on the next loop
    /// iteration; repeated copies of the current interaction keep polling.
    /// </summary>
    private async Task<HttpResponseMessage> PollDeferredAsync(
        Uri pendingUrl, DeferredPollerOptions? baseOptions, Interaction? deliveredInteraction, CancellationToken cancellationToken)
    {
        var options = (baseOptions ?? new DeferredPollerOptions()) with
        {
            StopWhenAccepted = response => IsActionable(response, deliveredInteraction),
        };
        try
        {
            using var pollActivity = AAuthDiagnostics.Source.StartActivity("AAuth.DeferredPoll");
            return await new DeferredPoller(_signedClient, options)
                .PollAsync(pendingUrl, cancellationToken).ConfigureAwait(false);
        }
        catch (PollingErrorException ex) when (ex.ErrorCode == PollingErrorCode.Denied)
        {
            // §Polling Error Codes: `denied` (403) is an explicit denial. Surface
            // the semantic interaction-denied exception so callers can distinguish
            // it from a transport-level polling failure.
            throw new AAuthInteractionDeniedException(
                "The Access Server denied the request.", ex);
        }
        catch (TimeoutException ex)
        {
            throw new AAuthInteractionTimeoutException(
                $"Access Server deferred response did not resolve within the polling budget: {ex.Message}",
                ex);
        }
    }

    private bool IsActionable(HttpResponseMessage response, Interaction? deliveredInteraction)
        => ExtractRequirementType(response) is ClaimsRequirement.RequirementType or ClarificationRequirement.RequirementType
            || (ExtractInteraction(response) is { } interaction
                && (interaction.Url != deliveredInteraction?.Url || interaction.Code != deliveredInteraction?.Code));

    private Uri ResolveLocation(HttpResponseMessage response, Uri @base)
    {
        var location = response.Headers.Location
            ?? throw new HttpRequestException(
                "Deferred Access Server response is missing the Location header — cannot poll.");
        return _metadata.Policy.ValidatePendingLocation(@base, location);
    }

    /// <summary>
    /// Resolve the pending <c>Location</c> and pin it to the AS's origin. The
    /// claims push carries a directed user identifier, so a relocated Location
    /// (e.g. from a tampered response) must not be allowed to exfiltrate it to
    /// another host.
    /// </summary>
    private Uri ResolveSameOriginLocation(HttpResponseMessage response, Uri @base, Uri origin)
    {
        var pendingUrl = ResolveLocation(response, @base);
        if (!string.Equals(
                pendingUrl.GetLeftPart(UriPartial.Authority),
                origin.GetLeftPart(UriPartial.Authority),
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Access Server claims Location must share an origin with {origin.GetLeftPart(UriPartial.Authority)}: {pendingUrl}");
        }
        return pendingUrl;
    }

    private static async Task<bool> IsDeniedAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        // Buffer the body so a subsequent ReadAuthTokenAsync still sees it,
        // preserving the original Content-Type so downstream JSON parsers
        // don't see a surprise media type.
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var originalMediaType = response.Content.Headers.ContentType?.MediaType ?? "application/json";
        var originalCharset = response.Content.Headers.ContentType?.CharSet;
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

    private static async Task<string> ReadAuthTokenAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            // The token endpoint signals failure with a JSON body carrying a
            // required 'error' code and optional 'detail'
            // (§Token Endpoint Error Response Format). Surface those as a typed
            // exception; non-AAuth bodies fall back to HttpRequestException.
            var errorCode = TryReadErrorCode(responseBody, out var detail);
            if (errorCode is not null)
            {
                throw new AAuthTokenExchangeException(
                    errorCode, detail, (int)response.StatusCode,
                    AAuthTokenExchangeException.IsTerminalCode(errorCode));
            }

            throw new HttpRequestException(
                $"Access Server federation failed with HTTP status {(int)response.StatusCode}.", null, response.StatusCode);
        }

        var json = JsonNode.Parse(responseBody) as JsonObject
            ?? throw new InvalidOperationException("Access Server response was not a JSON object.");
        return (string?)json["auth_token"]
            ?? throw new InvalidOperationException("Access Server response did not include 'auth_token'.");
    }

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
