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
        var resolvedCapabilities = capabilities ?? InferCapabilities(onInteractionRequired);
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

        try
        {
            // Deferred response: the PS needs user interaction (consent /
            // authentication) before it can issue an auth token. The
            // Location header carries the pending URL the agent polls;
            // the AAuth-Requirement header carries the user-facing URL+code.
            if (response.StatusCode == HttpStatusCode.Accepted)
            {
                if (onInteractionRequired is null)
                {
                    throw new HttpRequestException(
                        $"PS returned {(int)response.StatusCode} (deferred response) but no onInteractionRequired callback was provided.");
                }

                var interaction = ExtractInteraction(response);
                if (interaction is not null)
                {
                    await onInteractionRequired(interaction, cancellationToken).ConfigureAwait(false);
                }

                var pendingUrl = ResolveLocation(response, tokenEndpointUri);
                response.Dispose();
                try
                {
                    using var pollActivity = AAuthDiagnostics.Source.StartActivity("AAuth.DeferredPoll");
                    response = await new DeferredPoller(_signedClient, pollerOptions)
                        .PollAsync(pendingUrl, cancellationToken).ConfigureAwait(false);
                }
                catch (TimeoutException ex)
                {
                    throw new AAuthInteractionTimeoutException(
                        $"PS deferred interaction did not complete within the polling budget: {ex.Message}",
                        ex);
                }

                // 403 access_denied → user explicitly denied. Surface a
                // distinct typed exception so UIs / retry policies can
                // treat denial differently from "unknown id" (404) or
                // transport failure.
                if (response.StatusCode == HttpStatusCode.Forbidden
                    && await IsAccessDeniedAsync(response, cancellationToken).ConfigureAwait(false))
                {
                    response.Dispose();
                    throw new AAuthInteractionDeniedException(
                        "The user denied the AAuth interaction request.");
                }
            }

            return await ReadAuthTokenAsync(response, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            response.Dispose();
        }
    }

    // Default capability inference: declare "interaction" when the caller
    // can handle a 202 + user-facing consent redirect. An explicit
    // capabilities list passed to ExchangeAsync overrides this.
    private static IReadOnlyList<string> InferCapabilities(
        Func<AAuthInteraction, CancellationToken, Task>? onInteractionRequired)
        => onInteractionRequired is not null
            ? new[] { "interaction" }
            : Array.Empty<string>();

    private static async Task<bool> IsAccessDeniedAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        // Buffer the body so the subsequent ReadAuthTokenAsync (if we
        // decide it isn't access_denied) still sees it. Preserve the
        // original Content-Type so downstream JSON parsers don't see a
        // surprise text/plain media type.
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

    private static AAuthInteraction? ExtractInteraction(HttpResponseMessage response)
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
            var interaction = AAuthInteraction.FromRequirement(parsed);
            if (interaction is not null) { return interaction; }
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
