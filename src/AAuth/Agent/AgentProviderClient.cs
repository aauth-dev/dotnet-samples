using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;

namespace AAuth.Agent;

/// <summary>
/// Agent-side client for Agent Provider (AP) bootstrap and refresh flows (§7).
/// Handles enrollment (generating a key, registering with the AP) and
/// refreshing agent tokens before expiration.
/// </summary>
public sealed class AgentProviderClient
{
    private readonly HttpClient _http;
    private readonly IKeyStore _keyStore;
    private readonly IPlatformAttestor _attestor;

    /// <summary>Create the client.</summary>
    /// <param name="http">HttpClient for AP communication.</param>
    /// <param name="keyStore">Key store for persisting the durable agent key.</param>
    /// <param name="attestor">Platform attestor (optional, defaults to no-op).</param>
    public AgentProviderClient(HttpClient http, IKeyStore keyStore, IPlatformAttestor? attestor = null)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(keyStore);
        _http = http;
        _keyStore = keyStore;
        _attestor = attestor ?? new NoopAttestor();
    }

    /// <summary>
    /// Enrol with an Agent Provider. Generates a new key pair, registers the
    /// public key with the AP, and returns the issued agent token.
    /// </summary>
    /// <param name="apIssuer">The AP's issuer URL.</param>
    /// <param name="agentId">Desired agent identifier (e.g. aauth:myagent@example.com).</param>
    /// <param name="enrollEndpoint">The AP's enrollment endpoint URL.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The issued agent token (JWT).</returns>
    public async Task<EnrollResult> EnrolAsync(
        string apIssuer,
        string agentId,
        string enrollEndpoint,
        string? personServer = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(apIssuer);
        ArgumentException.ThrowIfNullOrEmpty(agentId);
        ArgumentException.ThrowIfNullOrEmpty(enrollEndpoint);

        // Generate a new key pair for this agent
        var key = AAuthKey.Generate();
        var keyId = $"{agentId}:{Guid.NewGuid():N}";

        // Build enrollment request
        var request = new JsonObject
        {
            ["agent_id"] = agentId,
            ["jwk"] = key.ToPublicJwk(),
        };
        if (!string.IsNullOrEmpty(personServer))
        {
            request["ps"] = personServer;
        }

        // Platform attestation if supported
        var attestation = await _attestor.AttestAsync(keyId, ct);
        if (!string.IsNullOrEmpty(attestation))
        {
            request["attestation"] = attestation;
        }

        using var response = await _http.PostAsJsonAsync(enrollEndpoint, request, ct);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonObject>(ct)
            ?? throw new InvalidOperationException("AP enrollment response is not a JSON object.");

        var agentToken = (string?)body["agent_token"]
            ?? throw new InvalidOperationException("AP enrollment response missing 'agent_token'.");

        // Use the kid assigned by the AP (authoritative), falling back to locally generated one
        var assignedKeyId = (string?)body["key_id"] ?? keyId;

        // Persist the key
        await _keyStore.StoreAsync(assignedKeyId, key, ct);

        return new EnrollResult
        {
            AgentToken = agentToken,
            EnrolledKeyId = assignedKeyId,
            Key = key,
            JwksUri = (string?)body["jwks_uri"],
        };
    }

    /// <summary>
    /// Refresh an agent token. Signs the request with the durable key per spec
    /// (single-key refresh, hwk scheme). The AP identifies the agent by verifying
    /// the HTTP signature and matching the JWK thumbprint against its enrollment database.
    /// </summary>
    /// <param name="refreshEndpoint">The AP's refresh/token endpoint.</param>
    /// <param name="currentAgentToken">The current agent token (informational, not required by spec).</param>
    /// <param name="enrolledKeyId">Local keystore reference to load the durable signing key.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>New agent token.</returns>
    public async Task<string> RefreshAsync(
        string refreshEndpoint,
        string currentAgentToken,
        string enrolledKeyId,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(currentAgentToken);
        ArgumentException.ThrowIfNullOrEmpty(enrolledKeyId);

        return await RefreshCoreAsync(refreshEndpoint, enrolledKeyId, ct);
    }

    /// <summary>
    /// Request a fresh agent token from the AP using only the durable key.
    /// Used for initial token acquisition (lazy startup) when no current token exists.
    /// The AP identifies the agent by verifying the HTTP signature and matching
    /// the JWK thumbprint against its enrollment database.
    /// </summary>
    /// <param name="refreshEndpoint">The AP's refresh/token endpoint.</param>
    /// <param name="enrolledKeyId">Local keystore reference to load the durable signing key.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>New agent token.</returns>
    public async Task<string> RefreshAsync(
        string refreshEndpoint,
        string enrolledKeyId,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(enrolledKeyId);

        return await RefreshCoreAsync(refreshEndpoint, enrolledKeyId, ct);
    }

    private async Task<string> RefreshCoreAsync(
        string refreshEndpoint,
        string enrolledKeyId,
        CancellationToken ct)
    {
        var key = await _keyStore.LoadAsync(enrolledKeyId, ct)
            ?? throw new InvalidOperationException($"Key '{enrolledKeyId}' not found in store.");

        // Per spec: single-key refresh signs the POST with the durable key (hwk scheme).
        // The body is empty — the AP identifies the agent via the signature.
        using var signingHandler = new HttpSig.AAuthSigningHandler(
            key, new HttpSig.HwkSignatureKeyProvider(key))
        {
            InnerHandler = new HttpClientHandler(),
        };
        using var signedClient = new HttpClient(signingHandler);

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, refreshEndpoint)
        {
            Content = JsonContent.Create(new JsonObject()),
        };

        using var response = await signedClient.SendAsync(httpRequest, ct);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonObject>(ct)
            ?? throw new InvalidOperationException("AP refresh response is not a JSON object.");

        return (string?)body["agent_token"]
            ?? throw new InvalidOperationException("AP refresh response missing 'agent_token'.");
    }
}

/// <summary>Result of enrolling with an Agent Provider.</summary>
public sealed class EnrollResult
{
    /// <summary>The issued agent token.</summary>
    public required string AgentToken { get; init; }

    /// <summary>The AP-assigned key identifier used as the local keystore reference. The AP identifies the agent by JWK thumbprint at refresh time, not by this string.</summary>
    public required string EnrolledKeyId { get; init; }

    /// <summary>The generated key (for immediate use in signing).</summary>
    public required AAuthKey Key { get; init; }

    /// <summary>
    /// The per-agent JWKS URI where the AP publishes this agent's public key.
    /// Used with <c>scheme=jwks_uri</c> for identity-based access.
    /// Null if the AP didn't provide one.
    /// </summary>
    public string? JwksUri { get; init; }
}
