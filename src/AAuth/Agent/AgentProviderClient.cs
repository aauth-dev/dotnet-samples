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

        // Persist the key
        await _keyStore.StoreAsync(keyId, key, ct);

        return new EnrollResult
        {
            AgentToken = agentToken,
            KeyId = keyId,
            Key = key,
        };
    }

    /// <summary>
    /// Refresh an agent token before expiration. Uses the existing key to
    /// authenticate the refresh request.
    /// </summary>
    /// <param name="refreshEndpoint">The AP's refresh/token endpoint.</param>
    /// <param name="currentAgentToken">The current (still valid) agent token.</param>
    /// <param name="keyId">The key ID to sign the refresh request.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>New agent token.</returns>
    public async Task<string> RefreshAsync(
        string refreshEndpoint,
        string currentAgentToken,
        string keyId,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(currentAgentToken);
        ArgumentException.ThrowIfNullOrEmpty(keyId);

        var key = await _keyStore.LoadAsync(keyId, ct)
            ?? throw new InvalidOperationException($"Key '{keyId}' not found in store.");

        var request = new JsonObject
        {
            ["grant_type"] = "refresh",
            ["agent_token"] = currentAgentToken,
        };

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, refreshEndpoint)
        {
            Content = JsonContent.Create(request),
        };

        using var response = await _http.SendAsync(httpRequest, ct);
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

    /// <summary>The key identifier in the key store.</summary>
    public required string KeyId { get; init; }

    /// <summary>The generated key (for immediate use in signing).</summary>
    public required AAuthKey Key { get; init; }
}
