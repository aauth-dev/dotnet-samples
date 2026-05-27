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
/// <remarks>
/// The AP and the agent never share a keystore. The agent holds the durable
/// <b>private</b> key in its own <see cref="IKeyStore"/>; the AP holds only
/// the <b>public</b> key, indexed in its enrollment database by JWK thumbprint.
/// At refresh time the AP identifies the agent from the HTTP signature
/// (matching the thumbprint of the bound JWK) — never from a string the agent
/// sends. See <c>aauth-spec/draft-hardt-aauth-bootstrap.md</c> § "Refresh Patterns".
/// </remarks>
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

        // Generate a new key pair for this agent.
        // The local handle is the durable key's JWK thumbprint (RFC 7638) —
        // stable, collision-free, derivable from the key itself, and spec-
        // endorsed (§ "Agent Identifier Strategies"). It is a purely local
        // identifier used by IKeyStore; it is never sent to the AP.
        var key = AAuthKey.Generate();
        var localKeyHandle = key.ComputeJwkThumbprint();

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
        var attestation = await _attestor.AttestAsync(localKeyHandle, ct);
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

        // The AP may return an opaque "key_id" — this is the AP-internal JWT
        // `kid` it uses inside the issued agent token. Receivers treat it as
        // opaque (spec § "Agent Identifier Strategies") and the agent never
        // needs to send it back at refresh time. We expose it on the result
        // for diagnostics only; the local keystore key remains the thumbprint.
        var agentTokenKid = (string?)body["key_id"];

        // Persist the key under the local handle (thumbprint).
        await _keyStore.StoreAsync(localKeyHandle, key, ct);

        return new EnrollResult
        {
            AgentToken = agentToken,
            LocalKeyHandle = localKeyHandle,
            AgentTokenKid = agentTokenKid,
            Key = key,
            JwksUri = (string?)body["jwks_uri"],
        };
    }

    /// <summary>
    /// Request a fresh agent token from the AP using the durable key.
    /// </summary>
    /// <remarks>
    /// Signs the request with the durable key per spec (single-key refresh, <c>hwk</c>
    /// scheme). The body is empty — the AP identifies the agent by verifying the
    /// HTTP signature and matching the JWK thumbprint against its enrollment
    /// database. The <paramref name="localKeyHandle"/> never leaves the agent;
    /// it is used only by <see cref="IKeyStore.LoadAsync"/> to load the private key.
    /// </remarks>
    /// <param name="refreshEndpoint">The AP's refresh/token endpoint.</param>
    /// <param name="localKeyHandle">Agent-local <see cref="IKeyStore"/> handle for the durable signing key (returned from <see cref="EnrolAsync"/> as <see cref="EnrollResult.LocalKeyHandle"/>).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>New agent token.</returns>
    public async Task<string> RefreshAsync(
        string refreshEndpoint,
        string localKeyHandle,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(localKeyHandle);

        return await RefreshCoreAsync(refreshEndpoint, localKeyHandle, ct);
    }

    private async Task<string> RefreshCoreAsync(
        string refreshEndpoint,
        string localKeyHandle,
        CancellationToken ct)
    {
        var key = await _keyStore.LoadAsync(localKeyHandle, ct)
            ?? throw new InvalidOperationException($"Key '{localKeyHandle}' not found in store.");

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
    /// <summary>The issued <c>aa-agent+jwt</c> token.</summary>
    public required string AgentToken { get; init; }

    /// <summary>
    /// Agent-local handle for the durable private key inside <see cref="IKeyStore"/>.
    /// Persist this in your application config so the agent can re-load the key
    /// at startup (<c>IKeyStore.LoadAsync(LocalKeyHandle)</c>).
    /// </summary>
    /// <remarks>
    /// Defaults to the durable key's JWK thumbprint (RFC 7638). This value is
    /// purely local — it never leaves the agent process. At refresh time the AP
    /// identifies the agent from the HTTP signature (matching the JWK thumbprint
    /// in its enrollment database), not from this string.
    /// </remarks>
    public required string LocalKeyHandle { get; init; }

    /// <summary>The generated durable signing key (for immediate use without re-loading from the keystore).</summary>
    public required AAuthKey Key { get; init; }

    /// <summary>
    /// AP-internal opaque identifier returned by the AP in the enrollment response
    /// (typically the JWT <c>kid</c> header on the issued agent token). Diagnostic
    /// only — receivers treat it as opaque (spec § "Agent Identifier Strategies"),
    /// and the agent never needs to send it back to refresh.
    /// </summary>
    public string? AgentTokenKid { get; init; }

    /// <summary>
    /// The per-agent JWKS URI where the AP publishes this agent's public key.
    /// Used with <c>scheme=jwks_uri</c> for identity-based access.
    /// Null if the AP didn't provide one.
    /// </summary>
    public string? JwksUri { get; init; }
}
