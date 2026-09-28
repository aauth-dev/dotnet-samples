using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;

namespace AAuth.Agent.Governance;

/// <summary>
/// The agent's surface for the missions it owns at the PS's <c>mission_endpoint</c>:
/// propose (§Mission Creation, §Mission Approval), update (§Mission Update), and
/// propose completion (§Mission Completion).
/// </summary>
/// <remarks>
/// The supplied <see cref="HttpClient"/> MUST be wired with an
/// <see cref="HttpSig.AAuthSigningHandler"/> so each request is signed and
/// carries the agent token via <c>Signature-Key</c>.
/// </remarks>
public sealed class MissionClient
{
    private readonly DeferredExchange _exchange;
    private readonly string _personServer;

    /// <summary>Create the mission client bound to a Person Server.</summary>
    /// <param name="signedClient">HttpClient wired with an <see cref="HttpSig.AAuthSigningHandler"/>.</param>
    /// <param name="metadata">Metadata client for resolving the PS <c>mission_endpoint</c>.</param>
    /// <param name="personServer">The PS this client targets.</param>
    public MissionClient(HttpClient signedClient, MetadataClient metadata, string personServer)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        _exchange = new DeferredExchange(signedClient, metadata);
        _personServer = personServer;
    }

    /// <summary>
    /// Propose a mission to the bound PS and return the approved
    /// <see cref="Mission"/>. Handles the <c>202</c> review / clarification path
    /// via <paramref name="options"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The approval response is malformed, or its <c>s256</c> does not match the mission blob.
    /// </exception>
    public async Task<Mission> ProposeAsync(
        MissionProposal proposal,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proposal);
        var endpoint = await _exchange.ResolveEndpointAsync(
            _personServer, "mission_endpoint", cancellationToken).ConfigureAwait(false);
        using var response = await PostAsync(endpoint, proposal.ToJsonObject(), options, "Mission proposal", cancellationToken)
            .ConfigureAwait(false);
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        return Mission.FromApprovalResponse(bytes, _personServer);
    }

    /// <summary>
    /// Record a change in the work (§Mission Update). Returns the accepted update's
    /// <c>s256</c>. The mission and its <c>mission_s256</c> are unchanged.
    /// </summary>
    public async Task<string> UpdateAsync(
        Mission mission,
        string description,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mission);
        ArgumentException.ThrowIfNullOrEmpty(description);
        using var response = await PostActionAsync(mission,
            new JsonObject { ["action"] = "update", ["description"] = description }, options, "Mission update", cancellationToken)
            .ConfigureAwait(false);
        var body = await ReadObjectAsync(response, cancellationToken).ConfigureAwait(false);
        return (string?)body?["s256"]
            ?? throw new HttpRequestException("Mission update response is missing 's256'.");
    }

    /// <summary>
    /// Propose that the mission is finished (§Mission Completion). Returns
    /// <see langword="true"/> when the person accepted and the PS terminated the
    /// mission; <see langword="false"/> when the mission stays active.
    /// </summary>
    public async Task<bool> CompleteAsync(
        Mission mission,
        string summary,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mission);
        ArgumentException.ThrowIfNullOrEmpty(summary);
        using var response = await PostActionAsync(mission,
            new JsonObject { ["action"] = "completion", ["summary"] = summary }, options, "Mission completion", cancellationToken)
            .ConfigureAwait(false);
        var body = await ReadObjectAsync(response, cancellationToken).ConfigureAwait(false);
        return (string?)body?["mission_status"] != "active";
    }

    private async Task<HttpResponseMessage> PostActionAsync(
        Mission mission, JsonObject body, GovernanceOptions? options, string operation, CancellationToken cancellationToken)
    {
        var endpoint = await _exchange.ResolveEndpointAsync(
            _personServer, "mission_endpoint", cancellationToken).ConfigureAwait(false);
        var target = new Uri(endpoint.ToString().TrimEnd('/') + "/" + Uri.EscapeDataString(mission.S256));
        return await PostAsync(target, body, options, operation, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> PostAsync(
        Uri endpoint, JsonObject body, GovernanceOptions? options, string operation, CancellationToken cancellationToken)
    {
        var response = await _exchange.PostAsync(
            endpoint, body,
            options?.ToExchangeOptions() ?? new DeferredExchangeOptions(), cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessStatusCode) return response;
        try
        {
            var error = await DeferredExchange.BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode == System.Net.HttpStatusCode.Forbidden && error.Contains("mission_terminated", StringComparison.Ordinal))
                throw new AAuth.Errors.AAuthMissionTerminatedException("terminated");
            throw new HttpRequestException($"{operation} failed with {(int)response.StatusCode}: {error}");
        }
        finally
        {
            response.Dispose();
        }
    }

    private static async Task<JsonObject?> ReadObjectAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var raw = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(raw)) return null;
        try { return JsonNode.Parse(raw) as JsonObject; }
        catch (JsonException) { return null; }
    }
}
