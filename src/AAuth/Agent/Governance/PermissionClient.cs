using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;

namespace AAuth.Agent.Governance;

/// <summary>
/// Requests permission for actions not governed by a remote resource at the PS's
/// <c>permission_endpoint</c> (§Permission Endpoint) — tool calls, file writes,
/// sending messages. May be used with or without a mission.
/// </summary>
/// <remarks>
/// The supplied <see cref="HttpClient"/> MUST be wired with an
/// <see cref="HttpSig.AAuthSigningHandler"/>.
/// </remarks>
public sealed class PermissionClient
{
    private readonly DeferredExchange _exchange;
    private readonly string _personServer;

    /// <summary>Create the permission client bound to a Person Server.</summary>
    public PermissionClient(HttpClient signedClient, MetadataClient metadata, string personServer)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        _exchange = new DeferredExchange(signedClient, metadata);
        _personServer = personServer;
    }

    /// <summary>
    /// Request permission for <paramref name="request"/> from the bound PS.
    /// Handles deferred (user-input) responses.
    /// </summary>
    public async Task<PermissionResult> RequestAsync(
        PermissionRequest request,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var endpoint = await _exchange.ResolveEndpointAsync(
            _personServer, "permission_endpoint", cancellationToken).ConfigureAwait(false);

        var response = await _exchange.PostAsync(
            endpoint, request.ToJsonObject(),
            options?.ToExchangeOptions() ?? new DeferredExchangeOptions(), cancellationToken).ConfigureAwait(false);
        try
        {
            if (!response.IsSuccessStatusCode)
            {
                var error = await DeferredExchange.BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
                throw new HttpRequestException(
                    $"Permission request failed with {(int)response.StatusCode}: {error}");
            }

            var raw = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            JsonObject? json;
            try { json = JsonNode.Parse(raw) as JsonObject; }
            catch (JsonException ex)
            {
                throw new HttpRequestException("Permission response body is not valid JSON.", ex);
            }
            if (json is null)
            {
                throw new HttpRequestException("Permission response body is not a JSON object.");
            }
            return PermissionResult.FromJson(json);
        }
        finally
        {
            response.Dispose();
        }
    }

    /// <summary>
    /// Request permission for <paramref name="action"/> within
    /// <paramref name="mission"/>, short-circuiting to <see cref="PermissionGrant.Granted"/>
    /// when the action is a pre-approved tool on the mission (§Permission Endpoint —
    /// "the agent calls the permission endpoint only for actions not covered by
    /// pre-approved tools"). Otherwise calls the PS.
    /// </summary>
    public Task<PermissionResult> RequestAsync(
        MissionAction action,
        Mission mission,
        string? description = null,
        JsonObject? parameters = null,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentException.ThrowIfNullOrEmpty(action.Name);
        ArgumentNullException.ThrowIfNull(mission);

        foreach (var tool in mission.ApprovedTools)
        {
            if (string.Equals(tool.Name, action.Name, StringComparison.Ordinal))
            {
                return Task.FromResult(new PermissionResult(
                    PermissionGrant.Granted, "Pre-approved tool on the active mission."));
            }
        }

        var request = new PermissionRequest(action)
        {
            Description = description,
            Parameters = parameters,
            Mission = new Tokens.MissionClaim(mission.Approver, mission.S256),
        };
        return RequestAsync(request, options, cancellationToken);
    }
}
