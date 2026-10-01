using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;
using AAuth.Tokens;

namespace AAuth.Agent.Governance;

/// <summary>
/// Reaches the user through the PS's <c>interaction_endpoint</c> (§Interaction
/// Endpoint): relay resource interactions, forward payments, or ask questions.
/// Mission completion is proposed at the mission endpoint
/// (<see cref="MissionClient.CompleteAsync"/>). For resource-hosted
/// interactions, the resource's original pending URL remains authoritative; the
/// PS relay result only reports relay progress or unavailability. May be used
/// with or without a mission.
/// </summary>
/// <remarks>
/// The supplied <see cref="HttpClient"/> MUST be wired with an
/// <see cref="HttpSig.AAuthSigningHandler"/>.
/// </remarks>
public sealed class InteractionClient
{
    private readonly DeferredExchange _exchange;
    private readonly string _personServer;

    /// <summary>Create the interaction client bound to a Person Server.</summary>
    public InteractionClient(HttpClient signedClient, MetadataClient metadata, string personServer)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        _exchange = new DeferredExchange(signedClient, metadata);
        _personServer = personServer;
    }

    /// <summary>
    /// Send <paramref name="request"/> to the bound PS and return the terminal
    /// result, polling through any deferred response.
    /// </summary>
    public async Task<InteractionResult> SendAsync(
        InteractionRequest request,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Type == InteractionType.Completion)
            throw new ArgumentException("Mission completion is proposed at the mission endpoint (MissionClient.CompleteAsync).", nameof(request));

        var endpoint = await _exchange.ResolveEndpointAsync(
            _personServer, "interaction_endpoint", cancellationToken).ConfigureAwait(false);

        var response = await _exchange.PostAsync(
            endpoint, request.ToJsonObject(),
            options?.ToExchangeOptions() ?? new DeferredExchangeOptions(), cancellationToken).ConfigureAwait(false);
        try
        {
            // §Interaction Endpoint Errors: 424 interaction_unavailable is
            // non-terminal — the PS cannot relay this specific interaction, so the
            // agent falls back to directing the user itself. Surface it as a
            // structured result, not an exception (per the migration ruling Q5).
            if ((int)response.StatusCode == StatusCodes424
                && await IsInteractionUnavailableAsync(response, cancellationToken).ConfigureAwait(false))
            {
                return new InteractionResult(request.Type) { Unavailable = true };
            }

            if (!response.IsSuccessStatusCode)
            {
                var error = await DeferredExchange.BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
                throw new HttpRequestException(
                    $"Interaction request failed with {(int)response.StatusCode}: {error}");
            }

            var raw = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            JsonObject? body = null;
            if (!string.IsNullOrWhiteSpace(raw))
            {
                try { body = JsonNode.Parse(raw) as JsonObject; }
                catch (JsonException) { body = null; }
            }

            var status = (string?)body?["status"];

            return request.Type switch
            {
                InteractionType.Question => new InteractionResult(request.Type)
                {
                    Answer = (string?)body?["answer"],
                    Status = status,
                    Body = body,
                },
                InteractionType.Completion => new InteractionResult(request.Type)
                {
                    // The PS terminates the mission on acceptance and returns 200.
                    // A body may carry mission_status=active when the user kept it open.
                    Terminated = (string?)body?["mission_status"] != "active",
                    Status = status,
                    Body = body,
                },
                _ => new InteractionResult(request.Type) { Status = status, Body = body },
            };
        }
        finally
        {
            response.Dispose();
        }
    }

    private const int StatusCodes424 = 424;

    // True when a 424 response actually carries error=interaction_unavailable, so
    // an unrelated 424 still surfaces as an error rather than a silent fallback.
    private static async Task<bool> IsInteractionUnavailableAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var raw = await DeferredExchange.BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(raw)) { return false; }
        try
        {
            return JsonNode.Parse(raw) is JsonObject obj
                && (string?)obj["error"] == AAuthConstants.Governance.ErrorCodes.InteractionUnavailable;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>Relay a resource interaction (URL + code) to the user.</summary>
    public Task<InteractionResult> RelayInteractionAsync(
        string url, string code,
        string? description = null, string? missionS256 = null,
        GovernanceOptions? options = null, CancellationToken cancellationToken = default)
        => SendAsync(new InteractionRequest(InteractionType.Interaction)
        {
            Url = url,
            Code = code,
            Description = description,
            MissionS256 = missionS256,
        }, options, cancellationToken);

    /// <summary>Forward a payment approval (URL + code) to the user.</summary>
    public Task<InteractionResult> RelayPaymentAsync(
        string url, string code,
        string? description = null, string? missionS256 = null,
        GovernanceOptions? options = null, CancellationToken cancellationToken = default)
        => SendAsync(new InteractionRequest(InteractionType.Payment)
        {
            Url = url,
            Code = code,
            Description = description,
            MissionS256 = missionS256,
        }, options, cancellationToken);

    /// <summary>Ask the user a question and return the answer.</summary>
    public async Task<string?> AskQuestionAsync(
        string question,
        string? description = null, string? missionS256 = null,
        GovernanceOptions? options = null, CancellationToken cancellationToken = default)
    {
        var result = await SendAsync(new InteractionRequest(InteractionType.Question)
        {
            Question = question,
            Description = description,
            MissionS256 = missionS256,
        }, options, cancellationToken).ConfigureAwait(false);
        return result.Answer;
    }
}
