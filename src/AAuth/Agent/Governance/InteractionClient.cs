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
/// Endpoint): relay resource interactions, forward payments, ask questions, or
/// propose mission completion. May be used with or without a mission.
/// </summary>
/// <remarks>
/// The supplied <see cref="HttpClient"/> MUST be wired with an
/// <see cref="HttpSig.AAuthSigningHandler"/>.
/// </remarks>
public sealed class InteractionClient
{
    private readonly GovernanceExchange _exchange;

    /// <summary>Create the interaction client.</summary>
    public InteractionClient(HttpClient signedClient, MetadataClient metadata)
        => _exchange = new GovernanceExchange(signedClient, metadata);

    /// <summary>
    /// Send <paramref name="request"/> to the PS at <paramref name="personServer"/>
    /// and return the terminal result, polling through any deferred response.
    /// </summary>
    public async Task<InteractionResult> SendAsync(
        string personServer,
        InteractionRequest request,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        ArgumentNullException.ThrowIfNull(request);

        var endpoint = await _exchange.ResolveEndpointAsync(
            personServer, "interaction_endpoint", cancellationToken).ConfigureAwait(false);

        var response = await _exchange.PostAsync(
            endpoint, request.ToJsonObject(), options, cancellationToken).ConfigureAwait(false);
        try
        {
            if (!response.IsSuccessStatusCode)
            {
                var error = await GovernanceExchange.BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
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

            return request.Type switch
            {
                InteractionType.Question => new InteractionResult(request.Type)
                {
                    Answer = (string?)body?["answer"],
                    Body = body,
                },
                InteractionType.Completion => new InteractionResult(request.Type)
                {
                    // The PS terminates the mission on acceptance and returns 200.
                    // A body may carry mission_status=active when the user kept it open.
                    Terminated = (string?)body?["mission_status"] != "active",
                    Body = body,
                },
                _ => new InteractionResult(request.Type) { Body = body },
            };
        }
        finally
        {
            response.Dispose();
        }
    }

    /// <summary>Relay a resource interaction (URL + code) to the user.</summary>
    public Task<InteractionResult> RelayInteractionAsync(
        string personServer, string url, string code,
        string? description = null, MissionClaim? mission = null,
        GovernanceOptions? options = null, CancellationToken cancellationToken = default)
        => SendAsync(personServer, new InteractionRequest(InteractionType.Interaction)
        {
            Url = url,
            Code = code,
            Description = description,
            Mission = mission,
        }, options, cancellationToken);

    /// <summary>Forward a payment approval (URL + code) to the user.</summary>
    public Task<InteractionResult> RelayPaymentAsync(
        string personServer, string url, string code,
        string? description = null, MissionClaim? mission = null,
        GovernanceOptions? options = null, CancellationToken cancellationToken = default)
        => SendAsync(personServer, new InteractionRequest(InteractionType.Payment)
        {
            Url = url,
            Code = code,
            Description = description,
            Mission = mission,
        }, options, cancellationToken);

    /// <summary>Ask the user a question and return the answer.</summary>
    public async Task<string?> AskQuestionAsync(
        string personServer, string question,
        string? description = null, MissionClaim? mission = null,
        GovernanceOptions? options = null, CancellationToken cancellationToken = default)
    {
        var result = await SendAsync(personServer, new InteractionRequest(InteractionType.Question)
        {
            Question = question,
            Description = description,
            Mission = mission,
        }, options, cancellationToken).ConfigureAwait(false);
        return result.Answer;
    }

    /// <summary>
    /// Propose mission completion with a summary. Returns <see langword="true"/>
    /// when the user accepted and the PS terminated the mission.
    /// </summary>
    public async Task<bool> ProposeCompletionAsync(
        string personServer, string summary, MissionClaim mission,
        GovernanceOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mission);
        var result = await SendAsync(personServer, new InteractionRequest(InteractionType.Completion)
        {
            Summary = summary,
            Mission = mission,
        }, options, cancellationToken).ConfigureAwait(false);
        return result.Terminated;
    }
}
