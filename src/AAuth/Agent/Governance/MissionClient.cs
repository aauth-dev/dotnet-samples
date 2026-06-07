using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;
using AAuth.Headers;

namespace AAuth.Agent.Governance;

/// <summary>
/// Proposes missions at the PS's <c>mission_endpoint</c> (§Mission Creation,
/// §Mission Approval). The PS may engage in a clarification chat to refine the
/// scope before approving; on approval the PS returns the mission blob plus an
/// <c>AAuth-Mission</c> header carrying the <c>approver</c> and <c>s256</c>.
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
    /// The PS did not return an <c>AAuth-Mission</c> header, or the returned
    /// <c>s256</c> does not match the hash of the approval body.
    /// </exception>
    public async Task<Mission> ProposeAsync(
        MissionProposal proposal,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proposal);

        var endpoint = await _exchange.ResolveEndpointAsync(
            _personServer, "mission_endpoint", cancellationToken).ConfigureAwait(false);

        var response = await _exchange.PostAsync(
            endpoint, proposal.ToJsonObject(),
            options?.ToExchangeOptions() ?? new DeferredExchangeOptions(), cancellationToken).ConfigureAwait(false);
        try
        {
            if (!response.IsSuccessStatusCode)
            {
                var error = await DeferredExchange.BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
                throw new HttpRequestException(
                    $"Mission proposal failed with {(int)response.StatusCode}: {error}");
            }

            // The agent MUST store the approval body bytes exactly as received —
            // no re-serialization — so the s256 can be verified (§Mission Approval).
            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            var mission = Mission.FromApprovalBytes(bytes);

            // Verify the s256 in the AAuth-Mission header matches the computed hash.
            if (!response.Headers.TryGetValues(AAuthMissionHeader.Name, out var values))
            {
                throw new InvalidOperationException(
                    "Mission approval response is missing the AAuth-Mission header.");
            }
            var headerS256 = ParseHeaderS256(string.Join(",", values));
            if (string.IsNullOrEmpty(headerS256) || !mission.VerifyS256(headerS256))
            {
                throw new InvalidOperationException(
                    "AAuth-Mission header 's256' does not match the hash of the approval body.");
            }

            return mission;
        }
        finally
        {
            response.Dispose();
        }
    }

    // Extract the s256 value from an AAuth-Mission header (approver="..."; s256="...").
    private static string? ParseHeaderS256(string headerValue)
    {
        foreach (var part in headerValue.Split(';'))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("s256=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed["s256=".Length..].Trim().Trim('"');
            }
        }
        return null;
    }
}
