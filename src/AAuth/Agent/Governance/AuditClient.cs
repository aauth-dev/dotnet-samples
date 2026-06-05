using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;

namespace AAuth.Agent.Governance;

/// <summary>
/// Logs actions the agent has performed at the PS's <c>audit_endpoint</c>
/// (§Audit Endpoint). The audit endpoint requires a mission and is
/// fire-and-forget — the PS returns <c>201 Created</c> to acknowledge.
/// </summary>
/// <remarks>
/// The supplied <see cref="HttpClient"/> MUST be wired with an
/// <see cref="HttpSig.AAuthSigningHandler"/>.
/// </remarks>
public sealed class AuditClient
{
    private readonly GovernanceExchange _exchange;

    /// <summary>Create the audit client.</summary>
    public AuditClient(HttpClient signedClient, MetadataClient metadata)
        => _exchange = new GovernanceExchange(signedClient, metadata);

    /// <summary>
    /// Record <paramref name="record"/> at the PS at <paramref name="personServer"/>.
    /// Returns once the PS acknowledges with <c>201 Created</c>. Surfaces
    /// <c>mission_terminated</c> as <see cref="Errors.AAuthMissionTerminatedException"/>.
    /// </summary>
    public async Task RecordAsync(
        string personServer,
        AuditRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        ArgumentNullException.ThrowIfNull(record);

        var endpoint = await _exchange.ResolveEndpointAsync(
            personServer, "audit_endpoint", cancellationToken).ConfigureAwait(false);

        // Audit is fire-and-forget; no deferral handling is expected.
        var response = await _exchange.PostAsync(
            endpoint, record.ToJsonObject(), options: null, cancellationToken).ConfigureAwait(false);
        try
        {
            if (response.StatusCode == HttpStatusCode.Created
                || response.StatusCode == HttpStatusCode.OK
                || response.StatusCode == HttpStatusCode.NoContent)
            {
                return;
            }

            var error = await GovernanceExchange.BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
            throw new HttpRequestException(
                $"Audit record failed with {(int)response.StatusCode}: {error}");
        }
        finally
        {
            response.Dispose();
        }
    }
}
