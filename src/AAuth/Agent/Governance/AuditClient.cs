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
    private readonly DeferredExchange _exchange;
    private readonly string _personServer;

    /// <summary>Create the audit client bound to a Person Server.</summary>
    public AuditClient(HttpClient signedClient, MetadataClient metadata, string personServer)
    {
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        _exchange = new DeferredExchange(signedClient, metadata);
        _personServer = personServer;
    }

    /// <summary>
    /// Record <paramref name="record"/> at the bound PS. Returns once the PS
    /// acknowledges with <c>201 Created</c>. Surfaces <c>mission_terminated</c> as
    /// <see cref="Errors.AAuthMissionTerminatedException"/>.
    /// </summary>
    public async Task RecordAsync(
        AuditRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        var endpoint = await _exchange.ResolveEndpointAsync(
            _personServer, "audit_endpoint", cancellationToken).ConfigureAwait(false);

        // Audit is fire-and-forget; no deferral handling is expected.
        var response = await _exchange.PostAsync(
            endpoint, record.ToJsonObject(), new DeferredExchangeOptions(), cancellationToken).ConfigureAwait(false);
        try
        {
            if (response.StatusCode == HttpStatusCode.Created)
            {
                return;
            }

            var error = await DeferredExchange.BufferBodyAsync(response, cancellationToken).ConfigureAwait(false);
            throw new HttpRequestException(
                $"Audit record failed with {(int)response.StatusCode}: {error}");
        }
        finally
        {
            response.Dispose();
        }
    }
}
