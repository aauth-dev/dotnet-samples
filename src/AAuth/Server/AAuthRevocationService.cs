using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Person;
using AAuth.Server.Governance;
using AAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Server;

/// <summary>
/// The revocation engine of one registered role instance (#token-revocation,
/// #revocation-cascade). The inbound revocation endpoint and app code (an admin UI, a
/// background job, a webhook) share it. Downstream revocations are signed as the role's
/// identity. Every call is idempotent per <c>(iss, jti)</c>: it records nothing new,
/// re-attempts each downstream revocation, and reports the current outcome. Calls do not
/// throw for downstream failures; they report them per recipient.
/// </summary>
/// <remarks>
/// Resolve a Person Server's or Access Server's service as a keyed service by instance name;
/// a resource registered with <c>AddAAuthResource</c> registers an unkeyed one.
/// </remarks>
public interface IAAuthRevocationService
{
    /// <summary>
    /// Revoke <paramref name="jti"/>, a token this role issued, at <paramref name="endpoint"/>,
    /// signed as this role. <paramref name="expiresAt"/> is the token's own <c>exp</c>.
    /// </summary>
    Task<RevocationDownstreamResult> RevokeAtAsync(Uri endpoint, string jti, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revoke a person token or auth token this role issued: record it, revoke it at the
    /// resource it was issued for, and cascade. For a person token that reaches every Access
    /// Server it was presented to and the person tokens later derived from it as an
    /// <c>upstream_token</c>. A token with no record here reports nothing.
    /// </summary>
    Task<RevocationCascadeResult> RevokeTokenAsync(string jti, CancellationToken cancellationToken = default);

    /// <summary>
    /// Record a revocation of <paramref name="token"/>, issued by <see cref="TokenKey.Issuer"/>,
    /// and cascade to what this role issued or federated against it. For an agent token the
    /// cascade is by the agent's <c>sub</c>, whichever agent token it presented. The inbound
    /// revocation endpoint calls this with the verified caller as issuer.
    /// </summary>
    Task<RevocationCascadeResult> CascadeAsync(TokenKey token, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revoke a mission (Person Server): mark it terminated, so later token requests under
    /// <paramref name="s256"/> are denied, and revoke the tokens issued under it.
    /// </summary>
    Task<RevocationCascadeResult> RevokeMissionAsync(string s256, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revoke every person token and auth token this Person Server issued to the agent
    /// <paramref name="sub"/> of <paramref name="agentIssuer"/>, whichever agent token it
    /// presented, and revoke the agent-person binding so a new binding can be
    /// established only after the cascade.
    /// </summary>
    Task<RevocationCascadeResult> RevokeAgentAsync(string agentIssuer, string sub,
        CancellationToken cancellationToken = default);
}

internal sealed class AAuthRevocationService : IAAuthRevocationService, IDisposable
{
    private readonly MetadataClient? _metadata;
    private readonly RevocationClient? _client;
    private readonly HttpClient? _ownedHttp;
    private readonly IMissionStore? _missions;
    private readonly IAgentPersonBindingStore? _agentBindings;
    private readonly Func<TokenGrant, CancellationToken, Task<RevocationDownstreamError?>>? _revokeGrant;

    // An issuer-less engine treats every grant as its own and delivers through the hook.
    internal AAuthRevocationService(IJtiStore inventory, TimeProvider clock,
        Func<TokenGrant, CancellationToken, Task<RevocationDownstreamError?>>? revokeGrant)
    {
        Inventory = inventory;
        Clock = clock;
        _revokeGrant = revokeGrant;
    }

    private AAuthRevocationService(IAAuthServerIdentity identity, IJtiStore inventory, TimeProvider clock,
        MetadataClient metadata, RevocationClient? client, IMissionStore? missions,
        IAgentPersonBindingStore? agentBindings)
    {
        Issuer = identity.Issuer;
        EgressPolicy = identity.EgressPolicy;
        Inventory = inventory;
        Clock = clock;
        _metadata = metadata;
        _missions = missions;
        _agentBindings = agentBindings;
        if (client is null)
        {
            _ownedHttp = identity.CreateSignedClient();
            client = new RevocationClient(_ownedHttp);
        }
        _client = client;
    }

    /// <summary>Sign as <paramref name="identity"/>; a <see cref="RevocationClient"/> keyed by <paramref name="key"/>, else an unkeyed one, overrides the transport.</summary>
    internal static AAuthRevocationService ForIdentity(IServiceProvider services, IAAuthServerIdentity identity,
        IJtiStore inventory, TimeProvider clock, object? key, IMissionStore? missions = null)
        => new(identity, inventory, clock, services.GetRequiredService<MetadataClient>(),
            (key is null ? null : services.GetKeyedService<RevocationClient>(key)) ?? services.GetService<RevocationClient>(),
            missions, key is null ? services.GetService<IAgentPersonBindingStore>()
                : services.GetKeyedService<IAgentPersonBindingStore>(key) ?? services.GetService<IAgentPersonBindingStore>());

    internal string? Issuer { get; }
    internal AAuthEgressPolicy EgressPolicy { get; } = AAuthEgressPolicy.Production;
    internal IJtiStore Inventory { get; }
    internal TimeProvider Clock { get; }

    public void Dispose() => _ownedHttp?.Dispose();

    public async Task<RevocationDownstreamResult> RevokeAtAsync(Uri endpoint, string jti, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(jti);
        var recipient = endpoint.GetLeftPart(UriPartial.Authority);
        if (_client is null) return new(recipient, RevocationDownstreamError.RevocationUnsupported);
        try
        {
            var result = await _client.RevokeAsync(endpoint, jti, expiresAt, cancellationToken);
            return new(recipient, result.Failure) { Downstream = result.Downstream };
        }
        catch (Exception ex) when (IsDeliveryFailure(ex, cancellationToken))
        {
            return new(recipient, RevocationDownstreamError.RevocationUnavailable);
        }
    }

    public async Task<RevocationCascadeResult> RevokeTokenAsync(string jti, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jti);
        var token = new TokenKey(RequireIssuer(), jti);
        if (await Inventory.GetGrantAsync(token, cancellationToken) is not { } grant) return new();
        await Inventory.RevokeAsync(token, grant.ExpiresAt, cancellationToken);
        var outcomes = new Dictionary<string, RevocationDownstreamResult>(StringComparer.Ordinal);
        Record(outcomes, await RevokeGrantAsync(grant, cancellationToken));
        return await WalkAsync([new(token, grant.ExpiresAt, true)], outcomes, cancellationToken);
    }

    public async Task<RevocationCascadeResult> CascadeAsync(TokenKey token, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        await Inventory.RevokeAsync(token, expiresAt, cancellationToken);
        return await WalkAsync(await StartsAsync(token, expiresAt, cancellationToken), [], cancellationToken);
    }

    public async Task<RevocationCascadeResult> RevokeMissionAsync(string s256, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(s256);
        var mission = RevocationRecords.Mission(RequireIssuer(), s256);
        if (_missions is not null) await _missions.SetStateAsync(s256, MissionState.Terminated, cancellationToken);
        await Inventory.RevokeAsync(mission, RevocationRecords.ExpiresAt, cancellationToken);
        return await WalkAsync([new(mission, RevocationRecords.ExpiresAt, false)], [], cancellationToken);
    }

    public async Task<RevocationCascadeResult> RevokeAgentAsync(string agentIssuer, string sub,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(sub);
        var issuer = RequireIssuer();
        var agent = RevocationRecords.Subject(issuer, agentIssuer, sub);
        var starts = new List<CascadeSource> { new(agent, RevocationRecords.ExpiresAt, false) };
        if (_agentBindings is not null)
        {
            var binding = await AgentPersonBinding.RevokeAsync(Inventory, _agentBindings, issuer, agentIssuer, sub, cancellationToken);
            if (binding is not null)
                starts.Add(new(binding.InventoryKey, AgentPersonBinding.ExpiresAt, true));
        }
        return await WalkAsync(starts, [], cancellationToken);
    }

    /// <summary>Where a revocation of <paramref name="token"/> cascades from: the token, and its agent's records.</summary>
    internal async Task<IReadOnlyList<CascadeSource>> StartsAsync(TokenKey token, DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        var starts = new List<CascadeSource> { new(token, expiresAt, true) };
        if (Issuer is not null && await Inventory.GetSubjectAsync(token, cancellationToken) is { } subject)
            starts.Add(new(RevocationRecords.Subject(Issuer, token.Issuer, subject), RevocationRecords.ExpiresAt, false));
        return starts;
    }

    internal async Task<bool> HasDownstreamAsync(IReadOnlyList<CascadeSource> starts, CancellationToken cancellationToken)
    {
        foreach (var start in starts)
            if ((await Inventory.GetGrantsAsync(start.Key, cancellationToken)).Count > 0) return true;
        return false;
    }

    internal async Task<RevocationCascadeResult> WalkAsync(IReadOnlyList<CascadeSource> starts,
        Dictionary<string, RevocationDownstreamResult> outcomes, CancellationToken cancellationToken)
    {
        var visited = new HashSet<TokenKey>();
        var federated = new HashSet<(TokenKey, string)>();
        var remaining = new Queue<CascadeSource>();
        foreach (var start in starts)
            if (visited.Add(start.Key)) remaining.Enqueue(start);
        while (remaining.TryDequeue(out var source))
        {
            foreach (var grant in await Inventory.GetGrantsAsync(source.Key, cancellationToken))
            {
                var own = Issuer is null || grant.Token.Issuer == Issuer;
                // Four-party: a token an AS issued against one of ours is terminated by revoking
                // ours at that AS, which cascades to what it issued (#revocation-cascade).
                if (!own && source.IsToken && source.Key.Issuer == Issuer && federated.Add((source.Key, grant.Token.Issuer)))
                    Record(outcomes, await DeliverAsync(grant.Token.Issuer, AuthTokenBuilder.AccessDwk,
                        source.Key.TokenId, source.ExpiresAt, cancellationToken));
                if (!visited.Add(grant.Token)) continue;
                remaining.Enqueue(new(grant.Token, grant.ExpiresAt, true));
                await Inventory.RevokeAsync(grant.Token, grant.ExpiresAt, cancellationToken);
                if (own) Record(outcomes, await RevokeGrantAsync(grant, cancellationToken));
            }
        }
        return new() { Downstream = [.. outcomes.Values] };
    }

    private Task<RevocationDownstreamResult> RevokeGrantAsync(TokenGrant grant, CancellationToken cancellationToken)
        => _client is not null
            ? DeliverAsync(grant.Resource, ResourceTokenBuilder.ResourceDwk, grant.Token.TokenId, grant.ExpiresAt, cancellationToken)
            : RevokeThroughHookAsync(grant, cancellationToken);

    private async Task<RevocationDownstreamResult> RevokeThroughHookAsync(TokenGrant grant, CancellationToken cancellationToken)
    {
        if (_revokeGrant is null) return new(grant.Resource, RevocationDownstreamError.RevocationUnsupported);
        try { return new(grant.Resource, await _revokeGrant(grant, cancellationToken)); }
        catch (Exception ex) when (IsDeliveryFailure(ex, cancellationToken))
        {
            return new(grant.Resource, RevocationDownstreamError.RevocationUnavailable);
        }
    }

    private async Task<RevocationDownstreamResult> DeliverAsync(string recipient, string dwk, string jti, DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        if (_client is null || _metadata is null) return new(recipient, RevocationDownstreamError.RevocationUnsupported);
        try
        {
            var document = await _metadata.FetchAsync(_metadata.GetUrl(recipient, dwk), cancellationToken);
            if ((string?)document["revocation_endpoint"] is not { } endpoint)
                return new(recipient, RevocationDownstreamError.RevocationUnsupported);
            var endpointUri = EgressPolicy.ValidateUrl(endpoint, endpoint: true);
            if (endpointUri.GetLeftPart(UriPartial.Authority) != new Uri(recipient).GetLeftPart(UriPartial.Authority))
                return new(recipient, RevocationDownstreamError.RevocationUnsupported);
            var result = await _client.RevokeAsync(endpointUri, jti, expiresAt, cancellationToken);
            return new(recipient, result.Failure) { Downstream = result.Downstream };
        }
        catch (Exception ex) when (IsDeliveryFailure(ex, cancellationToken))
        {
            return new(recipient, RevocationDownstreamError.RevocationUnavailable);
        }
    }

    private static bool IsDeliveryFailure(Exception ex, CancellationToken cancellationToken)
        => ex is HttpRequestException or AAuthMetadataException or ArgumentException or InvalidOperationException
            or JsonException || ex is OperationCanceledException && !cancellationToken.IsCancellationRequested;

    // Keep the worst outcome per recipient: unavailable (retryable) over unsupported over recorded.
    private static void Record(Dictionary<string, RevocationDownstreamResult> outcomes, RevocationDownstreamResult result)
    {
        if (!outcomes.TryGetValue(result.Recipient, out var current)
            || (current.Error is null ? result.Error is not null : result.Error == RevocationDownstreamError.RevocationUnavailable))
            outcomes[result.Recipient] = result;
    }

    private string RequireIssuer() => Issuer
        ?? throw new InvalidOperationException("This revocation endpoint has no issuer identity; register a role to revoke its own tokens.");

    internal readonly record struct CascadeSource(TokenKey Key, DateTimeOffset ExpiresAt, bool IsToken);
}

/// <summary>
/// The Person Server's cascade indexes (#revocation-cascade, Records): every token it issues to
/// an agent is recorded as a grant of the agent's identity and, under a mission, of the mission.
/// </summary>
internal static class RevocationRecords
{
    // Indexes outlive any one token; a fixed far expiry keeps re-registration idempotent.
    internal static readonly DateTimeOffset ExpiresAt = AAuth.Person.AgentPersonBinding.ExpiresAt;

    internal static TokenKey Subject(string personServer, string agentIssuer, string sub)
        => new(personServer, "agent-subject " + agentIssuer + " " + sub);

    internal static TokenKey Mission(string personServer, string s256) => new(personServer, "mission " + s256);

    internal static TokenRegistration Registration(TokenKey index) => new(index, ExpiresAt);
}
