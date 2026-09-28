using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Agent;

/// <summary>
/// DelegatingHandler that tags outbound requests with the agent's approved
/// <see cref="Mission"/> (<see cref="AAuthRequestOptions.MissionS256"/>). The
/// challenge handler names the mission when it requests a person token; the PS
/// puts <c>mission_s256</c> in the token and the resource copies it from there
/// (§Missions). A caller-set value is left untouched.
/// </summary>
public sealed class MissionContextHandler : DelegatingHandler
{
    private readonly Mission _mission;

    /// <summary>Creates the handler for the agent's approved mission.</summary>
    public MissionContextHandler(Mission mission)
    {
        _mission = mission ?? throw new System.ArgumentNullException(nameof(mission));
    }

    /// <inheritdoc/>
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (AAuthRequestOptions.GetMissionS256(request) is null)
            request.Options.Set(AAuthRequestOptions.MissionS256, _mission.S256);
        return base.SendAsync(request, cancellationToken);
    }
}
