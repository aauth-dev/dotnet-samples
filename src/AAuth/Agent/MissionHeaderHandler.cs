using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Agent;

/// <summary>
/// DelegatingHandler that emits the <c>AAuth-Mission</c> header on outbound
/// requests from an agent's own approved <see cref="Mission"/>.
/// </summary>
/// <remarks>
/// Per §Mission Context at Resources, "the agent includes the <c>AAuth-Mission</c>
/// header when sending requests to resources, unless the mission is already conveyed
/// in an auth token", and per the HTTP Message Signatures section it "adds
/// <c>aauth-mission</c> to the signed components". The signing handler beneath this
/// one auto-covers the <c>aauth-mission</c> component whenever the header is present,
/// so this handler only needs to set the header value.
/// <para>
/// This is the seam for the <em>originating</em> agent that holds its own approved
/// mission. Call-chaining intermediaries that re-emit a mission extracted from an
/// upstream auth token use <see cref="MissionForwardingHandler"/> instead. The
/// header is left untouched if a caller already set it, honoring the spec's
/// "unless already conveyed" carve-out.
/// </para>
/// </remarks>
public sealed class MissionHeaderHandler : DelegatingHandler
{
    private readonly Mission _mission;

    /// <summary>
    /// Creates a new <see cref="MissionHeaderHandler"/> for the agent's approved mission.
    /// </summary>
    /// <param name="mission">The agent's own approved mission.</param>
    public MissionHeaderHandler(Mission mission)
    {
        _mission = mission ?? throw new System.ArgumentNullException(nameof(mission));
    }

    /// <inheritdoc/>
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!request.Headers.Contains(AAuthMissionHeader.Name))
        {
            request.Headers.TryAddWithoutValidation(
                AAuthMissionHeader.Name,
                AAuthMissionHeader.FormatStructured(_mission.Approver, _mission.S256));
        }

        return base.SendAsync(request, cancellationToken);
    }
}
