using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Agent;

/// <summary>
/// DelegatingHandler that automatically emits the <c>AAuth-Mission</c> header
/// on downstream requests when the upstream auth token contains mission claims.
/// </summary>
/// <remarks>
/// Per §Call Chaining, intermediaries operating in a mission context MUST include
/// the <c>AAuth-Mission</c> header on all downstream requests. This handler reads
/// <c>mission.approver</c> and <c>mission.s256</c> from the upstream auth token
/// and formats the structured header value.
/// </remarks>
public sealed class MissionForwardingHandler : DelegatingHandler
{
    private readonly Func<string?> _upstreamTokenProvider;

    /// <summary>
    /// Creates a new <see cref="MissionForwardingHandler"/>.
    /// </summary>
    /// <param name="upstreamTokenProvider">Delegate returning the upstream auth token, or null if unavailable.</param>
    public MissionForwardingHandler(Func<string?> upstreamTokenProvider)
    {
        _upstreamTokenProvider = upstreamTokenProvider ?? throw new ArgumentNullException(nameof(upstreamTokenProvider));
    }

    /// <inheritdoc/>
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = _upstreamTokenProvider();
        if (token is not null)
        {
            var mission = ExtractMission(token);
            if (mission is not null)
            {
                request.Headers.TryAddWithoutValidation(
                    AAuthMissionHeader.Name,
                    AAuthMissionHeader.FormatStructured(mission.Value.Approver, mission.Value.S256));
            }
        }

        return base.SendAsync(request, cancellationToken);
    }

    internal static (string Approver, string S256)? ExtractMission(string token)
    {
        var segments = token.Split('.');
        if (segments.Length != 3)
            return null;

        JsonObject? payload;
        try
        {
            var payloadJson = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(segments[1]));
            payload = JsonNode.Parse(payloadJson) as JsonObject;
        }
        catch
        {
            return null;
        }

        if (payload is null)
            return null;

        if (payload["mission"] is not JsonObject mission)
            return null;

        var approver = (string?)mission["approver"];
        var s256 = (string?)mission["s256"];

        if (string.IsNullOrEmpty(approver) || string.IsNullOrEmpty(s256))
            return null;

        return (approver, s256);
    }
}
