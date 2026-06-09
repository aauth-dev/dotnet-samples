using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for the originating-agent mission seam
/// (<see cref="AAuthClientBuilder.WithMission"/> /
/// <see cref="MissionHeaderHandler"/>). Per §Mission Context at Resources the
/// agent "includes the <c>AAuth-Mission</c> header when sending requests to
/// resources, unless the mission is already conveyed in an auth token", and per
/// the HTTP Message Signatures section it "adds <c>aauth-mission</c> to the signed
/// components". A client configured with <c>WithMission(...)</c> emits the header
/// from the agent's own approved mission and the signing pipeline covers it.
/// </summary>
public class MissionHeaderSeamTests
{
    private const string Approver = "https://ps.example";

    private static Mission BuildMission()
    {
        var blob = new JsonObject
        {
            ["approver"] = Approver,
            ["agent"] = "aauth:agent@example",
            ["approved_at"] = "2026-06-06T00:00:00Z",
            ["description"] = "Plan my weekend trip to Seattle",
            ["approved_tools"] = new JsonArray(),
        }.ToJsonString();
        return Mission.FromApprovalBytes(Encoding.UTF8.GetBytes(blob));
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Captured { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Captured = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    [Fact(DisplayName = "§Mission Context at Resources — WithMission emits the AAuth-Mission header")]
    public async Task WithMission_EmitsMissionHeader()
    {
        var mission = BuildMission();
        var capture = new CaptureHandler();
        using var client = new AAuthClientBuilder(AAuthKey.Generate())
            .UseJwt("a.b.c")
            .WithMission(mission)
            .WithInnerHandler(capture)
            .Build();

        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://r.example/path"));

        var value = capture.Captured!.Headers.GetValues(AAuthMissionHeader.Name).Single();
        Assert.Equal(AAuthMissionHeader.FormatStructured(mission.Approver, mission.S256), value);
    }

    [Fact(DisplayName = "§HTTP Message Signatures — the emitted mission header is covered as aauth-mission")]
    public async Task WithMission_CoversAauthMissionComponent()
    {
        var mission = BuildMission();
        var capture = new CaptureHandler();
        using var client = new AAuthClientBuilder(AAuthKey.Generate())
            .UseJwt("a.b.c")
            .WithMission(mission)
            .WithInnerHandler(capture)
            .Build();

        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://r.example/path"));

        var input = string.Join(',', capture.Captured!.Headers.GetValues("Signature-Input"));
        Assert.Contains("\"aauth-mission\"", input);
    }

    [Fact(DisplayName = "§Mission Context at Resources — the header is not emitted twice when already present")]
    public async Task WithMission_DoesNotDuplicate_WhenAlreadyPresent()
    {
        var mission = BuildMission();
        var capture = new CaptureHandler();
        using var client = new AAuthClientBuilder(AAuthKey.Generate())
            .UseJwt("a.b.c")
            .WithMission(mission)
            .WithInnerHandler(capture)
            .Build();

        var request = new HttpRequestMessage(HttpMethod.Get, "https://r.example/path");
        var preset = AAuthMissionHeader.FormatStructured(Approver, "preset-s256-value");
        request.Headers.TryAddWithoutValidation(AAuthMissionHeader.Name, preset);

        await client.SendAsync(request);

        var values = capture.Captured!.Headers.GetValues(AAuthMissionHeader.Name).ToArray();
        Assert.Single(values);
        Assert.Equal(preset, values[0]);
    }

    [Fact(DisplayName = "§Mission Context at Resources — no mission header without WithMission")]
    public async Task WithoutMission_NoMissionHeader()
    {
        var capture = new CaptureHandler();
        using var client = new AAuthClientBuilder(AAuthKey.Generate())
            .UseJwt("a.b.c")
            .WithInnerHandler(capture)
            .Build();

        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://r.example/path"));

        Assert.False(capture.Captured!.Headers.Contains(AAuthMissionHeader.Name));
    }
}
