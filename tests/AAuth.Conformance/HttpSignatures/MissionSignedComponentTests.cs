using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// Conformance for covering the <c>aauth-mission</c> component when the agent
/// operates in a mission context (§Authorization Endpoint Request — the agent
/// includes the <c>AAuth-Mission</c> header and adds <c>aauth-mission</c> to the
/// signed components).
/// </summary>
public class MissionSignedComponentTests
{
    private const string Approver = "https://ps.example";
    private const string S256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

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

    private static async Task<HttpRequestMessage> Sign(
        AAuthKey key, string token, DateTimeOffset clock, string? missionHeader)
    {
        var capture = new CaptureHandler();
        var pipeline = new AAuthSigningHandler(key, () => token, () => clock) { InnerHandler = capture };
        using var client = new HttpClient(pipeline);
        var request = new HttpRequestMessage(HttpMethod.Get, "https://r.example/path");
        if (missionHeader is not null)
        {
            request.Headers.TryAddWithoutValidation(AAuthMissionHeader.Name, missionHeader);
        }
        await client.SendAsync(request);
        return capture.Captured!;
    }

    [Fact(DisplayName = "§Authorization Endpoint Request — aauth-mission covered when AAuth-Mission present")]
    public async Task SignatureInput_CoversMission_WhenHeaderPresent()
    {
        var key = AAuthKey.Generate();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var mission = AAuthMissionHeader.FormatStructured(Approver, S256);

        var req = await Sign(key, "a.b.c", clock, mission);
        var input = req.Headers.GetValues("Signature-Input").Single();

        Assert.Contains("\"aauth-mission\"", input);
        // §spec example: aauth-mission is the last covered component, after signature-key.
        Assert.EndsWith("\"signature-key\" \"aauth-mission\");created=" + clock.ToUnixTimeSeconds(), input);
    }

    [Fact(DisplayName = "§Authorization Endpoint Request — aauth-mission absent when no header")]
    public async Task SignatureInput_OmitsMission_WhenHeaderAbsent()
    {
        var key = AAuthKey.Generate();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);

        var req = await Sign(key, "a.b.c", clock, missionHeader: null);
        var input = req.Headers.GetValues("Signature-Input").Single();

        Assert.DoesNotContain("aauth-mission", input);
    }

    [Fact(DisplayName = "§Authorization Endpoint Request — signed mission request round-trips through the verifier")]
    public async Task SignedMissionRequest_VerifiesSuccessfully()
    {
        var key = AAuthKey.Generate();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var mission = AAuthMissionHeader.FormatStructured(Approver, S256);

        var req = await Sign(key, "a.b.c", clock, mission);

        var verifier = new AAuthVerifier { Clock = () => clock };
        verifier.Verify("GET", "r.example", "/path",
            req.Headers.GetValues("Signature-Key").Single(),
            req.Headers.GetValues("Signature-Input").Single(),
            req.Headers.GetValues("Signature").Single(),
            AAuthKey.FromJwk(key.ToPublicJwk()),
            mission: req.Headers.GetValues(AAuthMissionHeader.Name).Single());
    }

    [Fact(DisplayName = "§Authorization Endpoint Request — verifier rejects when mission header present but uncovered")]
    public async Task Verifier_Rejects_WhenMissionHeaderPresentButUncovered()
    {
        var key = AAuthKey.Generate();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);

        // Sign WITHOUT the mission header so aauth-mission is not covered...
        var req = await Sign(key, "a.b.c", clock, missionHeader: null);

        var verifier = new AAuthVerifier { Clock = () => clock };
        // ...but present the mission header at verification time.
        Assert.Throws<AAuthVerificationException>(() =>
            verifier.Verify("GET", "r.example", "/path",
                req.Headers.GetValues("Signature-Key").Single(),
                req.Headers.GetValues("Signature-Input").Single(),
                req.Headers.GetValues("Signature").Single(),
                AAuthKey.FromJwk(key.ToPublicJwk()),
                mission: AAuthMissionHeader.FormatStructured(Approver, S256)));
    }

    [Fact(DisplayName = "§Authorization Endpoint Request — aauth-mission not double-covered when explicitly requested")]
    public async Task SignatureInput_DoesNotDoubleCoverMission()
    {
        var key = AAuthKey.Generate();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var mission = AAuthMissionHeader.FormatStructured(Approver, S256);

        var capture = new CaptureHandler();
        var pipeline = new AAuthSigningHandler(key, () => "a.b.c", () => clock) { InnerHandler = capture };
        using var client = new HttpClient(pipeline);
        var request = new HttpRequestMessage(HttpMethod.Get, "https://r.example/path");
        request.Headers.TryAddWithoutValidation(AAuthMissionHeader.Name, mission);
        // Explicitly also request aauth-mission as an additional component.
        request.Options.Set(
            AAuthSigningHandler.AdditionalComponentsKey,
            Array.AsReadOnly(new[] { "aauth-mission" }));
        await client.SendAsync(request);

        var input = capture.Captured!.Headers.GetValues("Signature-Input").Single();
        var occurrences = input.Split("\"aauth-mission\"").Length - 1;
        Assert.Equal(1, occurrences);
    }
}
