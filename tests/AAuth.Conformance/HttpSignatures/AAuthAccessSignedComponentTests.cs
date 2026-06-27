using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Headers;
using AAuth.HttpSig;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// Conformance for binding an opaque <c>AAuth-Access</c> token to the request
/// signature: the agent MUST include <c>authorization</c> in the covered
/// components when presenting <c>Authorization: AAuth</c>, so the token is useless
/// without a valid AAuth signature (§AAuth-Access Response Header;
/// §AAuth-Access Security).
/// </summary>
public class AAuthAccessSignedComponentTests
{
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
        AAuthKey key, DateTimeOffset clock, string? opaqueToken)
    {
        var capture = new CaptureHandler();
        var pipeline = new AAuthSigningHandler(key, () => "a.b.c", () => clock) { InnerHandler = capture };
        using var client = new HttpClient(pipeline);
        var request = new HttpRequestMessage(HttpMethod.Get, "https://r.example/path");
        if (opaqueToken is not null)
        {
            request.Headers.Authorization =
                new AuthenticationHeaderValue(AAuthAccessHeader.AuthorizationScheme, opaqueToken);
        }

        await client.SendAsync(request);
        return capture.Captured!;
    }

    [Fact(DisplayName = "§AAuth-Access — Signature-Input covers authorization when Authorization: AAuth present")]
    public async Task SignatureInput_CoversAuthorization_WhenPresent()
    {
        var key = AAuthKey.Generate();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);

        var req = await Sign(key, clock, "opaque-token-value");
        var input = req.Headers.GetValues("Signature-Input").Single();

        Assert.Contains("\"authorization\"", input);
    }

    [Fact(DisplayName = "§AAuth-Access — fully-bound request round-trips through the verifier")]
    public async Task BoundRequest_VerifiesSuccessfully()
    {
        var key = AAuthKey.Generate();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);

        var req = await Sign(key, clock, "opaque-token-value");

        var verifier = new AAuthVerifier { Clock = () => clock };
        verifier.Verify("GET", "r.example", "/path",
            req.Headers.GetValues("Signature-Key").Single(),
            req.Headers.GetValues("Signature-Input").Single(),
            req.Headers.GetValues("Signature").Single(),
            AAuthKey.FromJwk(key.ToPublicJwk()),
            authorization: req.Headers.GetValues("Authorization").Single());
    }

    [Fact(DisplayName = "§AAuth-Access Security — verifier rejects when Authorization present but uncovered")]
    public async Task Verifier_Rejects_WhenAuthorizationPresentButUncovered()
    {
        var key = AAuthKey.Generate();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);

        // Sign WITHOUT Authorization so `authorization` is not covered...
        var req = await Sign(key, clock, opaqueToken: null);

        var verifier = new AAuthVerifier { Clock = () => clock };
        // ...but present an Authorization: AAuth credential at verification time.
        Assert.Throws<AAuthVerificationException>(() =>
            verifier.Verify("GET", "r.example", "/path",
                req.Headers.GetValues("Signature-Key").Single(),
                req.Headers.GetValues("Signature-Input").Single(),
                req.Headers.GetValues("Signature").Single(),
                AAuthKey.FromJwk(key.ToPublicJwk()),
                authorization: "AAuth opaque-token-value"));
    }
}
