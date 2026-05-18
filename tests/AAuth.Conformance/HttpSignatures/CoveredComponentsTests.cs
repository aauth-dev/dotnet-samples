using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.HttpSig;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// Conformance for the AAuth profile of RFC 9421 covered components per
/// draft-hardt-oauth-aauth-protocol-01 §HTTP Signature Profile.
/// </summary>
public class CoveredComponentsTests
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

    private static async Task<HttpRequestMessage> Sign(AAuthKey key, string token, DateTimeOffset clock)
    {
        var capture = new CaptureHandler();
        var pipeline = new AAuthSigningHandler(key, () => token, () => clock) { InnerHandler = capture };
        using var client = new HttpClient(pipeline);
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://r.example/path"));
        return capture.Captured!;
    }

    /// <summary>
    /// "Signers MUST cover, in order: @method, @authority, @path, signature-key."
    /// </summary>
    [Fact(DisplayName = "§HTTP Signature Profile — exact covered-component set and order")]
    public void CoveredComponents_FixedOrder()
    {
        Assert.Equal(
            new[] { "@method", "@authority", "@path", "signature-key" },
            AAuthSigningHandler.CoveredComponents.ToArray());
    }

    /// <summary>
    /// "Signature-Input MUST include the 'created' parameter for freshness."
    /// </summary>
    [Fact(DisplayName = "§HTTP Signature Profile — Signature-Input includes created=")]
    public async Task SignatureInput_IncludesCreated()
    {
        var key = AAuthKey.Generate();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var req = await Sign(key, "a.b.c", clock);
        var input = req.Headers.GetValues("Signature-Input").Single();

        Assert.Contains(";created=" + clock.ToUnixTimeSeconds(), input);
    }

    /// <summary>
    /// "Verifiers MUST reject signatures whose Signature-Input does not match
    /// the mandated covered-component set."
    /// </summary>
    [Fact(DisplayName = "§HTTP Signature Profile — verifier rejects mismatched covered components")]
    public void Verifier_RejectsMismatchedComponents()
    {
        var verifier = new AAuthVerifier();
        var key = AAuthKey.Generate();
        Assert.Throws<AAuthVerificationException>(() =>
            verifier.Verify("GET", "r.example", "/",
                "sig=jwt;jwt=\"a.b.c\"",
                $"sig=(\"@method\");created={DateTimeOffset.UtcNow.ToUnixTimeSeconds()}",
                "sig=:AAAA:",
                AAuthKey.FromJwk(key.ToPublicJwk())));
    }

    /// <summary>
    /// "Verifiers MUST reject signatures outside the configured freshness window."
    /// </summary>
    [Fact(DisplayName = "§HTTP Signature Profile — verifier rejects stale created parameter")]
    public async Task Verifier_RejectsStaleCreated()
    {
        var key = AAuthKey.Generate();
        var signed = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var req = await Sign(key, "a.b.c", signed);

        var verifier = new AAuthVerifier { Clock = () => signed.AddMinutes(10) };
        Assert.Throws<AAuthVerificationException>(() =>
            verifier.Verify("GET", "r.example", "/path",
                req.Headers.GetValues("Signature-Key").Single(),
                req.Headers.GetValues("Signature-Input").Single(),
                req.Headers.GetValues("Signature").Single(),
                AAuthKey.FromJwk(key.ToPublicJwk())));
    }
}
