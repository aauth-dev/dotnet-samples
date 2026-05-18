using System;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.HttpSig;
using Xunit;

namespace AAuth.Tests.HttpSig;

public class AAuthVerifierTests
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

    private static async Task<HttpRequestMessage> SignedRequest(
        AAuthKey key, string jwt, DateTimeOffset clock, HttpMethod method, string url)
    {
        var capture = new CaptureHandler();
        var signing = new AAuthSigningHandler(key, () => jwt, () => clock) { InnerHandler = capture };
        using var client = new HttpClient(signing);
        await client.SendAsync(new HttpRequestMessage(method, url));
        return capture.Captured!;
    }

    [Fact]
    public async Task Verify_RoundTripsAgainstSigner()
    {
        var key = AAuthKey.Generate();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var req = await SignedRequest(key, "abc.def.ghi", clock, HttpMethod.Get, "https://resource.example/api");

        var verifier = new AAuthVerifier { Clock = () => clock };
        verifier.Verify(
            method: "GET",
            authority: "resource.example",
            path: "/api",
            signatureKey: string.Join(',', req.Headers.GetValues("Signature-Key")),
            signatureInput: string.Join(',', req.Headers.GetValues("Signature-Input")),
            signatureHeader: string.Join(',', req.Headers.GetValues("Signature")),
            publicKey: AAuthKey.FromJwk(key.ToPublicJwk()));
    }

    [Fact]
    public async Task Verify_RejectsExpiredCreated()
    {
        var key = AAuthKey.Generate();
        var signed = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var req = await SignedRequest(key, "abc.def.ghi", signed, HttpMethod.Get, "https://r.example/");

        // Clock advanced past the freshness window (default 60s).
        var verifier = new AAuthVerifier { Clock = () => signed.AddMinutes(5) };
        Assert.Throws<AAuthVerificationException>(() =>
            verifier.Verify("GET", "r.example", "/", req.Headers.GetValues("Signature-Key").Single(),
                req.Headers.GetValues("Signature-Input").Single(),
                req.Headers.GetValues("Signature").Single(),
                AAuthKey.FromJwk(key.ToPublicJwk())));
    }

    [Fact]
    public async Task Verify_RejectsTamperedPath()
    {
        var key = AAuthKey.Generate();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var req = await SignedRequest(key, "abc.def.ghi", clock, HttpMethod.Get, "https://r.example/legit");

        var verifier = new AAuthVerifier { Clock = () => clock };
        Assert.Throws<AAuthVerificationException>(() =>
            verifier.Verify("GET", "r.example", "/tampered",
                req.Headers.GetValues("Signature-Key").Single(),
                req.Headers.GetValues("Signature-Input").Single(),
                req.Headers.GetValues("Signature").Single(),
                AAuthKey.FromJwk(key.ToPublicJwk())));
    }

    [Fact]
    public void Verify_RejectsWrongCoveredComponents()
    {
        var key = AAuthKey.Generate();
        var verifier = new AAuthVerifier();
        Assert.Throws<AAuthVerificationException>(() =>
            verifier.Verify("GET", "r.example", "/",
                "sig=jwt;jwt=\"a.b.c\"",
                "sig=(\"@method\");created=" + DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                "sig=:AAAA:",
                AAuthKey.FromJwk(key.ToPublicJwk())));
    }
}
