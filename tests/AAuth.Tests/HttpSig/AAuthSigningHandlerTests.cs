using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.HttpSig;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests;

public class AAuthSigningHandlerTests
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

    [Fact]
    public async Task SendAsync_AddsAllThreeSignatureHeaders()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);

        var signing = new AAuthSigningHandler(key, () => "eyJ.HEADER.PAYLOAD", () => clock)
        {
            InnerHandler = capture,
        };
        using var client = new HttpClient(signing);

        await client.GetAsync("https://resource.example/api/data");

        var req = capture.Captured;
        Assert.NotNull(req);
        Assert.True(req.Headers.Contains("Signature"));
        Assert.True(req.Headers.Contains("Signature-Input"));
        Assert.True(req.Headers.Contains("Signature-Key"));
    }

    [Fact]
    public async Task SendAsync_SignatureKeyCarriesJwt()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi") { InnerHandler = capture };
        using var client = new HttpClient(signing);

        await client.GetAsync("https://resource.example/");

        var headerValue = string.Join(',', capture.Captured!.Headers.GetValues("Signature-Key"));
        Assert.Equal("sig=jwt;jwt=\"abc.def.ghi\"", headerValue);
    }

    [Fact]
    public async Task SendAsync_SignatureInputUsesAAuthCoveredComponents()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", () => clock) { InnerHandler = capture };
        using var client = new HttpClient(signing);

        await client.GetAsync("https://resource.example/api");

        var input = string.Join(',', capture.Captured!.Headers.GetValues("Signature-Input"));
        Assert.Equal($"sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created={clock.ToUnixTimeSeconds()}", input);
    }

    [Fact]
    public async Task SendAsync_SignatureVerifiesAgainstReconstructedBase()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var jwt = "abc.def.ghi";
        var signing = new AAuthSigningHandler(key, () => jwt, () => clock) { InnerHandler = capture };
        using var client = new HttpClient(signing);

        await client.PostAsync("https://resource.example/authorize", new StringContent(""));

        var req = capture.Captured!;
        var sigHeader = string.Join(',', req.Headers.GetValues("Signature"));
        var paramsHeader = string.Join(',', req.Headers.GetValues("Signature-Input"));

        // Strip "sig=" label and the colon delimiters from the sf-binary value.
        var match = Regex.Match(sigHeader, @"^sig=:(?<b64>[^:]+):$");
        Assert.True(match.Success, $"Unexpected Signature header: {sigHeader}");
        var signature = Convert.FromBase64String(match.Groups["b64"].Value);
        var paramsLine = paramsHeader["sig=".Length..];

        var baseBuilder = new StringBuilder();
        baseBuilder.Append("\"@method\": POST\n");
        baseBuilder.Append("\"@authority\": resource.example\n");
        baseBuilder.Append("\"@path\": /authorize\n");
        baseBuilder.Append("\"signature-key\": sig=jwt;jwt=\"abc.def.ghi\"\n");
        baseBuilder.Append("\"@signature-params\": ").Append(paramsLine);

        Assert.True(key.Verify(Encoding.ASCII.GetBytes(baseBuilder.ToString()), signature));
    }

    [Fact]
    public void Constructor_RejectsPublicOnlyKey()
    {
        var pub = AAuthKey.FromJwk(AAuthKey.Generate().ToPublicJwk());
        Assert.Throws<ArgumentException>(() => new AAuthSigningHandler(pub, () => "x"));
    }
}
