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

    [Fact]
    public async Task SendAsync_LowercasesAuthorityInSignatureBase()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", () => clock) { InnerHandler = capture };
        using var client = new HttpClient(signing);

        // Mixed-case host: RFC 9421 §2.2.3 requires the signed @authority
        // value to be lowercase per RFC 3986 §3.2.2.
        await client.GetAsync("https://Resource.EXAMPLE/path");

        var req = capture.Captured!;
        var sigHeader = string.Join(',', req.Headers.GetValues("Signature"));
        var paramsHeader = string.Join(',', req.Headers.GetValues("Signature-Input"));
        var match = Regex.Match(sigHeader, @"^sig=:(?<b64>[^:]+):$");
        Assert.True(match.Success);
        var signature = Convert.FromBase64String(match.Groups["b64"].Value);
        var paramsLine = paramsHeader["sig=".Length..];

        // The reconstructed base must use the lowercase authority for the
        // signature to verify.
        var lower = new StringBuilder()
            .Append("\"@method\": GET\n")
            .Append("\"@authority\": resource.example\n")
            .Append("\"@path\": /path\n")
            .Append("\"signature-key\": sig=jwt;jwt=\"abc.def.ghi\"\n")
            .Append("\"@signature-params\": ").Append(paramsLine);
        Assert.True(key.Verify(Encoding.ASCII.GetBytes(lower.ToString()), signature));

        // Cross-check: the original mixed-case authority must NOT verify,
        // proving the handler emitted the lowercase form into the base.
        var mixed = new StringBuilder()
            .Append("\"@method\": GET\n")
            .Append("\"@authority\": Resource.EXAMPLE\n")
            .Append("\"@path\": /path\n")
            .Append("\"signature-key\": sig=jwt;jwt=\"abc.def.ghi\"\n")
            .Append("\"@signature-params\": ").Append(paramsLine);
        Assert.False(key.Verify(Encoding.ASCII.GetBytes(mixed.ToString()), signature));
    }

    [Fact]
    public async Task SendAsync_SignsPercentEncodedPathInWireForm()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", () => clock) { InnerHandler = capture };
        using var client = new HttpClient(signing);

        // Path contains a space (percent-encoded as %20) and a non-ASCII
        // character (percent-encoded by Uri). RFC 9421 §2.2.7 requires the
        // signed @path to match the request-target as transmitted on the
        // wire — i.e. the percent-encoded form.
        await client.GetAsync("https://resource.example/api/r%C3%A9sum%C3%A9%20draft");

        var req = capture.Captured!;
        var sigHeader = string.Join(',', req.Headers.GetValues("Signature"));
        var paramsHeader = string.Join(',', req.Headers.GetValues("Signature-Input"));
        var match = Regex.Match(sigHeader, @"^sig=:(?<b64>[^:]+):$");
        Assert.True(match.Success);
        var signature = Convert.FromBase64String(match.Groups["b64"].Value);
        var paramsLine = paramsHeader["sig=".Length..];

        var escaped = new StringBuilder()
            .Append("\"@method\": GET\n")
            .Append("\"@authority\": resource.example\n")
            .Append("\"@path\": /api/r%C3%A9sum%C3%A9%20draft\n")
            .Append("\"signature-key\": sig=jwt;jwt=\"abc.def.ghi\"\n")
            .Append("\"@signature-params\": ").Append(paramsLine);
        Assert.True(key.Verify(Encoding.ASCII.GetBytes(escaped.ToString()), signature));

        // The unescaped form must NOT verify, proving the handler signed
        // the wire-form (percent-encoded) bytes.
        var unescaped = new StringBuilder()
            .Append("\"@method\": GET\n")
            .Append("\"@authority\": resource.example\n")
            .Append("\"@path\": /api/résumé draft\n")
            .Append("\"signature-key\": sig=jwt;jwt=\"abc.def.ghi\"\n")
            .Append("\"@signature-params\": ").Append(paramsLine);
        Assert.False(key.Verify(Encoding.UTF8.GetBytes(unescaped.ToString()), signature));
    }
}
