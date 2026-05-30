using System;
using System.Linq;
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

    [Fact]
    public async Task OnSignatureBase_IsInvokedWithBytesActuallySigned()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        string? observedBase = null;
        HttpRequestMessage? observedRequest = null;

        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi")
        {
            InnerHandler = capture,
            OnSignatureBase = (req, b) =>
            {
                observedRequest = req;
                observedBase = b;
            },
        };
        using var client = new HttpClient(signing);

        await client.GetAsync("https://resource.example/api");

        Assert.NotNull(observedBase);
        Assert.Same(capture.Captured, observedRequest);
        // The hook must receive the canonical signature base — the exact
        // bytes the signature is computed over — so a verifier rebuilding
        // the same string and re-verifying the emitted signature must succeed.
        var sigHeader = capture.Captured!.Headers.GetValues("Signature").Single();
        var b64 = Regex.Match(sigHeader, @":(?<v>[^:]+):").Groups["v"].Value;
        Assert.True(key.Verify(Encoding.ASCII.GetBytes(observedBase!), Convert.FromBase64String(b64)));
    }

    [Fact]
    public async Task SendAsync_NoAdditionalComponents_SignsBaseComponentsOnly()
    {
        // Regression guard: when no additional components are requested, the
        // Signature-Input must contain only the four base AAuth components.
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", () => clock) { InnerHandler = capture };
        using var client = new HttpClient(signing);

        await client.GetAsync("https://resource.example/api");

        var input = string.Join(',', capture.Captured!.Headers.GetValues("Signature-Input"));
        Assert.Equal(
            $"sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created={clock.ToUnixTimeSeconds()}",
            input);
    }

    [Fact]
    public async Task SendAsync_AdditionalComponents_AppendedAfterBaseAndVerify()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", () => clock) { InnerHandler = capture };
        using var client = new HttpClient(signing);

        var request = new HttpRequestMessage(HttpMethod.Post, "https://resource.example/api")
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        request.Content.Headers.Add("Content-Digest", "sha-256=:abc:");
        request.Options.Set(
            AAuthSigningHandler.AdditionalComponentsKey,
            new[] { "content-type", "content-digest" });

        await client.SendAsync(request);

        var req = capture.Captured!;
        var input = string.Join(',', req.Headers.GetValues("Signature-Input"));
        Assert.Equal(
            $"sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\" \"content-type\" \"content-digest\");created={clock.ToUnixTimeSeconds()}",
            input);

        // The additional components must be covered by the signature too.
        var sigHeader = string.Join(',', req.Headers.GetValues("Signature"));
        var signature = Convert.FromBase64String(
            Regex.Match(sigHeader, @"^sig=:(?<b64>[^:]+):$").Groups["b64"].Value);
        var paramsLine = input["sig=".Length..];
        var baseStr = new StringBuilder()
            .Append("\"@method\": POST\n")
            .Append("\"@authority\": resource.example\n")
            .Append("\"@path\": /api\n")
            .Append("\"signature-key\": sig=jwt;jwt=\"abc.def.ghi\"\n")
            .Append("\"content-type\": application/json; charset=utf-8\n")
            .Append("\"content-digest\": sha-256=:abc:\n")
            .Append("\"@signature-params\": ").Append(paramsLine)
            .ToString();
        Assert.True(key.Verify(Encoding.ASCII.GetBytes(baseStr), signature));
    }

    [Fact]
    public async Task SendAsync_AdditionalComponents_DeduplicatesAndIgnoresBaseComponents()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", () => clock) { InnerHandler = capture };
        using var client = new HttpClient(signing);

        var request = new HttpRequestMessage(HttpMethod.Get, "https://resource.example/api");
        request.Headers.Add("X-Custom", "v1");
        // Base components and duplicates must be filtered out.
        request.Options.Set(
            AAuthSigningHandler.AdditionalComponentsKey,
            new[] { "@method", "signature-key", "x-custom", "x-custom" });

        await client.SendAsync(request);

        var input = string.Join(',', capture.Captured!.Headers.GetValues("Signature-Input"));
        Assert.Equal(
            $"sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\" \"x-custom\");created={clock.ToUnixTimeSeconds()}",
            input);
    }

    [Fact]
    public async Task SendAsync_AdditionalComponentMissingFromRequest_Throws()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi") { InnerHandler = capture };
        using var client = new HttpClient(signing);

        var request = new HttpRequestMessage(HttpMethod.Get, "https://resource.example/api");
        request.Options.Set(
            AAuthSigningHandler.AdditionalComponentsKey,
            new[] { "content-digest" });

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.SendAsync(request));
    }
}
