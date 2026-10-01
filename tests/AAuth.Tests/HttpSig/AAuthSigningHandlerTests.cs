using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.HttpSig;
using Microsoft.Extensions.Time.Testing;
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

    private sealed class RecordingHandler(FakeTimeProvider clock) : HttpMessageHandler
    {
        public ConcurrentQueue<CapturedRequest> Captured { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Captured.Enqueue(new CapturedRequest(
                request.Method.Method,
                request.RequestUri!,
                request.Headers.GetValues("Signature-Input").Single(),
                clock.GetUtcNow()));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private sealed record CapturedRequest(
        string Method,
        Uri Uri,
        string SignatureInput,
        DateTimeOffset ObservedAt);

    [Fact]
    public async Task SendAsync_IdenticalRequestsInOneSecond_WaitsForCurrentCreated()
    {
        var key = AAuthKey.Generate();
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero));
        var capture = new RecordingHandler(clock);
        using var first = new InProcessHttpClient(new AAuthSigningHandler(key, () => "abc.def.ghi", clock) { InnerHandler = capture });
        using var second = new InProcessHttpClient(new AAuthSigningHandler(key, () => "abc.def.ghi", clock) { InnerHandler = capture });

        await first.GetAsync("https://resource.example/api/data");
        var delayed = second.GetAsync("https://resource.example/api/data");
        await Task.Delay(50);

        Assert.False(delayed.IsCompleted);
        clock.Advance(TimeSpan.FromSeconds(1));
        await delayed;

        var requests = capture.Captured.ToArray();
        Assert.Equal(clock.GetUtcNow().AddSeconds(-1).ToUnixTimeSeconds(), Created(requests[0].SignatureInput));
        Assert.Equal(clock.GetUtcNow().ToUnixTimeSeconds(), Created(requests[1].SignatureInput));
        Assert.All(requests, request => Assert.True(Created(request.SignatureInput) <= request.ObservedAt.ToUnixTimeSeconds()));
    }

    [Fact]
    public async Task SendAsync_BurstOfIdenticalRequests_WaitsWithoutFutureCreatedOrTupleCollision()
    {
        var key = AAuthKey.Generate();
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero));
        var capture = new RecordingHandler(clock);
        using var client = new InProcessHttpClient(new AAuthSigningHandler(key, () => "abc.def.ghi", clock) { InnerHandler = capture });

        var sends = Enumerable.Range(0, 62)
            .Select(_ => client.GetAsync("https://resource.example/api/data"))
            .ToArray();
        await WaitForCountAsync(capture, 1);

        for (var i = 1; i < sends.Length; i++)
        {
            Assert.Equal(i, capture.Captured.Count);
            clock.Advance(TimeSpan.FromSeconds(1));
            await WaitForCountAsync(capture, i + 1);
        }

        await Task.WhenAll(sends);
        var tuples = new HashSet<string>(StringComparer.Ordinal);
        foreach (var request in capture.Captured)
        {
            var created = Created(request.SignatureInput);
            Assert.True(created <= request.ObservedAt.ToUnixTimeSeconds());
            var authority = request.Uri.Authority.ToLowerInvariant();
            var path = "/" + request.Uri.GetComponents(UriComponents.Path, UriFormat.UriEscaped);
            Assert.True(tuples.Add($"{created}|{request.Method}|{authority}|{path}"));
        }
    }

    [Fact]
    public async Task SendAsync_CancelledWhileWaiting_SendsNothing()
    {
        var key = AAuthKey.Generate();
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero));
        var capture = new RecordingHandler(clock);
        using var client = new InProcessHttpClient(new AAuthSigningHandler(key, () => "abc.def.ghi", clock) { InnerHandler = capture });

        await client.GetAsync("https://resource.example/api/data");
        using var cts = new CancellationTokenSource();
        var delayed = client.GetAsync("https://resource.example/api/data", cts.Token);
        await Task.Delay(50);
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => delayed);
        Assert.Single(capture.Captured);
    }

    [Fact]
    public async Task SendAsync_DifferentReplayTupleParts_DoNotWait()
    {
        var key = AAuthKey.Generate();
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero));
        var capture = new RecordingHandler(clock);
        using var client = new InProcessHttpClient(new AAuthSigningHandler(key, () => "abc.def.ghi", clock) { InnerHandler = capture });

        var sends = new[]
        {
            client.GetAsync("https://resource.example/api/data"),
            client.GetAsync("https://resource.example/api/other"),
            client.GetAsync("https://other.example/api/data"),
            client.PostAsync("https://resource.example/api/data", content: null),
        };

        await Task.WhenAll(sends);
        Assert.Equal(4, capture.Captured.Count);
        Assert.All(capture.Captured, request => Assert.Equal(clock.GetUtcNow().ToUnixTimeSeconds(), Created(request.SignatureInput)));
    }

    [Fact]
    public async Task SendAsync_CreatedWait_EmitsMetric()
    {
        // The meter is process-wide: parallel tests may record while this test asserts.
        var measurements = new System.Collections.Concurrent.ConcurrentQueue<double>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == AAuthDiagnostics.SourceName
                && instrument.Name == "aauth.signing.created_wait")
            {
                meterListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<double>((_, value, _, _) => measurements.Enqueue(value));
        listener.Start();

        var key = AAuthKey.Generate();
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero));
        using var client = new InProcessHttpClient(new AAuthSigningHandler(key, () => "abc.def.ghi", clock)
        {
            InnerHandler = new RecordingHandler(clock),
        });

        await client.GetAsync("https://resource.example/api/data");
        var delayed = client.GetAsync("https://resource.example/api/data");
        await Task.Delay(50);
        clock.Advance(TimeSpan.FromSeconds(1));
        await delayed;

        Assert.Contains(measurements, value => value >= 1);
    }

    [Fact]
    public async Task SendAsync_AddsAllThreeSignatureHeaders()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);

        var signing = new AAuthSigningHandler(key, () => "eyJ.HEADER.PAYLOAD", new FakeTimeProvider(clock))
        {
            InnerHandler = capture,
        };
        using var client = new InProcessHttpClient(signing);

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
        using var client = new InProcessHttpClient(signing);

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
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", new FakeTimeProvider(clock)) { InnerHandler = capture };
        using var client = new InProcessHttpClient(signing);

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
        var signing = new AAuthSigningHandler(key, () => jwt, new FakeTimeProvider(clock)) { InnerHandler = capture };
        using var client = new InProcessHttpClient(signing);

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
        // A body is always covered by content-type and content-digest (§Covered Components).
        baseBuilder.Append("\"content-type\": ").Append(string.Join(", ", req.Content!.Headers.GetValues("Content-Type"))).Append('\n');
        baseBuilder.Append("\"content-digest\": ").Append(string.Join(", ", req.Content.Headers.GetValues("Content-Digest"))).Append('\n');
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
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", new FakeTimeProvider(clock)) { InnerHandler = capture };
        using var client = new InProcessHttpClient(signing);

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
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", new FakeTimeProvider(clock)) { InnerHandler = capture };
        using var client = new InProcessHttpClient(signing);

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
        using var client = new InProcessHttpClient(signing);

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
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", new FakeTimeProvider(clock)) { InnerHandler = capture };
        using var client = new InProcessHttpClient(signing);

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
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", new FakeTimeProvider(clock)) { InnerHandler = capture };
        using var client = new InProcessHttpClient(signing);

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
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", new FakeTimeProvider(clock)) { InnerHandler = capture };
        using var client = new InProcessHttpClient(signing);

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
        using var client = new InProcessHttpClient(signing);

        var request = new HttpRequestMessage(HttpMethod.Get, "https://resource.example/api");
        request.Options.Set(
            AAuthSigningHandler.AdditionalComponentsKey,
            new[] { "content-digest" });

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.SendAsync(request));
    }

    [Fact]
    public async Task SendAsync_BodyWithoutContentType_ThrowsBeforeSending()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi") { InnerHandler = capture };
        using var client = new InProcessHttpClient(signing);
        var request = new HttpRequestMessage(HttpMethod.Post, "https://resource.example/api")
        {
            Content = new ByteArrayContent([1, 2, 3]),
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => client.SendAsync(request));

        Assert.Contains("Content-Type", ex.Message);
        Assert.Null(capture.Captured);
        Assert.False(request.Headers.Contains("Signature"));
        Assert.False(request.Headers.Contains("Signature-Input"));
        Assert.False(request.Headers.Contains("Signature-Key"));
    }

    [Fact]
    public async Task SendAsync_RequiredContentDigest_ComputedAndCovered()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var clock = new DateTimeOffset(2026, 5, 18, 12, 0, 0, TimeSpan.Zero);
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi", new FakeTimeProvider(clock)) { InnerHandler = capture };
        using var client = new InProcessHttpClient(signing);

        const string bodyText = "{\"hello\":\"world\"}";
        var request = new HttpRequestMessage(HttpMethod.Post, "https://resource.example/api")
        {
            Content = new StringContent(bodyText, Encoding.UTF8, "application/json"),
        };
        // Resource requires content-digest, but the caller did not set it.
        request.Options.Set(
            AAuthSigningHandler.AdditionalComponentsKey,
            new[] { "content-digest" });

        await client.SendAsync(request);

        var req = capture.Captured!;
        var expectedDigest =
            $"sha-256=:{Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(bodyText)))}:";
        Assert.Equal(expectedDigest, string.Join(", ", req.Content!.Headers.GetValues("Content-Digest")));

        var input = string.Join(',', req.Headers.GetValues("Signature-Input"));
        Assert.Equal(
            $"sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\" \"content-digest\" \"content-type\");created={clock.ToUnixTimeSeconds()}",
            input);

        // The auto-computed digest must be covered by the signature.
        var sigHeader = string.Join(',', req.Headers.GetValues("Signature"));
        var signature = Convert.FromBase64String(
            Regex.Match(sigHeader, @"^sig=:(?<b64>[^:]+):$").Groups["b64"].Value);
        var paramsLine = input["sig=".Length..];
        var baseStr = new StringBuilder()
            .Append("\"@method\": POST\n")
            .Append("\"@authority\": resource.example\n")
            .Append("\"@path\": /api\n")
            .Append("\"signature-key\": sig=jwt;jwt=\"abc.def.ghi\"\n")
            .Append("\"content-digest\": ").Append(expectedDigest).Append('\n')
            .Append("\"content-type\": application/json; charset=utf-8\n")
            .Append("\"@signature-params\": ").Append(paramsLine)
            .ToString();
        Assert.True(key.Verify(Encoding.ASCII.GetBytes(baseStr), signature));
    }

    [Fact]
    public async Task SendAsync_RequiredContentDigest_DoesNotOverwriteCallerHeader()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        var signing = new AAuthSigningHandler(key, () => "abc.def.ghi") { InnerHandler = capture };
        using var client = new InProcessHttpClient(signing);

        var request = new HttpRequestMessage(HttpMethod.Post, "https://resource.example/api")
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        request.Content.Headers.Add("Content-Digest", "sha-256=:caller-supplied:");
        request.Options.Set(
            AAuthSigningHandler.AdditionalComponentsKey,
            new[] { "content-digest" });

        await client.SendAsync(request);

        Assert.Equal(
            "sha-256=:caller-supplied:",
            string.Join(", ", capture.Captured!.Content!.Headers.GetValues("Content-Digest")));
    }

    [Fact]
    public async Task SendAsync_SignatureKeyLabelMustMatchHandlerLabel()
    {
        var key = AAuthKey.Generate();
        using var mismatch = new InProcessHttpClient(new AAuthSigningHandler(
            key,
            new JwtSignatureKeyProvider(() => "abc.def.ghi", label: "alt"))
        {
            InnerHandler = new CaptureHandler(),
        });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => mismatch.GetAsync("https://resource.example/api"));
        Assert.Contains("provider label", ex.Message);

        var capture = new CaptureHandler();
        using var matching = new InProcessHttpClient(new AAuthSigningHandler(
            key,
            new JwtSignatureKeyProvider(() => "abc.def.ghi", label: "alt"))
        {
            Label = "alt",
            InnerHandler = capture,
        });
        await matching.GetAsync("https://resource.example/api");

        Assert.Equal("alt=jwt;jwt=\"abc.def.ghi\"", capture.Captured!.Headers.GetValues("Signature-Key").Single());
        Assert.StartsWith("alt=(", capture.Captured.Headers.GetValues("Signature-Input").Single(), StringComparison.Ordinal);
    }

    private static long Created(string signatureInput)
        => long.Parse(Regex.Match(signatureInput, @"created=(\d+)").Groups[1].Value);

    private static async Task WaitForCountAsync(RecordingHandler capture, int count)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (capture.Captured.Count < count)
        {
            cts.Token.ThrowIfCancellationRequested();
            await Task.Delay(10, cts.Token);
        }
    }
}
