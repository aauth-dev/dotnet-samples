using System;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth;
using AAuth.Errors;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.Errors;

/// <summary>
/// Conformance tests for <c>Signature-Error</c> header emission per
/// §Verification (Server) / §Authentication Errors.
/// </summary>
public class SignatureErrorTests : IAsyncLifetime
{
    private IHost? _host;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier());
        var app = builder.Build();
        app.UseAAuthVerification(new AAuthVerificationOptions
        {
            RequireIssuerVerification = false,
        });
        app.MapGet("/protected", () => Results.Ok("hello"));
        await app.StartAsync();
        _host = app;
    }

    public async Task DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.StopAsync();
            _host.Dispose();
        }
    }

    private System.Net.Http.HttpClient Client => _host!.GetTestClient();

    [Fact(DisplayName = "§Authentication Errors — missing headers returns invalid_request")]
    public async Task MissingHeaders_Returns_InvalidRequest()
    {
        var response = await Client.GetAsync("/protected");
        Assert.Equal(StatusCodes.Status401Unauthorized, (int)response.StatusCode);
        Assert.True(response.Headers.TryGetValues(SignatureError.HeaderName, out var values));
        Assert.Contains("invalid_request", string.Join(",", values));
    }

    [Fact(DisplayName = "§Authentication Errors — bad Signature-Key returns invalid_key")]
    public async Task BadSignatureKey_Returns_InvalidKey()
    {
        var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, "/protected");
        request.Headers.TryAddWithoutValidation("Signature", "sig=:AAAA:");
        request.Headers.TryAddWithoutValidation("Signature-Input", "sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=9999999999");
        request.Headers.TryAddWithoutValidation("Signature-Key", "sig=jwt;jwt=\"not-a-jwt\"");

        var response = await Client.SendAsync(request);
        Assert.Equal(StatusCodes.Status401Unauthorized, (int)response.StatusCode);
        Assert.True(response.Headers.TryGetValues(SignatureError.HeaderName, out var values));
        var header = string.Join(",", values);
        Assert.True(header.Contains("invalid_key") || header.Contains("invalid_jwt"),
            $"Expected invalid_key or invalid_jwt, got: {header}");
    }

    [Fact(DisplayName = "§Authentication Errors — stale created returns invalid_signature")]
    public async Task StaleCreated_Returns_InvalidSignature()
    {
        var agentKey = AAuthKey.Generate();
        var agentToken = new AAuth.Tokens.AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:test@ap.example",
            KeyId = "k1",
            Key = agentKey,
        }.Build();
        var signatureKey = SignatureKeyHeader.FormatJwt(agentToken);

        var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, "/protected");
        request.Headers.TryAddWithoutValidation("Signature-Key", signatureKey);

        var oldCreated = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
        var signatureInput = $"sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created={oldCreated}";
        request.Headers.TryAddWithoutValidation("Signature-Input", signatureInput);
        request.Headers.TryAddWithoutValidation("Signature", "sig=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:");

        var response = await Client.SendAsync(request);
        Assert.Equal(StatusCodes.Status401Unauthorized, (int)response.StatusCode);
        Assert.True(response.Headers.TryGetValues(SignatureError.HeaderName, out var values));
        Assert.Contains("invalid_signature", string.Join(",", values));
    }

    [Fact(DisplayName = "§Signature-Error — format round-trips all codes")]
    public void FormatAndParse_RoundTrips()
    {
        foreach (SignatureErrorCode code in Enum.GetValues<SignatureErrorCode>())
        {
            var formatted = SignatureError.ToHeaderValue(code);
            Assert.True(SignatureError.TryParse(formatted, out var parsed));
            Assert.Equal(code, parsed);
        }
    }

    [Fact(DisplayName = "§Signature-Error — invalid_input includes required_input parameter")]
    public void InvalidInput_IncludesRequiredInput()
    {
        var header = SignatureError.Format(SignatureErrorCode.InvalidInput,
            new[] { "content-digest" });
        Assert.Contains("invalid_input", header);
        Assert.Contains("required_input=\"content-digest\"", header);
    }

    [Fact(DisplayName = "§Signature-Error — ParseRequiredInput extracts space-separated components")]
    public void ParseRequiredInput_ExtractsComponents()
    {
        var components = SignatureError.ParseRequiredInput(
            "invalid_input; required_input=\"@method @authority content-digest\"");
        Assert.Equal(new[] { "@method", "@authority", "content-digest" }, components);
    }

    [Fact(DisplayName = "§Signature-Error — ParseRequiredInput ignores look-alike parameter names")]
    public void ParseRequiredInput_IgnoresLookAlikeParameter()
    {
        // A different parameter whose name merely ends in "required_input" must
        // not be mistaken for the real required_input parameter.
        var components = SignatureError.ParseRequiredInput(
            "invalid_input; x-required_input=\"content-digest\"");
        Assert.Empty(components);
    }

    [Fact(DisplayName = "§Signature-Error — ParseRequiredInput returns empty for missing parameter")]
    public void ParseRequiredInput_ReturnsEmptyWhenAbsent()
    {
        Assert.Empty(SignatureError.ParseRequiredInput("invalid_input"));
        Assert.Empty(SignatureError.ParseRequiredInput(null));
        Assert.Empty(SignatureError.ParseRequiredInput(""));
    }

    [Fact(DisplayName = "§Signature-Error — unsupported_algorithm includes supported_algorithms parameter")]
    public void UnsupportedAlgorithm_IncludesSupportedAlgorithms()
    {
        var header = SignatureError.Format(SignatureErrorCode.UnsupportedAlgorithm,
            supportedAlgorithms: new[] { "EdDSA" });
        Assert.Contains("unsupported_algorithm", header);
        Assert.Contains("supported_algorithms=\"EdDSA\"", header);
    }

    [Fact(DisplayName = "§Authentication Errors — non-Ed25519 key returns unsupported_algorithm with supported_algorithms")]
    public async Task NonEd25519Key_Returns_UnsupportedAlgorithm()
    {
        // Build a JWT with an EC P-256 key in cnf.jwk (unsupported algorithm)
        var ecJwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";
        var headerJson = "{\"alg\":\"ES256\",\"typ\":\"aa-agent+jwt\"}";
        var payloadJson = "{\"iss\":\"https://ap.example\",\"sub\":\"aauth:test@ap.example\",\"cnf\":{\"jwk\":" + ecJwk + "}}";
        var header64 = Base64UrlEncoder.Encode(System.Text.Encoding.UTF8.GetBytes(headerJson));
        var payload64 = Base64UrlEncoder.Encode(System.Text.Encoding.UTF8.GetBytes(payloadJson));
        var fakeJwt = $"{header64}.{payload64}.AAAA";

        var signatureKey = $"sig=jwt;jwt=\"{fakeJwt}\"";
        var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, "/protected");
        request.Headers.TryAddWithoutValidation("Signature-Key", signatureKey);
        request.Headers.TryAddWithoutValidation("Signature-Input", "sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=9999999999");
        request.Headers.TryAddWithoutValidation("Signature", "sig=:AAAA:");

        var response = await Client.SendAsync(request);
        Assert.Equal(StatusCodes.Status401Unauthorized, (int)response.StatusCode);
        Assert.True(response.Headers.TryGetValues(SignatureError.HeaderName, out var values));
        var headerValue = string.Join(",", values);
        Assert.Contains("unsupported_algorithm", headerValue);
        Assert.Contains("supported_algorithms=\"EdDSA ES256\"", headerValue);
    }
}
