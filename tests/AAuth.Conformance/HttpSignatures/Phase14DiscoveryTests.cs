using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

public class Phase14DiscoveryTests
{
    [Theory]
    [InlineData(".", "null", false)]
    [InlineData("..", "null", false)]
    [InlineData("aauth-agent.json", "null", false)]
    [InlineData("aauth-agent.json", "[]", false)]
    [InlineData("aauth-agent.json", "null", true)]
    [InlineData("aauth-agent.json", "[]", true)]
    [InlineData("aauth-agent.json", "{\"issuer\":\"{issuer}\",\"jwks_uri\":123}", false)]
    [InlineData("aauth-agent.json", "{\"issuer\":\"{issuer}\",\"jwks_uri\":[]}", false)]
    [InlineData("aauth-agent.json", "{\"issuer\":\"{issuer}\",\"jwks_uri\":{}}", false)]
    [InlineData("aauth-agent.json", "{\"issuer\":\"{issuer}\",\"jwks_uri\":\"{issuer}/keys\",\"auth_token_endpoint\":123}", false)]
    [InlineData("aauth-agent.json", "{}", true)]
    [InlineData("aauth-agent.json", "{\"keys\":null}", true)]
    [InlineData("aauth-agent.json", "{\"keys\":{}}", true)]
    [InlineData("aauth-agent.json", "{\"keys\":[null]}", true)]
    [InlineData("aauth-agent.json", "{\"keys\":[123]}", true)]
    [InlineData("aauth-agent.json", "{\"keys\":[{\"kid\":123}]}", true)]
    [InlineData("aauth-agent.json", "{", false)]
    [InlineData("aauth-agent.json", "{", true)]
    [InlineData("aauth-agent.json", "{\"issuer\":\"{issuer}\",\"issuer\":\"{issuer}\",\"jwks_uri\":\"{issuer}/keys\"}", false)]
    [InlineData("aauth-agent.json", "{\"keys\":[],\"keys\":[]}", true)]
    [InlineData("aauth-agent.json", "{\"keys\":[{\"kid\":\"issuer\",\"kid\":\"issuer\"}]}", true)]
    public async Task MalformedDiscoveryFailsBeforeHttpSignature(string dwk, string document, bool badJwks)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var app = builder.Build();
        string issuer = "";
        var fetched = 0;
        app.MapGet("/.well-known/aauth-agent.json", () =>
        {
            fetched++;
            return Results.Text(badJwks ? "{\"issuer\":\"" + issuer + "\",\"jwks_uri\":\"" + issuer + "/keys\"}" : document.Replace("{issuer}", issuer), "application/json");
        });
        app.MapGet("/keys", () => Results.Text(document, "application/json"));
        app.MapGet("/protected", async context =>
        {
            var policy = AAuthEgressPolicy.ForDevelopmentLoopback(issuer);
            using var discovery = AAuthHttpTransport.CreateClient(policy);
            using var metadata = new MetadataClient(discovery);
            using var jwks = new JwksClient(discovery);
            var middleware = new AAuthVerificationMiddleware(_ => throw new Exception("Must not authenticate"),
                new AAuthVerifier(), new DefaultSignatureKeyResolver(), metadata, jwks,
                new AAuthVerificationOptions { EgressPolicy = policy, AcceptedSchemes = ["jwt", "jwks_uri"] });
            await middleware.InvokeAsync(context);
        });
        await app.StartAsync();
        issuer = app.Urls.Single().Replace("127.0.0.1", "localhost", StringComparison.Ordinal);
        var key = AAuthKey.Generate();
        var token = new AgentTokenBuilder { EgressPolicy = AAuthEgressPolicy.ForDevelopmentLoopback(issuer), Issuer = issuer,
            Subject = "aauth:test@example.com", Key = key, KeyId = "issuer", ConfirmationKey = key }.Build();
        using var request = new HttpRequestMessage(HttpMethod.Get, issuer + "/protected");
        request.Headers.TryAddWithoutValidation("Signature-Key", dwk is "." or ".."
            ? $"sig=jwks_uri;id=\"{issuer}\";dwk=\"{dwk}\";kid=\"issuer\""
            : SignatureKeyHeader.FormatJwt(token));
        request.Headers.TryAddWithoutValidation("Signature-Input", "sig=(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=" + DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        request.Headers.TryAddWithoutValidation("Signature", "sig=:AQID:");
        using var client = new HttpClient();
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("error=invalid_key", response.Headers.GetValues("Signature-Error").Single());
        Assert.Equal(dwk is "." or ".." ? 0 : 1, fetched);
    }
}