using System;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Agent;

public class SelfIssuedTokenRefresherTests
{
    private readonly AAuthKey _key = AAuthKey.Generate();

    [Fact]
    public void Constructor_ThrowsOnNullKey()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new SelfIssuedTokenRefresher(null!, "https://svc.example", "aauth:svc@svc.example", "k1"));
    }

    [Fact]
    public void Constructor_ThrowsOnEmptyIssuer()
    {
        Assert.Throws<ArgumentException>(() =>
            new SelfIssuedTokenRefresher(_key, "", "aauth:svc@svc.example", "k1"));
    }

    [Fact]
    public void Constructor_ThrowsOnEmptySubject()
    {
        Assert.Throws<ArgumentException>(() =>
            new SelfIssuedTokenRefresher(_key, "https://svc.example", "", "k1"));
    }

    [Fact]
    public void Constructor_ThrowsOnEmptyKid()
    {
        Assert.Throws<ArgumentException>(() =>
            new SelfIssuedTokenRefresher(_key, "https://svc.example", "aauth:svc@svc.example", ""));
    }

    [Fact]
    public async Task RefreshAsync_ReturnsValidJwt()
    {
        var refresher = new SelfIssuedTokenRefresher(
            _key, "https://svc.example", "aauth:svc@svc.example", "k1",
            personServer: "https://ps.example");

        var context = new TokenRefreshContext
        {
            CurrentToken = "",
            Issuer = "https://svc.example",
            AgentId = "aauth:svc@svc.example",
            SigningKeyThumbprint = "k1",
        };

        var token = await refresher.RefreshAsync(context, CancellationToken.None);

        Assert.NotEmpty(token);
        // Verify it's a valid 3-part JWT
        var parts = token.Split('.');
        Assert.Equal(3, parts.Length);
    }

    [Fact]
    public async Task RefreshAsync_TokenHasCorrectClaims()
    {
        var refresher = new SelfIssuedTokenRefresher(
            _key, "https://svc.example", "aauth:svc@svc.example", "k1",
            personServer: "https://ps.example");

        var context = new TokenRefreshContext
        {
            CurrentToken = "",
            Issuer = "https://svc.example",
            AgentId = "aauth:svc@svc.example",
            SigningKeyThumbprint = "k1",
        };

        var token = await refresher.RefreshAsync(context, CancellationToken.None);

        var parts = token.Split('.');
        var header = JsonNode.Parse(Base64UrlEncoder.Decode(parts[0]))!.AsObject();
        var payload = JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!.AsObject();

        Assert.Equal("https://svc.example", (string?)payload["iss"]);
        Assert.Equal("aauth:svc@svc.example", (string?)payload["sub"]);
        Assert.Equal("k1", (string?)header["kid"]);
        Assert.Equal("aa-agent+jwt", (string?)header["typ"]);
    }

    [Fact]
    public async Task RefreshAsync_CustomLifetime_IsHonoured()
    {
        var refresher = new SelfIssuedTokenRefresher(
            _key, "https://svc.example", "aauth:svc@svc.example", "k1",
            lifetime: TimeSpan.FromMinutes(10));

        var context = new TokenRefreshContext
        {
            CurrentToken = "",
            Issuer = "https://svc.example",
            AgentId = "aauth:svc@svc.example",
            SigningKeyThumbprint = "k1",
        };

        var token = await refresher.RefreshAsync(context, CancellationToken.None);

        var parts = token.Split('.');
        var payload = JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!.AsObject();
        var iat = (long)payload["iat"]!;
        var exp = (long)payload["exp"]!;
        var lifetime = TimeSpan.FromSeconds(exp - iat);

        Assert.InRange(lifetime.TotalMinutes, 9.5, 10.5);
    }

    [Fact]
    public async Task RefreshAsync_WithoutPersonServer_OmitsPsClaim()
    {
        var refresher = new SelfIssuedTokenRefresher(
            _key, "https://svc.example", "aauth:svc@svc.example", "k1");

        var context = new TokenRefreshContext
        {
            CurrentToken = "",
            Issuer = "https://svc.example",
            AgentId = "aauth:svc@svc.example",
            SigningKeyThumbprint = "k1",
        };

        var token = await refresher.RefreshAsync(context, CancellationToken.None);

        var parts = token.Split('.');
        var payload = JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!.AsObject();

        Assert.False(payload.ContainsKey("ps"));
    }
}
