using AAuth.Agent;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Agent;

public class AAuthTokenHolderTests
{
    [Fact]
    public void Update_ReplacesCurrentToken()
    {
        var holder = new AAuthTokenHolder("first");
        Assert.Equal("first", holder.Current);
        holder.Update("second");
        Assert.Equal("second", holder.Current);
    }

    [Fact]
    public void SelectForRequest_DoesNotPresentCachedCarrierInsideRefreshMargin()
    {
        var cache = new InMemoryAAuthTokenCache();
        var holder = new AAuthTokenHolder(cache);
        var agentToken = TokenExpiringIn(TimeSpan.FromHours(1));
        var carrier = TokenExpiringIn(TimeSpan.FromMinutes(4));
        var key = new AAuthTokenCacheKey(agentToken, null, null, "https://resource.example", null, "thumb");
        cache.Set(key, carrier, DateTimeOffset.UtcNow.AddMinutes(4));
        using var request = new System.Net.Http.HttpRequestMessage(
            System.Net.Http.HttpMethod.Get,
            "https://resource.example/data");

        var selected = holder.SelectForRequest(request, agentToken, "thumb");

        Assert.Equal(agentToken, selected);
    }

    private static string TokenExpiringIn(TimeSpan lifetime)
    {
        var payload = new System.Text.Json.Nodes.JsonObject
        {
            ["exp"] = DateTimeOffset.UtcNow.Add(lifetime).ToUnixTimeSeconds(),
        };
        return "e30." + Base64UrlEncoder.Encode(System.Text.Encoding.UTF8.GetBytes(payload.ToJsonString())) + ".sig";
    }
}
