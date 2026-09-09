using GuidedTour;
using GuidedTour.Components;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AAuth.Tests.Integration;

public class RenderedInputSecurityTests
{
    [Theory]
    [InlineData("<script>injected()</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("[link](javascript:alert(1))")]
    public async Task TokenDisplay_EncodesUntrustedMetadataAndClaims(string untrusted)
    {
        var services = new ServiceCollection().AddLogging().AddOptions();
        services.Configure<TourOptions>(_ => { });
        await using var provider = services.BuildServiceProvider();
        await using var renderer = new HtmlRenderer(provider, provider.GetRequiredService<ILoggerFactory>());
        var html = await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var component = await renderer.RenderComponentAsync<TokenView>(ParameterView.FromDictionary(new Dictionary<string, object?>
            {
                [nameof(TokenView.Header)] = "{\"name\":\"" + untrusted + "\"}",
                [nameof(TokenView.Payload)] = "{\"description\":\"" + untrusted + "\"}",
                [nameof(TokenView.Decoded)] = untrusted,
            }));
            return component.ToHtmlString();
        });
        Assert.DoesNotContain("<script>", html);
        Assert.DoesNotContain("<img src=x", html);
        Assert.DoesNotContain("href=\"javascript:", html);
        Assert.Contains(System.Net.WebUtility.HtmlEncode(untrusted), html);
    }
}