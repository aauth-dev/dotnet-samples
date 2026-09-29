using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Testing;

public static class TestConsentBrowser
{
    public static void UseIsolatedDemoConsent(this IWebHostBuilder builder)
    {
        builder.UseSetting("AAuth:EnableIsolatedDemoConsent", "true");
        builder.ConfigureServices(services => services.AddSingleton<IStartupFilter, LoopbackPeer>());
    }

    private sealed class LoopbackPeer : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, continuation) =>
            {
                context.Connection.RemoteIpAddress = IPAddress.Loopback;
                context.Connection.LocalIpAddress = IPAddress.Loopback;
                if (context.Request.Path.StartsWithSegments("/interaction") || context.Request.Path.StartsWithSegments("/consent")
                    || context.Request.Path.StartsWithSegments("/dashboard"))
                    context.Request.Host = new Microsoft.AspNetCore.Http.HostString("localhost");
                return continuation(context);
            });
            next(app);
        };
    }

    public static async Task<HttpResponseMessage> DecideAsync(HttpClient client, string arrival, string decisionPath, Action<string>? inspectPage = null)
    {
        var cookies = new Dictionary<string, string>();
        async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
        {
            for (var redirect = 0; redirect < 8; redirect++)
            {
                if (cookies.Count > 0) request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", cookies.Values));
                var response = await client.SendAsync(request);
                if (response.Headers.TryGetValues("Set-Cookie", out var values))
                    foreach (var value in values)
                    {
                        var cookie = value.Split(';')[0];
                        cookies[cookie.Split('=')[0]] = cookie;
                    }
                if ((int)response.StatusCode is not (301 or 302 or 303 or 307 or 308)) return response;
                var location = new Uri(response.RequestMessage!.RequestUri!, response.Headers.Location!);
                response.Dispose();
                request = new HttpRequestMessage(HttpMethod.Get, location);
            }
            throw new InvalidOperationException("Consent redirect limit exceeded.");
        }

        var page = await SendAsync(new HttpRequestMessage(HttpMethod.Get, arrival));
        page.EnsureSuccessStatusCode();
        var html = await page.Content.ReadAsStringAsync();
        if (html.Contains("class=demo-login", StringComparison.Ordinal))
        {
            var loginUri = page.RequestMessage!.RequestUri;
            page.Dispose();
            page = await SendAsync(new HttpRequestMessage(HttpMethod.Post, loginUri)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["sign_in"] = "demo", ["csrf"] = Field(html, "csrf"),
                }),
            });
            page.EnsureSuccessStatusCode();
            html = await page.Content.ReadAsStringAsync();
        }
        inspectPage?.Invoke(html);
        page.Dispose();
        return await SendAsync(new HttpRequestMessage(HttpMethod.Post, decisionPath)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["session"] = Field(html, "session"), ["csrf"] = Field(html, "csrf"),
            }),
        });
    }

    public static string Field(string html, string name)
    {
        var match = Regex.Match(html, "name=" + Regex.Escape(name) + " value=['\"]([^'\"]+)['\"]");
        if (!match.Success) throw new InvalidOperationException("Missing consent form field: " + name);
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }
}