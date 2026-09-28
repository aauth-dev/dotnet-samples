using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Errors;

namespace AAuth.Tests.Agent;

public class DeferredExchangeTests
{
    private static readonly Uri Endpoint = new("https://ps.example/token");

    [Theory]
    [InlineData(null)]
    [InlineData("requirement=approval")]
    public async Task TokenExchange_ApprovalNeedsNoInteractionCallback(string? requirement)
    {
        using var handler = new SequenceHandler(
            _ => Json(HttpStatusCode.OK, "{\"issuer\":\"https://ps.example\",\"auth_token_endpoint\":\"https://ps.example/token\"}"),
            _ => Pending(requirement),
            _ => Json(HttpStatusCode.Forbidden, "{\"error\":\"denied\"}"));
        using var http = new InProcessHttpClient(handler);
        var client = new TokenExchangeClient(http, new MetadataClient(http));
        await Assert.ThrowsAsync<AAuthInteractionDeniedException>(() => client.ExchangeAsync(
            "https://ps.example", TestTokens.Resource, new TokenExchangeRequest
            {
                PollerOptions = new DeferredPollerOptions { MinPollInterval = TimeSpan.Zero },
            }));
        Assert.Equal(new[] { "GET", "POST", "GET" }, handler.Methods);
    }

    [Fact]
    public async Task ApprovalThenNewInteractions_DispatchesEveryChangedUrlAndCode()
    {
        var seen = new List<string>();
        using var handler = new SequenceHandler(
            _ => Pending("requirement=approval"),
            _ => Pending("requirement=interaction; url=\"https://ps.example/consent\"; code=\"ONE\""),
            _ => Pending("requirement=interaction; url=\"https://ps.example/consent\"; code=\"ONE\""),
            _ => Pending("requirement=interaction; url=\"https://ps.example/consent\"; code=\"TWO\""),
            _ => Pending("requirement=interaction; url=\"https://ps.example/next\"; code=\"TWO\""),
            _ => Json(HttpStatusCode.OK, "{}"));
        using var http = new InProcessHttpClient(handler);
        using var result = await new DeferredExchange(http, new MetadataClient(http)).PostAsync(
            Endpoint, new JsonObject(), new DeferredExchangeOptions
            {
                OnInteractionRequired = (interaction, _) => { seen.Add(interaction.BuildUserUrl()); return Task.CompletedTask; },
                PollerOptions = new DeferredPollerOptions { MinPollInterval = TimeSpan.Zero },
            }, CancellationToken.None);
        Assert.Equal(3, seen.Count);
        Assert.Equal(new[] { "POST", "GET", "GET", "GET", "GET", "GET" }, handler.Methods);
    }

    internal static HttpResponseMessage Pending(string? requirement)
    {
        var response = Json(HttpStatusCode.Accepted, "{\"status\":\"pending\"}");
        response.Headers.Location = new Uri("https://ps.example/pending/1");
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.Zero);
        if (requirement is not null) response.Headers.TryAddWithoutValidation("AAuth-Requirement", requirement);
        return response;
    }

    internal static HttpResponseMessage Json(HttpStatusCode status, string body)
        => new(status) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };

    internal sealed class SequenceHandler(params Func<HttpRequestMessage, HttpResponseMessage>[] responses) : HttpMessageHandler
    {
        public List<string> Methods { get; } = new();
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var index = Methods.Count;
            Methods.Add(request.Method.Method);
            return Task.FromResult(responses[index](request));
        }
    }
}