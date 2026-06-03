using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Headers;
using Xunit;

namespace AAuth.Tests.Agent;

/// <summary>
/// Interaction Chaining (AAuth protocol §Interaction Chaining): an intermediary
/// that has no user aborts an in-flight token exchange by throwing
/// <see cref="AAuthInteractionChainedException"/> from its
/// <c>OnInteractionRequired</c> callback, so it can re-emit its own
/// <c>202 requirement=interaction</c> instead of blocking-polling the deferred
/// <c>Location</c>.
/// </summary>
public class InteractionChainingTests
{
    private const string PsUrl = "http://localhost:5555";
    private const string InteractionUrl = "http://localhost:5555/interaction";
    private const string InteractionCode = "pending-123";

    [Fact(DisplayName = "Chaining — callback throwing AAuthInteractionChainedException aborts before polling")]
    public async Task ChainedException_AbortsBeforePolling_AndSurfacesInteraction()
    {
        var handler = new DeferredExchangeHandler();
        var metaClient = new MetadataClient(new HttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(handler), metaClient);

        Interaction? captured = null;

        var ex = await Assert.ThrowsAsync<AAuthInteractionChainedException>(
            () => exchangeClient.ExchangeAsync(
                PsUrl, "fake-resource-token",
                new TokenExchangeRequest
                {
                    OnInteractionRequired = (interaction, _) =>
                    {
                        captured = interaction;
                        throw new AAuthInteractionChainedException(interaction);
                    },
                }));

        // The interaction (PS url + code) is carried on the exception so the
        // intermediary can pass it through when re-emitting its own 202.
        Assert.NotNull(captured);
        Assert.Same(captured, ex.Interaction);
        Assert.Equal(InteractionUrl, ex.Interaction.Url);
        Assert.Equal(InteractionCode, ex.Interaction.Code);

        // The poll (GET on the pending Location) must NEVER run — the throw
        // unwinds the exchange before DeferredPoller.PollAsync is reached.
        Assert.False(handler.PendingPolled,
            "DeferredPoller must not poll the pending URL when the callback aborts via AAuthInteractionChainedException.");
    }

    [Fact(DisplayName = "Chaining — direct-interaction callback (returns normally) still blocking-polls to the auth token")]
    public async Task DirectInteractionCallback_StillPollsToTerminal()
    {
        var handler = new DeferredExchangeHandler();
        var metaClient = new MetadataClient(new HttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(handler), metaClient);

        var authToken = await exchangeClient.ExchangeAsync(
            PsUrl, "fake-resource-token",
            new TokenExchangeRequest
            {
                OnInteractionRequired = (_, _) => Task.CompletedTask,
            });

        Assert.Equal("fake-auth-token", authToken);
        Assert.True(handler.PendingPolled);
    }

    [Fact(DisplayName = "Chaining — no callback on a 202 still throws the existing HttpRequestException")]
    public async Task NoCallback_StillThrowsExisting()
    {
        var handler = new DeferredExchangeHandler();
        var metaClient = new MetadataClient(new HttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(handler), metaClient);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => exchangeClient.ExchangeAsync(PsUrl, "fake-resource-token"));

        Assert.False(handler.PendingPolled);
    }

    /// <summary>
    /// Serves PS metadata, returns a single <c>202 requirement=interaction</c>
    /// on the token POST, and a <c>200 + auth_token</c> on any subsequent poll
    /// of the pending <c>Location</c>. Records whether the pending URL was ever
    /// polled so tests can assert the chained-abort path never reaches it.
    /// </summary>
    private sealed class DeferredExchangeHandler : HttpMessageHandler
    {
        public bool PendingPolled { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;

            if (path.Contains("well-known", StringComparison.Ordinal))
            {
                var origin = request.RequestUri.GetLeftPart(UriPartial.Authority);
                var metadata = new JsonObject
                {
                    ["issuer"] = origin,
                    ["token_endpoint"] = $"{origin}/token",
                };
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(metadata.ToJsonString(), Encoding.UTF8, "application/json"),
                });
            }

            // Pending poll → terminal 200 with the auth token.
            if (path.StartsWith("/pending/", StringComparison.Ordinal))
            {
                PendingPolled = true;
                var ok = new JsonObject { ["auth_token"] = "fake-auth-token" };
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(ok.ToJsonString(), Encoding.UTF8, "application/json"),
                });
            }

            // Token POST → 202 deferred interaction.
            var response = new HttpResponseMessage(HttpStatusCode.Accepted)
            {
                Content = new StringContent(
                    new JsonObject { ["status"] = "pending" }.ToJsonString(),
                    Encoding.UTF8, "application/json"),
            };
            response.Headers.Location = new Uri($"{PsUrl}/pending/{InteractionCode}");
            response.Headers.TryAddWithoutValidation("Retry-After", "0");
            response.Headers.TryAddWithoutValidation("Cache-Control", "no-store");
            response.Headers.TryAddWithoutValidation(
                AAuthRequirementHeader.Name,
                Interaction.Format(InteractionUrl, InteractionCode));
            return Task.FromResult(response);
        }
    }
}
