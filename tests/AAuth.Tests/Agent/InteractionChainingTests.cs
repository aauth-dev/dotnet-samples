using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;
using AAuth.Server.CallChaining;
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
        var metaClient = new MetadataClient(new InProcessHttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(handler), metaClient);

        Interaction? captured = null;

        var ex = await Assert.ThrowsAsync<AAuthInteractionChainedException>(
            () => exchangeClient.ExchangeAsync(
                PsUrl, TestTokens.Resource,
                new TokenExchangeRequest
                {
                    PresentedToken = "presented",
                    OnInteractionRequired = (interaction, _) =>
                    {
                        captured = interaction;
                        throw new AAuthInteractionChainedException(interaction);
                    },
                }));

        // The downstream interaction is carried on the exception so the
        // intermediary can wrap it in an intermediary-owned code and URL.
        Assert.NotNull(captured);
        Assert.Same(captured, ex.DownstreamInteraction);
        Assert.Equal(InteractionUrl, ex.DownstreamInteraction.Url);
        Assert.Equal(InteractionCode, ex.DownstreamInteraction.Code);

        // The poll (GET on the pending Location) must NEVER run — the throw
        // unwinds the exchange before DeferredPoller.PollAsync is reached.
        Assert.False(handler.PendingPolled,
            "DeferredPoller must not poll the pending URL when the callback aborts via AAuthInteractionChainedException.");
    }

    [Fact(DisplayName = "Chaining — SDK helper emits an intermediary code and keeps downstream code private")]
    public void ChainedInteraction_ParksOwnCodeAndRedirectsToDownstream()
    {
        var downstream = new Interaction(InteractionUrl, InteractionCode);
        var entry = AAuthChainedInteractions.Park(
            "http://localhost:5200", "/pending", "/chain-interaction",
            new AAuthInteractionChainedException(downstream),
            "calendar.events", new JsonObject { ["path"] = "/events" },
            DateTimeOffset.UtcNow.AddMinutes(5));

        Assert.NotEqual(InteractionCode, entry.Code);
        Assert.Equal("http://localhost:5200/chain-interaction/" + entry.Id, entry.InteractionUrl);
        Assert.Equal("/pending/" + entry.Id, entry.PendingUrl);
        Assert.Equal(downstream, entry.DownstreamInteraction);
        Assert.Equal("calendar.events", entry.OperationName);
    }

    [Fact(DisplayName = "Chaining — direct-interaction callback (returns normally) still blocking-polls to the auth token")]
    public async Task DirectInteractionCallback_StillPollsToTerminal()
    {
        var handler = new DeferredExchangeHandler();
        var metaClient = new MetadataClient(new InProcessHttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(handler), metaClient);

        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => exchangeClient.ExchangeAsync(
            PsUrl, TestTokens.Resource,
            new TokenExchangeRequest
            {
                PresentedToken = "presented",
                OnInteractionRequired = (_, _) => Task.CompletedTask,
            }));
        Assert.True(handler.PendingPolled);
    }

    [Fact(DisplayName = "Chaining — no callback on a 202 throws a terminal user_unreachable token-exchange error")]
    public async Task NoCallback_ThrowsUserUnreachable()
    {
        var handler = new DeferredExchangeHandler();
        var metaClient = new MetadataClient(new InProcessHttpClient(handler));
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(handler), metaClient);

        var ex = await Assert.ThrowsAsync<AAuthTokenExchangeException>(
            () => exchangeClient.ExchangeAsync(PsUrl, TestTokens.Resource, "presented"));

        Assert.Equal("user_unreachable", ex.ErrorCode);
        Assert.Equal(403, ex.StatusCode);
        Assert.True(ex.IsTerminal);
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
                    ["auth_token_endpoint"] = $"{origin}/token",
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
                Interaction.Format(InteractionUrl, InteractionCode, TestEgress.Policy));
            return Task.FromResult(response);
        }
    }
}
