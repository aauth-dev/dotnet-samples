using System;
using System.Collections.Generic;
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

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for the clarification seam on the embedded challenge exchange
/// (<see cref="ChallengeHandler.OnClarificationRequired"/>, surfaced on the
/// high-level builder as
/// <see cref="AAuth.HttpSig.ChallengeHandlingOptions.OnClarificationRequired"/>).
/// Per §Clarification Chat a PS MAY return <c>202 + requirement=clarification</c>
/// while resolving a resource-token exchange; an agent that wires the seam answers
/// the question (respond / cancel) and the exchange resumes — all within the single
/// signed request to the resource. This closes the gap where only the low-level
/// <see cref="TokenExchangeClient"/> could participate in clarification. The full
/// builder path (<c>WithChallengeHandling(o =&gt; o.OnClarificationRequired = ...)</c>)
/// is exercised end-to-end by the SampleApp mission-call-chain Playwright spec.
/// </summary>
public class ChallengeClarificationSeamTests
{
    private const string ResourceUrl = "https://r.example";
    private const string Ps = "https://ps.example";

    private static ChallengeHandler BuildChallengeHandler(
        ClarifyingExchangeHandler exchangeHandler,
        Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>> onClarification,
        Func<Interaction, CancellationToken, Task>? onInteraction = null)
    {
        var holder = new AAuthTokenHolder("initial-agent-token");
        var metaClient = new MetadataClient(new HttpClient(exchangeHandler));
        var exchangeClient = new TokenExchangeClient(new HttpClient(exchangeHandler), metaClient);

        return new ChallengeHandler(
            exchangeClient, holder,
            personServer: Ps,
            onInteractionRequired: onInteraction,
            pollerOptions: null,
            upstreamTokenProvider: null)
        {
            InnerHandler = new ChallengingResourceHandler(),
            OnClarificationRequired = onClarification,
        };
    }

    [Fact(DisplayName = "§Clarification Chat — the challenge seam answers a clarification then completes the exchange")]
    public async Task ChallengeSeam_AnswersClarification_ThenRetriesTo200()
    {
        var exchangeHandler = new ClarifyingExchangeHandler();
        ClarificationRequirement? seen = null;
        var challenge = BuildChallengeHandler(exchangeHandler, (clarification, _) =>
        {
            seen = clarification;
            return Task.FromResult(ClarificationResponse.Respond("Needed to summarize the inbox."));
        });

        using var client = new HttpClient(challenge) { BaseAddress = new Uri(ResourceUrl) };
        using var response = await client.GetAsync("/data");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(seen);
        Assert.Equal("Why does this mission need this access?", seen!.Clarification);
        Assert.Equal("Needed to summarize the inbox.", exchangeHandler.LastClarificationResponse);
    }

    [Fact(DisplayName = "§Clarification Chat — the challenge seam surfaces a user interaction that follows the clarification")]
    public async Task ChallengeSeam_ClarificationThenInteraction_SurfacesInteractionTo200()
    {
        var exchangeHandler = new ClarifyingExchangeHandler { EscalateToInteraction = true };
        Interaction? surfaced = null;
        var challenge = BuildChallengeHandler(
            exchangeHandler,
            (_, _) => Task.FromResult(ClarificationResponse.Respond("Needed to summarize the inbox.")),
            (interaction, _) => { surfaced = interaction; return Task.CompletedTask; });

        using var client = new HttpClient(challenge) { BaseAddress = new Uri(ResourceUrl) };
        using var response = await client.GetAsync("/data");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // The clarification was answered AND the follow-on user-interaction gate
        // was surfaced (a bare poll would have swallowed it).
        Assert.Equal("Needed to summarize the inbox.", exchangeHandler.LastClarificationResponse);
        Assert.NotNull(surfaced);
    }

    [Fact(DisplayName = "§Clarification Chat — the challenge seam declares the clarification capability")]
    public async Task ChallengeSeam_DeclaresClarificationCapability()
    {
        var exchangeHandler = new ClarifyingExchangeHandler();
        var challenge = BuildChallengeHandler(exchangeHandler, (_, _) =>
            Task.FromResult(ClarificationResponse.Respond("ok")));

        using var client = new HttpClient(challenge) { BaseAddress = new Uri(ResourceUrl) };
        using var response = await client.GetAsync("/data");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("clarification", exchangeHandler.DeclaredCapabilities);
    }

    [Fact(DisplayName = "§Cancel Request — the challenge seam can withdraw the request during clarification")]
    public async Task ChallengeSeam_CancelDuringClarification_Throws()
    {
        var exchangeHandler = new ClarifyingExchangeHandler();
        var challenge = BuildChallengeHandler(exchangeHandler, (_, _) =>
            Task.FromResult(ClarificationResponse.Cancel()));

        using var client = new HttpClient(challenge) { BaseAddress = new Uri(ResourceUrl) };

        await Assert.ThrowsAsync<AAuthClarificationCancelledException>(
            () => client.GetAsync("/data"));
        Assert.True(exchangeHandler.DeleteCalled);
    }

    /// <summary>Resource handler: 401 challenge first, 200 once an auth token is exchanged.</summary>
    private sealed class ChallengingResourceHandler : HttpMessageHandler
    {
        private int _callCount;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            if (Interlocked.Increment(ref _callCount) == 1)
            {
                var challenge = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                challenge.Headers.TryAddWithoutValidation(
                    AAuthRequirementHeader.Name,
                    AAuthRequirementHeader.FormatAuthToken("fake-resource-token"));
                return Task.FromResult(challenge);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true}", Encoding.UTF8, "application/json"),
            });
        }
    }

    /// <summary>
    /// PS exchange mock: serves metadata, returns a single
    /// <c>202 + requirement=clarification</c> on the token request, then mints the
    /// auth token once the agent answers on the pending URL.
    /// </summary>
    private sealed class ClarifyingExchangeHandler : HttpMessageHandler
    {
        public string? LastClarificationResponse { get; private set; }
        public bool DeleteCalled { get; private set; }
        public List<string> DeclaredCapabilities { get; } = new();

        /// <summary>When set, the PS moves to a user-interaction gate once the
        /// clarification is answered (clarification then §User Interaction).</summary>
        public bool EscalateToInteraction { get; init; }

        private bool _answered;
        private bool _interactionServed;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;

            if (path.Contains("well-known"))
            {
                return Json(HttpStatusCode.OK, new JsonObject
                {
                    ["issuer"] = Ps,
                    ["token_endpoint"] = Ps + "/token",
                });
            }

            if (request.Method == HttpMethod.Delete)
            {
                DeleteCalled = true;
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            if (path == "/token" && request.Method == HttpMethod.Post)
            {
                var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))?.AsObject();
                if (body?["capabilities"] is JsonArray caps)
                {
                    foreach (var c in caps)
                    {
                        if ((string?)c is { } v) { DeclaredCapabilities.Add(v); }
                    }
                }
                return Clarify();
            }

            if (path == "/pending/abc" && request.Method == HttpMethod.Post)
            {
                var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))?.AsObject();
                if (body?["clarification_response"] is { } cr)
                {
                    LastClarificationResponse = (string?)cr;
                }
                _answered = true;
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            if (path == "/pending/abc" && request.Method == HttpMethod.Get)
            {
                if (!_answered) { return Clarify(); }
                // After the answer, optionally escalate to a single user-interaction
                // gate before minting the token (clarification then §User Interaction).
                if (EscalateToInteraction && !_interactionServed)
                {
                    _interactionServed = true;
                    return Interact();
                }
                return Json(HttpStatusCode.OK, new JsonObject { ["auth_token"] = "fake-auth-token" });
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private static HttpResponseMessage Clarify()
        {
            var response = Json(HttpStatusCode.Accepted, new JsonObject
            {
                ["status"] = "pending",
                ["clarification"] = "Why does this mission need this access?",
                ["timeout"] = 120,
            });
            response.Headers.Location = new Uri(Ps + "/pending/abc");
            response.Headers.TryAddWithoutValidation(
                AAuthRequirementHeader.Name, "requirement=clarification");
            return response;
        }

        private static HttpResponseMessage Interact()
        {
            // Mirrors the real PS: the polled interaction 202 carries the
            // requirement header but NO Location (the pending URL is unchanged).
            var response = Json(HttpStatusCode.Accepted, new JsonObject { ["status"] = "pending" });
            response.Headers.TryAddWithoutValidation(
                AAuthRequirementHeader.Name,
                Interaction.Format(Ps + "/interaction", "abc"));
            return response;
        }

        private static HttpResponseMessage Json(HttpStatusCode status, JsonObject body)
            => new(status)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
            };
    }
}
