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
    private static readonly AAuth.Crypto.AAuthKey SigningKey = AAuth.Crypto.AAuthKey.Generate();
    // Static field initializer cannot await; local key signing completes synchronously.
    private static readonly string AgentToken = new AAuth.Tokens.AgentTokenBuilder
    {
        Issuer = "https://ap.example", Subject = "aauth:test@ap.example", KeyId = "key",
        Key = SigningKey, ConfirmationKey = SigningKey,
    }.BuildAsync().AsTask().GetAwaiter().GetResult();
    private static ValueTask<string> ResourceTokenAsync(string presentedToken)
    {
        var presented = AAuth.Tokens.TokenVerifier.DecodeJsonSegment(presentedToken.Split('.')[1], "payload");
        return new AAuth.Tokens.ResourceTokenBuilder
        {
            Issuer = ResourceUrl, Audience = Ps, PersonServer = Ps,
            Subject = (string)presented["sub"]!, PresentedJti = (string)presented["jti"]!,
            AgentJkt = SigningKey.ComputeJwkThumbprint(), Key = SigningKey, KeyId = "key",
        }.BuildAsync();
    }

    private static ValueTask<string> PersonTokenAsync() => new AAuth.Tokens.PersonTokenBuilder
    {
        Issuer = Ps, Audience = ResourceUrl, Subject = "person-1", ConfirmationKey = SigningKey,
        AgentTokenExpiresAt = DateTimeOffset.FromUnixTimeSeconds(
            (long)AAuth.Tokens.TokenVerifier.DecodeJsonSegment(AgentToken.Split('.')[1], "payload")["exp"]!),
        Lifetime = TimeSpan.FromMinutes(30), Key = SigningKey, KeyId = "key",
    }.BuildAsync();

    private static ChallengeHandler BuildChallengeHandler(
        ClarifyingExchangeHandler exchangeHandler,
        Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>> onClarification,
        Func<Interaction, CancellationToken, Task>? onInteraction = null,
        int maxRounds = ClarificationExchange.DefaultMaxRounds)
    {
        var holder = new AAuthTokenHolder();
        var metaClient = new MetadataClient(new InProcessHttpClient(exchangeHandler));
        // The PS exchange is agent-signed; the resource request presents the current carrier.
        var exchangeClient = new TokenExchangeClient(new InProcessHttpClient(
            new AAuth.HttpSig.AAuthSigningHandler(SigningKey, () => AgentToken) { InnerHandler = exchangeHandler }), metaClient);

        return new ChallengeHandler(
            exchangeClient, holder, new AAuth.Tokens.TokenVerifier { EgressPolicy = TestEgress.Policy },
            metaClient, new JwksClient(new InProcessHttpClient(exchangeHandler)),
            personServer: Ps,
            onInteractionRequired: onInteraction,
            pollerOptions: new DeferredPollerOptions
            {
                DefaultPollInterval = TimeSpan.Zero,
                MinPollInterval = TimeSpan.Zero,
            },
            upstreamTokenProvider: null)
        {
            InnerHandler = new AAuth.HttpSig.AAuthSigningHandler(SigningKey, new AAuth.HttpSig.JwtSignatureKeyProvider(
                request => holder.SelectForRequest(request, AgentToken, SigningKey.ComputeJwkThumbprint())))
            {
                InnerHandler = new ChallengingResourceHandler(),
            },
            OnClarificationRequired = onClarification,
            MaxClarificationRounds = maxRounds,
        };
    }

    [Fact(DisplayName = "§Clarification Chat — a per-request clarification handler beats the configured one and the round limit applies")]
    public async Task PerRequestClarificationHandler_BeatsConfigured_AndHitsRoundLimit()
    {
        var exchangeHandler = new ClarifyingExchangeHandler { AlwaysClarify = true };
        var configured = 0;
        var challenge = BuildChallengeHandler(exchangeHandler, (_, _) =>
        {
            configured++;
            return Task.FromResult(ClarificationResponse.Respond("configured"));
        }, maxRounds: 2);
        var perRequest = new CountingClarificationHandler();

        using var client = new InProcessHttpClient(challenge) { BaseAddress = new Uri(ResourceUrl) };
        using var request = new HttpRequestMessage(HttpMethod.Get, "/data");
        request.Options.Set(AAuthRequestOptions.ClarificationHandler, perRequest);

        await Assert.ThrowsAsync<AAuthClarificationLimitException>(() => client.SendAsync(request));
        Assert.Equal(0, configured);
        Assert.True(perRequest.Calls >= 2, $"calls={perRequest.Calls}");
        Assert.Equal("per-request", exchangeHandler.LastClarificationResponse);
    }

    [Fact(DisplayName = "§User Interaction — PS- and resource-initiated interactions reach the same handler with their Source")]
    public async Task PersonServerAndResourceInteraction_ReachTheSameHandler()
    {
        var handler = new SourceRecorder();
        var challenge = BuildChallengeHandler(new ClarifyingExchangeHandler { EscalateToInteraction = true },
            (_, _) => Task.FromResult(ClarificationResponse.Respond("ok")), handler.OnInteractionRequiredAsync);
        using (var client = new InProcessHttpClient(challenge) { BaseAddress = new Uri(ResourceUrl) })
            await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => client.GetAsync("/data"));

        var resource = new InteractionHandler(handler, observer: null, minPollInterval: TimeSpan.Zero)
        {
            EgressPolicy = TestEgress.Policy,
            TransportContract = AAuthTransportContract.InProcessOnly,
            InnerHandler = new InteractingResourceHandler(),
        };
        using (var client = new InProcessHttpClient(resource))
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(ResourceUrl + "/deferred")).StatusCode);

        Assert.Equal([InteractionSource.PersonServer, InteractionSource.Resource], handler.Sources);
    }

    private sealed class CountingClarificationHandler : IAAuthClarificationHandler
    {
        public int Calls { get; private set; }

        public Task<ClarificationResponse> OnClarificationRequiredAsync(ClarificationRequirement clarification,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(ClarificationResponse.Respond("per-request"));
        }
    }

    private sealed class SourceRecorder : IAAuthInteractionHandler
    {
        public List<InteractionSource> Sources { get; } = [];

        public Task OnInteractionRequiredAsync(Interaction interaction, CancellationToken cancellationToken)
        {
            Sources.Add(interaction.Source);
            return Task.CompletedTask;
        }
    }

    /// <summary>Answers <c>202 + requirement=interaction</c>, then <c>200</c> on its pending URL.</summary>
    private sealed class InteractingResourceHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.AbsolutePath == "/pending/1")
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            var response = new HttpResponseMessage(HttpStatusCode.Accepted);
            response.Headers.Location = new Uri(ResourceUrl + "/pending/1");
            response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.Zero);
            response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name,
                Interaction.Format(ResourceUrl + "/consent", "resource-code"));
            return Task.FromResult(response);
        }
    }

    [Fact(DisplayName = "§Clarification Chat — the challenge seam answers a clarification then completes the exchange")]
    public async Task ChallengeSeam_AnswersClarification_ThenRetriesTo200()
    {
        var exchangeHandler = new ClarifyingExchangeHandler();
        ClarificationRequirement? seen = null;
        var challenge = BuildChallengeHandler(exchangeHandler, (clarification, _) =>
        {
            seen = clarification;
            return Task.FromResult(ClarificationResponse.Respond("Needed to compare available trip options."));
        });

        using var client = new InProcessHttpClient(challenge) { BaseAddress = new Uri(ResourceUrl) };
        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => client.GetAsync("/data"));
        Assert.NotNull(seen);
        Assert.Equal("Why does this mission need this access?", seen!.Clarification);
        Assert.Equal("Needed to compare available trip options.", exchangeHandler.LastClarificationResponse);
    }

    [Fact(DisplayName = "§Clarification Chat — the challenge seam surfaces a user interaction that follows the clarification")]
    public async Task ChallengeSeam_ClarificationThenInteraction_SurfacesInteractionTo200()
    {
        var exchangeHandler = new ClarifyingExchangeHandler { EscalateToInteraction = true };
        Interaction? surfaced = null;
        var challenge = BuildChallengeHandler(
            exchangeHandler,
            (_, _) => Task.FromResult(ClarificationResponse.Respond("Needed to compare available trip options.")),
            (interaction, _) => { surfaced = interaction; return Task.CompletedTask; });

        using var client = new InProcessHttpClient(challenge) { BaseAddress = new Uri(ResourceUrl) };
        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => client.GetAsync("/data"));
        // The clarification was answered AND the follow-on user-interaction gate
        // was surfaced (a bare poll would have swallowed it).
        Assert.Equal("Needed to compare available trip options.", exchangeHandler.LastClarificationResponse);
        Assert.NotNull(surfaced);
    }

    [Fact(DisplayName = "§Clarification Chat — the challenge seam declares the clarification capability")]
    public async Task ChallengeSeam_DeclaresClarificationCapability()
    {
        var exchangeHandler = new ClarifyingExchangeHandler();
        var challenge = BuildChallengeHandler(exchangeHandler, (_, _) =>
            Task.FromResult(ClarificationResponse.Respond("ok")));

        using var client = new InProcessHttpClient(challenge) { BaseAddress = new Uri(ResourceUrl) };
        await Assert.ThrowsAsync<AAuth.Tokens.TokenVerificationException>(() => client.GetAsync("/data"));
        Assert.Contains("clarification", exchangeHandler.DeclaredCapabilities);
    }

    [Fact(DisplayName = "§Cancel Request — the challenge seam can withdraw the request during clarification")]
    public async Task ChallengeSeam_CancelDuringClarification_Throws()
    {
        var exchangeHandler = new ClarifyingExchangeHandler();
        var challenge = BuildChallengeHandler(exchangeHandler, (_, _) =>
            Task.FromResult(ClarificationResponse.Cancel()));

        using var client = new InProcessHttpClient(challenge) { BaseAddress = new Uri(ResourceUrl) };

        await Assert.ThrowsAsync<AAuthClarificationCancelledException>(
            () => client.GetAsync("/data"));
        Assert.True(exchangeHandler.DeleteCalled);
    }

    /// <summary>
    /// Resource handler: an agent token gets <c>requirement=person-token</c>; a person
    /// token gets a resource token naming it; an auth token gets 200.
    /// </summary>
    private sealed class ChallengingResourceHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var carrier = AAuth.HttpSig.SignatureKeyParser.Parse(request.Headers.GetValues("Signature-Key").Single()).Jwt!;
            var typ = (string?)AAuth.Tokens.TokenVerifier.DecodeJsonSegment(carrier.Split('.')[0], "header")["typ"];
            if (typ == AAuth.Tokens.AuthTokenBuilder.TokenType)
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"ok\":true}", Encoding.UTF8, "application/json"),
                };
            }
            var challenge = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            challenge.Headers.TryAddWithoutValidation(
                AAuthRequirementHeader.Name,
                typ == AAuth.Tokens.PersonTokenBuilder.TokenType
                    ? AAuthRequirementHeader.FormatAuthToken(await ResourceTokenAsync(carrier))
                    : AAuthRequirementHeader.FormatPersonToken());
            return challenge;
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

        /// <summary>When set, the PS asks again after every answer.</summary>
        public bool AlwaysClarify { get; init; }

        private bool _answered;
        private bool _interactionServed;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;

            if (path == "/jwks")
            {
                var key = SigningKey.ToPublicJwk();
                key["kid"] = "key";
                return Json(HttpStatusCode.OK, new JsonObject { ["keys"] = new JsonArray(key) });
            }
            if (path.Contains("well-known"))
            {
                var origin = request.RequestUri.GetLeftPart(UriPartial.Authority);
                return Json(HttpStatusCode.OK, new JsonObject
                {
                    ["issuer"] = origin,
                    ["jwks_uri"] = origin + "/jwks",
                    ["auth_token_endpoint"] = Ps + "/token",
                    ["person_token_endpoint"] = Ps + "/person",
                });
            }

            if (path == "/person" && request.Method == HttpMethod.Post)
                return Json(HttpStatusCode.OK, new JsonObject { ["person_token"] = await PersonTokenAsync() });

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
                if (!_answered || AlwaysClarify) { return Clarify(); }
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
