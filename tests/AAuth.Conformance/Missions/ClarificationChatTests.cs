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
/// Conformance for the agent side of the clarification chat (AAuth protocol
/// §Clarification Chat, §Agent Response to Clarification, §Clarification Limits).
/// </summary>
public class ClarificationChatTests
{
    private const string Ps = "http://localhost:5555";

    private static TokenExchangeClient BuildClient(HttpMessageHandler handler)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri(Ps) };
        var metadata = new MetadataClient(new HttpClient(handler));
        return new TokenExchangeClient(http, metadata);
    }

    [Fact(DisplayName = "§Clarification Required — requirement=clarification parsed into a typed model")]
    public void ClarificationRequirement_ParsedFromResponse()
    {
        var parsed = AAuthRequirementHeader.Parse("requirement=clarification");
        var body = new JsonObject
        {
            ["status"] = "pending",
            ["clarification"] = "Why do you need write access to my calendar?",
            ["timeout"] = 120,
            ["options"] = new JsonArray { "read-only", "read-write" },
        };

        var clarification = ClarificationRequirement.FromResponse(parsed, body);

        Assert.NotNull(clarification);
        Assert.Equal("Why do you need write access to my calendar?", clarification!.Clarification);
        Assert.Equal(120, clarification.TimeoutSeconds);
        Assert.Equal(new[] { "read-only", "read-write" }, clarification.Options);
    }

    [Fact(DisplayName = "§Clarification Required — missing clarification field throws")]
    public void ClarificationRequirement_MissingQuestion_Throws()
    {
        var parsed = AAuthRequirementHeader.Parse("requirement=clarification");
        Assert.Throws<FormatException>(() =>
            ClarificationRequirement.FromResponse(parsed, new JsonObject { ["status"] = "pending" }));
    }

    [Fact(DisplayName = "§Agent Response to Clarification — clarification_response POST then resume polling yields auth token")]
    public async Task ClarificationResponse_PostThenPoll_ReturnsAuthToken()
    {
        var handler = new ClarificationHandler();
        var client = BuildClient(handler);

        ClarificationRequirement? seen = null;
        var token = await client.ExchangeAsync(Ps, "fake-resource-token", new TokenExchangeRequest
        {
            OnClarificationRequired = (clarification, _) =>
            {
                seen = clarification;
                return Task.FromResult(ClarificationResponse.Respond("I need to create a calendar invite."));
            },
        });

        Assert.Equal("fake-auth-token", token);
        Assert.NotNull(seen);
        Assert.Equal("Why do you need write access?", seen!.Clarification);
        Assert.Equal("I need to create a calendar invite.", handler.LastClarificationResponse);
    }

    [Fact(DisplayName = "§Agent Response to Clarification — updated resource_token POST replaces the request")]
    public async Task ClarificationResponse_UpdatedRequest_PostsNewResourceToken()
    {
        var handler = new ClarificationHandler();
        var client = BuildClient(handler);

        var token = await client.ExchangeAsync(Ps, "fake-resource-token", new TokenExchangeRequest
        {
            OnClarificationRequired = (_, _) =>
                Task.FromResult(ClarificationResponse.Update("reduced-resource-token", "Reduced to read-only.")),
        });

        Assert.Equal("fake-auth-token", token);
        Assert.Equal("reduced-resource-token", handler.LastUpdatedResourceToken);
        Assert.Equal("Reduced to read-only.", handler.LastUpdatedJustification);
    }

    [Fact(DisplayName = "§Cancel Request — DELETE withdraws and surfaces a cancelled exception")]
    public async Task ClarificationResponse_Cancel_DeletesPendingUrl()
    {
        var handler = new ClarificationHandler();
        var client = BuildClient(handler);

        await Assert.ThrowsAsync<AAuthClarificationCancelledException>(() =>
            client.ExchangeAsync(Ps, "fake-resource-token", new TokenExchangeRequest
            {
                OnClarificationRequired = (_, _) => Task.FromResult(ClarificationResponse.Cancel()),
            }));

        Assert.True(handler.DeleteCalled);
    }

    [Fact(DisplayName = "§Clarification — missing callback throws when PS asks for clarification")]
    public async Task Clarification_NoCallback_Throws()
    {
        var handler = new ClarificationHandler();
        var client = BuildClient(handler);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.ExchangeAsync(Ps, "fake-resource-token", new TokenExchangeRequest()));
    }

    [Fact(DisplayName = "§Clarification Limits — exceeding the round limit throws")]
    public async Task Clarification_RoundLimit_Enforced()
    {
        // PS keeps asking for clarification forever.
        var handler = new ClarificationHandler { AlwaysClarify = true };
        var client = BuildClient(handler);

        await Assert.ThrowsAsync<AAuthClarificationLimitException>(() =>
            client.ExchangeAsync(Ps, "fake-resource-token", new TokenExchangeRequest
            {
                MaxClarificationRounds = 2,
                OnClarificationRequired = (_, _) =>
                    Task.FromResult(ClarificationResponse.Respond("Still need it.")),
            }));
    }

    [Fact(DisplayName = "§Clarification — agent declares the clarification capability")]
    public async Task Clarification_CapabilityDeclared()
    {
        var handler = new ClarificationHandler();
        var client = BuildClient(handler);

        await client.ExchangeAsync(Ps, "fake-resource-token", new TokenExchangeRequest
        {
            OnClarificationRequired = (_, _) =>
                Task.FromResult(ClarificationResponse.Respond("ok")),
        });

        Assert.Contains("clarification", handler.DeclaredCapabilities);
    }

    /// <summary>
    /// Stateful PS mock: first POST /token returns a clarification 202; after the
    /// agent answers on the pending URL, a GET returns the auth token. With
    /// <see cref="AlwaysClarify"/>, every poll returns a new clarification 202.
    /// </summary>
    private sealed class ClarificationHandler : HttpMessageHandler
    {
        public bool AlwaysClarify { get; init; }
        public string? LastClarificationResponse { get; private set; }
        public string? LastUpdatedResourceToken { get; private set; }
        public string? LastUpdatedJustification { get; private set; }
        public bool DeleteCalled { get; private set; }
        public List<string> DeclaredCapabilities { get; } = new();

        private bool _answered;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;

            if (path == "/.well-known/aauth-person.json")
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
                        var v = (string?)c;
                        if (v is not null) { DeclaredCapabilities.Add(v); }
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
                if (body?["resource_token"] is { } rt)
                {
                    LastUpdatedResourceToken = (string?)rt;
                    LastUpdatedJustification = (string?)body["justification"];
                }
                _answered = true;
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            if (path == "/pending/abc" && request.Method == HttpMethod.Get)
            {
                if (AlwaysClarify)
                {
                    return Clarify();
                }
                return _answered
                    ? Json(HttpStatusCode.OK, new JsonObject { ["auth_token"] = "fake-auth-token" })
                    : Clarify();
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private static HttpResponseMessage Clarify()
        {
            var response = Json(HttpStatusCode.Accepted, new JsonObject
            {
                ["status"] = "pending",
                ["clarification"] = "Why do you need write access?",
                ["timeout"] = 120,
            });
            response.Headers.Location = new Uri(Ps + "/pending/abc");
            response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name, "requirement=clarification");
            return response;
        }

        private static HttpResponseMessage Json(HttpStatusCode status, JsonObject body)
            => new(status)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
            };
    }
}
