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
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for the <c>403 mission_terminated</c> response (AAuth protocol
/// §Mission Status Errors). The PS rejects any request referencing a mission
/// that is no longer active; the agent surfaces a typed exception.
/// </summary>
public class MissionTerminatedTests
{
    private const string Ps = "http://localhost:5555";

    private static TokenExchangeClient BuildClient(HttpMessageHandler handler)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri(Ps) };
        var metadata = new MetadataClient(new HttpClient(handler));
        return new TokenExchangeClient(http, metadata);
    }

    [Fact(DisplayName = "§Mission Status Errors — 403 mission_terminated on token request throws typed exception")]
    public async Task MissionTerminated_OnTokenRequest_Throws()
    {
        var client = BuildClient(new TerminatedHandler(deferUntilPoll: false));

        var ex = await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() =>
            client.ExchangeAsync(Ps, "fake-resource-token"));

        Assert.Equal("terminated", ex.MissionStatus);
    }

    [Fact(DisplayName = "§Mission Status Errors — 403 mission_terminated surfaced during polling")]
    public async Task MissionTerminated_DuringPolling_Throws()
    {
        var client = BuildClient(new TerminatedHandler(deferUntilPoll: true));

        var ex = await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() =>
            client.ExchangeAsync(Ps, "fake-resource-token", new TokenExchangeRequest
            {
                OnInteractionRequired = (_, _) => Task.CompletedTask,
            }));

        Assert.Equal("terminated", ex.MissionStatus);
    }

    [Fact(DisplayName = "§Mission Status Errors — error/mission_status codes round-trip via TokenErrorCode")]
    public void MissionTerminated_TokenErrorCode_RoundTrips()
    {
        Assert.True(TokenErrorResponse.TryParseCode("mission_terminated", out var code));
        Assert.Equal(TokenErrorCode.MissionTerminated, code);
        Assert.Equal("mission_terminated", new TokenErrorResponse(code).ErrorCode);
    }

    /// <summary>
    /// PS mock that returns <c>403 mission_terminated</c> — either immediately on
    /// the token request, or after an interaction deferral on the polled pending URL.
    /// </summary>
    private sealed class TerminatedHandler : HttpMessageHandler
    {
        private readonly bool _deferUntilPoll;
        public TerminatedHandler(bool deferUntilPoll) => _deferUntilPoll = deferUntilPoll;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;

            if (path == "/.well-known/aauth-person.json")
            {
                return Task.FromResult(Json(HttpStatusCode.OK, new JsonObject
                {
                    ["issuer"] = Ps,
                    ["token_endpoint"] = Ps + "/token",
                }));
            }

            if (path == "/token")
            {
                if (_deferUntilPoll)
                {
                    var pending = Json(HttpStatusCode.Accepted, new JsonObject { ["status"] = "pending" });
                    pending.Headers.Location = new Uri(Ps + "/pending/abc");
                    pending.Headers.TryAddWithoutValidation(
                        AAuthRequirementHeader.Name,
                        "requirement=interaction; url=\"" + Ps + "/i\"; code=\"ABCD1234\"");
                    return Task.FromResult(pending);
                }
                return Task.FromResult(Terminated());
            }

            // Pending URL poll → mission terminated.
            return Task.FromResult(Terminated());
        }

        private static HttpResponseMessage Terminated()
            => Json(HttpStatusCode.Forbidden, new JsonObject
            {
                ["error"] = "mission_terminated",
                ["mission_status"] = "terminated",
            });

        private static HttpResponseMessage Json(HttpStatusCode status, JsonObject body)
            => new(status)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
            };
    }
}
