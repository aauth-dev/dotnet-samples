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
        var http = new InProcessHttpClient(handler) { BaseAddress = new Uri(Ps) };
        var metadata = new MetadataClient(new InProcessHttpClient(handler));
        return new TokenExchangeClient(http, metadata);
    }

    [Fact(DisplayName = "§Mission Status Errors — 403 mission_terminated on token request throws typed exception")]
    public async Task MissionTerminated_OnTokenRequest_Throws()
    {
        var client = BuildClient(new TerminatedHandler(deferUntilPoll: false));

        var ex = await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() =>
            client.ExchangeAsync(Ps, TestTokens.Resource, "presented.person.token"));

        Assert.Equal("terminated", ex.MissionStatus);
        Assert.Equal("expired", ex.TerminationReason);
    }

    [Fact(DisplayName = "§Mission Status Errors — 403 mission_terminated surfaced during polling")]
    public async Task MissionTerminated_DuringPolling_Throws()
    {
        var client = BuildClient(new TerminatedHandler(deferUntilPoll: true));

        var ex = await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() =>
            client.ExchangeAsync(Ps, TestTokens.Resource, new TokenExchangeRequest
            {
                PresentedToken = "presented.person.token",
                PollerOptions = new DeferredPollerOptions
                {
                    DefaultPollInterval = TimeSpan.Zero,
                    MinPollInterval = TimeSpan.Zero,
                },
                OnInteractionRequired = (_, _) => Task.CompletedTask,
            }));

        Assert.Equal("terminated", ex.MissionStatus);
        Assert.Equal("expired", ex.TerminationReason);
    }

    [Fact(DisplayName = "§Mission Status Errors — error/mission_status codes round-trip via TokenErrorCode")]
    public void MissionTerminated_TokenErrorCode_RoundTrips()
    {
        Assert.True(TokenErrorResponse.TryParseCode("mission_terminated", out var code));
        Assert.Equal(TokenErrorCode.MissionTerminated, code);
        Assert.Equal("mission_terminated", new TokenErrorResponse(code).ErrorCode);
    }

    [Fact(DisplayName = "§Mission Management — termination reason constants match the spec table")]
    public void TerminationReasons_MatchSpecTable()
    {
        Assert.Equal("completed", AAuthConstants.MissionTerminationReasons.Completed);
        Assert.Equal("revoked", AAuthConstants.MissionTerminationReasons.Revoked);
        Assert.Equal("expired", AAuthConstants.MissionTerminationReasons.Expired);
        Assert.Equal("superseded", AAuthConstants.MissionTerminationReasons.Superseded);
        Assert.Equal("administrative", AAuthConstants.MissionTerminationReasons.Administrative);
    }

    [Fact(DisplayName = "§Mission Management — an unrecognized termination reason round-trips as an opaque value")]
    public async Task UnknownTerminationReason_RoundTrips()
    {
        var client = BuildClient(new TerminatedHandler(deferUntilPoll: false, reason: "budget_exhausted"));

        var ex = await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() =>
            client.ExchangeAsync(Ps, TestTokens.Resource, "presented.person.token"));

        Assert.Equal("terminated", ex.MissionStatus);
        Assert.Equal("budget_exhausted", ex.TerminationReason);
    }

    /// <summary>
    /// PS mock that returns <c>403 mission_terminated</c> — either immediately on
    /// the token request, or after an interaction deferral on the polled pending URL.
    /// </summary>
    private sealed class TerminatedHandler : HttpMessageHandler
    {
        private readonly bool _deferUntilPoll;
        private readonly string _reason;
        public TerminatedHandler(bool deferUntilPoll, string reason = AAuthConstants.MissionTerminationReasons.Expired)
        {
            _deferUntilPoll = deferUntilPoll;
            _reason = reason;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;

            if (path == "/.well-known/aauth-person.json")
            {
                return Task.FromResult(Json(HttpStatusCode.OK, new JsonObject
                {
                    ["issuer"] = Ps,
                    ["auth_token_endpoint"] = Ps + "/token",
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

        private HttpResponseMessage Terminated()
            => Json(HttpStatusCode.Forbidden, new JsonObject
            {
                ["error"] = "mission_terminated",
                ["mission_status"] = "terminated",
                ["termination_reason"] = _reason,
            });

        private static HttpResponseMessage Json(HttpStatusCode status, JsonObject body)
            => new(status)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
            };
    }
}
