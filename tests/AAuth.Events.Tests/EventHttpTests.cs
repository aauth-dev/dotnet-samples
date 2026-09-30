using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Samples.Events;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Events.Tests;

public class EventHttpTests
{
    [Theory]
    [InlineData("/events", "self-jwt", "unregistered")]
    [InlineData("/events", "self-jwt", "hwk")]
    [InlineData("/subscribe/public", "jwt", "unregistered")]
    [InlineData("/subscribe/public", "jwt", "hwk")]
    public async Task UnsupportedSchemeRetainsEndpointNegotiation(string path, string accepted, string scheme)
    {
        await using var host = await EventHost.StartAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, host.Issuer + path) { Content = JsonContent.Create(new { }) };
        request.Options.Set(AAuthSigningHandler.AdditionalComponentsKey, ["content-type", "content-digest"]);
        using var signer = new AAuthSigningHandler(host.AgentKey, new HwkSignatureKeyProvider(host.AgentKey));
        await signer.SignAsync(request);
        if (scheme == "unregistered")
        {
            request.Headers.Remove("Signature-Key");
            request.Headers.TryAddWithoutValidation("Signature-Key", "sig=unregistered");
        }
        using var response = await host.Http.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("error=unsupported_scheme", response.Headers.GetValues("Signature-Error").Single());
        Assert.Equal(accepted, response.Headers.GetValues("Accept-Signature-Scheme").Single());
    }

    [Fact]
    public async Task ForeignIssuerCannotSpendVictimTicketOrInjectSubscription()
    {
        await using var evil = await EventHost.StartAsync();
        await using var victim = await EventHost.StartAsync(evil.Issuer, localhost: true);
        const string agent = "aauth:victim@localhost";
        victim.Store.SetState("receive", "work", "state");
        victim.Store.IssueTicket(new("ticket", victim.AgentKey.ComputeJwkThumbprint(), "receive", "work", "state", DateTimeOffset.UtcNow.AddMinutes(5)));
        var header = new JsonObject { ["alg"] = AAuthKey.Ed25519Algorithm, ["typ"] = EventsTokens.SubscribeType, ["kid"] = "key" };
        var payload = new JsonObject { ["iss"] = evil.Issuer, ["dwk"] = EventsTokens.AgentDwk, ["sub"] = agent,
            ["aud"] = victim.Issuer, ["eid"] = "evil", ["cnf"] = new JsonObject { ["jwk"] = evil.AgentKey.ToPublicJwk() },
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() };
        var input = Base64UrlEncoder.Encode(header.ToJsonString()) + "." + Base64UrlEncoder.Encode(payload.ToJsonString());
        var forged = input + "." + Base64UrlEncoder.Encode(await evil.ResourceKey.SignAsync(Encoding.ASCII.GetBytes(input)));
        foreach (var ticket in new[] { "ticket", "fake-ticket", "public" })
        {
            using var denied = await victim.Protocol.SendAsync(HttpMethod.Post, new(victim.Issuer + "/subscribe/" + ticket),
                evil.AgentKey, forged, false, "{\"event_types\":[\"reservation.available\"]}"u8.ToArray());
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        }
        Assert.Null(victim.Store.FindNotification(evil.Issuer, "evil"));
        Assert.Empty(evil.Store.Pending(agent));
        Assert.Empty(victim.Store.Pending(agent));
        var legitimate = await new SubscribeTokenBuilder { Issuer = victim.Issuer, Subject = agent, Audience = victim.Issuer,
            Eid = "legitimate", Key = victim.ResourceKey, KeyId = "key", ConfirmationKey = victim.AgentKey,
            Verifier = victim.Protocol.TokenVerifier }.BuildAsync();
        using var accepted = await victim.Protocol.SendAsync(HttpMethod.Post, new(victim.Issuer + "/subscribe/ticket"),
            victim.AgentKey, legitimate, false, "{\"event_types\":[\"reservation.available\"]}"u8.ToArray());
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal("work", victim.Store.FindNotification(victim.Issuer, "legitimate")!.Account);
    }

    [Fact]
    public async Task EventDemoSessionRecoversLostSuccessfulLocalResponseWithoutDuplicateAction()
    {
        await using var host = await EventHost.StartAsync();
        var directory = Path.Combine(Path.GetTempPath(), "event-session-" + Guid.NewGuid().ToString("N"));
        var policy = host.Protocol.TokenVerifier.EgressPolicy;
        var loss = new LoseNotifyResponse { InnerHandler = AAuthHttpTransport.CreateHandler(policy) };
        using var http = AAuthHttpTransport.AttachPolicy(new HttpClient(loss), policy, AAuthTransportContract.EnforcesEgressPolicy);
        try
        {
            await using var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection().AddAAuthAgentFactory().BuildServiceProvider();
            using var session = new EventDemoSession(
                Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions.GetRequiredService<AAuth.Agent.IAAuthAgentFactory>(services),
                directory, host.Issuer, host.Issuer, host.Issuer, http) { Protected = false };
            for (var step = 0; step < 4; step++) await session.NextAsync();
            await Assert.ThrowsAsync<HttpRequestException>(() => session.NextAsync());
            Assert.Equal(4, session.Step);
            Assert.Equal(1, host.Deliveries);
            Assert.Null(host.Store.Find(host.Issuer, session.Eid!, DateTimeOffset.UtcNow));
            await session.NextAsync();
            Assert.Equal(5, session.Step);
            Assert.Equal(1, host.Deliveries);
            await session.NextAsync();
            Assert.Equal(6, session.Step);
            Assert.Single(new SqliteEventStore(Path.Combine(directory, "agent.db")).ReadEvents(session.Agent));
            Assert.Empty(host.Store.Pending(session.Agent));
            Assert.Contains("\"duplicate_ignored\": true", session.Evidence[^1].Json);
        }
        finally { Directory.Delete(directory, true); }
    }

    private sealed class LoseNotifyResponse : DelegatingHandler
    {
        private bool _lost;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = await base.SendAsync(request, cancellationToken);
            if (!_lost && request.RequestUri!.AbsolutePath.EndsWith("/notify") && response.IsSuccessStatusCode)
            {
                _lost = true;
                await response.Content.LoadIntoBufferAsync(cancellationToken);
                response.Dispose();
                throw new HttpRequestException("Lost successful local response.");
            }
            return response;
        }
    }

    [Fact]
    public async Task LostSuccessfulNotifyResponseReturnsPersistedReceiptWithoutAnotherDelivery()
    {
        await using var host = await EventHost.StartAsync();
        host.Store.Create(new("eid", EventHost.Agent, host.Issuer, DateTimeOffset.UtcNow.AddHours(1), 1));
        host.Store.Register(new("eid", host.Issuer, EventHost.Agent, BookingsEvents.Operation, "work", "state", DateTimeOffset.UtcNow.AddHours(1)), null, DateTimeOffset.UtcNow);
        using var first = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/local/events/eid/notify?account=work"), host.AgentKey, await host.AgentTokenAsync(), false);
        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        var expected = await first.Content.ReadAsStringAsync();
        var reopened = new SqliteEventStore(host.Database);
        Assert.Null(reopened.Find(host.Issuer, "eid", DateTimeOffset.UtcNow));
        var subscription = reopened.FindNotification(host.Issuer, "eid")!;
        Assert.Equal(expected, reopened.DeliveryReceipt(subscription));
        Assert.Null(reopened.DeliveryReceipt(subscription with { Account = "personal" }));
        Assert.Null(reopened.DeliveryReceipt(subscription with { Agent = "aauth:other@127.0.0.1" }));
        using var retry = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/local/events/eid/notify?account=work"), host.AgentKey, await host.AgentTokenAsync(), false);
        Assert.Equal(HttpStatusCode.Accepted, retry.StatusCode);
        Assert.Equal(expected, await retry.Content.ReadAsStringAsync());
        Assert.Equal(1, host.Deliveries);
        Assert.Single(reopened.Pending(EventHost.Agent));
        using var wrongAccount = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/local/events/eid/notify?account=personal"), host.AgentKey, await host.AgentTokenAsync(), false);
        Assert.Equal(HttpStatusCode.Forbidden, wrongAccount.StatusCode);
    }

    [Fact]
    public async Task MaximumPayloadInboxDrainsInBoundedPagesAndAcknowledgementRequiresOwner()
    {
        await using var host = await EventHost.StartAsync();
        for (var index = 0; index < 13; index++)
        {
            var eid = "large-" + index;
            host.Store.Create(new(eid, EventHost.Agent, host.Issuer, DateTimeOffset.UtcNow.AddHours(1), 1));
            using var delivery = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/events"), host.ResourceKey,
                await host.EventTokenAsync(eid), true, new byte[65536]);
            Assert.Equal(HttpStatusCode.Accepted, delivery.StatusCode);
        }
        using var limited = await host.Protocol.SendAsync(HttpMethod.Get, new(host.Issuer + "/local/events/inbox?limit=1"), host.AgentKey, await host.AgentTokenAsync(), false);
        var first = Assert.Single((await limited.Content.ReadFromJsonAsync<PendingEvent[]>())!);
        using var next = await host.Protocol.SendAsync(HttpMethod.Get, new(host.Issuer + "/local/events/inbox?limit=1&after=" + first.Receipt), host.AgentKey, await host.AgentTokenAsync(), false);
        Assert.NotEqual(first.Receipt, Assert.Single((await next.Content.ReadFromJsonAsync<PendingEvent[]>())!).Receipt);
        var otherToken = await new AgentTokenBuilder { Issuer = host.Issuer, Subject = "aauth:other@127.0.0.1", Key = host.ResourceKey,
            ConfirmationKey = host.AgentKey, KeyId = "key", EgressPolicy = host.Protocol.TokenVerifier.EgressPolicy }.BuildAsync();
        using var stolen = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/local/events/inbox/" + first.Receipt + "/ack"), host.AgentKey, otherToken, false);
        Assert.Equal(HttpStatusCode.NotFound, stolen.StatusCode);
        var seen = new HashSet<string>();
        var pages = 0;
        while (true)
        {
            using var response = await host.Protocol.SendAsync(HttpMethod.Get, new(host.Issuer + "/local/events/inbox"), host.AgentKey, await host.AgentTokenAsync(), false);
            response.EnsureSuccessStatusCode();
            Assert.InRange((await response.Content.ReadAsByteArrayAsync()).Length, 2, 1024 * 1024);
            var batch = (await response.Content.ReadFromJsonAsync<PendingEvent[]>())!;
            if (batch.Length == 0) break;
            pages++;
            Assert.True(pages <= 13);
            foreach (var item in batch)
            {
                Assert.True(seen.Add(item.Receipt));
                Assert.Equal(65536, item.Event.Body.Length);
                using var ack = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/local/events/inbox/" + item.Receipt + "/ack"), host.AgentKey, await host.AgentTokenAsync(), false);
                Assert.Equal(HttpStatusCode.NoContent, ack.StatusCode);
            }
        }
        Assert.Equal(13, seen.Count);
        Assert.True(pages > 1);
    }

    [Fact]
    public async Task MalformedDeliveryIs400AndDurableFailureIs503Never202()
    {
        await using var host = await EventHost.StartAsync();
        using var malformed = await host.Http.PostAsync(host.Issuer + "/events", new StringContent("{}"));
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        host.Store.Create(new("eid", EventHost.Agent, host.Issuer, DateTimeOffset.UtcNow.AddHours(1), 1));
        using var connection = new SqliteConnection("Data Source=" + host.Database);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "CREATE TRIGGER fail_outbox BEFORE INSERT ON event_outbox BEGIN SELECT RAISE(ABORT, 'failure'); END;";
        command.ExecuteNonQuery();
        var jwt = await host.EventTokenAsync("eid");
        using var failed = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/events"), host.ResourceKey, jwt, true);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, failed.StatusCode);
        Assert.Empty(host.Store.Pending(EventHost.Agent));
        command.CommandText = "DROP TRIGGER fail_outbox";
        command.ExecuteNonQuery();
        using var retry = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/events"), host.ResourceKey, jwt, true);
        Assert.Equal(HttpStatusCode.Accepted, retry.StatusCode);
        var another = await new EventTokenBuilder { Issuer = host.Issuer, Audience = EventHost.Agent, Eid = "eid", Key = host.ResourceKey,
            KeyId = "key", Verifier = host.Protocol.TokenVerifier, Lifetime = TimeSpan.FromMinutes(6) }.BuildAsync();
        using var exceeded = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/events"), host.ResourceKey, another, true);
        Assert.Equal(HttpStatusCode.TooManyRequests, exceeded.StatusCode);
    }

    [Fact]
    public async Task AgentRejectsExpiredTokenAndForgedIssuerSignature()
    {
        await using var host = await EventHost.StartAsync();
        host.Store.Remember(new("eid", host.Issuer, EventHost.Agent, "reservation"));
        var receiver = new EventReceiver(host.Protocol, host.Store, EventHost.Agent);
        var oldVerifier = new TokenVerifier { EgressPolicy = host.Protocol.TokenVerifier.EgressPolicy,
            TimeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow.AddHours(-1)) };
        var expired = await new EventTokenBuilder { Issuer = host.Issuer, Audience = EventHost.Agent, Eid = "eid", Key = host.ResourceKey,
            KeyId = "key", Verifier = oldVerifier }.BuildAsync();
        var expiration = await Assert.ThrowsAsync<AAuthVerificationException>(() => receiver.ReceiveAsync(expired, []));
        Assert.Equal(AAuth.Errors.SignatureErrorCode.ExpiredJwt, expiration.Code);
        var forged = await new EventTokenBuilder { Issuer = host.Issuer, Audience = EventHost.Agent, Eid = "eid", Key = host.AgentKey,
            KeyId = "key", Verifier = host.Protocol.TokenVerifier }.BuildAsync();
        await Assert.ThrowsAsync<TokenVerificationException>(() => receiver.ReceiveAsync(forged, []));
        Assert.Empty(host.Store.ReadEvents(EventHost.Agent));
    }

    [Fact]
    public async Task RegistrationSchemaAndWrongAudienceFailWithoutConsumingTicket()
    {
        await using var host = await EventHost.StartAsync();
        host.Store.SetState("receive", "work", "state");
        host.Store.IssueTicket(new("ticket", host.AgentKey.ComputeJwkThumbprint(), "receive", "work", "state", DateTimeOffset.UtcNow.AddMinutes(5)));
        ValueTask<string> SubscribeAsync(string audience) => new SubscribeTokenBuilder { Issuer = host.Issuer, Subject = EventHost.Agent,
            Audience = audience, Eid = "eid", Key = host.ResourceKey, KeyId = "key", ConfirmationKey = host.AgentKey,
            Verifier = host.Protocol.TokenVerifier }.BuildAsync();
        using var invalid = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/subscribe/ticket"), host.AgentKey,
            await SubscribeAsync(host.Issuer), false, "{\"event_types\":[\"other\"]}"u8.ToArray());
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        using var wrongAudience = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/subscribe/ticket"), host.AgentKey,
            await SubscribeAsync("https://other.example"), false, "{\"event_types\":[\"reservation.available\"]}"u8.ToArray());
        Assert.Equal(HttpStatusCode.Unauthorized, wrongAudience.StatusCode);
        using var valid = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/subscribe/ticket"), host.AgentKey,
            await SubscribeAsync(host.Issuer), false, "{\"event_types\":[\"reservation.available\"]}"u8.ToArray());
        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualHttpSubscriptionDeliveryAndAuthenticatedInbox(bool protectedChannel)
    {
        await using var host = await EventHost.StartAsync();
        var agentToken = await host.AgentTokenAsync();
        using var issued = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/local/events/subscribe"),
            host.AgentKey, agentToken, false, Encoding.UTF8.GetBytes(new JsonObject { ["resource"] = host.Issuer, ["max_uses"] = 1 }.ToJsonString()));
        Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
        var artifact = (await issued.Content.ReadFromJsonAsync<JsonObject>())!;
        var eid = artifact["eid"]!.GetValue<string>();
        if (protectedChannel)
        {
            host.Store.SetState("receive", "work", "reservation-1");
            host.Store.IssueTicket(new("ticket", host.AgentKey.ComputeJwkThumbprint(), "receive", "work", "reservation-1", DateTimeOffset.UtcNow.AddMinutes(2)));
        }
        var path = protectedChannel ? "/subscribe/ticket" : "/subscribe/public";
        using var registered = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + path), host.AgentKey,
            artifact["subscribe_token"]!.GetValue<string>(), false, "{\"event_types\":[\"reservation.available\"]}"u8.ToArray());
        Assert.Equal(HttpStatusCode.OK, registered.StatusCode);
        Assert.Equal(protectedChannel ? "work" : null, host.Store.Find(host.Issuer, eid, DateTimeOffset.UtcNow)!.Account);
        var jwt = await host.EventTokenAsync(eid);
        var payload = Encoding.UTF8.GetBytes("{\n  \"event_type\": \"reservation.available\", \"label\": \"caf\u00e9\"\n}");
        using var delivered = await host.Protocol.SendAsync(HttpMethod.Post, await host.Protocol.ResolveEventEndpointAsync(host.Issuer), host.ResourceKey, jwt, true, payload);
        Assert.Equal(HttpStatusCode.Accepted, delivered.StatusCode);
        Assert.Equal(0, (await delivered.Content.ReadFromJsonAsync<JsonObject>())!["remaining_uses"]!.GetValue<int>());
        Assert.Contains("sig=self-jwt;", host.LastSignatureKey);
        Assert.Contains("\"content-digest\"", host.LastSignatureInput);
        using var pendingResponse = await host.Protocol.SendAsync(HttpMethod.Get, new(host.Issuer + "/local/events/inbox"), host.AgentKey, agentToken, false);
        var pending = Assert.Single((await pendingResponse.Content.ReadFromJsonAsync<PendingEvent[]>())!);
        Assert.Equal(payload, pending.Event.Body);
        host.Store.Remember(new(eid, host.Issuer, EventHost.Agent, "work reservation"));
        var receiver = new EventReceiver(host.Protocol, host.Store, EventHost.Agent);
        Assert.True(await receiver.ReceiveAsync(pending.Event.Token, pending.Event.Body));
        Assert.False(await receiver.ReceiveAsync(pending.Event.Token, pending.Event.Body));
        using var ack = await host.Protocol.SendAsync(HttpMethod.Post, new(host.Issuer + "/local/events/inbox/" + pending.Receipt + "/ack"), host.AgentKey, agentToken, false);
        Assert.Equal(HttpStatusCode.NoContent, ack.StatusCode);
        Assert.Empty(host.Store.Pending(EventHost.Agent));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task TamperedActualBodyOrMismatchedHttpKeyFails(bool tamperBody, bool wrongKey)
    {
        await using var host = await EventHost.StartAsync();
        host.Store.Create(new("eid", EventHost.Agent, host.Issuer, DateTimeOffset.UtcNow.AddHours(1), 1));
        using var request = new HttpRequestMessage(HttpMethod.Post, host.Issuer + "/events") { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
        request.Options.Set(AAuthSigningHandler.AdditionalComponentsKey, ["content-type", "content-digest"]);
        var eventToken = await host.EventTokenAsync("eid");
        using var signer = new AAuthSigningHandler(wrongKey ? host.AgentKey : host.ResourceKey, new SelfJwtSignatureKeyProvider(() => eventToken));
        await signer.SignAsync(request);
        if (tamperBody)
        {
            var digest = request.Content.Headers.GetValues("Content-Digest").Single();
            request.Content = new StringContent("{\"modified\":true}", Encoding.UTF8, "application/json");
            request.Content.Headers.TryAddWithoutValidation("Content-Digest", digest);
        }
        using var response = await host.Http.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(host.Store.Pending(EventHost.Agent));
    }

    [Fact]
    public async Task CompanionRegistrationIsRequiredAndUnknownTypesFailClosed()
    {
        await using var host = await EventHost.StartAsync();
        var resolver = new DefaultSignatureKeyResolver(new JwksClient(host.Http), new MetadataClient(host.Http));
        var parsed = SignatureKeyParser.ParseAny(SignatureKeyHeader.FormatSelfJwt(await host.EventTokenAsync("eid")));
        await Assert.ThrowsAsync<AAuthVerificationException>(() => resolver.ResolveAsync(parsed));
        var noCompanion = new EventsProtocol(host.Http, []);
        var eventToken = await host.EventTokenAsync("eid");
        await Assert.ThrowsAsync<AAuthVerificationException>(() => noCompanion.VerifyEventAsync(eventToken, EventHost.Agent));
    }

    [Fact]
    public async Task HttpStatusQuotaUnlimitedUnknownAndWrongAudience()
    {
        await using var host = await EventHost.StartAsync();
        async Task<HttpResponseMessage> Deliver(string eid, string? agent = null, string? token = null) => await host.Protocol.SendAsync(HttpMethod.Post,
            new(host.Issuer + "/events"), host.ResourceKey, token ?? await host.EventTokenAsync(eid, agent), true);
        using var unknown = await Deliver("unknown");
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        host.Store.Create(new("eid", EventHost.Agent, host.Issuer, DateTimeOffset.UtcNow.AddHours(1), 1));
        using var wrongAudience = await Deliver("eid", "aauth:other@ap.example");
        Assert.Equal(HttpStatusCode.Forbidden, wrongAudience.StatusCode);
        var eventToken = await host.EventTokenAsync("eid");
        using var first = await Deliver("eid", token: eventToken);
        using var retry = await Deliver("eid", token: eventToken);
        using var another = await Deliver("eid");
        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, retry.StatusCode);
        Assert.Equal((HttpStatusCode)429, another.StatusCode);
        host.Store.Create(new("unlimited", EventHost.Agent, host.Issuer, DateTimeOffset.UtcNow.AddHours(1), null));
        using var unlimited = await Deliver("unlimited");
        Assert.Equal(HttpStatusCode.Accepted, unlimited.StatusCode);
        Assert.Empty(await unlimited.Content.ReadAsStringAsync());
        host.Store.Create(new("foreign", EventHost.Agent, "https://other.example", DateTimeOffset.UtcNow.AddHours(1), 1));
        using var wrongIssuer = await Deliver("foreign");
        Assert.Equal(HttpStatusCode.Forbidden, wrongIssuer.StatusCode);
    }

    [Fact]
    public async Task AgentRejectsWrongAudienceMissingContextAndUnexpectedIssuer()
    {
        await using var host = await EventHost.StartAsync();
        var receiver = new EventReceiver(host.Protocol, host.Store, EventHost.Agent);
        await Assert.ThrowsAsync<TokenVerificationException>(async () => await receiver.ReceiveAsync(await host.EventTokenAsync("eid"), []));
        host.Store.Remember(new("eid", "https://unexpected.example", EventHost.Agent, "wrong resource"));
        await Assert.ThrowsAsync<TokenVerificationException>(async () => await receiver.ReceiveAsync(await host.EventTokenAsync("eid"), []));
        await Assert.ThrowsAsync<TokenVerificationException>(async () => await receiver.ReceiveAsync(await host.EventTokenAsync("eid", "aauth:other@ap.example"), []));
        Assert.Empty(host.Store.ReadEvents(EventHost.Agent));
    }

    private sealed class EventHost : IAsyncDisposable
    {
        public const string Agent = "aauth:agent@127.0.0.1";
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "event-http-" + Guid.NewGuid().ToString("N"));
        private WebApplication _app = null!;
        public string Issuer { get; private set; } = null!;
        public string Database => Path.Combine(_directory, "events.db");
        public AAuthKey ResourceKey { get; } = AAuthKey.Generate();
        public AAuthKey AgentKey { get; } = AAuthKey.Generate();
        public SqliteEventStore Store { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;
        public EventsProtocol Protocol { get; private set; } = null!;
        public string? LastSignatureKey { get; private set; }
        public string? LastSignatureInput { get; private set; }
        public int Deliveries { get; private set; }

        public static async Task<EventHost> StartAsync(string? otherProvider = null, bool localhost = false)
        {
            var host = new EventHost();
            host.Store = new SqliteEventStore(Path.Combine(host._directory, "events.db"));
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            builder.Logging.ClearProviders();
            // The issuer is known only once the host listens; the protocol is built on first resolution.
            builder.Services.AddAAuthEvents(options => options.EgressPolicy =
                new AAuthEgressPolicy(otherProvider is null ? [host.Issuer] : [host.Issuer, otherProvider]));
            builder.Services.AddSingleton<IAgentProviderEventStore>(host.Store);
            builder.Services.AddSingleton<IResourceEventStore>(host.Store);
            host._app = builder.Build();
            host._app.Use(async (context, next) =>
            {
                if (context.Request.Path == "/events")
                {
                    host.Deliveries++;
                    host.LastSignatureKey = context.Request.Headers["Signature-Key"];
                    host.LastSignatureInput = context.Request.Headers["Signature-Input"];
                }
                await next();
            });
            foreach (var dwk in new[] { EventsTokens.AgentDwk, EventsTokens.ResourceDwk })
                host._app.MapGet("/.well-known/" + dwk, () => Results.Json(new { issuer = host.Issuer,
                    jwks_uri = host.Issuer + "/jwks.json", event_endpoint = host.Issuer + "/events",
                    r3_vocabularies = new Dictionary<string, string> { ["urn:aauth:vocabulary:asyncapi"] = host.Issuer + "/asyncapi.json" } }));
            host._app.MapGet("/jwks.json", () =>
            {
                var jwk = host.ResourceKey.ToPublicJwk(); jwk["kid"] = "key";
                return Results.Json(new JsonObject { ["keys"] = new JsonArray(jwk) });
            });
            host._app.Map("/events/{**rest}", () => Results.NotFound());
            await host._app.StartAsync();
            host.Issuer = host._app.Urls.Single();
            if (localhost) host.Issuer = host.Issuer.Replace("127.0.0.1", "localhost");
            host.Http = AAuthHttpTransport.CreateClient(new AAuthEgressPolicy(otherProvider is null ? [host.Issuer] : [host.Issuer, otherProvider]));
            host.Protocol = host._app.Services.GetRequiredService<EventsProtocol>();
            host._app.MapLocalEventProvider(host.Issuer, host.ResourceKey, "key");
            host._app.MapAAuthSubscriptionEndpoint("/subscribe/public", channel =>
            {
                channel.Resource = host.Issuer;
                channel.Operation = "receive";
                channel.ValidateParameters = Validate;
            });
            host._app.MapAAuthSubscriptionEndpoint("/subscribe/{ticket}", channel =>
            {
                channel.Resource = host.Issuer;
                channel.Operation = "receive";
                channel.ProtectedChannel = true;
                channel.ValidateParameters = Validate;
            });
            new BookingsEvents(host.Issuer, host.ResourceKey, "key", host.Protocol, host.Store).Map(host._app);
            host._app.MapSampleAgentEnrollment(host.Issuer, host.ResourceKey, "key", host.Protocol.TokenVerifier.EgressPolicy,
                new SampleAgentRegistry(Path.Combine(host._directory, "agents.db")));
            return host;
        }

        private static bool Validate(JsonObject body) => body.Count == 1 && body["event_types"] is JsonArray values
            && values.Count == 1 && values[0]?.GetValue<string>() == "reservation.available";

        public ValueTask<string> AgentTokenAsync() => new AgentTokenBuilder
        {
            Issuer = Issuer, Subject = Agent, Key = ResourceKey, ConfirmationKey = AgentKey,
            KeyId = "key", EgressPolicy = Protocol.TokenVerifier.EgressPolicy
        }.BuildAsync();

        public ValueTask<string> EventTokenAsync(string eid, string? agent = null) => new EventTokenBuilder
        {
            Issuer = Issuer, Audience = agent ?? Agent, Eid = eid, Key = ResourceKey, KeyId = "key", Verifier = Protocol.TokenVerifier
        }.BuildAsync();

        public async ValueTask DisposeAsync()
        {
            Http.Dispose();
            await _app.DisposeAsync();
            Directory.Delete(_directory, true);
        }
    }
}