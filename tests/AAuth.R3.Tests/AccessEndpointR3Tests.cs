using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.R3.Model;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.R3.Tests;

public class AccessEndpointR3Tests
{
    [Fact]
    public async Task TokenEndpoint_MintsR3AuthTokenThatPassesVerifier()
    {
        var fixture = await R3AccessFixture.CreateAsync();
        await using var app = fixture.App;

        var response = await fixture.PostTokenAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var payload = await ReadAuthPayloadAsync(response);
        var verified = new TokenVerifier().VerifyAuthToken(
            (string)payload["auth_token"]!,
            fixture.AsKey,
            R3TestData.ResourceIssuer,
            fixture.AgentKey,
            R3TestData.AgentId,
            expectedDwk: AuthTokenBuilder.AccessDwk);
        var claims = R3ClaimReader.ReadAuthToken(verified.Payload);
        Assert.Equal(fixture.R3Uri, claims.Uri);
        Assert.Equal(fixture.R3S256, claims.S256);
        Assert.True(claims.Granted.Contains("search_trip_options"));
        Assert.True(claims.Granted.Contains("hold_itinerary"));
        Assert.True(claims.Conditional!.Contains("book_trip"));
    }

    [Fact]
    public async Task TokenEndpoint_AuditsClassR3TokenIssuance()
    {
        var auditSink = new InMemoryR3AuditSink();
        var fixture = await R3AccessFixture.CreateAsync(auditSink: auditSink);
        await using var app = fixture.App;
        var before = DateTimeOffset.UtcNow;

        var response = await fixture.PostTokenAsync();
        var after = DateTimeOffset.UtcNow;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var record = Assert.Single(auditSink.Records);
        AssertAuditRecord(
            record,
            fixture.R3Uri,
            fixture.R3S256,
            R3TokenIssuanceKind.Class,
            before,
            after);
    }

    [Fact]
    public async Task TokenEndpoint_FetchesDocumentOverInjectedHandler_ThenMints()
    {
        // Exercises the REAL R3FetchClient signed fetch + hash-verify path (not the
        // in-memory FetchAndVerifyAsync bypass): the AS fetches the class document from
        // an in-proc resource doc server via FetchHttpMessageHandler, hash-verifies it,
        // and mints — the seam that lets an in-proc AS reach an in-proc resource.
        var docBuilder = WebApplication.CreateBuilder();
        docBuilder.WebHost.UseTestServer();
        await using var docApp = docBuilder.Build();
        docApp.MapGet("/r3/doc", () => Results.Bytes(R3TestData.Document().ToUtf8Bytes(), "application/json"));
        await docApp.StartAsync();

        var fixture = await R3AccessFixture.CreateAsync(fetchHandler: docApp.GetTestServer().CreateHandler());
        await using var app = fixture.App;

        var response = await fixture.PostTokenAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var payload = await ReadAuthPayloadAsync(response);
        var verified = new TokenVerifier().VerifyAuthToken(
            (string)payload["auth_token"]!,
            fixture.AsKey,
            R3TestData.ResourceIssuer,
            fixture.AgentKey,
            R3TestData.AgentId,
            expectedDwk: AuthTokenBuilder.AccessDwk);
        var claims = R3ClaimReader.ReadAuthToken(verified.Payload);
        Assert.Equal(fixture.R3Uri, claims.Uri);
        Assert.True(claims.Granted.Contains("search_trip_options"));
        Assert.True(claims.Conditional?.Contains("book_trip") ?? false);
    }

    [Fact]
    public async Task TokenEndpoint_AuditsPerCallProposalTokenIssuance()
    {
        var auditSink = new InMemoryR3AuditSink();
        var fixture = await R3AccessFixture.CreateAsync(auditSink: auditSink);
        await using var app = fixture.App;
        var before = DateTimeOffset.UtcNow;

        var response = await fixture.PostTokenAsync(fixture.ProposalResourceToken);
        var after = DateTimeOffset.UtcNow;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var record = Assert.Single(auditSink.Records);
        AssertAuditRecord(
            record,
            fixture.ProposalUri,
            fixture.ProposalS256,
            R3TokenIssuanceKind.Proposal,
            before,
            after);
    }

    [Fact]
    public async Task TokenEndpoint_DoesNotIssueTokenWhenConfiguredAuditSinkFails()
    {
        var fixture = await R3AccessFixture.CreateAsync(auditSink: new ThrowingAuditSink());
        await using var app = fixture.App;

        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.PostTokenAsync());
    }

    [Fact]
    public async Task TokenEndpoint_RequiresConsentForProposal_ThenMintsOnApproval()
    {
        // r3 §Per-Call Proposals, Flow step 2: when the AS requires human consent, the
        // proposal parks as 202 (requirement=interaction) — no token — until the user
        // approves at the consent screen; only then is the per-call token minted.
        var auditSink = new InMemoryR3AuditSink();
        var fixture = await R3AccessFixture.CreateAsync(auditSink: auditSink, requireProposalConsent: true);
        await using var app = fixture.App;

        var pending = await fixture.PostTokenAsync(fixture.ProposalResourceToken);

        Assert.Equal(HttpStatusCode.Accepted, pending.StatusCode);
        Assert.NotNull(pending.Headers.Location);
        Assert.True(pending.Headers.TryGetValues("AAuth-Requirement", out var requirement));
        Assert.Contains(requirement, v => v.Contains("interaction", StringComparison.Ordinal));
        Assert.Empty(auditSink.Records); // nothing minted before approval

        var location = pending.Headers.Location!.ToString();
        var code = location.Split('/')[^1];
        using var browser = app.GetTestClient();
        browser.BaseAddress = new Uri(R3TestData.AsIssuer);

        var approve = await browser.PostAsync(
            "/interaction/consent/approve",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = code }));
        Assert.Equal(HttpStatusCode.OK, approve.StatusCode);

        var granted = await fixture.PollPendingAsync(location);

        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
        var payload = await ReadAuthPayloadAsync(granted);
        var verified = new TokenVerifier().VerifyAuthToken(
            (string)payload["auth_token"]!,
            fixture.AsKey,
            R3TestData.ResourceIssuer,
            fixture.AgentKey,
            R3TestData.AgentId,
            expectedDwk: AuthTokenBuilder.AccessDwk);
        var claims = R3ClaimReader.ReadAuthToken(verified.Payload);
        Assert.Equal(fixture.ProposalUri, claims.Uri);
        Assert.True(claims.Granted.Contains("book_trip"));
        var record = Assert.Single(auditSink.Records);
        Assert.Equal(R3TokenIssuanceKind.Proposal, record.IssuanceKind);
    }

    [Fact]
    public async Task TokenEndpoint_DeniedProposalConsent_ReturnsForbiddenAndMintsNothing()
    {
        var auditSink = new InMemoryR3AuditSink();
        var fixture = await R3AccessFixture.CreateAsync(auditSink: auditSink, requireProposalConsent: true);
        await using var app = fixture.App;

        var pending = await fixture.PostTokenAsync(fixture.ProposalResourceToken);
        var location = pending.Headers.Location!.ToString();
        var code = location.Split('/')[^1];
        using var browser = app.GetTestClient();
        browser.BaseAddress = new Uri(R3TestData.AsIssuer);

        var deny = await browser.PostAsync(
            "/interaction/consent/deny",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = code }));
        Assert.Equal(HttpStatusCode.OK, deny.StatusCode);

        var polled = await fixture.PollPendingAsync(location);

        Assert.Equal(HttpStatusCode.Forbidden, polled.StatusCode);
        Assert.Empty(auditSink.Records);
    }

    [Fact]
    public async Task TokenEndpoint_ConcurrentPendingPolls_MintAndAuditExactlyOnce()
    {
        // Concurrent polls of the SAME approval must mint (and audit) exactly once
        // (§Audit Log Integrity). The yielding sink forces a real async suspension so
        // an unguarded `??=` would double-mint; the per-entry gate prevents it.
        var auditSink = new YieldingR3AuditSink();
        var fixture = await R3AccessFixture.CreateAsync(auditSink: auditSink, requireProposalConsent: true);
        await using var app = fixture.App;

        var pending = await fixture.PostTokenAsync(fixture.ProposalResourceToken);
        var location = pending.Headers.Location!.ToString();
        var code = location.Split('/')[^1];
        using var browser = app.GetTestClient();
        browser.BaseAddress = new Uri(R3TestData.AsIssuer);
        var approve = await browser.PostAsync(
            "/interaction/consent/approve",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = code }));
        Assert.Equal(HttpStatusCode.OK, approve.StatusCode);

        // Fire several concurrent signed polls of the same approval.
        var polls = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => fixture.PollPendingAsync(location)));

        var tokens = new HashSet<string>(StringComparer.Ordinal);
        foreach (var poll in polls)
        {
            Assert.Equal(HttpStatusCode.OK, poll.StatusCode);
            var payload = await poll.Content.ReadFromJsonAsync<JsonObject>();
            tokens.Add((string)payload!["auth_token"]!);
        }

        Assert.Single(tokens);              // one token for the whole approval
        Assert.Single(auditSink.Records);   // one audit record, not one-per-poll
    }

    [Fact]
    public async Task TokenEndpoint_PendingPoll_RejectsDifferentTrustedPersonServer()
    {
        // Cross-PS isolation: even another *verifiable/trusted* PS cannot poll a pending
        // entry parked by a different PS (mirrors the core AS's same-PS re-pin). Open trust
        // makes any verifiable jwks_uri caller "trusted"; the origin re-pin still rejects it.
        var auditSink = new InMemoryR3AuditSink();
        var fixture = await R3AccessFixture.CreateAsync(auditSink: auditSink, requireProposalConsent: true, openPersonServerTrust: true);
        await using var app = fixture.App;

        var pending = await fixture.PostTokenAsync(fixture.ProposalResourceToken); // parked by the PS
        var location = pending.Headers.Location!.ToString();
        var code = location.Split('/')[^1];
        using var browser = app.GetTestClient();
        browser.BaseAddress = new Uri(R3TestData.AsIssuer);
        var approve = await browser.PostAsync(
            "/interaction/consent/approve",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = code }));
        Assert.Equal(HttpStatusCode.OK, approve.StatusCode);

        // Poll as a DIFFERENT verifiable identity (the AP's jwks_uri) — not the PS that
        // parked the entry.
        var polled = await fixture.PollPendingAsAsync(
            location, fixture.ApKey, $"{R3TestData.ApIssuer}/.well-known/jwks.json", R3TestData.ApKid);

        Assert.Equal(HttpStatusCode.Forbidden, polled.StatusCode);
        Assert.Empty(auditSink.Records); // the wrong PS never triggers a mint/audit
    }

    [Fact]
    public async Task TokenEndpoint_PendingPoll_RejectsUnsignedCaller()
    {
        // The pending poll rides the signed PS→AS channel: an unsigned GET to the
        // Location is refused (only the browser consent endpoints are unsigned).
        var fixture = await R3AccessFixture.CreateAsync(requireProposalConsent: true);
        await using var app = fixture.App;

        var pending = await fixture.PostTokenAsync(fixture.ProposalResourceToken);
        var location = pending.Headers.Location!.ToString();

        using var unsigned = app.GetTestClient();
        unsigned.BaseAddress = new Uri(R3TestData.AsIssuer);
        var polled = await unsigned.GetAsync(location);

        Assert.Equal(HttpStatusCode.Unauthorized, polled.StatusCode);
    }

    [Fact]
    public async Task TokenEndpoint_RejectsFetchedBytesWhoseHashDoesNotMatchResourceToken()
    {
        var fixture = await R3AccessFixture.CreateAsync(resourceTokenS256Override: "wrong");
        await using var app = fixture.App;

        var response = await fixture.PostTokenAsync();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("r3_evaluation_failed", (string?)body!["error"]);
    }

    [Fact]
    public async Task TokenEndpoint_AcceptsAnyVerifiablePersonServer_WhenTrustListUnset()
    {
        // draft-08 PS-AS trust: an unset (null) trust list is OPEN — the AS brokers for
        // any *verifiable* Person Server. Only an explicit set narrows (empty ⇒ deny-all).
        var fixture = await R3AccessFixture.CreateAsync(openPersonServerTrust: true);
        await using var app = fixture.App;

        var response = await fixture.PostTokenAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task TokenEndpoint_RejectsPersonServerWhenAllowListIsEmpty()
    {
        var fixture = await R3AccessFixture.CreateAsync(trustedPersonServers: []);
        await using var app = fixture.App;

        var response = await fixture.PostTokenAsync();

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("untrusted_person_server", (string?)body!["error"]);
    }

    [Fact]
    public async Task TokenEndpoint_RejectsR3UriWhoseOriginDoesNotMatchResourceIssuer()
    {
        var fixture = await R3AccessFixture.CreateAsync(resourceTokenUriOverride: "https://evil.test/r3/doc");
        await using var app = fixture.App;

        var response = await fixture.PostTokenAsync();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("r3_evaluation_failed", (string?)body!["error"]);
    }

    [Fact]
    public async Task TokenEndpoint_MintsPerCallTokenForProposal()
    {
        var fixture = await R3AccessFixture.CreateAsync();
        await using var app = fixture.App;

        var response = await fixture.PostTokenAsync(fixture.ProposalResourceToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var payload = await ReadAuthPayloadAsync(response);
        var verified = new TokenVerifier().VerifyAuthToken(
            (string)payload["auth_token"]!,
            fixture.AsKey,
            R3TestData.ResourceIssuer,
            fixture.AgentKey,
            R3TestData.AgentId,
            expectedDwk: AuthTokenBuilder.AccessDwk);
        var claims = R3ClaimReader.ReadAuthToken(verified.Payload);
        Assert.Equal(fixture.ProposalUri, claims.Uri);
        Assert.Equal(fixture.ProposalS256, claims.S256);
        Assert.True(claims.Granted.Contains("book_trip"));
        Assert.Null(claims.Conditional);
    }

    [Fact]
    public async Task TokenEndpoint_MetadataAdvertisesDedicatedTokenEndpointAndJwks()
    {
        var fixture = await R3AccessFixture.CreateAsync();
        await using var app = fixture.App;
        using var client = app.GetTestClient();
        client.BaseAddress = new Uri(R3TestData.AsIssuer);

        var metadata = await client.GetFromJsonAsync<JsonObject>("/.well-known/aauth-access.json");
        var jwks = await client.GetFromJsonAsync<JsonObject>("/.well-known/jwks.json");

        Assert.Equal(R3TestData.AsIssuer, (string?)metadata!["issuer"]);
        Assert.Equal($"{R3TestData.AsIssuer}/token", (string?)metadata["token_endpoint"]);
        Assert.NotEmpty((JsonArray)jwks!["keys"]!);
    }

    private static async Task<JsonObject> ReadAuthPayloadAsync(HttpResponseMessage response)
    {
        var payload = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.False(string.IsNullOrWhiteSpace((string?)payload!["auth_token"]));
        return payload!;
    }

    private static void AssertAuditRecord(
        R3TokenIssuanceAuditRecord record,
        string expectedUri,
        string expectedS256,
        R3TokenIssuanceKind expectedKind,
        DateTimeOffset earliest,
        DateTimeOffset latest)
    {
        Assert.Equal(expectedUri, record.R3Uri);
        Assert.Equal(expectedS256, record.R3S256);
        Assert.Equal(R3TestData.AgentId, record.AgentId);
        Assert.Equal(R3TestData.ResourceIssuer, record.ResourceIssuer);
        Assert.Equal(R3TestData.AsIssuer, record.AccessServerIssuer);
        Assert.Equal(expectedKind, record.IssuanceKind);
        Assert.InRange(record.IssuedAt, earliest, latest);
    }

    private sealed class ThrowingAuditSink : IR3AuditSink
    {
        public Task RecordTokenIssuanceAsync(R3TokenIssuanceAuditRecord record, CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("audit sink unavailable");
        }
    }

    // Records issuance but yields first, forcing a real async suspension so the
    // mint-once gate is actually exercised under concurrent polls.
    private sealed class YieldingR3AuditSink : IR3AuditSink
    {
        private readonly ConcurrentBag<R3TokenIssuanceAuditRecord> _records = new();
        public IReadOnlyCollection<R3TokenIssuanceAuditRecord> Records => _records;
        public async Task RecordTokenIssuanceAsync(R3TokenIssuanceAuditRecord record, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            _records.Add(record);
        }
    }

    private sealed class R3AccessFixture
    {
        public required WebApplication App { get; init; }
        public required AAuthKey AsKey { get; init; }
        public required AAuthKey PsKey { get; init; }
        public required AAuthKey ApKey { get; init; }
        public required AAuthKey ResourceKey { get; init; }
        public required AAuthKey AgentKey { get; init; }
        public required string AgentToken { get; init; }
        public required string ResourceToken { get; init; }
        public required string R3Uri { get; init; }
        public required string R3S256 { get; init; }
        public required string ProposalUri { get; init; }
        public required string ProposalS256 { get; init; }
        public required string ProposalResourceToken { get; init; }

        public static async Task<R3AccessFixture> CreateAsync(
            string? resourceTokenS256Override = null,
            string? resourceTokenUriOverride = null,
            IReadOnlyCollection<string>? trustedPersonServers = null,
            bool openPersonServerTrust = false,
            bool requireProposalConsent = false,
            HttpMessageHandler? fetchHandler = null,
            IR3AuditSink? auditSink = null)
        {
            var asKey = AAuthKey.Generate();
            var psKey = AAuthKey.Generate();
            var apKey = AAuthKey.Generate();
            var resourceKey = AAuthKey.Generate();
            var agentKey = AAuthKey.Generate();
            var r3Uri = $"{R3TestData.ResourceIssuer}/r3/doc";
            var docBytes = R3TestData.Document().ToUtf8Bytes();
            var r3S256 = R3Hash.ComputeS256(docBytes);
            var proposal = new R3ProposalDocument
            {
                Version = "v02",
                Vocabulary = Vocabulary.OpenApi,
                Operations = [R3Operation.OpenApi("book_trip")],
                Parameters = new Dictionary<string, R3Parameter>
                {
                    ["itinerary_id"] = R3Parameter.Inline(JsonValue.Create("it-123")!),
                    ["total_usd"] = R3Parameter.Inline(JsonValue.Create(1200)!),
                },
                Display = new R3Display { Summary = "Approve booking", Detail = "Book the exact itinerary." },
            };
            var proposalBytes = proposal.ToUtf8Bytes();
            var proposalS256 = R3Hash.ComputeS256(proposalBytes);
            var proposalUri = $"{R3TestData.ResourceIssuer}/r3/proposals/{proposalS256}";

            var discovery = new StaticJsonHandler()
                .AddJson($"{R3TestData.PsIssuer}/.well-known/jwks.json", R3TestData.Jwks(R3TestData.PsKid, psKey))
                .AddJson($"{R3TestData.ApIssuer}/.well-known/aauth-agent.json", R3TestData.Metadata(R3TestData.ApIssuer, AgentTokenBuilder.AgentDwk))
                .AddJson($"{R3TestData.ApIssuer}/.well-known/jwks.json", R3TestData.Jwks(R3TestData.ApKid, apKey))
                .AddJson($"{R3TestData.ResourceIssuer}/.well-known/aauth-resource.json", R3TestData.Metadata(R3TestData.ResourceIssuer, ResourceTokenBuilder.ResourceDwk))
                .AddJson($"{R3TestData.ResourceIssuer}/.well-known/jwks.json", R3TestData.Jwks(R3TestData.ResourceKid, resourceKey));

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddSingleton(new JwksClient(new HttpClient(discovery)));
            builder.Services.AddSingleton(new MetadataClient(new HttpClient(discovery)));
            var app = builder.Build();
            // When a fetch handler is supplied, exercise the REAL R3FetchClient signed
            // fetch (routed at the in-proc doc server) instead of the in-memory bypass.
            Func<HttpContext, string, string, string, CancellationToken, Task<byte[]>>? fetchOverride =
                fetchHandler is not null ? null : (_, uri, s256, _, _) =>
                {
                    var bytes = uri == r3Uri ? docBytes : uri == proposalUri ? proposalBytes : throw new InvalidOperationException("unknown R3 URI");
                    R3Hash.Verify(bytes, s256);
                    return Task.FromResult(bytes);
                };
            app.MapR3AccessTokenEndpoint(new R3AccessTokenEndpointOptions
            {
                Issuer = R3TestData.AsIssuer,
                SigningKeys = new Dictionary<string, AAuthKey> { [R3TestData.AsKid] = asKey },
                TrustedPersonServers = openPersonServerTrust ? null : (trustedPersonServers ?? [R3TestData.PsIssuer]),
                // AS policy: book_trip requires per-call approval (r3 §Auth Token Extensions —
                // the AS decides granted vs conditional, not the R3 document).
                IsConditionalOperation = op => op.Id == "book_trip",
                RequireProposalConsent = requireProposalConsent,
                AuditSink = auditSink ?? R3NoOpAuditSink.Instance,
                FetchAndVerifyAsync = fetchOverride,
                FetchHttpMessageHandler = fetchHandler,
            });
            await app.StartAsync();

            return new R3AccessFixture
            {
                App = app,
                AsKey = asKey,
                PsKey = psKey,
                ApKey = apKey,
                ResourceKey = resourceKey,
                AgentKey = agentKey,
                AgentToken = R3TestData.AgentToken(apKey, agentKey),
                ResourceToken = R3TestData.ResourceToken(resourceKey, agentKey, resourceTokenUriOverride ?? r3Uri, resourceTokenS256Override ?? r3S256),
                R3Uri = r3Uri,
                R3S256 = r3S256,
                ProposalUri = proposalUri,
                ProposalS256 = proposalS256,
                ProposalResourceToken = R3TestData.ResourceToken(resourceKey, agentKey, proposalUri, proposalS256),
            };
        }

        public async Task<HttpResponseMessage> PostTokenAsync(string? resourceToken = null, JsonObject? extra = null)
        {
            using var client = new AAuthClientBuilder(PsKey)
                .UseJwksUri($"{R3TestData.PsIssuer}/.well-known/jwks.json", R3TestData.PsKid)
                .WithInnerHandler(App.GetTestServer().CreateHandler())
                .Build();
            client.BaseAddress = new Uri(R3TestData.AsIssuer);
            var body = new JsonObject
            {
                ["agent_token"] = AgentToken,
                ["resource_token"] = resourceToken ?? ResourceToken,
            };
            if (extra is not null)
            {
                foreach (var (key, value) in extra)
                {
                    body[key] = value?.DeepClone();
                }
            }
            return await client.PostAsJsonAsync("/token", body);
        }

        // Poll the AS pending Location the way the PS does: a signed GET over the
        // trusted-PS federation channel (the endpoint verifies the signature).
        public async Task<HttpResponseMessage> PollPendingAsync(string path)
        {
            using var client = new AAuthClientBuilder(PsKey)
                .UseJwksUri($"{R3TestData.PsIssuer}/.well-known/jwks.json", R3TestData.PsKid)
                .WithInnerHandler(App.GetTestServer().CreateHandler())
                .Build();
            client.BaseAddress = new Uri(R3TestData.AsIssuer);
            return await client.GetAsync(path);
        }

        // Poll as a specific signing identity/jwks_uri (used to simulate a DIFFERENT
        // Person Server polling a pending entry it did not park).
        public async Task<HttpResponseMessage> PollPendingAsAsync(string path, AAuthKey key, string jwksUri, string kid)
        {
            using var client = new AAuthClientBuilder(key)
                .UseJwksUri(jwksUri, kid)
                .WithInnerHandler(App.GetTestServer().CreateHandler())
                .Build();
            client.BaseAddress = new Uri(R3TestData.AsIssuer);
            return await client.GetAsync(path);
        }
    }
}
