using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.R3.Model;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
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
        Assert.True(claims.Granted.ContainsTool("search_trip_options"));
        Assert.True(claims.Granted.ContainsTool("hold_itinerary"));
        Assert.True(claims.Conditional!.ContainsTool("book_trip"));
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
    public async Task TokenEndpoint_RejectsPersonServerWhenAllowListIsMissing()
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
        Assert.True(claims.Granted.ContainsTool("book_trip"));
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
                Vocabulary = Vocabulary.Mcp,
                Operations = [new McpOperation { Tool = "book_trip" }],
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
            app.MapR3AccessTokenEndpoint(new R3AccessTokenEndpointOptions
            {
                Issuer = R3TestData.AsIssuer,
                SigningKeys = new Dictionary<string, AAuthKey> { [R3TestData.AsKid] = asKey },
                TrustedPersonServers = trustedPersonServers ?? [R3TestData.PsIssuer],
                ConditionalTools = new HashSet<string>(StringComparer.Ordinal) { "book_trip" },
                AuditSink = auditSink ?? R3NoOpAuditSink.Instance,
                FetchAndVerifyAsync = (_, uri, s256, _, _) =>
                {
                    var bytes = uri == r3Uri ? docBytes : uri == proposalUri ? proposalBytes : throw new InvalidOperationException("unknown R3 URI");
                    R3Hash.Verify(bytes, s256);
                    return Task.FromResult(bytes);
                },
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
    }
}
