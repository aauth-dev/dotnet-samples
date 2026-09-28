using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.R3.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.R3.Tests;

public class ResourceR3Tests
{
    [Fact]
    public void ProposalAndDocumentRemainAvailableWhileIssuedGrantIsValid()
    {
        var clock = new RetentionClock();
        var store = new R3ProposalStore();
        var document = store.AddBytes(R3TestData.Document().ToUtf8Bytes(), new Uri(R3TestData.ResourceIssuer));
        var enforcement = new R3Enforcement(store, new Uri(R3TestData.ResourceIssuer));
        var claims = new R3ClaimReader.AuthTokenClaims(document.Uri, document.S256, R3Grant.Mcp(), R3Grant.Mcp("book"));
        var parameters = new Dictionary<string, R3Parameter> { ["id"] = R3Parameter.Inline(JsonValue.Create("reservation")!) };
        var proposal = enforcement.Evaluate(claims, R3OperationIdentity.Mcp("book"), parameters);
        var issued = clock.Now;
        var issuerKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var token = new AAuth.Tokens.AuthTokenBuilder
        {
            Issuer = R3TestData.AsIssuer, Audience = R3TestData.ResourceIssuer,
            PersonServer = R3TestData.PsIssuer, Subject = R3TestData.PersonSubject, AgentConfirmationKey = agentKey,
            Scope = "book",
            Key = issuerKey, KeyId = "issuer", Dwk = AAuth.Tokens.AuthTokenBuilder.AccessDwk,
            IssuedAt = issued, AgentTokenExpiresAt = issued.AddHours(1),
            AdditionalClaims = R3AuthClaims.AuthToken(proposal.ProposalUri!, proposal.ProposalS256!, R3Grant.Mcp("book")),
        }.Build();
        clock.Now = issued.AddMinutes(11);
        var verified = new AAuth.Tokens.TokenVerifier { Clock = () => clock.Now }.VerifyAuthToken(
            token, issuerKey, R3TestData.ResourceIssuer, agentKey);
        var approved = R3ClaimReader.ReadAuthToken(verified.Payload);
        Assert.True(store.TryGet(document.S256, out var documentBytes));
        R3Hash.Verify(documentBytes, document.S256);
        Assert.Equal(R3EnforcementDecisionKind.Granted, enforcement.Evaluate(approved, R3OperationIdentity.Mcp("book"), parameters,
            approvedProposalS256: approved.S256).Kind);
    }

    [Fact]
    public void ContentCapacityRejectsNewEntriesWithoutEvictingPublishedReferences()
    {
        var store = new R3ProposalStore(maxEntries: 1);
        var bytes = R3TestData.Document().ToUtf8Bytes();
        var stored = store.AddBytes(bytes, new Uri(R3TestData.ResourceIssuer));
        Assert.Equal(stored.S256, store.AddBytes(bytes, new Uri(R3TestData.ResourceIssuer)).S256);
        Assert.Throws<InvalidOperationException>(() => store.AddBytes("{}"u8.ToArray(), new Uri(R3TestData.ResourceIssuer)));
        Assert.True(store.TryGet(stored.S256, out var retrieved));
        Assert.Equal(bytes, retrieved);
        Assert.Throws<ArgumentOutOfRangeException>(() => new R3ProposalStore(0));
    }

    private sealed class RetentionClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public void ProposalAccount_CannotBeReusedAcrossAccountsOrAccountlessRequests()
    {
        var claims = new R3ClaimReader.AuthTokenClaims("https://resource.test/r3/doc", "hash",
            R3Grant.Mcp("search"), R3Grant.Mcp("book")) { Account = "personal" };
        var store = new R3ProposalStore();
        var enforcement = new R3Enforcement(store, new Uri(R3TestData.ResourceIssuer));
        var parameters = new Dictionary<string, R3Parameter> { ["id"] = R3Parameter.Inline(JsonValue.Create("reservation")!) };
        Assert.Equal("account_mismatch", enforcement.Evaluate(claims, R3OperationIdentity.Mcp("search"), expectedAccount: "work").Error);
        Assert.Equal("account_mismatch", enforcement.Evaluate(claims, R3OperationIdentity.Mcp("search")).Error);
        var proposal = enforcement.Evaluate(claims, R3OperationIdentity.Mcp("book"), parameters, expectedAccount: "personal");
        Assert.Equal(R3EnforcementDecisionKind.PerCall, proposal.Kind);
        Assert.True(store.TryGet(proposal.ProposalS256!, out var bytes));
        Assert.Equal("personal", R3ProposalDocument.FromUtf8Bytes(bytes).Account);
        var approved = new R3ClaimReader.AuthTokenClaims(proposal.ProposalUri!, proposal.ProposalS256!, R3Grant.Mcp("book"), null)
            { Account = "personal" };
        Assert.Equal(R3EnforcementDecisionKind.Granted, enforcement.Evaluate(approved, R3OperationIdentity.Mcp("book"), parameters,
            approvedProposalS256: approved.S256, expectedAccount: "personal").Kind);
        Assert.Equal("account_mismatch", enforcement.Evaluate(approved, R3OperationIdentity.Mcp("book"), parameters,
            approvedProposalS256: approved.S256, expectedAccount: "work").Error);
        Assert.Equal("proposal_account_mismatch", enforcement.Evaluate(approved with { Account = "work" }, R3OperationIdentity.Mcp("book"), parameters,
            approvedProposalS256: approved.S256, expectedAccount: "work").Error);
    }

    [Fact]
    public void Metadata_AddsR3Vocabularies()
    {
        var doc = R3Metadata.CreateResourceMetadata(
            R3TestData.ResourceIssuer,
            $"{R3TestData.ResourceIssuer}/.well-known/jwks.json",
            $"{R3TestData.ResourceIssuer}/authorize");

        var vocabularies = Assert.IsType<JsonObject>(doc["r3_vocabularies"]);
        Assert.Equal($"{R3TestData.ResourceIssuer}/mcp", (string?)vocabularies[Vocabulary.Mcp]);
    }

    [Fact]
    public async Task DocumentEndpoint_VerifiesSignatureAndTrustsOnlyConfiguredAsOrPs()
    {
        var asKey = AAuthKey.Generate();
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var untrustedKey = AAuthKey.Generate();
        var bytes = R3TestData.Document().ToUtf8Bytes();
        var discovery = new StaticJsonHandler()
            .AddJson("https://as.test/.well-known/aauth-access.json", R3TestData.Metadata("https://as.test", "aauth-access.json"))
            .AddJson("https://ps.test/.well-known/aauth-access.json", R3TestData.Metadata("https://ps.test", "aauth-access.json"))
            .AddJson("https://agent.test/.well-known/aauth-access.json", R3TestData.Metadata("https://agent.test", "aauth-access.json"))
            .AddJson("https://agent.test/.well-known/jwks.json", R3TestData.Jwks("agent-1", agentKey))
            .AddJson("https://other.test/.well-known/aauth-access.json", R3TestData.Metadata("https://other.test", "aauth-access.json"))
            .AddJson("https://other.test/.well-known/jwks.json", R3TestData.Jwks("other-1", untrustedKey))
            .AddJson("https://as.test/.well-known/jwks.json", R3TestData.Jwks("as-1", asKey))
            .AddJson("https://ps.test/.well-known/jwks.json", R3TestData.Jwks("ps-1", psKey))
            .AddJson("http://ps.test/.well-known/jwks.json", R3TestData.Jwks("ps-1", psKey));

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new JwksClient(new InProcessHttpClient(discovery)));
        builder.Services.AddSingleton(new MetadataClient(new InProcessHttpClient(discovery)));
        var app = builder.Build();
        app.MapR3Document("/r3/doc", _ => bytes, fetcher =>
            fetcher.Identifier is "https://as.test" or "https://ps.test" or "http://ps.test");
        await app.StartAsync();
        try
        {
            Assert.Equal(HttpStatusCode.OK, (await SignedGet(app, asKey, "https://as.test/.well-known/jwks.json", "as-1")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await SignedGet(app, psKey, "https://ps.test/.well-known/jwks.json", "ps-1")).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await SignedGet(app, psKey, "http://ps.test/.well-known/jwks.json", "ps-1")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await SignedGet(app, agentKey, "https://agent.test/.well-known/jwks.json", "agent-1")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await SignedGet(app, untrustedKey, "https://other.test/.well-known/jwks.json", "other-1")).StatusCode);

            using var unsigned = app.GetTestClient();
            unsigned.BaseAddress = new Uri(R3TestData.ResourceIssuer);
            var response = await unsigned.GetAsync("/r3/doc");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
            var error = await response.Content.ReadFromJsonAsync<JsonObject>();
            Assert.Equal("invalid_signature", (string?)error!["error"]);
            Assert.Equal("error=invalid_signature", response.Headers.GetValues("Signature-Error").Single());
        }
        finally
        {
            await app.DisposeAsync();
        }
    }

    [Fact]
    public async Task VerifyFetcher_RejectsJwksUriWhenTrustPredicateIsMissing()
    {
        var asKey = AAuthKey.Generate();
        var discovery = new StaticJsonHandler()
            .AddJson("https://as.test/.well-known/aauth-access.json", R3TestData.Metadata("https://as.test", "aauth-access.json"))
            .AddJson("https://as.test/.well-known/jwks.json", R3TestData.Jwks("as-1", asKey));

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new JwksClient(new InProcessHttpClient(discovery)));
        builder.Services.AddSingleton(new MetadataClient(new InProcessHttpClient(discovery)));
        var app = builder.Build();
        app.MapGet("/verify", async (HttpContext context) =>
        {
            try
            {
                await R3DocumentEndpoint.VerifyFetcherAsync(context);
                return Results.Ok();
            }
            catch (R3UntrustedJwksUriException)
            {
                return Results.Json(new { error = "untrusted_fetcher" }, statusCode: StatusCodes.Status403Forbidden);
            }
        });
        await app.StartAsync();
        try
        {
            using var client = new AAuthClientBuilder(asKey)
                .UseJwksUri("https://as.test", "aauth-access.json", "as-1")
                .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(app.GetTestServer().CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
                .Build();
            client.BaseAddress = new Uri(R3TestData.ResourceIssuer);

            var response = await client.GetAsync("/verify");

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        finally
        {
            await app.DisposeAsync();
        }
    }

    [Fact]
    public void FetchClient_BindsR3UriToResourceIssuerAndRejectsPrivateTargets()
    {
        var sameOrigin = R3FetchClient.ValidateFetchTarget(
            "https://resource.test/r3/doc",
            R3TestData.ResourceIssuer);
        Assert.Equal("https://resource.test/r3/doc", sameOrigin.ToString());

        var loopback = R3FetchClient.ValidateFetchTarget(
            "http://localhost:5004/r3/doc",
            "http://localhost:5004", TestEgress.Policy);
        Assert.Equal("localhost", loopback.Host);

        Assert.Throws<InvalidOperationException>(() =>
            R3FetchClient.ValidateFetchTarget("https://evil.test/r3/doc", R3TestData.ResourceIssuer));
        Assert.Throws<ArgumentException>(() =>
            R3FetchClient.ValidateFetchTarget("https://192.168.1.10/r3/doc", "https://192.168.1.10"));
        Assert.Throws<ArgumentException>(() =>
            R3FetchClient.ValidateFetchTarget("http://resource.test/r3/doc", "http://resource.test"));
    }

    [Fact]
    public async Task FetchClient_SignsWithJwksUriAndRejectsHashMismatch()
    {
        var asKey = AAuthKey.Generate();
        var bytes = R3TestData.Document().ToUtf8Bytes();
        var s256 = R3Hash.ComputeS256(bytes);
        var discovery = new StaticJsonHandler()
            .AddJson("https://as.test/.well-known/aauth-access.json", R3TestData.Metadata("https://as.test", "aauth-access.json"))
            .AddJson("https://as.test/.well-known/jwks.json", R3TestData.Jwks("as-1", asKey));

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new JwksClient(new InProcessHttpClient(discovery)));
        builder.Services.AddSingleton(new MetadataClient(new InProcessHttpClient(discovery)));
        var app = builder.Build();
        app.MapR3Document("/r3/doc", _ => bytes, fetcher => fetcher.Identifier == "https://as.test");
        await app.StartAsync();
        try
        {
            var client = R3FetchClient.Create(asKey, "https://as.test", "aauth-access.json", "as-1",
                app.GetTestServer().CreateHandler(), transportContract: AAuthTransportContract.InProcessOnly);

            var fetched = await client.FetchAndVerifyAsync($"{R3TestData.ResourceIssuer}/r3/doc", s256, R3TestData.ResourceIssuer);

            Assert.Equal(bytes, fetched);
            await Assert.ThrowsAsync<R3HashMismatchException>(() =>
                client.FetchAndVerifyAsync($"{R3TestData.ResourceIssuer}/r3/doc", "tampered", R3TestData.ResourceIssuer));
        }
        finally
        {
            await app.DisposeAsync();
        }
    }

    [Fact]
    public void Enforcement_GrantsChallengesRejectsAndDigestMatchesProposalRetry()
    {
        var claims = new R3ClaimReader.AuthTokenClaims(
            "https://resource.test/r3/doc",
            "doc-hash",
            R3Grant.Mcp("search_trip_options"),
            R3Grant.Mcp("book_trip"));
        var store = new R3ProposalStore();
        var enforcement = new R3Enforcement(store, new Uri(R3TestData.ResourceIssuer));
        var parameters = new Dictionary<string, R3Parameter>
        {
            ["itinerary_id"] = R3Parameter.Inline(JsonValue.Create("it-123")!),
            ["total_usd"] = R3Parameter.Inline(JsonValue.Create(1200)!),
            ["traveler"] = R3Parameter.Inline(new JsonObject
            {
                ["name"] = "Aria",
                ["party_size"] = 1,
            }),
        };

        Assert.Equal(R3EnforcementDecisionKind.Granted,
            enforcement.Evaluate(claims, R3OperationIdentity.Mcp("search_trip_options")).Kind);
        Assert.Equal(R3EnforcementDecisionKind.Rejected,
            enforcement.Evaluate(claims, R3OperationIdentity.Mcp("cancel_trip")).Kind);

        var perCall = enforcement.Evaluate(claims, R3OperationIdentity.Mcp("book_trip"), parameters, (tool, _) =>
            new R3Display { Summary = $"Approve {tool}", Detail = "Concrete itinerary." });
        Assert.Equal(R3EnforcementDecisionKind.PerCall, perCall.Kind);
        Assert.True(store.TryGet(perCall.ProposalS256!, out _));

        var reorderedInline = new Dictionary<string, R3Parameter>(parameters)
        {
            ["traveler"] = R3Parameter.Inline(new JsonObject
            {
                ["party_size"] = 1,
                ["name"] = "Aria",
            }),
        };
        var classTokenRetry = enforcement.Evaluate(claims, R3OperationIdentity.Mcp("book_trip"), reorderedInline, approvedProposalS256: perCall.ProposalS256);
        Assert.Equal(R3EnforcementDecisionKind.Rejected, classTokenRetry.Kind);
        Assert.Equal("operation_not_granted", classTokenRetry.Error);

        var approvedClaims = new R3ClaimReader.AuthTokenClaims(
            perCall.ProposalUri!,
            perCall.ProposalS256!,
            R3Grant.Mcp("book_trip"),
            null);
        Assert.Equal(R3EnforcementDecisionKind.Granted,
            enforcement.Evaluate(approvedClaims, R3OperationIdentity.Mcp("book_trip"), reorderedInline, approvedProposalS256: perCall.ProposalS256).Kind);

        var mismatchedToken = approvedClaims with { S256 = "different-proposal-hash" };
        var mismatched = enforcement.Evaluate(mismatchedToken, R3OperationIdentity.Mcp("book_trip"), reorderedInline, approvedProposalS256: perCall.ProposalS256);
        Assert.Equal(R3EnforcementDecisionKind.Rejected, mismatched.Kind);
        Assert.Equal("proposal_token_mismatch", mismatched.Error);

        var tampered = new Dictionary<string, R3Parameter>(parameters)
        {
            ["total_usd"] = R3Parameter.Inline(JsonValue.Create(1300)!),
        };
        Assert.Equal(R3EnforcementDecisionKind.Rejected,
            enforcement.Evaluate(approvedClaims, R3OperationIdentity.Mcp("book_trip"), tampered, approvedProposalS256: perCall.ProposalS256).Kind);
    }

    [Fact]
    public void Enforcement_DigestBackedProposalRetryMatchesPresentedBytes()
    {
        var initialClaims = new R3ClaimReader.AuthTokenClaims(
            "https://resource.test/r3/doc",
            "doc-hash",
            R3Grant.Mcp("search_trip_options"),
            R3Grant.Mcp("book_trip"));
        var store = new R3ProposalStore();
        var enforcement = new R3Enforcement(store, new Uri(R3TestData.ResourceIssuer));
        var policyBytes = Encoding.UTF8.GetBytes("Refundable for 24 hours, then airline fare rules apply.");
        var parameters = new Dictionary<string, R3Parameter>
        {
            ["itinerary_id"] = R3Parameter.Inline(JsonValue.Create("it-123")!),
            ["cancellation_policy"] = R3Parameter.Digest(
                R3Hash.ComputeS256(policyBytes),
                excerpt: "Refundable for 24 hours",
                mediaType: "text/plain"),
        };

        var perCall = enforcement.Evaluate(initialClaims, R3OperationIdentity.Mcp("book_trip"), parameters);
        var approvedClaims = new R3ClaimReader.AuthTokenClaims(
            perCall.ProposalUri!,
            perCall.ProposalS256!,
            R3Grant.Mcp("book_trip"),
            null);
        var presented = new R3PresentedParameters(
            new Dictionary<string, R3Parameter>
            {
                ["itinerary_id"] = R3Parameter.Inline(JsonValue.Create("it-123")!),
            },
            new Dictionary<string, byte[]>
            {
                ["cancellation_policy"] = policyBytes,
            });

        Assert.Equal(R3EnforcementDecisionKind.Granted,
            enforcement.Evaluate(approvedClaims, R3OperationIdentity.Mcp("book_trip"), presented, approvedClaims.S256).Kind);

        var tampered = new R3PresentedParameters(
            presented.JsonParameters,
            new Dictionary<string, byte[]>
            {
                ["cancellation_policy"] = Encoding.UTF8.GetBytes("Non-refundable after purchase."),
            });
        var rejected = enforcement.Evaluate(approvedClaims, R3OperationIdentity.Mcp("book_trip"), tampered, approvedClaims.S256);
        Assert.Equal(R3EnforcementDecisionKind.Rejected, rejected.Kind);
        Assert.Equal("proposal_digest_mismatch", rejected.Error);
    }

    [Fact]
    public async Task Enforcement_PerCallChallengeResultEmitsAAuthRequirementWithProposalResourceToken()
    {
        var resourceKey = AAuthKey.Generate();
        var asKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var authToken = new AAuth.Tokens.AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy, Issuer = R3TestData.AsIssuer, Audience = R3TestData.ResourceIssuer,
            PersonServer = R3TestData.PsIssuer, Subject = R3TestData.PersonSubject, AgentConfirmationKey = agentKey,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1), Key = asKey, KeyId = R3TestData.AsKid,
            Dwk = AAuth.Tokens.AuthTokenBuilder.AccessDwk, Account = "personal",
        }.Build();
        var verifiedAuthToken = new AAuth.Tokens.TokenVerifier { EgressPolicy = TestEgress.Policy }
            .VerifyAuthToken(authToken, asKey, R3TestData.ResourceIssuer, agentKey);
        var decision = R3EnforcementDecision.PerCall(
            "https://resource.test/r3/proposals/proposal-hash",
            "proposal-hash");
        var context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider(),
            Response =
            {
                Body = new MemoryStream(),
            },
        };
        var challenge = new R3Challenge
        {
            ResourceIssuer = R3TestData.ResourceIssuer,
            Audience = R3TestData.AsIssuer,
            Key = resourceKey,
            KeyId = R3TestData.ResourceKid,
        };

        await decision.ToResult(
            context,
            challenge,
            verifiedAuthToken).ExecuteAsync(context);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal("application/problem+json", context.Response.ContentType);
        context.Response.Body.Position = 0;
        var body = (JsonObject)(await JsonNode.ParseAsync(context.Response.Body))!;
        Assert.Equal("r3_approval_required", (string?)body["error"]);
        Assert.Equal(decision.ProposalUri, (string?)body["r3_uri"]);
        Assert.Equal(decision.ProposalS256, (string?)body["r3_s256"]);
        Assert.False(body.ContainsKey("detail"));
        var header = Assert.Single(context.Response.Headers[AAuthRequirementHeader.Name]);
        var parsed = AAuthRequirementHeader.Parse(header!);
        Assert.Equal(AAuthRequirementHeader.AuthTokenRequirement, parsed.Requirement);
        Assert.False(string.IsNullOrWhiteSpace(parsed.ResourceToken));
        var resourceToken = parsed.ResourceToken!;
        var payload = (JsonObject)JsonNode.Parse(Base64UrlEncoder.DecodeBytes(resourceToken.Split('.')[1]))!;
        Assert.Equal(decision.ProposalUri, (string?)payload[R3AuthClaims.UriClaim]);
        Assert.Equal(decision.ProposalS256, (string?)payload[R3AuthClaims.S256Claim]);
        Assert.Equal(R3TestData.PsIssuer, (string?)payload["ps"]);
        Assert.Equal(R3TestData.PersonSubject, (string?)payload["sub"]);
        Assert.Equal(verifiedAuthToken.Jti, (string?)payload["presented_jti"]);
        Assert.Equal(agentKey.ComputeJwkThumbprint(), (string?)payload["agent_jkt"]);
        Assert.Equal("personal", (string?)payload["account"]);
        Assert.False(payload.ContainsKey("agent"));
    }

    private static async Task<HttpResponseMessage> SignedGet(WebApplication app, AAuthKey key, string jwksUri, string kid)
    {
        using var client = new AAuthClientBuilder(key)
            .UseJwksUri(new Uri(jwksUri).GetLeftPart(UriPartial.Authority), "aauth-access.json", kid)
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(app.GetTestServer().CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
            .Build();
        client.BaseAddress = new Uri(R3TestData.ResourceIssuer);
        return await client.GetAsync("/r3/doc");
    }
}
