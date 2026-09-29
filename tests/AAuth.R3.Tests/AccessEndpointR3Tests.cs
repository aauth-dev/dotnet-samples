using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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
    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("{\"agent_token\":\"bad\",\"agent_token\":\"bad\"}")]
    [InlineData("{\"nested\":{\"claim\":1,\"claim\":2}}")]
    [InlineData("{")]
    public async Task RawBodyIsRejectedBeforeR3Effects(string json)
    {
        var audit = new InMemoryR3AuditSink();
        var fetches = 0;
        var policies = 0;
        var fixture = await R3AccessFixture.CreateAsync(auditSink: audit, onFetch: () => fetches++, onPolicy: () => policies++);
        await using var app = fixture.App;
        using var client = new AAuthClientBuilder(fixture.PsKey)
            .UseJwksUri(R3TestData.PsIssuer, AAuthConstants.DwkFiles.Person, R3TestData.PsKid)
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(app.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly).Build();
        using var response = await client.PostAsync(R3TestData.AsIssuer + "/token", new StringContent(json, System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        Assert.False(response.Headers.Contains("Signature-Error"));
        Assert.Equal(0, fetches);
        Assert.Equal(0, policies);
        Assert.Empty(audit.Records);
    }

    [Theory]
    [MemberData(nameof(TestTokens.InvalidCredentials), MemberType = typeof(TestTokens))]
    public async Task BodyCredentialFailuresPrecedeFetchPolicyAndAudit(string field, string variant, string error)
    {
        var audit = new InMemoryR3AuditSink();
        var fetches = 0;
        var policies = 0;
        var fixture = await R3AccessFixture.CreateAsync(auditSink: audit, onFetch: () => fetches++, onPolicy: () => policies++);
        await using var app = fixture.App;
        var token = field == "resource_token" ? fixture.ResourceToken : field == "upstream_token" ? UpstreamToken(fixture)
            : field == "presented_token" ? fixture.PersonToken : fixture.AgentToken;
        var key = field == "resource_token" ? fixture.ResourceKey : field is "upstream_token" or "presented_token" ? fixture.PsKey : fixture.ApKey;
        using var response = await fixture.PostTokenAsync(extra: new JsonObject
        { [field] = TestTokens.MalformedCredential(token, key, variant) });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
        Assert.Equal(error, (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        Assert.False(response.Headers.Contains("Signature-Error"));
        Assert.Equal(0, fetches);
        Assert.Equal(0, policies);
        Assert.Empty(audit.Records);
    }

    public static IEnumerable<object[]> InvalidPresentedCredentials =>
        TestTokens.InvalidCredentials.Where(row => (string)row[0] == "agent_token").Select(row => new object[]
            { "presented_token", row[1], TestTokens.CredentialError("presented_token", (string)row[1]) });

    [Theory]
    [MemberData(nameof(InvalidPresentedCredentials))]
    public Task PresentedCredentialFailuresPrecedeFetchPolicyAndAudit(string field, string variant, string error) =>
        BodyCredentialFailuresPrecedeFetchPolicyAndAudit(field, variant, error);

    private static string UpstreamToken(R3AccessFixture fixture, string? missionS256 = null, TimeProvider? clock = null,
        DateTimeOffset? expiresAt = null, string? account = null) => new AuthTokenBuilder
    {
        EgressPolicy = TestEgress.Policy,
        Issuer = R3TestData.PsIssuer, Audience = R3TestData.ApIssuer,
        PersonServer = R3TestData.PsIssuer, Subject = "upstream-person", AgentConfirmationKey = fixture.AgentKey,
        Key = fixture.PsKey, KeyId = R3TestData.PsKid, TimeProvider = clock ?? TimeProvider.System,
        AgentTokenExpiresAt = expiresAt ?? DateTimeOffset.UtcNow.AddMinutes(5), Scope = "read",
        MissionS256 = missionS256, Account = account,
    }.Build();

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PersonServerFederationAcceptsRealR3MissionToken(bool deferred)
    {
        var audit = new InMemoryR3AuditSink();
        var fixture = await R3AccessFixture.CreateAsync(requireProposalConsent: deferred, auditSink: audit);
        await using var app = fixture.App;
        var mission = R3Hash.ComputeS256("mission"u8);
        var (personToken, resourceToken) = fixture.PersonRequest(proposal: deferred, missionS256: mission);
        var presented = R3TestData.VerifyPersonToken(personToken, fixture.PsKey, fixture.AgentKey);
        using var discovery = new InProcessHttpClient(app.GetTestServer().CreateHandler());
        using var metadata = new MetadataClient(discovery);
        using var jwks = new JwksClient(discovery);
        using var signed = new AAuthClientBuilder(fixture.PsKey)
            .UseJwksUri(R3TestData.PsIssuer, AAuthConstants.DwkFiles.Person, R3TestData.PsKid)
            .WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(app.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly).Build();
        var federation = new AAuth.Access.AccessServerClient(signed, metadata, new AuthTokenResponseValidator(metadata, jwks));
        var token = await federation.FederateAsync(R3TestData.AsIssuer, new AAuth.Access.AccessServerRequest
        {
            ResourceToken = resourceToken, AgentToken = fixture.AgentToken,
            PresentedToken = personToken, PresentedTokenExpiresAt = presented.ExpiresAt,
            AgentKey = fixture.AgentKey, ExpectedAudience = R3TestData.ResourceIssuer,
            ExpectedSubject = R3TestData.PersonSubject, ExpectedPersonServer = R3TestData.PsIssuer,
            ExpectedMissionS256 = mission,
            AuthorizationExpiresAt = new TokenVerifier().Verify(fixture.AgentToken, fixture.ApKey,
                AgentTokenBuilder.TokenType, AgentTokenBuilder.AgentDwk).ExpiresAt,
            PollerOptions = new AAuth.Agent.DeferredPollerOptions { MinPollInterval = TimeSpan.Zero, DefaultPollInterval = TimeSpan.FromMilliseconds(1) },
            OnInteractionRequired = async (interaction, _) =>
            {
                using var browser = app.GetTestClient();
                browser.BaseAddress = new Uri(R3TestData.AsIssuer);
                using var approved = await TestConsentBrowser.DecideAsync(browser,
                    interaction.Url + "?code=" + interaction.Code, "/interaction/consent/approve");
                Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
            },
        });

        var verified = new TokenVerifier().VerifyAuthToken(token, fixture.AsKey, R3TestData.ResourceIssuer, fixture.AgentKey);
        Assert.Equal(mission, verified.MissionS256);
        Assert.Equal(R3TestData.PsIssuer, (string?)verified.Payload["ps"]);
        Assert.Equal(R3TestData.PersonSubject, verified.Subject);
        Assert.Single(audit.Records);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ResourceMissionCannotBeDroppedOrChangedFromUpstream(bool deferred, bool changed)
    {
        var audit = new InMemoryR3AuditSink();
        var fetches = 0;
        var policies = 0;
        var fixture = await R3AccessFixture.CreateAsync(requireProposalConsent: deferred, auditSink: audit,
            onFetch: () => fetches++, onPolicy: () => policies++);
        await using var app = fixture.App;
        // The resource token honestly names its presented token; only the upstream mission differs.
        var (personToken, token) = fixture.PersonRequest(proposal: deferred,
            missionS256: changed ? R3Hash.ComputeS256("changed"u8) : null);
        var upstream = UpstreamToken(fixture, missionS256: R3Hash.ComputeS256("original"u8));

        using var response = await fixture.PostTokenAsync(token,
            new JsonObject { ["upstream_token"] = upstream, ["presented_token"] = personToken });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_resource_token", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        Assert.Equal(0, fetches);
        Assert.Equal(0, policies);
        Assert.Empty(audit.Records);
    }

    [Theory]
    [InlineData("uncovered")]
    [InlineData("tampered")]
    public async Task UncoveredOrTamperedBodyFailsBeforeDocumentPolicyOrAudit(string bodyMode)
    {
        var audit = new InMemoryR3AuditSink();
        var fetches = 0;
        var policies = 0;
        var fixture = await R3AccessFixture.CreateAsync(auditSink: audit, onFetch: () => fetches++, onPolicy: () => policies++);
        await using var app = fixture.App;

        using var response = await fixture.PostTokenAsync(bodyMode: bodyMode);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(bodyMode == "uncovered" ? "invalid_input" : "invalid_signature",
            Assert.Single(response.Headers.GetValues("Signature-Error")));
        Assert.Equal(0, fetches);
        Assert.Equal(0, policies);
        Assert.Empty(audit.Records);
    }

    [Theory]
    [InlineData(false, "added")]
    [InlineData(true, "added")]
    [InlineData(false, "stripped")]
    [InlineData(true, "stripped")]
    [InlineData(false, "malformed")]
    [InlineData(true, "malformed")]
    public async Task ResourceMissionMustMatchPresentedTokenBeforeDocumentPolicyOrAudit(bool deferred, string mutation)
    {
        var audit = new InMemoryR3AuditSink();
        var fetches = 0;
        var policies = 0;
        var fixture = await R3AccessFixture.CreateAsync(requireProposalConsent: deferred, auditSink: audit,
            onFetch: () => fetches++, onPolicy: () => policies++);
        await using var app = fixture.App;
        var (personToken, token) = mutation == "stripped"
            ? fixture.PersonRequest(proposal: deferred, missionS256: R3Hash.ComputeS256("mission"u8))
            : (fixture.PersonToken, deferred ? fixture.ProposalResourceToken : fixture.ResourceToken);
        token = WithResourceMission(token, mutation switch
        {
            "added" => R3Hash.ComputeS256("mission"u8),
            "malformed" => "not-a-sha256-digest",
            _ => null,
        }, fixture.ResourceKey);

        using var response = await fixture.PostTokenAsync(token, new JsonObject { ["presented_token"] = personToken });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_resource_token", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        Assert.Equal(0, fetches);
        Assert.Equal(0, policies);
        Assert.Empty(audit.Records);
    }

    private static string WithResourceMission(string token, string? missionS256, IAAuthKey key)
    {
        var segments = token.Split('.');
        var payload = JsonNode.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Decode(segments[1]))!.AsObject();
        if (missionS256 is null) payload.Remove("mission_s256");
        else payload["mission_s256"] = missionS256;
        var input = segments[0] + "." + Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(payload.ToJsonString());
        return input + "." + Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(key.Sign(System.Text.Encoding.ASCII.GetBytes(input)));
    }

    [Theory]
    [InlineData("{}", true)]
    [InlineData("{\"id\":1}", true)]
    [InlineData("{\"description\":null}", true)]
    [InlineData("null", false)]
    [InlineData("[]", false)]
    [InlineData("123", false)]
    [InlineData("\"invalid\"", false)]
    public async Task TokenEndpoint_ProposalParametersRequireObject(string parameters, bool accepted)
    {
        var document = new JsonObject
        {
            ["vocabulary"] = Vocabulary.Mcp,
            ["operations"] = new JsonArray(new JsonObject { ["tool"] = "ping" }),
            ["parameters"] = JsonNode.Parse(parameters),
        };
        var audit = new InMemoryR3AuditSink();
        var policyCalls = 0;
        var fixture = await R3AccessFixture.CreateAsync(requireProposalConsent: true, auditSink: audit,
            proposalBytesOverride: System.Text.Encoding.UTF8.GetBytes(document.ToJsonString()),
            isProposalAllowed: proposal =>
            {
                policyCalls++;
                if (parameters == "{\"description\":null}")
                {
                    Assert.True(proposal.Parameters.ContainsKey("description"));
                    Assert.NotNull(proposal.Parameters["description"]);
                    Assert.Null(proposal.Parameters["description"].Json);
                }
                return true;
            });
        await using var app = fixture.App;
        using var response = await fixture.PostTokenAsync(fixture.ProposalResourceToken);
        Assert.Equal(accepted ? HttpStatusCode.Accepted : HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(accepted ? 1 : 0, policyCalls);
        Assert.Empty(audit.Records);
        if (!accepted)
        {
            Assert.Equal("r3_evaluation_failed", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
            return;
        }
        await ApproveAsync(fixture, response);
        using var minted = await fixture.PollPendingAsync(response.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.OK, minted.StatusCode);
        var body = await minted.Content.ReadFromJsonAsync<JsonObject>();
        var verified = new TokenVerifier().VerifyAuthToken((string)body!["auth_token"]!, fixture.AsKey,
            R3TestData.ResourceIssuer, fixture.AgentKey);
        Assert.True(R3ClaimReader.ReadAuthToken(verified.Payload).Granted.Contains(R3OperationIdentity.Mcp("ping")));
        Assert.Equal(R3TokenIssuanceKind.Proposal, Assert.Single(audit.Records).IssuanceKind);
    }

    [Theory]
    [MemberData(nameof(R3VocabularyTests.Shapes), MemberType = typeof(R3VocabularyTests))]
    public async Task TokenEndpoint_AllVocabulariesRetainReorderedOperation(string vocabulary, R3Operation operation)
    {
        var wire = JsonSerializer.SerializeToNode(operation)!.AsObject();
        var reordered = new JsonObject(wire.Reverse().Select(member => new KeyValuePair<string, JsonNode?>(member.Key, member.Value?.DeepClone())));
        var document = new JsonObject { ["operations"] = new JsonArray(reordered), ["vocabulary"] = vocabulary };
        var fixture = await R3AccessFixture.CreateAsync(documentBytesOverride: System.Text.Encoding.UTF8.GetBytes(document.ToJsonString()));
        await using var app = fixture.App;
        using var response = await fixture.PostTokenAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var verified = new TokenVerifier().VerifyAuthToken((string)body!["auth_token"]!, fixture.AsKey,
            R3TestData.ResourceIssuer, fixture.AgentKey);
        Assert.True(R3ClaimReader.ReadAuthToken(verified.Payload).Granted.Contains(new(vocabulary, operation)));
    }

    [Theory]
    [InlineData("task", false)]
    [InlineData("task", true)]
    [InlineData("service", false)]
    [InlineData("service", true)]
    public async Task TokenEndpoint_CustomSchemaSelectsIdentityBeforePolicy(string identifier, bool reverse)
    {
        const string vocabulary = "https://custom.test/vocabulary";
        var schemas = new R3VocabularySchemas(new Dictionary<string, R3VocabularySchema>
        {
            [vocabulary] = new(identifier, operation =>
            {
                Assert.Equal(identifier, operation.Field);
                Assert.Equal("read", operation.Id);
                Assert.Equal(123, operation.Extensions!["type"].GetInt32());
            }),
        });
        var wire = new JsonObject { [identifier] = "read", ["region"] = "west", ["type"] = 123, ["operation"] = "qualifier" };
        if (reverse) wire = new JsonObject(wire.Reverse().Select(member => new KeyValuePair<string, JsonNode?>(member.Key, member.Value?.DeepClone())));
        var document = new JsonObject { ["operations"] = new JsonArray(wire), ["vocabulary"] = vocabulary };
        var fixture = await R3AccessFixture.CreateAsync(vocabularySchemas: schemas,
            documentBytesOverride: System.Text.Encoding.UTF8.GetBytes(document.ToJsonString()));
        await using var app = fixture.App;
        using var response = await fixture.PostTokenAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var verified = new TokenVerifier().VerifyAuthToken((string)body!["auth_token"]!, fixture.AsKey,
            R3TestData.ResourceIssuer, fixture.AgentKey);
        var operation = Assert.Single(R3ClaimReader.ReadAuthToken(verified.Payload, schemas).Granted.Operations);
        Assert.Equal(identifier, operation.Field);
        Assert.True(JsonNode.DeepEquals(wire, JsonSerializer.SerializeToNode(operation)));
    }

    [Theory]
    [InlineData("agent_token", "{}")]
    [InlineData("agent_token", "[]")]
    [InlineData("agent_token", "123")]
    [InlineData("resource_token", "{}")]
    [InlineData("resource_token", "[]")]
    [InlineData("resource_token", "123")]
    [InlineData("subagent_token", "{}")]
    [InlineData("subagent_token", "[]")]
    [InlineData("subagent_token", "123")]
    [InlineData("upstream_token", "{}")]
    [InlineData("upstream_token", "[]")]
    [InlineData("upstream_token", "123")]
    [InlineData("presented_token", "{}")]
    [InlineData("presented_token", "[]")]
    [InlineData("presented_token", "123")]
    public async Task TokenEndpoint_MalformedCredentialIsBadRequest(string field, string json)
    {
        var audit = new InMemoryR3AuditSink();
        var fixture = await R3AccessFixture.CreateAsync(auditSink: audit);
        await using var app = fixture.App;
        using var response = await fixture.PostTokenAsync(extra: new JsonObject { [field] = JsonNode.Parse(json) });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)body!["error"]);
        Assert.Null(body["auth_token"]);
        Assert.Empty(audit.Records);
    }

    [Theory]
    [InlineData("missing", "invalid_request")]
    [InlineData("other-person-token", "invalid_resource_token")]
    [InlineData("other-agent-key", "invalid_presented_token")]
    [InlineData("wrong-audience", "invalid_presented_token")]
    public async Task TokenEndpoint_PresentedTokenMustBeTheOneTheResourceTokenNames(string variant, string error)
    {
        var audit = new InMemoryR3AuditSink();
        var fetches = 0;
        var fixture = await R3AccessFixture.CreateAsync(auditSink: audit, onFetch: () => fetches++);
        await using var app = fixture.App;
        JsonNode? presented = variant switch
        {
            "missing" => null,
            "other-person-token" => R3TestData.PersonToken(fixture.PsKey, fixture.AgentKey),
            "other-agent-key" => R3TestData.PersonToken(fixture.PsKey, AAuthKey.Generate()),
            _ => new PersonTokenBuilder
            {
                EgressPolicy = TestEgress.Policy, Issuer = R3TestData.PsIssuer, Audience = R3TestData.AsIssuer,
                Subject = R3TestData.PersonSubject, ConfirmationKey = fixture.AgentKey,
                AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1), Key = fixture.PsKey, KeyId = R3TestData.PsKid,
            }.Build(),
        };
        using var response = await fixture.PostTokenAsync(extra: new JsonObject { ["presented_token"] = presented });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(error, (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        Assert.Equal(0, fetches);
        Assert.Empty(audit.Records);
    }

    [Fact]
    public async Task TokenEndpoint_RejectsOtherRoleKeyClaimingPersonRole()
    {
        var fixture = await R3AccessFixture.CreateAsync();
        await using var app = fixture.App;
        using var client = new AAuthClientBuilder(fixture.ResourceKey)
            .UseJwksUri(R3TestData.PsIssuer, AAuthConstants.DwkFiles.Person, R3TestData.ResourceKid)
            .WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(app.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly)
            .Build();
        using var response = await client.PostAsJsonAsync(R3TestData.AsIssuer + "/token", new
        {
            agent_token = fixture.AgentToken,
            resource_token = fixture.ResourceToken,
            presented_token = fixture.PersonToken,
        });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("DELETE")]
    public async Task Pending_RequiresPersonRole(string method)
    {
        var discoveryClock = new IssuanceClock();
        var fixture = await R3AccessFixture.CreateAsync(requireProposalConsent: true, discoveryClock: discoveryClock);
        await using var app = fixture.App;
        using var pending = await fixture.PostTokenAsync(fixture.ProposalResourceToken);
        Assert.Equal(HttpStatusCode.Accepted, pending.StatusCode);
        discoveryClock.Now = discoveryClock.Now.AddMinutes(2);
        using var client = new AAuthClientBuilder(fixture.ResourceKey)
            .UseJwksUri(R3TestData.PsIssuer, AAuthConstants.DwkFiles.Resource, R3TestData.ResourceKid)
            .WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(app.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly)
            .Build();
        using var request = new HttpRequestMessage(new HttpMethod(method), new Uri(new Uri(R3TestData.AsIssuer), pending.Headers.Location!));
        using var denied = await client.SendAsync(request);
        Assert.True(denied.StatusCode == HttpStatusCode.Forbidden, await denied.Content.ReadAsStringAsync());
        Assert.Equal("untrusted_person_server", (string?)(await denied.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        using var poll = await fixture.PollPendingAsync(pending.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.Accepted, poll.StatusCode);
    }

    [Theory]
    [InlineData("aauth-person.json", false)]
    [InlineData("aauth-person.json", true)]
    [InlineData("aauth-resource.json", false)]
    [InlineData("aauth-resource.json", true)]
    [InlineData("aauth-access.json", false)]
    [InlineData("aauth-access.json", true)]
    [InlineData("aauth-agent.json", false)]
    [InlineData("aauth-agent.json", true)]
    public async Task TokenEndpoint_RequiresVerifiedPersonRoleAtTrustedOrigin(string role, bool openTrust)
    {
        var fixture = await R3AccessFixture.CreateAsync(openPersonServerTrust: openTrust);
        await using var app = fixture.App;
        var isPerson = role == AAuthConstants.DwkFiles.Person;
        using var client = new AAuthClientBuilder(isPerson ? fixture.PsKey : fixture.ResourceKey)
            .UseJwksUri(R3TestData.PsIssuer, role, isPerson ? R3TestData.PsKid : R3TestData.ResourceKid)
            .WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(app.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly)
            .Build();
        using var response = await client.PostAsJsonAsync(R3TestData.AsIssuer + "/token", new
        {
            agent_token = fixture.AgentToken,
            resource_token = fixture.ResourceToken,
            presented_token = fixture.PersonToken,
        });
        Assert.Equal(isPerson ? HttpStatusCode.OK : HttpStatusCode.Forbidden, response.StatusCode);
        if (!isPerson)
            Assert.Equal("untrusted_person_server", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ResourceScope_RequiresIndependentPolicy(bool allow)
    {
        var fixture = await R3AccessFixture.CreateAsync(isScopeAllowed: allow ?
            (resource, scope) => resource == R3TestData.ResourceIssuer && scope == "bookings.read" : null);
        await using var app = fixture.App;
        var token = R3TestData.ResourceToken(fixture.ResourceKey, fixture.Presented, fixture.AgentKey,
            fixture.R3Uri, fixture.R3S256, scope: "bookings.read");
        using var response = await fixture.PostTokenAsync(token);
        Assert.Equal(allow ? HttpStatusCode.OK : HttpStatusCode.BadRequest, response.StatusCode);
        if (allow)
        {
            var body = await response.Content.ReadFromJsonAsync<JsonObject>();
            var payload = JsonNode.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(((string)body!["auth_token"]!).Split('.')[1]))!;
            Assert.Equal("bookings.read", (string?)payload["scope"]);
            Assert.NotNull(payload["r3_granted"]);
        }
    }

    [Fact]
    public async Task Mapping_RejectsMissingAuditPersistence()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        Assert.Throws<InvalidOperationException>(() => app.MapR3AccessTokenEndpoint(new R3AccessTokenEndpointOptions
        {
            Issuer = R3TestData.AsIssuer, SigningKeys = new Dictionary<string, IAAuthKey> { ["as"] = AAuthKey.Generate() }, AuditSink = null!,
        }));
    }

    [Fact]
    public async Task DurableAudit_RecordsTheReleasedTokenAcrossRestart()
    {
        var directory = Path.Combine(Path.GetTempPath(), "r3-endpoint-audit-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "audit.sqlite");
        try
        {
            var fixture = await R3AccessFixture.CreateAsync(auditSink: new R3AccessServer.SqliteR3AuditSink(path));
            await using var app = fixture.App;
            using var response = await fixture.PostTokenAsync();
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<JsonObject>();
            var token = (string)body!["auth_token"]!;
            var record = Assert.Single(new R3AccessServer.SqliteR3AuditSink(path).ReadRecords());
            Assert.Equal(R3Hash.ComputeS256(System.Text.Encoding.ASCII.GetBytes(token)), record.TokenS256);
            Assert.Equal(fixture.R3S256, record.R3S256);
        }
        finally { Directory.Delete(directory, true); }
    }
    [Theory]
    [InlineData(null, null, false, true)]
    [InlineData("personal", "personal", false, true)]
    [InlineData("personal", "personal", true, true)]
    [InlineData("work", "personal", false, false)]
    [InlineData("work", "personal", true, false)]
    [InlineData(null, "personal", false, false)]
    [InlineData("personal", null, true, false)]
    public async Task Account_BindsResourceDocumentAndDirectOrDeferredDelivery(string? tokenAccount, string? documentAccount, bool deferred, bool accepted)
    {
        var audit = new InMemoryR3AuditSink();
        var fixture = await R3AccessFixture.CreateAsync(requireProposalConsent: deferred, documentAccount: documentAccount, auditSink: audit);
        await using var app = fixture.App;
        var resourceToken = R3TestData.ResourceToken(fixture.ResourceKey, fixture.Presented, fixture.AgentKey,
            deferred ? fixture.ProposalUri : fixture.R3Uri, deferred ? fixture.ProposalS256 : fixture.R3S256, account: tokenAccount);
        using var initial = await fixture.PostTokenAsync(resourceToken);
        if (!accepted)
        {
            Assert.Equal(HttpStatusCode.BadRequest, initial.StatusCode);
            Assert.DoesNotContain("auth_token", await initial.Content.ReadAsStringAsync());
            Assert.Empty(audit.Records);
            return;
        }
        if (deferred)
        {
            Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
            await ApproveAsync(fixture, initial);
        }
        using var response = deferred ? await fixture.PollPendingAsync(initial.Headers.Location!.ToString()) : initial;
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await ReadAuthPayloadAsync(response);
        var verified = new TokenVerifier().VerifyAuthToken((string)body["auth_token"]!, fixture.AsKey,
            R3TestData.ResourceIssuer, fixture.AgentKey,
            accountExpectation: new AccountExpectation(tokenAccount));
        Assert.Equal(tokenAccount, verified.Account);
        Assert.Equal(tokenAccount, Assert.Single(audit.Records).Account);
    }

    private static string ConsentCode(HttpResponseMessage pending)
    {
        var interaction = AAuth.Headers.Interaction.FromRequirement(AAuth.Headers.AAuthRequirementHeader.Parse(
            pending.Headers.GetValues("AAuth-Requirement").Single()), TestEgress.Policy)!;
        Assert.NotEqual(pending.Headers.Location!.ToString().Split('/')[^1], interaction.Code);
        Assert.All(interaction.Code!, symbol => Assert.Contains(symbol, AAuth.Headers.InteractionCode.Alphabet));
        return interaction.Code!;
    }

    [Theory]
    [InlineData(false, 120, 0, false, 3600)]
    [InlineData(true, 120, 0, false, 3600)]
    [InlineData(false, 120, 300, false, 3600)]
    [InlineData(true, 120, 300, false, 3600)]
    [InlineData(false, 300, 120, false, 3600)]
    [InlineData(true, 300, 120, false, 3600)]
    [InlineData(false, 300, 120, true, 3600)]
    [InlineData(true, 300, 120, true, 3600)]
    [InlineData(false, 300, 0, false, 90)]
    [InlineData(true, 300, 120, false, 90)]
    public async Task TokenEndpoint_BoundsDirectAndDeferredVerifiedContexts(bool deferred, int parentSeconds, int childSeconds, bool upstream, int presentedSeconds)
    {
        var clock = new IssuanceClock();
        var fixture = await R3AccessFixture.CreateAsync(requireProposalConsent: deferred, timeProvider: clock, documentAccount: "workspace/17");
        await using var app = fixture.App;
        var childKey = AAuthKey.Generate();
        const string childId = "aauth:demo+child@ap.test";
        var boundKey = childSeconds == 0 ? fixture.AgentKey : childKey;
        var personToken = R3TestData.PersonToken(fixture.PsKey, boundKey, agentTokenExpiresAt: clock.Now.AddSeconds(presentedSeconds));
        var resourceToken = R3TestData.ResourceToken(fixture.ResourceKey, R3TestData.VerifyPersonToken(personToken, fixture.PsKey, boundKey),
            boundKey, deferred ? fixture.ProposalUri : fixture.R3Uri, deferred ? fixture.ProposalS256 : fixture.R3S256, account: "workspace/17");
        var extra = new JsonObject { ["agent_token"] = ShortAgent(fixture, clock, parentSeconds), ["presented_token"] = personToken };
        if (childSeconds != 0)
            extra["subagent_token"] = new AgentTokenBuilder
            {
                EgressPolicy = TestEgress.Policy,
                Issuer = R3TestData.ApIssuer, Subject = childId, ParentAgent = R3TestData.AgentId,
                Key = fixture.ApKey, KeyId = R3TestData.ApKid, ConfirmationKey = childKey,
                IssuedAt = clock.Now.AddSeconds(childSeconds - 3600), Lifetime = TimeSpan.FromHours(1),
            }.Build();
        if (upstream)
            extra["upstream_token"] = UpstreamToken(fixture, clock: clock, expiresAt: clock.Now.AddSeconds(60),
                account: "upstream-resource/other-namespace");
        var expectedExpiry = clock.Now.AddSeconds(Math.Min(upstream ? 60 : 120, presentedSeconds));
        using var initial = await fixture.PostTokenAsync(resourceToken, extra);
        HttpResponseMessage response = initial;
        if (deferred)
        {
            Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
            await ApproveAsync(fixture, initial);
            clock.Now = clock.Now.AddSeconds(30);
            response = await fixture.PollPendingAsync(initial.Headers.Location!.ToString());
        }
        using (response)
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await ReadAuthPayloadAsync(response);
            var verified = new TokenVerifier { EgressPolicy = TestEgress.Policy, TimeProvider = clock }.VerifyAuthToken((string)body["auth_token"]!,
                fixture.AsKey, R3TestData.ResourceIssuer, boundKey);
            Assert.Equal(expectedExpiry, verified.ExpiresAt);
            Assert.Equal("workspace/17", verified.Account);
            Assert.Equal(expectedExpiry.ToUnixTimeSeconds() - clock.Now.ToUnixTimeSeconds(), (long)body["expires_in"]!);
            Assert.False(verified.Payload.ContainsKey("act"));
            Assert.False(verified.Payload.ContainsKey("agent"));
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Pending_RejectsExpiryBeforeMintOrAfterCachedMint(bool expireBeforeMint)
    {
        var clock = new IssuanceClock();
        var audit = new InMemoryR3AuditSink();
        var fixture = await R3AccessFixture.CreateAsync(requireProposalConsent: true, timeProvider: clock, auditSink: audit);
        await using var app = fixture.App;
        using var initial = await fixture.PostTokenAsync(fixture.ProposalResourceToken,
            new JsonObject { ["agent_token"] = ShortAgent(fixture, clock, 120) });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        await ApproveAsync(fixture, initial);
        if (!expireBeforeMint)
        {
            using var minted = await fixture.PollPendingAsync(initial.Headers.Location!.ToString());
            Assert.Equal(HttpStatusCode.OK, minted.StatusCode);
        }
        clock.Now = clock.Now.AddSeconds(120);
        using var expired = await fixture.PollPendingAsync(initial.Headers.Location!.ToString());
        Assert.Equal(expireBeforeMint ? HttpStatusCode.RequestTimeout : HttpStatusCode.Gone, expired.StatusCode);
        Assert.Null((await expired.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]);
        Assert.Equal(expireBeforeMint ? 0 : 1, audit.Records.Count);
    }

    [Fact]
    public async Task TokenEndpoint_DoesNotReleaseTokenThatExpiresDuringAudit()
    {
        var clock = new IssuanceClock();
        var fixture = await R3AccessFixture.CreateAsync(timeProvider: clock, auditSink: new AdvancingAuditSink(clock));
        await using var app = fixture.App;
        using var response = await fixture.PostTokenAsync(extra: new JsonObject { ["agent_token"] = ShortAgent(fixture, clock, 120) });
        // A fresh request names the expired parameter, not polling `expired` (#token-endpoint-error-codes).
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = (await response.Content.ReadFromJsonAsync<JsonObject>())!;
        Assert.Equal("expired_agent_token", (string?)body["error"]);
        Assert.Null(body["auth_token"]);
    }

    private static string ShortAgent(R3AccessFixture fixture, IssuanceClock clock, int seconds) => new AgentTokenBuilder
    {
        EgressPolicy = TestEgress.Policy,
        Issuer = R3TestData.ApIssuer, Subject = R3TestData.AgentId, Key = fixture.ApKey, KeyId = R3TestData.ApKid,
        ConfirmationKey = fixture.AgentKey, IssuedAt = clock.Now.AddSeconds(seconds - 3600), Lifetime = TimeSpan.FromHours(1),
    }.Build();

    [Fact]
    public async Task RevokedSource_CannotDeliverApprovedProposal()
    {
        var fixture = await R3AccessFixture.CreateAsync(requireProposalConsent: true);
        await using var app = fixture.App;
        using var pending = await fixture.PostTokenAsync(fixture.ProposalResourceToken);
        Assert.Equal(HttpStatusCode.Accepted, pending.StatusCode);
        var payload = JsonNode.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(fixture.AgentToken.Split('.')[1]))!.AsObject();
        using var provider = new AAuthClientBuilder(fixture.ApKey)
            .UseJwksUri(R3TestData.ApIssuer, AAuthConstants.DwkFiles.Agent, R3TestData.ApKid)
            .WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(app.GetTestServer().CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
            .Build();
        var result = await new AAuth.Server.RevocationClient(provider).RevokeAsync(
            new Uri(R3TestData.AsIssuer + "/revoke"), (string)payload["jti"]!, DateTimeOffset.FromUnixTimeSeconds((long)payload["exp"]!));
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        await ApproveAsync(fixture, pending);
        using var denied = await fixture.PollPendingAsync(pending.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        var body = await denied.Content.ReadAsStringAsync();
        Assert.Equal("revoked", (string?)JsonNode.Parse(body)!["error"]);
        Assert.DoesNotContain("auth_token", body);
    }

    private static async Task ApproveAsync(R3AccessFixture fixture, HttpResponseMessage pending)
    {
        using var browser = fixture.App.GetTestClient();
        using var response = await TestConsentBrowser.DecideAsync(browser,
            "/interaction/consent?code=" + ConsentCode(pending), "/interaction/consent/approve");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private sealed class IssuanceClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class AdvancingAuditSink(IssuanceClock clock) : IR3AuditSink
    {
        public Task RecordTokenIssuanceAsync(R3TokenIssuanceAuditRecord record, CancellationToken cancellationToken = default)
        {
            clock.Now = clock.Now.AddSeconds(120);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task TokenEndpoint_MintsR3AuthTokenThatPassesVerifier()
    {
        var fixture = await R3AccessFixture.CreateAsync();
        await using var app = fixture.App;

        var response = await fixture.PostTokenAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var payload = await ReadAuthPayloadAsync(response);
        var verified = new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(
            (string)payload["auth_token"]!,
            fixture.AsKey,
            R3TestData.ResourceIssuer,
            fixture.AgentKey,
            expectedDwk: AuthTokenBuilder.AccessDwk);
        var claims = R3ClaimReader.ReadAuthToken(verified.Payload);
        Assert.Equal(fixture.R3Uri, claims.Uri);
        Assert.Equal(fixture.R3S256, claims.S256);
        Assert.True(claims.Granted.Contains(R3OperationIdentity.OpenApi("search_trip_options")));
        Assert.True(claims.Granted.Contains(R3OperationIdentity.OpenApi("hold_itinerary")));
        Assert.True(claims.PerCall!.Contains(R3OperationIdentity.OpenApi("book_trip")));
    }

    [Fact]
    public async Task TokenEndpoint_RejectsReplayedSignedRequest_AndMintsAuditsOnce()
    {
        // §Freshness and Replay: with an IJtiStore registered, a captured signed
        // POST /token replayed verbatim within the freshness window is refused (401),
        // so it cannot re-mint an auth token or duplicate the audit record. The
        // legitimate first request still succeeds and audits exactly once.
        var auditSink = new InMemoryR3AuditSink();
        var fixture = await R3AccessFixture.CreateAsync(
            auditSink: auditSink, jtiStore: new AAuth.Server.InMemoryJtiStore());
        await using var app = fixture.App;

        var (first, replay) = await fixture.PostTokenThenReplayAsync();

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Equal("error=invalid_signature", replay.Headers.GetValues("Signature-Error").Single());
        Assert.Equal("application/problem+json", replay.Content.Headers.ContentType?.MediaType);
        var error = await replay.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_signature", (string?)error!["error"]);
        Assert.Equal("replayed request signature", (string?)error["detail"]);
        Assert.False(error.ContainsKey("error_description"));
        Assert.Single(auditSink.Records);
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
        var issued = (string)(await response.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!;
        var issuedPayload = JsonNode.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(issued.Split('.')[1]))!;
        Assert.Equal((string?)issuedPayload["jti"], record.TokenId);
        Assert.Equal(R3Hash.ComputeS256(System.Text.Encoding.ASCII.GetBytes(issued)), record.TokenS256);
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
        var verified = new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(
            (string)payload["auth_token"]!,
            fixture.AsKey,
            R3TestData.ResourceIssuer,
            fixture.AgentKey,
            expectedDwk: AuthTokenBuilder.AccessDwk);
        var claims = R3ClaimReader.ReadAuthToken(verified.Payload);
        Assert.Equal(fixture.R3Uri, claims.Uri);
        Assert.True(claims.Granted.Contains(R3OperationIdentity.OpenApi("search_trip_options")));
        Assert.True(claims.PerCall?.Contains(R3OperationIdentity.OpenApi("book_trip")) ?? false);
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
    public async Task DeferredAuditFailureReturnsTyped500ThenGone()
    {
        var fixture = await R3AccessFixture.CreateAsync(auditSink: new ThrowingAuditSink(), requireProposalConsent: true);
        await using var app = fixture.App;
        using var pending = await fixture.PostTokenAsync(fixture.ProposalResourceToken);
        await ApproveAsync(fixture, pending);
        using var failed = await fixture.PollPendingAsync(pending.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.InternalServerError, failed.StatusCode);
        Assert.Equal("application/problem+json", failed.Content.Headers.ContentType?.MediaType);
        Assert.Equal("server_error", (await failed.Content.ReadFromJsonAsync<JsonObject>())!["error"]!.GetValue<string>());
        using var replay = await fixture.PollPendingAsync(pending.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
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
        Assert.Equal("application/json", pending.Content.Headers.ContentType?.MediaType);
        Assert.NotNull(pending.Headers.Location);
        Assert.True(pending.Headers.TryGetValues("AAuth-Requirement", out var requirement));
        Assert.Contains(requirement, v => v.Contains("interaction", StringComparison.Ordinal));
        Assert.Empty(auditSink.Records); // nothing minted before approval

        var location = pending.Headers.Location!.ToString();
        var code = ConsentCode(pending);
        using var browser = app.GetTestClient();
        browser.BaseAddress = new Uri(R3TestData.AsIssuer);

        var approve = await TestConsentBrowser.DecideAsync(browser,
            "/interaction/consent?code=" + code, "/interaction/consent/approve");
        Assert.Equal(HttpStatusCode.OK, approve.StatusCode);

        var granted = await fixture.PollPendingAsync(location);

        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
        var payload = await ReadAuthPayloadAsync(granted);
        var verified = new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(
            (string)payload["auth_token"]!,
            fixture.AsKey,
            R3TestData.ResourceIssuer,
            fixture.AgentKey,
            expectedDwk: AuthTokenBuilder.AccessDwk);
        var claims = R3ClaimReader.ReadAuthToken(verified.Payload);
        Assert.Equal(fixture.ProposalUri, claims.Uri);
        Assert.True(claims.Granted.Contains(R3OperationIdentity.OpenApi("book_trip")));
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
        var code = ConsentCode(pending);
        using var browser = app.GetTestClient();
        browser.BaseAddress = new Uri(R3TestData.AsIssuer);

        var deny = await TestConsentBrowser.DecideAsync(browser,
            "/interaction/consent?code=" + code, "/interaction/consent/deny");
        Assert.Equal(HttpStatusCode.OK, deny.StatusCode);

        var polled = await fixture.PollPendingAsync(location);

        Assert.Equal(HttpStatusCode.Forbidden, polled.StatusCode);
        Assert.False(polled.Headers.Contains("Signature-Error"));
        Assert.False(polled.Headers.Contains("Accept-Signature-Scheme"));
        Assert.False(polled.Headers.Contains("Accept-Signature-Alg"));
        Assert.Equal("application/problem+json", polled.Content.Headers.ContentType?.MediaType);
        var error = await polled.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("denied", (string?)error!["error"]);
        Assert.False(error.ContainsKey("detail"));
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
        var code = ConsentCode(pending);
        using var browser = app.GetTestClient();
        browser.BaseAddress = new Uri(R3TestData.AsIssuer);
        var approve = await TestConsentBrowser.DecideAsync(browser,
            "/interaction/consent?code=" + code, "/interaction/consent/approve");
        Assert.Equal(HttpStatusCode.OK, approve.StatusCode);

        // Fire several concurrent signed polls of the same approval.
        var polls = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => fixture.PollPendingAsync(location)));

        var tokens = new HashSet<string>(StringComparer.Ordinal);
        Assert.Single(polls, poll => poll.StatusCode == HttpStatusCode.OK);
        Assert.Equal(7, polls.Count(poll => poll.StatusCode == HttpStatusCode.Gone));
        foreach (var poll in polls.Where(poll => poll.StatusCode == HttpStatusCode.OK))
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
        var code = ConsentCode(pending);
        using var browser = app.GetTestClient();
        browser.BaseAddress = new Uri(R3TestData.AsIssuer);
        var approve = await TestConsentBrowser.DecideAsync(browser,
            "/interaction/consent?code=" + code, "/interaction/consent/approve");
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
        Assert.Equal("error=invalid_signature", polled.Headers.GetValues("Signature-Error").Single());
    }

    [Fact]
    public async Task TokenEndpoint_RejectsWrongSchemeWithNegotiation()
    {
        var fixture = await R3AccessFixture.CreateAsync();
        await using var app = fixture.App;
        using var client = new AAuthClientBuilder(fixture.PsKey).UseHwk()
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(app.GetTestServer().CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly).Build();
        using var response = await client.PostAsJsonAsync(R3TestData.AsIssuer + "/token", new { });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("error=unsupported_scheme", response.Headers.GetValues("Signature-Error").Single());
        Assert.Equal("jwks_uri", response.Headers.GetValues("Accept-Signature-Scheme").Single());
    }

    [Fact]
    public async Task TokenEndpoint_RejectsFetchedBytesWhoseHashDoesNotMatchResourceToken()
    {
        var fixture = await R3AccessFixture.CreateAsync(resourceTokenS256Override: Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(new byte[32]));
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
        var verified = new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyAuthToken(
            (string)payload["auth_token"]!,
            fixture.AsKey,
            R3TestData.ResourceIssuer,
            fixture.AgentKey,
            expectedDwk: AuthTokenBuilder.AccessDwk);
        var claims = R3ClaimReader.ReadAuthToken(verified.Payload);
        Assert.Equal(fixture.ProposalUri, claims.Uri);
        Assert.Equal(fixture.ProposalS256, claims.S256);
        Assert.True(claims.Granted.Contains(R3OperationIdentity.OpenApi("book_trip")));
        Assert.Null(claims.PerCall);
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
        Assert.Equal($"{R3TestData.AsIssuer}/token", (string?)metadata["auth_token_endpoint"]);
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
        Assert.InRange(record.IssuedAt.ToUnixTimeSeconds(), earliest.ToUnixTimeSeconds(), latest.ToUnixTimeSeconds());
        Assert.False(string.IsNullOrWhiteSpace(record.TokenId));
        Assert.False(string.IsNullOrWhiteSpace(record.TokenS256));
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
        public required string PersonToken { get; init; }
        public required TokenVerifier.VerifiedToken Presented { get; init; }
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
            IR3AuditSink? auditSink = null,
            AAuth.Server.IJtiStore? jtiStore = null,
            TimeProvider? timeProvider = null,
            string? documentAccount = null,
            Func<string, string, bool>? isScopeAllowed = null,
            TimeProvider? discoveryClock = null,
            byte[]? documentBytesOverride = null,
            byte[]? proposalBytesOverride = null,
            R3VocabularySchemas? vocabularySchemas = null,
            Action? onFetch = null,
            Action? onPolicy = null,
            Func<R3ProposalDocument, bool>? isProposalAllowed = null)
        {
            var asKey = AAuthKey.Generate();
            var psKey = AAuthKey.Generate();
            var apKey = AAuthKey.Generate();
            var resourceKey = AAuthKey.Generate();
            var agentKey = AAuthKey.Generate();
            var r3Uri = $"{R3TestData.ResourceIssuer}/r3/doc";
            var docBytes = documentBytesOverride ?? (R3TestData.Document() with { Account = documentAccount }).ToUtf8Bytes();
            var r3S256 = R3Hash.ComputeS256(docBytes);
            var proposal = new R3ProposalDocument
            {
                Account = documentAccount,
                Vocabulary = Vocabulary.OpenApi,
                Operations = [R3Operation.OpenApi("book_trip")],
                Parameters = new Dictionary<string, R3Parameter>
                {
                    ["itinerary_id"] = R3Parameter.Inline(JsonValue.Create("it-123")!),
                    ["total_usd"] = R3Parameter.Inline(JsonValue.Create(1200)!),
                },
                Display = new R3Display { Summary = "Approve booking", Detail = "Book the exact itinerary." },
            };
            var proposalBytes = proposalBytesOverride ?? proposal.ToUtf8Bytes();
            var proposalS256 = R3Hash.ComputeS256(proposalBytes);
            var proposalUri = $"{R3TestData.ResourceIssuer}/r3/proposals/{proposalS256}";

            var discovery = new StaticJsonHandler()
                .AddJson($"{R3TestData.PsIssuer}/.well-known/aauth-person.json", R3TestData.Metadata(R3TestData.PsIssuer, AuthTokenBuilder.PersonDwk))
                .AddJson($"{R3TestData.PsIssuer}/.well-known/jwks.json", R3TestData.Jwks(R3TestData.PsKid, psKey))
                .AddJson($"{R3TestData.ApIssuer}/.well-known/aauth-agent.json", R3TestData.Metadata(R3TestData.ApIssuer, AgentTokenBuilder.AgentDwk))
                .AddJson($"{R3TestData.ApIssuer}/.well-known/aauth-person.json", R3TestData.Metadata(R3TestData.ApIssuer, AuthTokenBuilder.PersonDwk))
                .AddJson($"{R3TestData.ApIssuer}/.well-known/jwks.json", R3TestData.Jwks(R3TestData.ApKid, apKey))
                .AddJson($"{R3TestData.ResourceIssuer}/.well-known/aauth-resource.json", R3TestData.Metadata(R3TestData.ResourceIssuer, ResourceTokenBuilder.ResourceDwk))
                .AddJson($"{R3TestData.ResourceIssuer}/.well-known/jwks.json", R3TestData.Jwks(R3TestData.ResourceKid, resourceKey));

            foreach (var role in new[] { AAuthConstants.DwkFiles.Resource, AAuthConstants.DwkFiles.Access, AAuthConstants.DwkFiles.Agent })
                discovery.AddJson($"{R3TestData.PsIssuer}/.well-known/{role}", new JsonObject
                {
                    ["issuer"] = R3TestData.PsIssuer,
                    ["jwks_uri"] = $"{R3TestData.PsIssuer}/.well-known/other-role-jwks.json",
                });
            discovery.AddJson($"{R3TestData.PsIssuer}/.well-known/other-role-jwks.json", R3TestData.Jwks(R3TestData.ResourceKid, resourceKey));

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddSingleton(new JwksClient(new InProcessHttpClient(discovery), timeProvider: discoveryClock));
            builder.Services.AddSingleton(new MetadataClient(new InProcessHttpClient(discovery)));
            if (jtiStore is not null)
            {
                // Registered as the interface so R3DocumentEndpoint's replay guard resolves it.
                builder.Services.AddSingleton(jtiStore);
            }
            var app = builder.Build();
            // When a fetch handler is supplied, exercise the REAL R3FetchClient signed
            // fetch (routed at the in-proc doc server) instead of the in-memory bypass.
            Func<HttpContext, string, string, string, CancellationToken, Task<byte[]>>? fetchOverride =
                fetchHandler is not null ? null : (_, uri, s256, _, _) =>
                {
                    onFetch?.Invoke();
                    var bytes = uri == r3Uri ? docBytes : uri == proposalUri ? proposalBytes : throw new InvalidOperationException("unknown R3 URI");
                    return Task.FromResult(bytes);
                };
            app.MapR3AccessTokenEndpoint(new R3AccessTokenEndpointOptions
            {
                EgressPolicy = TestEgress.Policy,
                Issuer = R3TestData.AsIssuer,
                SigningKeys = new Dictionary<string, IAAuthKey> { [R3TestData.AsKid] = asKey },
                Trust = { PersonServers = { Allowed = openPersonServerTrust ? null : new HashSet<string>(trustedPersonServers ?? [R3TestData.PsIssuer]) } },
                // AS policy: book_trip requires per-call approval (r3 §Auth Token Extensions —
                // the AS decides granted vs per-call, not the R3 document).
                IsPerCallOperation = op => op.Matches(Vocabulary.OpenApi, R3Operation.OpenApi("book_trip")),
                RequireProposalConsent = requireProposalConsent,
                BrowserConsent = new AAuth.Server.BrowserConsentSessions("Test.R3.Consent", "isolated-test-user", isolatedDemoAccess: _ => true),
                AuditSink = auditSink ?? new InMemoryR3AuditSink(),
                VocabularySchemas = vocabularySchemas ?? R3VocabularySchemas.Standard,
                IsScopeAllowed = isScopeAllowed,
                IsOperationAllowed = _ => { onPolicy?.Invoke(); return true; },
                IsProposalAllowed = isProposalAllowed,
                FetchAndVerifyAsync = fetchOverride,
                FetchTransportContract = AAuth.Discovery.AAuthTransportContract.InProcessOnly,
                FetchHttpMessageHandler = fetchHandler,
                TimeProvider = timeProvider ?? TimeProvider.System,
            });
            await app.StartAsync();

            var personToken = R3TestData.PersonToken(psKey, agentKey);
            var presented = R3TestData.VerifyPersonToken(personToken, psKey, agentKey);
            return new R3AccessFixture
            {
                App = app,
                AsKey = asKey,
                PsKey = psKey,
                ApKey = apKey,
                ResourceKey = resourceKey,
                AgentKey = agentKey,
                AgentToken = R3TestData.AgentToken(apKey, agentKey),
                PersonToken = personToken,
                Presented = presented,
                ResourceToken = R3TestData.ResourceToken(resourceKey, presented, agentKey, resourceTokenUriOverride ?? r3Uri, resourceTokenS256Override ?? r3S256),
                R3Uri = r3Uri,
                R3S256 = r3S256,
                ProposalUri = proposalUri,
                ProposalS256 = proposalS256,
                ProposalResourceToken = R3TestData.ResourceToken(resourceKey, presented, agentKey, proposalUri, proposalS256),
            };
        }

        // A person token for this resource plus a resource token naming it, bound to agentKey.
        public (string PersonToken, string ResourceToken) PersonRequest(bool proposal = false, string? missionS256 = null,
            AAuthKey? agentKey = null, string? account = null, string? scope = null)
        {
            var key = agentKey ?? AgentKey;
            var person = R3TestData.PersonToken(PsKey, key, missionS256);
            var verified = R3TestData.VerifyPersonToken(person, PsKey, key);
            return (person, R3TestData.ResourceToken(ResourceKey, verified, key,
                proposal ? ProposalUri : R3Uri, proposal ? ProposalS256 : R3S256, scope, account));
        }

        public async Task<HttpResponseMessage> PostTokenAsync(string? resourceToken = null, JsonObject? extra = null, string? bodyMode = null)
        {
            using var client = bodyMode is null
                ? new AAuthClientBuilder(PsKey)
                    .UseJwksUri(R3TestData.PsIssuer, AAuthConstants.DwkFiles.Person, R3TestData.PsKid)
                    .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(App.GetTestServer().CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
                    .Build()
                : UnsafeBodyClient(bodyMode);
            client.BaseAddress = new Uri(R3TestData.AsIssuer);
            var body = new JsonObject
            {
                ["agent_token"] = AgentToken,
                ["resource_token"] = resourceToken ?? ResourceToken,
                ["presented_token"] = PersonToken,
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

        // "uncovered" signs without content-type/content-digest; "tampered" swaps the body after signing.
        private HttpClient UnsafeBodyClient(string bodyMode)
        {
            var signer = new AAuth.HttpSig.AAuthSigningHandler(PsKey,
                new AAuth.HttpSig.JwksUriSignatureKeyProvider(R3TestData.PsIssuer, AAuthConstants.DwkFiles.Person, R3TestData.PsKid));
            HttpMessageHandler handler;
            if (bodyMode == "uncovered")
            {
                handler = new UncoveredBodySigner(signer) { InnerHandler = App.GetTestServer().CreateHandler() };
            }
            else
            {
                signer.InnerHandler = new BodySwapHandler { InnerHandler = App.GetTestServer().CreateHandler() };
                handler = signer;
            }
            return new InProcessHttpClient(handler) { BaseAddress = new Uri(R3TestData.AsIssuer) };
        }

        // Poll the AS pending Location the way the PS does: a signed GET over the
        // trusted-PS federation channel (the endpoint verifies the signature).
        public async Task<HttpResponseMessage> PollPendingAsync(string path)
        {
            using var client = new AAuthClientBuilder(PsKey)
                .UseJwksUri(R3TestData.PsIssuer, AAuthConstants.DwkFiles.Person, R3TestData.PsKid)
                .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(App.GetTestServer().CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
                .Build();
            client.BaseAddress = new Uri(R3TestData.AsIssuer);
            return await client.GetAsync(path);
        }

        // Poll as a specific signing identity/jwks_uri (used to simulate a DIFFERENT
        // Person Server polling a pending entry it did not park).
        public async Task<HttpResponseMessage> PollPendingAsAsync(string path, AAuthKey key, string jwksUri, string kid)
        {
            using var client = new AAuthClientBuilder(key)
                .UseJwksUri(new Uri(jwksUri).GetLeftPart(UriPartial.Authority), AAuthConstants.DwkFiles.Person, kid)
                .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(App.GetTestServer().CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
                .Build();
            client.BaseAddress = new Uri(R3TestData.AsIssuer);
            return await client.GetAsync(path);
        }

        // Post a signed /token request, capturing the exact signed bytes, then replay
        // them verbatim over the raw (unsigned) TestServer transport. Returns both
        // responses so a test can assert the replayed request is refused.
        public async Task<(HttpResponseMessage First, HttpResponseMessage Replay)> PostTokenThenReplayAsync(
            string? resourceToken = null)
        {
            var capture = new SignedRequestCapture { InnerHandler = App.GetTestServer().CreateHandler() };
            using var client = new AAuthClientBuilder(PsKey)
                .UseJwksUri(R3TestData.PsIssuer, AAuthConstants.DwkFiles.Person, R3TestData.PsKid)
                .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(capture, AAuth.Discovery.AAuthTransportContract.InProcessOnly)
                .Build();
            client.BaseAddress = new Uri(R3TestData.AsIssuer);
            var body = new JsonObject
            {
                ["agent_token"] = AgentToken,
                ["resource_token"] = resourceToken ?? ResourceToken,
                ["presented_token"] = PersonToken,
            };
            var first = await client.PostAsJsonAsync("/token", body);

            var raw = App.GetTestServer().CreateClient();
            var replay = await raw.SendAsync(capture.BuildReplay());
            return (first, replay);
        }
    }

    // Captures the fully-signed outgoing request (method, uri, request + content
    // headers, body bytes) so a test can replay it verbatim through a raw client.
    private sealed class SignedRequestCapture : DelegatingHandler
    {
        private HttpMethod _method = HttpMethod.Get;
        private Uri? _uri;
        private readonly List<KeyValuePair<string, IEnumerable<string>>> _requestHeaders = new();
        private readonly List<KeyValuePair<string, IEnumerable<string>>> _contentHeaders = new();
        private byte[] _body = Array.Empty<byte>();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _method = request.Method;
            _uri = request.RequestUri;
            _requestHeaders.Clear();
            _requestHeaders.AddRange(request.Headers);
            _contentHeaders.Clear();
            if (request.Content is not null)
            {
                _body = await request.Content.ReadAsByteArrayAsync(cancellationToken);
                _contentHeaders.AddRange(request.Content.Headers);
            }
            return await base.SendAsync(request, cancellationToken);
        }

        public HttpRequestMessage BuildReplay()
        {
            var replay = new HttpRequestMessage(_method, _uri)
            {
                Content = new ByteArrayContent(_body),
            };
            foreach (var (key, values) in _contentHeaders)
            {
                replay.Content.Headers.TryAddWithoutValidation(key, values);
            }
            foreach (var (key, values) in _requestHeaders)
            {
                replay.Headers.TryAddWithoutValidation(key, values);
            }
            return replay;
        }
    }
}
