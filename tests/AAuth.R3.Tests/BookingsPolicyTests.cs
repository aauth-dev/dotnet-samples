using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.R3.Model;
using AAuth.Tokens;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.R3.Tests;

public class BookingsPolicyTests
{
    [Theory]
    [InlineData("searchAvailability", "/search_availability", "GET")]
    [InlineData("holdReservation", "/hold_reservation", "GET")]
    [InlineData("searchAvailabilityPost", "/search_availability", "POST")]
    [InlineData("holdReservationPost", "/hold_reservation", "POST")]
    [InlineData("confirmReservation", "/confirm_reservation", "POST")]
    public async Task EveryRoute_EnforcesGrantedPerCallRejectedAndApprovedParameters(string operation, string path, string method)
    {
        using var fixture = new Fixture();
        var document = await fixture.AuthorizeAsync(R3Operations.OpenApi(operation));
        var parameters = Parameters(operation);
        using var granted = await fixture.CallAsync(fixture.AuthToken(document, R3Grant.OpenApi(operation)), path, method, parameters);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
        using var denied = await fixture.CallAsync(fixture.AuthToken(document, R3Grant.OpenApi()), path, method, parameters);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        using var perCall = await fixture.CallAsync(fixture.AuthToken(document, R3Grant.OpenApi(), R3Grant.OpenApi(operation)), path, method, parameters);
        Assert.Equal(HttpStatusCode.Unauthorized, perCall.StatusCode);
        var proposal = Fixture.ResourceClaims(perCall);
        var approved = fixture.AuthToken(proposal, R3Grant.OpenApi(operation));
        using var retry = await fixture.CallAsync(approved, path, method, parameters);
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        // R3 per-call single use: the same grant, freshly signed, gets the retained result, not a second execution.
        var executed = await retry.Content.ReadAsStringAsync();
        await Task.Delay(1100);
        using var repeat = await fixture.CallAsync(approved, path, method, parameters);
        Assert.Equal(HttpStatusCode.OK, repeat.StatusCode);
        Assert.Equal(executed, await repeat.Content.ReadAsStringAsync());
        var changed = parameters.DeepClone().AsObject();
        changed[operation.StartsWith("searchAvailability", StringComparison.Ordinal) ? "venue" : "reservation_id"] = "different";
        using var tampered = await fixture.CallAsync(approved, path, method, changed);
        Assert.Equal(HttpStatusCode.Forbidden, tampered.StatusCode);
        using var crossAccount = await fixture.CallAsync(approved, path, method, parameters, "personal");
        Assert.NotEqual(HttpStatusCode.OK, crossAccount.StatusCode);
    }

    [Theory]
    [InlineData("{\"vocabulary\":\"urn:aauth:vocabulary:mcp\",\"operations\":[{\"tool\":\"searchAvailability\"}]}")]
    [InlineData("{\"vocabulary\":\"urn:aauth:vocabulary:openapi\",\"operations\":[{\"tool\":\"searchAvailability\"}]}")]
    [InlineData("{\"vocabulary\":\"urn:aauth:vocabulary:openapi-gateway\",\"operations\":[{\"operationId\":\"searchAvailability\",\"service\":\"billing\"}]}")]
    [InlineData("{\"vocabulary\":\"urn:aauth:vocabulary:openapi\",\"operations\":[{\"operationId\":\"unknown\"}]}")]
    [InlineData("{\"vocabulary\":\"urn:aauth:vocabulary:openapi\",\"operations\":[]}")]
    [InlineData("{\"vocabulary\":\"urn:aauth:vocabulary:openapi\",\"operations\":[null]}")]
    public async Task Authorize_RejectsNonAuthoritativeShapes(string json)
    {
        using var fixture = new Fixture();
        using var response = await fixture.PostAuthorizationAsync(new JsonObject { ["r3_operations"] = JsonNode.Parse(json), ["account"] = "work" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(response.Headers.Contains("AAuth-Requirement"));
    }

    [Fact]
    public async Task OpenApi_AnnotatesOnlyConfirmationAsPerCall()
    {
        using var fixture = new Fixture();
        using var client = fixture.Anonymous();
        var paths = (await client.GetFromJsonAsync<JsonObject>("/openapi.json"))!["paths"]!.AsObject();
        Assert.Equal(new R3OperationAccess(AAuthConstants.AccessModes.PerCall),
            R3AccessAnnotations.Read(paths["/confirm_reservation"]!["post"]!.AsObject(), Vocabulary.OpenApi));
        Assert.Null(R3AccessAnnotations.Read(paths["/search_availability"]!["get"]!.AsObject(), Vocabulary.OpenApi));
        Assert.Equal(AAuthConstants.AccessModes.AuthToken, R3AccessAnnotations.EffectiveAccessMode(
            R3AccessAnnotations.Read(paths["/hold_reservation"]!["get"]!.AsObject(), Vocabulary.OpenApi), AAuthConstants.AccessModes.AuthToken));
    }

    [Fact]
    public async Task ValidButWrongVocabulary_CannotGainSameIdGrant()
    {
        using var fixture = new Fixture();
        var document = await fixture.AuthorizeAsync(R3Operations.OpenApi("searchAvailability"));
        using var response = await fixture.CallAsync(fixture.AuthToken(document, R3Grant.Mcp("searchAvailability")),
            "/search_availability", "GET", new JsonObject());
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"parameters\":null}")]
    [InlineData("{\"parameters\":[]}")]
    [InlineData("{\"reservation_id\":false}")]
    public async Task Confirmation_RejectsIncompleteOrMalformedParameters(string json)
    {
        using var fixture = new Fixture();
        var document = await fixture.AuthorizeAsync(R3Operations.OpenApi("confirmReservation"));
        using var response = await fixture.CallAsync(fixture.AuthToken(document, R3Grant.OpenApi("confirmReservation")),
            "/confirm_reservation", "POST", JsonNode.Parse(json)!.AsObject());
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task DocumentReaders_DefaultToDesignatedAsAndRejectWrongRole()
    {
        using var fixture = new Fixture();
        var document = await fixture.AuthorizeAsync(R3Operations.OpenApi("searchAvailability"));
        using var access = fixture.SignedServer(fixture.AsKey, R3TestData.AsIssuer, AAuthConstants.DwkFiles.Access, R3TestData.AsKid);
        using var allowed = await access.GetAsync(document.Uri);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        R3Hash.Verify(await allowed.Content.ReadAsByteArrayAsync(), document.S256);
        using var wrongRole = fixture.SignedServer(fixture.AsKey, R3TestData.AsIssuer, AAuthConstants.DwkFiles.Person, R3TestData.AsKid);
        Assert.Equal(HttpStatusCode.Forbidden, (await wrongRole.GetAsync(document.Uri)).StatusCode);
        using var person = fixture.SignedServer(fixture.PsKey, R3TestData.PsIssuer, AAuthConstants.DwkFiles.Person, R3TestData.PsKid);
        Assert.Equal(HttpStatusCode.Forbidden, (await person.GetAsync(document.Uri)).StatusCode);
        using var agent = fixture.SignedAgent(fixture.AgentToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await agent.GetAsync(document.Uri)).StatusCode);
    }

    [Fact]
    public async Task PersonServerEvaluator_ReadsOnlyDocumentsItIsEntitledTo()
    {
        // Both PSes are configured evaluators and both are valid signers.
        using var fixture = new Fixture(R3TestData.PsIssuer, Fixture.ForeignPs);
        var document = await fixture.AuthorizeAsync(R3Operations.OpenApi("searchAvailability"));

        using var entitled = fixture.SignedServer(fixture.PsKey, R3TestData.PsIssuer, AAuthConstants.DwkFiles.Person, R3TestData.PsKid);
        using var own = await entitled.GetAsync(document.Uri);
        Assert.Equal(HttpStatusCode.OK, own.StatusCode);

        // The resource token for this document names the other PS, so the foreign PS cannot read it.
        using var foreign = fixture.SignedServer(fixture.ForeignPsKey, Fixture.ForeignPs, AAuthConstants.DwkFiles.Person, R3TestData.PsKid);
        using var denied = await foreign.GetAsync(document.Uri);
        Assert.Equal(HttpStatusCode.NotFound, denied.StatusCode);

        using var access = fixture.SignedServer(fixture.AsKey, R3TestData.AsIssuer, AAuthConstants.DwkFiles.Access, R3TestData.AsKid);
        Assert.Equal(HttpStatusCode.OK, (await access.GetAsync(document.Uri)).StatusCode);
    }

    [Fact]
    public async Task Authorize_AgentTokenGetsPersonTokenRequirement_PersonTokenGetsResourceTokenNamingIt()
    {
        using var fixture = new Fixture();
        var body = R3Request.CreateBody(R3Operations.OpenApi("searchAvailability"), "work");
        using var agent = fixture.SignedAgent(fixture.AgentToken);
        using var challenged = await agent.PostAsJsonAsync(R3TestData.ResourceIssuer + "/authorize", body);
        Assert.Equal(HttpStatusCode.Unauthorized, challenged.StatusCode);
        Assert.Equal(AAuthRequirementHeader.PersonTokenRequirement,
            AAuthRequirementHeader.Parse(challenged.Headers.GetValues("AAuth-Requirement").Single()).Requirement);

        using var authorized = await fixture.PostAuthorizationAsync(body);
        Assert.Equal(HttpStatusCode.OK, authorized.StatusCode);
        var resourceToken = AAuthRequirementHeader.Parse(authorized.Headers.GetValues("AAuth-Requirement").Single()).ResourceToken!;
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(resourceToken.Split('.')[1]))!.AsObject();
        var person = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(fixture.PersonToken.Split('.')[1]))!.AsObject();
        Assert.Equal(R3TestData.PsIssuer, (string?)payload["ps"]);
        Assert.Equal(R3TestData.PersonSubject, (string?)payload["sub"]);
        Assert.Equal((string?)person["jti"], (string?)payload["presented_jti"]);
        Assert.Equal("work", (string?)payload["account"]);
    }

    private static JsonObject Parameters(string operation) => operation.StartsWith("searchAvailability", StringComparison.Ordinal) ? new JsonObject { ["venue"] = "Dinner" } : new()
    {
        ["reservation_id"] = "reservation-1", ["venue"] = "Dinner", ["date"] = "2026-10-01T19:00",
        ["party_size"] = 2, ["deposit_usd"] = 40, ["cancellation_policy"] = "Non-refundable",
    };

    private sealed class Fixture : IDisposable
    {
        public AAuthKey AsKey { get; } = AAuthKey.Generate();
        public AAuthKey PsKey { get; } = AAuthKey.Generate();
        public AAuthKey ForeignPsKey { get; } = AAuthKey.Generate();
        public const string ForeignPs = "https://foreign-ps.test";
        private AAuthKey ApKey { get; } = AAuthKey.Generate();
        private AAuthKey AgentKey { get; } = AAuthKey.Generate();
        private WebApplicationFactory<Bookings.Entry> App { get; }
        public string AgentToken { get; }
        public string PersonToken { get; }

        public Fixture(params string[] personServerEvaluators)
        {
            AgentToken = R3TestData.AgentToken(ApKey, AgentKey);
            PersonToken = R3TestData.PersonToken(PsKey, AgentKey);
            var discovery = new StaticJsonHandler()
                .AddJson(R3TestData.ApIssuer + "/.well-known/aauth-agent.json", R3TestData.Metadata(R3TestData.ApIssuer, AgentTokenBuilder.AgentDwk))
                .AddJson(R3TestData.ApIssuer + "/.well-known/jwks.json", R3TestData.Jwks(R3TestData.ApKid, ApKey))
                .AddJson(R3TestData.AsIssuer + "/.well-known/aauth-access.json", R3TestData.Metadata(R3TestData.AsIssuer, AuthTokenBuilder.AccessDwk))
                .AddJson(R3TestData.AsIssuer + "/.well-known/aauth-person.json", R3TestData.Metadata(R3TestData.AsIssuer, AuthTokenBuilder.PersonDwk))
                .AddJson(R3TestData.AsIssuer + "/.well-known/jwks.json", R3TestData.Jwks(R3TestData.AsKid, AsKey))
                .AddJson(R3TestData.PsIssuer + "/.well-known/aauth-person.json", R3TestData.Metadata(R3TestData.PsIssuer, AuthTokenBuilder.PersonDwk))
                .AddJson(R3TestData.PsIssuer + "/.well-known/jwks.json", R3TestData.Jwks(R3TestData.PsKid, PsKey))
                .AddJson(ForeignPs + "/.well-known/aauth-person.json", R3TestData.Metadata(ForeignPs, AuthTokenBuilder.PersonDwk))
                .AddJson(ForeignPs + "/.well-known/jwks.json", R3TestData.Jwks(R3TestData.PsKid, ForeignPsKey));
            var evaluators = personServerEvaluators.Length == 0 ? ["https://disabled.test"] : personServerEvaluators;
            App = new WebApplicationFactory<Bookings.Entry>().WithWebHostBuilder(builder =>
            {
                builder.UseSetting("AAuth:Issuer", R3TestData.ResourceIssuer);
                builder.UseSetting("AAuth:AccessServer", R3TestData.AsIssuer);
                builder.UseSetting("AAuth:PersonServer", R3TestData.PsIssuer);
                for (var i = 0; i < evaluators.Length; i++)
                    builder.UseSetting($"Bookings:PersonServerEvaluators:{i}", evaluators[i]);
                builder.ConfigureServices(services =>
                {
                    services.RemoveAll<MetadataClient>();
                    services.RemoveAll<JwksClient>();
                    services.AddSingleton(new MetadataClient(new InProcessHttpClient(discovery)));
                    services.AddSingleton(new JwksClient(new InProcessHttpClient(discovery)));
                });
            });
            App.CreateClient();
        }

        public HttpClient Anonymous() => App.CreateClient();

        public HttpClient SignedAgent(string token) => new AAuthClientBuilder(AgentKey).UseJwt(() => token)
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(App.Server.CreateHandler(), AAuthTransportContract.InProcessOnly).Build();

        public HttpClient SignedServer(AAuthKey key, string issuer, string dwk, string kid) => new AAuthClientBuilder(key)
            .UseJwksUri(issuer, dwk, kid).WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(App.Server.CreateHandler(), AAuthTransportContract.InProcessOnly).Build();

        public async Task<HttpResponseMessage> PostAuthorizationAsync(JsonObject body)
        {
            using var client = SignedAgent(PersonToken);
            return await client.PostAsJsonAsync(R3TestData.ResourceIssuer + "/authorize", body);
        }

        public async Task<R3ClaimReader.ResourceDocumentClaims> AuthorizeAsync(R3Operations operations)
        {
            using var response = await PostAuthorizationAsync(R3Request.CreateBody(operations, "work"));
            Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
            return ResourceClaims(response);
        }

        public static R3ClaimReader.ResourceDocumentClaims ResourceClaims(HttpResponseMessage response)
        {
            var resourceToken = AAuthRequirementHeader.Parse(response.Headers.GetValues("AAuth-Requirement").Single()).ResourceToken!;
            return R3ClaimReader.ReadResourceDocument(JsonNode.Parse(Base64UrlEncoder.DecodeBytes(resourceToken.Split('.')[1]))!.AsObject())!;
        }

        public string AuthToken(R3ClaimReader.ResourceDocumentClaims document, R3Grant granted, R3Grant? perCall = null) => new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy, Issuer = R3TestData.AsIssuer, Audience = R3TestData.ResourceIssuer,
            PersonServer = R3TestData.PsIssuer, AgentConfirmationKey = AgentKey, AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            Key = AsKey, KeyId = R3TestData.AsKid, Dwk = AuthTokenBuilder.AccessDwk, Account = document.Account,
            Subject = "bookings-test-person",
            AdditionalClaims = R3AuthClaims.AuthToken(document.Uri, document.S256, granted, perCall),
        }.Build();

        public async Task<HttpResponseMessage> CallAsync(string token, string path, string method, JsonObject parameters, string account = "work")
        {
            using var client = SignedAgent(token);
            var url = R3TestData.ResourceIssuer + path + "?account=" + account;
            using var request = new HttpRequestMessage(new HttpMethod(method), url) { Content = JsonContent.Create(parameters) };
            return await client.SendAsync(request);
        }

        public void Dispose() => App.Dispose();
    }
}