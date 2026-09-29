using System;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Conformance.AuthTokens;

/// <summary>
/// Tests for AuthTokenResponseValidator per §Auth Token Delivery: the PS checks
/// an AS-issued auth token names the resource, this PS (<c>ps</c>), the resource
/// token's <c>sub</c>, the agent's key, and does not outlive the presented token.
/// </summary>
public class AuthTokenDeliveryTests
{
    private const string AsIssuer = "http://localhost:5300";
    private const string PsIssuer = "http://localhost:5100";
    private const string ResourceAudience = "http://localhost:5200";
    private const string Subject = "user-123";
    private const string AsKid = "as-1";

    private readonly AAuthKey _asKey = AAuthKey.Generate();
    private readonly AAuthKey _agentKey = AAuthKey.Generate();
    private readonly DateTimeOffset _presentedExpiresAt = DateTimeOffset.UtcNow.AddHours(2);

    [Theory]
    [InlineData("personal", "personal", true)]
    [InlineData("personal", "work", false)]
    [InlineData(null, "personal", false)]
    [InlineData("personal", null, false)]
    [InlineData("Personal", "personal", false)]
    public async Task AccountDelivery_MatchesExactResourceExpectation(string? actual, string? expected, bool accepted)
    {
        var result = await Validate(await BuildAuthTokenAsync(account: actual), expectedAccount: expected);
        Assert.Equal(accepted, result.IsValid);
        if (!accepted) Assert.Contains("account_mismatch", result.Error);
    }

    private async Task<string> BuildAuthTokenAsync(
        string? issuer = null,
        string? audience = null,
        string? subject = null,
        string? personServer = null,
        IAAuthKey? agentConfirmationKey = null,
        string? scope = null,
        string? account = null)
    {
        return await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Issuer = issuer ?? AsIssuer,
            Audience = audience ?? ResourceAudience,
            PersonServer = personServer ?? PsIssuer,
            AgentConfirmationKey = agentConfirmationKey ?? _agentKey,
            Key = _asKey,
            KeyId = AsKid,
            Scope = scope ?? "data.read",
            Subject = subject ?? Subject,
            Account = account,
            Dwk = AuthTokenBuilder.AccessDwk,
        }.BuildAsync();
    }

    private AuthTokenResponseValidator CreateValidator()
    {
        var mockHandler = new MockAsHandler(_asKey, AsKid, AsIssuer);
        var httpClient = new InProcessHttpClient(mockHandler);
        var metadata = new MetadataClient(httpClient);
        var jwks = new JwksClient(httpClient);
        return new AuthTokenResponseValidator(metadata, jwks);
    }

    private Task<AuthTokenDeliveryResult> Validate(string token, string issuer = AsIssuer, string audience = ResourceAudience,
        string subject = Subject, IAAuthKey? agentKey = null, DateTimeOffset? presentedExpiresAt = null,
        string? requestedScope = null, string? expectedAccount = null)
        => CreateValidator().ValidateAsync(token, issuer, audience, subject, PsIssuer, agentKey ?? _agentKey,
            presentedExpiresAt ?? _presentedExpiresAt, requestedScope, expectedAccount: expectedAccount);

    [Fact(DisplayName = "§Auth Token Delivery — valid token accepted")]
    public async Task ValidToken_Accepted()
    {
        var result = await Validate(await BuildAuthTokenAsync());

        Assert.True(result.IsValid, result.Error);
        Assert.Null(result.Error);
        Assert.NotNull(result.Verified);
    }

    [Fact(DisplayName = "§Auth Token Delivery — issuer mismatch rejected")]
    public async Task IssuerMismatch_Rejected()
    {
        var result = await Validate(await BuildAuthTokenAsync(), issuer: "http://localhost:9999");

        Assert.False(result.IsValid);
        Assert.Contains("issuer_mismatch", result.Error);
    }

    [Fact(DisplayName = "§Auth Token Delivery — audience mismatch rejected")]
    public async Task AudienceMismatch_Rejected()
    {
        var result = await Validate(await BuildAuthTokenAsync(), audience: "http://localhost:9999");

        Assert.False(result.IsValid);
        Assert.Contains("aud", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Theory(DisplayName = "§Auth Token Delivery — a token naming another person or PS is rejected")]
    [InlineData("sub")]
    [InlineData("ps")]
    public async Task PersonMismatch_Rejected(string field)
    {
        var token = field == "sub"
            ? await BuildAuthTokenAsync(subject: "someone-else")
            : await BuildAuthTokenAsync(personServer: "http://localhost:9999");

        var result = await Validate(token);

        Assert.False(result.IsValid);
        Assert.Contains("person_mismatch", result.Error);
    }

    [Fact(DisplayName = "§Auth Token Delivery — cnf.jwk mismatch rejected")]
    public async Task ConfirmationKeyMismatch_Rejected()
    {
        var result = await Validate(await BuildAuthTokenAsync(), agentKey: AAuthKey.Generate());

        Assert.False(result.IsValid);
        Assert.Contains("cnf.jwk", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Auth Token Delivery — a token outliving the presented token is rejected")]
    public async Task OutlivesPresentedToken_Rejected()
    {
        var result = await Validate(await BuildAuthTokenAsync(), presentedExpiresAt: DateTimeOffset.UtcNow.AddMinutes(5));

        Assert.False(result.IsValid);
        Assert.Contains("lifetime_mismatch", result.Error);
    }

    [Fact(DisplayName = "§Auth Token Delivery — scope escalation rejected")]
    public async Task ScopeEscalation_Rejected()
    {
        var result = await Validate(await BuildAuthTokenAsync(scope: "data.read data.write"), requestedScope: "data.read");

        Assert.False(result.IsValid);
        Assert.Contains("scope", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "§Auth Token Delivery — scope narrowing accepted")]
    public async Task ScopeNarrowing_Accepted()
    {
        var result = await Validate(await BuildAuthTokenAsync(scope: "data.read"), requestedScope: "data.read data.write");

        Assert.True(result.IsValid, result.Error);
    }

    /// <summary>
    /// Mock HTTP handler that serves AS metadata + JWKS.
    /// </summary>
    private sealed class MockAsHandler(AAuthKey key, string kid, string issuer) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri?.AbsolutePath ?? "";

            if (path.EndsWith("aauth-access.json"))
            {
                return JsonResponse(new JsonObject
                {
                    ["issuer"] = issuer,
                    ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
                    ["auth_token_endpoint"] = $"{issuer}/token",
                });
            }

            if (path.EndsWith("jwks.json"))
            {
                var jwk = key.ToPublicJwk();
                jwk["kid"] = kid;
                jwk["use"] = "sig";
                jwk["alg"] = AAuthKey.Ed25519Algorithm;
                return JsonResponse(new JsonObject { ["keys"] = new JsonArray { jwk } });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static Task<HttpResponseMessage> JsonResponse(JsonObject json) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json.ToJsonString(), System.Text.Encoding.UTF8, "application/json"),
            });
    }
}
