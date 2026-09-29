using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AAuth.Conformance.Discovery;

/// <summary>
/// Conformance tests for the JTI store (replay detection) and the revocation
/// endpoint. Per §Token Revocation the endpoint MUST verify the caller's HTTP
/// Message Signature, keys the revocation by (verified caller, jti), and answers
/// unsupported_iss to callers it does not accept — deny-by-default.
/// </summary>
public class JtiStoreAndRevocationTests : IAsyncLifetime
{
    private const string ApIssuer = "http://localhost:5556";
    private const string AgentId = "aauth:revoker@ap.example";

    private static readonly DateTimeOffset FixedClock = DateTimeOffset.UtcNow;

    private readonly AAuthKey _apKey = AAuthKey.Generate();
    private readonly AAuthKey _agentKey = AAuthKey.Generate();
    private readonly InMemoryJtiStore _jtiStore = new();

    private IHost? _metadataHost;
    private IHost? _host;

    public async Task InitializeAsync()
    {
        _metadataHost = await StartMetadataServer();
    }

    public async Task DisposeAsync()
    {
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }
        if (_metadataHost is not null) { await _metadataHost.StopAsync(); _metadataHost.Dispose(); }
    }

    [Fact(DisplayName = "§8.5 — JTI store: first recording succeeds")]
    public async Task JtiStore_FirstRecordSucceeds()
    {
        var store = new InMemoryJtiStore();
        var result = await store.TryRecordRequestAsync("request-1", DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.True(result);
    }

    [Fact(DisplayName = "§8.5 — JTI store: duplicate JTI is rejected (replay detection)")]
    public async Task JtiStore_DuplicateRejected()
    {
        var store = new InMemoryJtiStore();
        await store.TryRecordRequestAsync("request-dup", DateTimeOffset.UtcNow.AddMinutes(5));
        var result = await store.TryRecordRequestAsync("request-dup", DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.False(result);
    }

    [Fact(DisplayName = "§8.5 — JTI store: revoked JTI is rejected on record")]
    public async Task JtiStore_RevokedJtiRejected()
    {
        var store = new InMemoryJtiStore();
        var token = new TokenKey(ApIssuer, "jti-revoked");
        var expiration = DateTimeOffset.UtcNow.AddMinutes(5);
        await store.RegisterAsync(token, expiration);
        await store.RevokeAsync(token, expiration);
        var result = await store.RegisterAsync(token, expiration);
        Assert.False(result);
        Assert.True(await store.TryRecordRequestAsync(token.TokenId, expiration));
    }

    [Fact(DisplayName = "§8.5 — JTI store: IsRevokedAsync returns true for revoked tokens")]
    public async Task JtiStore_IsRevokedReturnsTrue()
    {
        var store = new InMemoryJtiStore();
        var token = new TokenKey(ApIssuer, "jti-check");
        await store.RegisterAsync(token, DateTimeOffset.UtcNow.AddMinutes(5));
        await store.RevokeAsync(token, DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.True(await store.IsRevokedAsync(token));
    }

    [Fact(DisplayName = "§8.5 — JTI store: IsRevokedAsync returns false for unknown tokens")]
    public async Task JtiStore_IsRevokedReturnsFalse()
    {
        var store = new InMemoryJtiStore();
        Assert.False(await store.IsRevokedAsync(new TokenKey(ApIssuer, "unknown")));
    }

    [Fact(DisplayName = "§Token Revocation — verified + accepted caller revokes (200, empty body)")]
    public async Task Revocation_RevokesForTrustedSignedCaller()
    {
        await StartRevocationHost(o => o.IsAcceptedIssuer = id => id == ApIssuer);
        await _jtiStore.RegisterAsync(new TokenKey(ApIssuer, "jti-trusted"), FixedClock.AddMinutes(5));

        var response = await SendSignedRevoke("jti-trusted");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
        Assert.Null(response.Content.Headers.ContentType);
        Assert.True(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "jti-trusted")));
    }

    [Fact(DisplayName = "§Token Revocation — a signature not covering content-digest/content-type is 401 invalid_input, even when the host verifier does not require them")]
    public async Task Revocation_RequiresBodyCoverageAtEveryRecipient()
    {
        await StartRevocationHost(o => o.IsAcceptedIssuer = AAuthTrust.Any);
        await _jtiStore.RegisterAsync(new TokenKey(ApIssuer, "jti-uncovered"), FixedClock.AddMinutes(5));

        var response = await PostSignedRevoke(JsonContent.Create(new JsonObject { ["jti"] = "jti-uncovered", ["exp"] = Exp() }),
            coverContent: false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var error = Assert.Single(response.Headers.GetValues("Signature-Error"));
        Assert.Contains("invalid_input", error);
        Assert.Contains("content-digest", error);
        Assert.Contains("content-type", error);
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "jti-uncovered")));
    }

    [Fact(DisplayName = "§Token Revocation — a body that does not match the covered Content-Digest is rejected")]
    public async Task Revocation_RejectsTamperedBody()
    {
        await StartRevocationHost(o => o.IsAcceptedIssuer = AAuthTrust.Any);
        await _jtiStore.RegisterAsync(new TokenKey(ApIssuer, "jti-signed"), FixedClock.AddMinutes(5));
        var content = JsonContent.Create(new JsonObject { ["jti"] = "jti-other", ["exp"] = Exp() });
        var signedBody = System.Text.Encoding.UTF8.GetBytes($"{{\"jti\":\"jti-signed\",\"exp\":{Exp()}}}");
        content.Headers.TryAddWithoutValidation("Content-Digest",
            $"sha-256=:{Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(signedBody))}:");

        var response = await PostSignedRevoke(content);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "jti-other")));
    }

    [Fact(DisplayName = "§Token Revocation — unsigned caller is rejected (401)")]
    public async Task Revocation_RejectsUnsignedCaller()
    {
        await StartRevocationHost(o => o.IsAcceptedIssuer = AAuthTrust.Any);

        using var client = _host!.GetTestServer().CreateClient();
        var response = await client.PostAsJsonAsync("http://localhost/revoke", new JsonObject { ["jti"] = "jti-unsigned", ["exp"] = Exp() });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "jti-unsigned")));
    }

    [Fact(DisplayName = "§Token Revocation — verified but not accepted caller is unsupported_iss (403)")]
    public async Task Revocation_RejectsUntrustedCaller()
    {
        // Caller's verified identity (ApIssuer) is NOT accepted.
        await StartRevocationHost(o => o.IsAcceptedIssuer = id => id == "https://some-other-ps.example");

        var response = await SendSignedRevoke("jti-untrusted");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("unsupported_iss", (string?)body!["error"]);
        Assert.Contains("not accepted", (string?)body["detail"]);
        Assert.False(response.Headers.Contains("Signature-Error"));
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "jti-untrusted")));
    }

    [Fact(DisplayName = "§Token Revocation — deny-by-default when no issuers are accepted (403 unsupported_iss)")]
    public async Task Revocation_DeniesByDefault()
    {
        await StartRevocationHost(configure: null);

        var response = await SendSignedRevoke("jti-default-deny");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("unsupported_iss", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "jti-default-deny")));
    }

    [Fact(DisplayName = "§Token Revocation — AAuthTrust.Any accepts any verified issuer (200)")]
    public async Task Revocation_RevokesWhenAnyIssuerAccepted()
    {
        await StartRevocationHost(o => o.IsAcceptedIssuer = AAuthTrust.Any);
        await _jtiStore.RegisterAsync(new TokenKey(ApIssuer, "jti-predicate"), FixedClock.AddMinutes(5));

        var response = await SendSignedRevoke("jti-predicate");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "jti-predicate")));
    }

    [Fact(DisplayName = "§Token Revocation — missing 'jti' in body is rejected (400)")]
    public async Task Revocation_RejectsMissingJti()
    {
        await StartRevocationHost(o => o.IsAcceptedIssuer = AAuthTrust.Any);

        var response = await SendSignedRevoke(jti: null);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)body!["error"]);
        Assert.Contains("'jti' string", (string?)body["detail"]);
    }

    [Fact(DisplayName = "§Token Revocation — non-JSON Content-Type is rejected (400, not 500)")]
    public async Task Revocation_RejectsNonJsonContentType()
    {
        await StartRevocationHost(o => o.IsAcceptedIssuer = AAuthTrust.Any);

        // Verified + accepted caller, but a non-JSON body: ReadFromJsonAsync
        // throws InvalidOperationException, which must surface as 400, not 500.
        var response = await PostSignedRevoke(
            new StringContent("jti=x", System.Text.Encoding.UTF8, "application/x-www-form-urlencoded"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Revocation_WithoutVerification_ReturnsProblemDetails()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.MapAAuthRevocationEndpoint(_jtiStore);
        await app.StartAsync();
        using var client = app.GetTestClient();

        var response = await client.PostAsJsonAsync("/revoke", new { jti = "unverified", exp = Exp() });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", body!["error"]!.GetValue<string>());
        Assert.Contains("verified AAuth signature", body["detail"]!.GetValue<string>());
        Assert.False(body.ContainsKey("error_description"));
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "unverified")));
    }

    [Fact(DisplayName = "§Token Revocation — missing 'exp' is invalid_request (400)")]
    public async Task Revocation_RejectsMissingExp()
    {
        await StartRevocationHost(options => options.IsAcceptedIssuer = AAuthTrust.Any);

        var response = await PostSignedRevoke(JsonContent.Create(new { jti = "missing-exp" }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "missing-exp")));
    }

    [Fact(DisplayName = "§Token Revocation — an agent signing with its agent token is unsupported_iss (403)")]
    public async Task Revocation_AgentCannotImpersonateItsProvider()
    {
        await StartRevocationHost(options => options.IsAcceptedIssuer = AAuthTrust.Any);

        var response = await PostSignedRevoke(JsonContent.Create(new { jti = "provider-token", exp = Exp() }), asAgent: true);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("unsupported_iss", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "provider-token")));
    }

    [Fact(DisplayName = "§Token Revocation — an unseen token is recorded (200, no not-found) and refused when presented")]
    public async Task Revocation_UnseenRecorded_RepeatedIdempotent()
    {
        await StartRevocationHost(options => options.IsAcceptedIssuer = AAuthTrust.Any);
        var unseen = new TokenKey(ApIssuer, "unseen");

        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("unseen")).StatusCode);
        Assert.True(await _jtiStore.IsRevokedAsync(unseen));
        Assert.False(await _jtiStore.RegisterAsync(unseen, FixedClock.AddMinutes(5)));
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("unseen")).StatusCode);

        var known = new TokenKey(ApIssuer, "known");
        await _jtiStore.RegisterAsync(known, FixedClock.AddMinutes(5));
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("known")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("known")).StatusCode);
        Assert.True(await _jtiStore.IsRevokedAsync(known));
    }

    [Fact(DisplayName = "§Token Revocation — one issuer beyond its entry bound is 429 rate_limited with Retry-After")]
    public async Task Revocation_EntryBound_IsRateLimited()
    {
        await StartRevocationHost(options =>
        {
            options.IsAcceptedIssuer = AAuthTrust.Any;
            options.Limits = new RevocationLimits { MaxEntriesPerIssuer = 2 };
        });
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("entry-a")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("entry-b")).StatusCode);

        var limited = await SendSignedRevoke("entry-c");

        Assert.Equal((HttpStatusCode)429, limited.StatusCode);
        Assert.Equal("rate_limited", (string?)(await limited.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        Assert.True(limited.Headers.RetryAfter?.Delta > TimeSpan.Zero);
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "entry-c")));
        // A repeat of a held entry is not a new entry.
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("entry-a")).StatusCode);
    }

    [Fact(DisplayName = "§Token Revocation — one issuer beyond its rate bound is 429 rate_limited with Retry-After")]
    public async Task Revocation_RateBound_IsRateLimited()
    {
        await StartRevocationHost(options =>
        {
            options.IsAcceptedIssuer = AAuthTrust.Any;
            options.Limits = new RevocationLimits { MaxRequestsPerIssuer = 2, Window = TimeSpan.FromMinutes(1) };
        });
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("rate-a")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("rate-a")).StatusCode);

        var limited = await SendSignedRevoke("rate-b");

        Assert.Equal((HttpStatusCode)429, limited.StatusCode);
        Assert.InRange(limited.Headers.RetryAfter!.Delta!.Value.TotalSeconds, 1, 60);
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "rate-b")));
    }

    [Fact(DisplayName = "§Token Revocation — a slow cascade answers 202; only the revoker's identity can poll, and the poll ends with the synchronous result")]
    public async Task Revocation_SlowCascade_DefersAndOnlyTheRevokerPolls()
    {
        var release = new TaskCompletionSource<RevocationDownstreamError?>(TaskCreationOptions.RunContinuationsAsynchronously);
        await StartDeferringHost(release, TimeSpan.FromMilliseconds(200));

        using var deferred = await SendSignedRevoke("slow");

        Assert.Equal(HttpStatusCode.Accepted, deferred.StatusCode);
        var location = deferred.Headers.Location!.ToString();
        Assert.StartsWith("/revoke/pending/", location);
        Assert.Equal(TimeSpan.Zero, deferred.Headers.RetryAfter?.Delta);
        Assert.True(deferred.Headers.CacheControl?.NoStore);
        Assert.False(deferred.Headers.Contains("AAuth-Requirement"));
        using (var agent = SignedClient(asAgent: true))
            Assert.Equal(HttpStatusCode.NotFound, (await agent.GetAsync(location)).StatusCode);
        using var revoker = SignedClient();
        using (var stillPending = new HttpRequestMessage(HttpMethod.Get, location))
        {
            stillPending.Headers.TryAddWithoutValidation("Prefer", "wait=0");
            Assert.Equal(HttpStatusCode.Accepted, (await revoker.SendAsync(stillPending)).StatusCode);
        }

        release.SetResult(null);
        using var done = await revoker.GetAsync(location);

        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        Assert.Equal(new System.Collections.Generic.Dictionary<string, string?> { ["https://downstream.example"] = null },
            Downstream(await done.Content.ReadFromJsonAsync<JsonObject>()));
    }

    [Fact(DisplayName = "§Token Revocation — a recipient with nothing downstream never answers 202")]
    public async Task Revocation_NothingDownstream_NeverDefers()
    {
        await StartRevocationHost(options => { options.IsAcceptedIssuer = AAuthTrust.Any; options.DeferAfter = TimeSpan.Zero; });
        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("lonely")).StatusCode);
    }

    [Fact(DisplayName = "§Token Revocation — RevocationClient polls a deferred recipient to its terminal result")]
    public async Task RevocationClient_FollowsDeferredRecipient()
    {
        var release = new TaskCompletionSource<RevocationDownstreamError?>(TaskCreationOptions.RunContinuationsAsynchronously);
        await StartDeferringHost(release, TimeSpan.FromMilliseconds(100));
        using var signed = new AAuthClientBuilder(_apKey).UseJwksUri(ApIssuer, "aauth-agent.json", "ap-key-1")
            .WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(_host!.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly).Build();
        _ = Task.Delay(TimeSpan.FromMilliseconds(400)).ContinueWith(_ => release.SetResult(RevocationDownstreamError.RevocationUnsupported));

        var result = await new RevocationClient(signed).RevokeAsync(new Uri("http://localhost/revoke"), "slow", DateTimeOffset.UtcNow.AddMinutes(5));

        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.Null(result.Failure);
        Assert.Equal(RevocationDownstreamError.RevocationUnsupported, Assert.Single(result.Downstream).Error);
    }

    private async Task StartDeferringHost(TaskCompletionSource<RevocationDownstreamError?> release, TimeSpan deferAfter)
    {
        await StartRevocationHost(options =>
        {
            options.IsAcceptedIssuer = AAuthTrust.Any;
            options.DeferAfter = deferAfter;
            options.RevokeGrantAsync = (_, _) => release.Task;
        });
        var source = new TokenKey(ApIssuer, "slow");
        Assert.True(await _jtiStore.RegisterAsync(source, DateTimeOffset.UtcNow.AddMinutes(10)));
        Assert.True(await _jtiStore.RegisterGrantAsync([source],
            new TokenGrant(new TokenKey("https://self.example", "child"), "https://downstream.example", DateTimeOffset.UtcNow.AddMinutes(9))));
    }

    [Fact(DisplayName = "§Token Revocation — a body 'iss' is ignored: the caller revokes only its own token")]
    public async Task Revocation_IssuerCannotRevokeOtherIssuerWithSameId()
    {
        await StartRevocationHost(options => options.IsAcceptedIssuer = AAuthTrust.Any);
        var own = new TokenKey(ApIssuer, "shared");
        var other = new TokenKey("https://other.example", "shared");
        var foreign = new TokenKey("https://other.example", "foreign-only");
        await _jtiStore.RegisterAsync(own, FixedClock.AddMinutes(5));
        await _jtiStore.RegisterAsync(other, FixedClock.AddMinutes(5));
        await _jtiStore.RegisterAsync(foreign, FixedClock.AddMinutes(5));

        var response = await PostSignedRevoke(JsonContent.Create(new { iss = other.Issuer, jti = other.TokenId, exp = Exp() }));
        var foreignResponse = await PostSignedRevoke(JsonContent.Create(new { iss = foreign.Issuer, jti = foreign.TokenId, exp = Exp() }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, foreignResponse.StatusCode);
        Assert.True(await _jtiStore.IsRevokedAsync(own));
        Assert.False(await _jtiStore.IsRevokedAsync(other));
        Assert.False(await _jtiStore.IsRevokedAsync(foreign));
        Assert.True(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "foreign-only")));
    }

    [Theory(DisplayName = "§Token Revocation — malformed JSON, jti or exp is invalid_request (400)")]
    [InlineData("{\"jti\":1,\"exp\":EXP}")]
    [InlineData("{\"jti\":[],\"exp\":EXP}")]
    [InlineData("{\"jti\":\"\",\"exp\":EXP}")]
    [InlineData("{\"jti\":\" \",\"exp\":EXP}")]
    [InlineData("{\"exp\":EXP}")]
    [InlineData("{\"jti\":\"id\"}")]
    [InlineData("{\"jti\":\"id\",\"exp\":\"EXP\"}")]
    [InlineData("{\"jti\":\"id\",\"exp\":EXP.5}")]
    [InlineData("{\"jti\":\"id\",\"exp\":-1}")]
    [InlineData("{\"jti\":\"id\",\"exp\":null}")]
    [InlineData("[\"id\",EXP]")]
    [InlineData("{\"jti\":\"id\",")]
    public async Task Revocation_RejectsMalformedRequest(string json)
    {
        await StartRevocationHost(options => options.IsAcceptedIssuer = AAuthTrust.Any);
        var response = await PostSignedRevoke(new StringContent(json.Replace("EXP", Exp().ToString()),
            System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "id")));
    }

    [Fact(DisplayName = "§Token Revocation — exp beyond the longest accepted lifetime is invalid_request; an expired exp is 200")]
    public async Task Revocation_BoundsExpToMaxTokenLifetime()
    {
        await StartRevocationHost(options =>
        {
            options.IsAcceptedIssuer = AAuthTrust.Any;
            options.MaxTokenLifetime = TimeSpan.FromHours(1);
        });

        var tooLate = await PostSignedRevoke(JsonContent.Create(new { jti = "far", exp = DateTimeOffset.UtcNow.AddHours(2).ToUnixTimeSeconds() }));
        var expired = await PostSignedRevoke(JsonContent.Create(new { jti = "past", exp = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds() }));

        Assert.Equal(HttpStatusCode.BadRequest, tooLate.StatusCode);
        Assert.False(await _jtiStore.IsRevokedAsync(new TokenKey(ApIssuer, "far")));
        Assert.Equal(HttpStatusCode.OK, expired.StatusCode);
    }

    [Fact(DisplayName = "§Token Revocation — a full inventory answers server_error (500) without evicting revocations")]
    public async Task Revocation_CapacityExhausted_IsServerError()
    {
        var store = new InMemoryJtiStore(capacity: 1);
        await StartRevocationHost(options => options.IsAcceptedIssuer = AAuthTrust.Any, store);

        Assert.Equal(HttpStatusCode.OK, (await SendSignedRevoke("first")).StatusCode);
        var full = await SendSignedRevoke("second");

        Assert.Equal(HttpStatusCode.InternalServerError, full.StatusCode);
        Assert.Equal("server_error", (string?)(await full.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
        Assert.True(await store.IsRevokedAsync(new TokenKey(ApIssuer, "first")));
    }

    [Fact(DisplayName = "§Token Revocation — cascade reports each downstream recipient; failures are 200 with downstream errors")]
    public async Task Revocation_CascadesExactRecords_AndReportsDownstream()
    {
        var first = new TokenKey(ApIssuer, "cascade");
        var other = new TokenKey("https://other.example", "cascade");
        var expiry = FixedClock.AddMinutes(5);
        await _jtiStore.RegisterAsync(first, expiry);
        await _jtiStore.RegisterAsync(other, expiry);
        var grant = new TokenGrant(new TokenKey("https://ps.example", "provided"), "https://r.example", expiry);
        var second = new TokenGrant(new TokenKey("https://ps.example", "second"), "https://r2.example", expiry);
        var foreign = new TokenGrant(new TokenKey("https://as.example", "provided"), "https://other-r.example", expiry);
        await _jtiStore.RegisterGrantAsync([first], grant);
        await _jtiStore.RegisterGrantAsync([first], second);
        await _jtiStore.RegisterGrantAsync([other], foreign);

        // No delivery hook: every downstream recipient is revocation_unsupported.
        await StartRevocationHost(options => options.IsAcceptedIssuer = AAuthTrust.Any);
        var unsupported = await SendSignedRevoke(first.TokenId);
        Assert.Equal(HttpStatusCode.OK, unsupported.StatusCode);
        Assert.Equal("application/json", unsupported.Content.Headers.ContentType?.MediaType);
        var report = Downstream(await unsupported.Content.ReadFromJsonAsync<JsonObject>());
        Assert.Equal("revocation_unsupported", report["https://r.example"]);
        Assert.Equal("revocation_unsupported", report["https://r2.example"]);
        Assert.True(await _jtiStore.IsRevokedAsync(first));
        Assert.True(await _jtiStore.IsRevokedAsync(grant.Token));
        Assert.False(await _jtiStore.IsRevokedAsync(other));
        Assert.False(await _jtiStore.IsRevokedAsync(foreign.Token));

        // Repeating re-attempts delivery: one recipient records, one is unavailable.
        var delivered = new System.Collections.Generic.List<TokenGrant>();
        await StartRevocationHost(options =>
        {
            options.IsAcceptedIssuer = AAuthTrust.Any;
            options.RevokeGrantAsync = (record, _) =>
            {
                delivered.Add(record);
                return record == grant
                    ? Task.FromResult<AAuth.Errors.RevocationDownstreamError?>(null)
                    : throw new HttpRequestException("resource unreachable");
            };
        });
        var partial = await SendSignedRevoke(first.TokenId);
        Assert.Equal(HttpStatusCode.OK, partial.StatusCode);
        var body = (await partial.Content.ReadFromJsonAsync<JsonObject>())!;
        report = Downstream(body);
        Assert.Null(report["https://r.example"]);
        Assert.False(((JsonObject)body["downstream"]!.AsArray().Single(entry => (string?)entry!["recipient"] == "https://r.example")!).ContainsKey("error"));
        Assert.Equal("revocation_unavailable", report["https://r2.example"]);
        Assert.Equal(new[] { grant, second }, delivered.OrderBy(record => record.Token.TokenId == "second"));

        // A PS reports nothing to an agent provider.
        await StartRevocationHost(options =>
        {
            options.IsAcceptedIssuer = AAuthTrust.Any;
            options.ReportDownstream = false;
        });
        var silent = await SendSignedRevoke(first.TokenId);
        Assert.Equal(HttpStatusCode.OK, silent.StatusCode);
        Assert.Empty(await silent.Content.ReadAsByteArrayAsync());
    }

    [Theory(DisplayName = "§Token Revocation — RevocationClient reads the 200 body, unsupported_iss and failures")]
    [InlineData(200, "application/json", "", null, 0)]
    [InlineData(200, "application/json", "{}", null, 0)]
    [InlineData(200, "application/json", "{\"downstream\":[{\"recipient\":\"https://r.example\"},{\"recipient\":\"https://r2.example\",\"error\":\"revocation_unavailable\"}]}", null, 2)]
    [InlineData(200, "application/json", "{\"downstream\":[{\"error\":\"revocation_unavailable\"}]}", "RevocationUnavailable", 0)]
    [InlineData(200, "application/json", "{\"downstream\":[{\"recipient\":\"https://r.example\",\"error\":\"revocation_incomplete\"}]}", "RevocationUnavailable", 0)]
    [InlineData(200, "application/json", "[]", "RevocationUnavailable", 0)]
    [InlineData(200, "text/plain", "ok", "RevocationUnavailable", 0)]
    [InlineData(403, "application/problem+json", "{\"error\":\"unsupported_iss\"}", "RevocationUnsupported", 0)]
    [InlineData(400, "application/problem+json", "{\"error\":\"invalid_request\"}", "RevocationUnavailable", 0)]
    [InlineData(500, "application/problem+json", "{\"error\":\"server_error\"}", "RevocationUnavailable", 0)]
    [InlineData(503, "text/html", "<html/>", "RevocationUnavailable", 0)]
    public void RevocationClient_ParsesResponses(int status, string mediaType, string body, string? failure, int entries)
    {
        var result = RevocationClient.Parse((HttpStatusCode)status, mediaType, body);
        Assert.Equal(failure, result.Failure?.ToString());
        Assert.Equal(entries, result.Downstream.Count);
        if (entries == 2)
        {
            Assert.Null(result.Downstream[0].Error);
            Assert.Equal(AAuth.Errors.RevocationDownstreamError.RevocationUnavailable, result.Downstream[1].Error);
        }
    }

    [Fact(DisplayName = "§Token Revocation — RevocationClient sends {jti, exp} covering content-type and content-digest")]
    public async Task RevocationClient_SendsJtiAndExpOnly()
    {
        JsonObject? sent = null;
        string? signatureInput = null;
        var signing = new AAuthSigningHandler(_apKey, new JwksUriSignatureKeyProvider(ApIssuer, "aauth-agent.json", "ap-key-1"))
        {
            InnerHandler = new CaptureHandler(async request =>
            {
                sent = JsonNode.Parse(await request.Content!.ReadAsStringAsync())!.AsObject();
                signatureInput = request.Headers.GetValues("Signature-Input").Single();
            }),
        };
        using var http = AAuthHttpTransport.AttachPolicy(new HttpClient(signing), TestEgress.Policy, AAuthTransportContract.InProcessOnly);
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(1788727813);

        var result = await new RevocationClient(http).RevokeAsync(new Uri("https://resource.example/revoke"), "token-id", expiresAt);

        Assert.Null(result.Failure);
        Assert.NotNull(sent);
        Assert.Equal(new[] { "exp", "jti" }, sent.Select(member => member.Key).Order());
        Assert.Equal("token-id", (string?)sent["jti"]);
        Assert.Equal(1788727813, (long)sent["exp"]!);
        Assert.Contains("\"content-type\"", signatureInput);
        Assert.Contains("\"content-digest\"", signatureInput);
    }

    private static System.Collections.Generic.Dictionary<string, string?> Downstream(JsonObject? body)
        => body!["downstream"]!.AsArray().ToDictionary(entry => (string)entry!["recipient"]!, entry => (string?)entry!["error"]);

    private static long Exp() => DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();

    private sealed class CaptureHandler(Func<HttpRequestMessage, Task> capture) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            await capture(request);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────

    private async Task StartRevocationHost(Action<AAuthRevocationOptions>? configure, IJtiStore? store = null)
    {
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { TimeProvider = new FakeTimeProvider(FixedClock) });
        builder.Services.AddSingleton<HttpClient>(_metadataHost!.GetTestClient());
        builder.Services.AddSingleton(sp => new MetadataClient(sp.GetRequiredService<HttpClient>(),
            policy: TestEgress.Policy, transportContract: AAuthTransportContract.InProcessOnly));
        builder.Services.AddSingleton(sp => new JwksClient(sp.GetRequiredService<HttpClient>(),
            policy: TestEgress.Policy, transportContract: AAuthTransportContract.InProcessOnly));
        var app = builder.Build();

        app.UseAAuthVerification(new AAuthVerificationOptions
        {
            EgressPolicy = TestEgress.Policy,
            AcceptedSchemes = ["jwt", "jwks_uri"],
        });
        app.MapAAuthRevocationEndpoint(store ?? _jtiStore, configure);
        await app.StartAsync();
        _host = app;
    }

    private Task<HttpResponseMessage> SendSignedRevoke(string? jti)
    {
        var body = new JsonObject { ["exp"] = Exp() };
        if (jti is not null) body["jti"] = jti;
        return PostSignedRevoke(JsonContent.Create(body));
    }

    private async Task<HttpResponseMessage> PostSignedRevoke(HttpContent content, bool asAgent = false, bool coverContent = true)
    {
        using var client = SignedClient(asAgent, coverContent);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/revoke") { Content = content };
        return await client.SendAsync(request);
    }

    private HttpClient SignedClient(bool asAgent = false, bool coverContent = true)
    {
        var agentToken = new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = ApIssuer,
            Subject = AgentId,
            Key = _apKey,
            KeyId = "ap-key-1",
            ConfirmationKey = _agentKey,
            IssuedAt = FixedClock,
        }.Build();

        ISignatureKeyProvider provider = asAgent
            ? new JwtSignatureKeyProvider(() => agentToken)
            : new JwksUriSignatureKeyProvider(ApIssuer, "aauth-agent.json", "ap-key-1");
        var signing = new AAuthSigningHandler(asAgent ? _agentKey : _apKey, provider, new FakeTimeProvider(FixedClock));
        if (!coverContent)
            return new HttpClient(new AAuth.Testing.UncoveredBodySigner(signing) { InnerHandler = _host!.GetTestServer().CreateHandler() })
                { BaseAddress = new Uri("http://localhost") };
        signing.InnerHandler = _host!.GetTestServer().CreateHandler();
        return new HttpClient(signing) { BaseAddress = new Uri("http://localhost") };
    }

    private async Task<IHost> StartMetadataServer()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();

        app.MapGet("/.well-known/aauth-agent.json", () => Results.Json(new
        {
            issuer = ApIssuer,
            jwks_uri = $"{ApIssuer}/.well-known/ap-jwks.json",
        }));

        app.MapGet("/.well-known/ap-jwks.json", () =>
        {
            var jwk = _apKey.ToPublicJwk();
            jwk["kid"] = "ap-key-1";
            jwk["use"] = "sig";
            return Results.Json(new JsonObject { ["keys"] = new JsonArray { jwk } });
        });

        await app.StartAsync();
        return app;
    }
}
