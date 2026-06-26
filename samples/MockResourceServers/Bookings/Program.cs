using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.R3;
using AAuth.R3.Model;
using AAuth.Tokens;

var builder = WebApplication.CreateBuilder(args);

var resourceKey = AAuthKey.Generate();
const string ResourceKid = "bookings-1";

const string SearchTripOptions = "search_trip_options";
const string HoldItinerary = "hold_itinerary";
const string BookTrip = "book_trip";
string[] SupportedTools = [SearchTripOptions, HoldItinerary, BookTrip];

var resourceUrl = (builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5004").TrimEnd('/');
var accessServerUrl = (builder.Configuration["AAuth:AccessServer"] ?? "http://localhost:5501").TrimEnd('/');
var personServerUrl = (builder.Configuration["AAuth:PersonServer"] ?? "http://localhost:5100").TrimEnd('/');
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;
var missionAware = builder.Configuration.GetValue("Bookings:MissionAware", false);
var trustedFetcherAuthorities = builder.Configuration
    .GetSection("Bookings:TrustedR3Fetchers")
    .Get<string[]>() ?? [accessServerUrl, personServerUrl];
var trustedFetcherSet = trustedFetcherAuthorities
    .Select(ToOrigin)
    .Where(static origin => origin is not null)
    .Select(static origin => origin!)
    .ToHashSet(StringComparer.OrdinalIgnoreCase);

builder.Services.AddSingleton(resourceKey);
builder.Services.AddSingleton(new AAuthVerifier { MaxAge = TimeSpan.FromSeconds(signatureWindowSeconds) });
builder.Services.AddSingleton(new TokenVerifier());
builder.Services.AddSingleton<MetadataClient>(sp =>
    new MetadataClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-metadata")));
builder.Services.AddSingleton<JwksClient>(sp =>
    new JwksClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-jwks")));
builder.Services.AddSingleton<R3ProposalStore>();
builder.Services.AddHttpClient("aauth-metadata");
builder.Services.AddHttpClient("aauth-jwks");

var app = builder.Build();

// Bookings is deliberately not mission-aware. Do not read or enforce AAuth-Mission here.
app.MapGet("/.well-known/aauth-resource.json", () => Results.Json(new JsonObject
{
    ["issuer"] = resourceUrl,
    ["jwks_uri"] = $"{resourceUrl}/.well-known/jwks.json",
    ["access_mode"] = AAuthConstants.AccessModes.AuthToken,
    ["client_name"] = "Aria Bookings",
    ["description"] = "R3 rich trip booking demo resource.",
    ["authorization_endpoint"] = $"{resourceUrl}/authorize",
    ["mission_aware"] = missionAware,
    ["r3_vocabularies"] = new JsonObject
    {
        [Vocabulary.Mcp] = $"{resourceUrl}/mcp",
    },
}, contentType: "application/json"));

app.MapGet("/.well-known/jwks.json", () => Results.Json(BuildJwks(ResourceKid, resourceKey), contentType: "application/json"));

app.MapGet("/", () => Results.Ok(new
{
    resource = "Aria Bookings",
    accessMode = "four-party-r3",
    missionAware,
    authorization_endpoint = $"{resourceUrl}/authorize",
    r3_vocabularies = new Dictionary<string, string> { [Vocabulary.Mcp] = $"{resourceUrl}/mcp" },
    flows = new[]
    {
        new { path = "/search_trip_options", tool = SearchTripOptions, grant = "r3_granted" },
        new { path = "/hold_itinerary", tool = HoldItinerary, grant = "r3_granted" },
        new { path = "/book_trip", tool = BookTrip, grant = "r3_conditional + per-call proposal" },
    },
}));

app.MapGet("/mcp", () => Results.Json(new
{
    vocabulary = Vocabulary.Mcp,
    tools = SupportedTools.Select(tool => new { name = tool }).ToArray(),
}));

app.MapPost("/authorize", async (HttpContext ctx, R3ProposalStore documents) =>
{
    SignedAgent agent;
    try
    {
        agent = await VerifyAgentAsync(ctx);
    }
    catch (Exception ex) when (ex is R3FetchVerificationException or AAuthVerificationException or TokenVerificationException or InvalidOperationException)
    {
        return Results.Json(new { error = "invalid_agent_signature", detail = ex.Message }, statusCode: StatusCodes.Status401Unauthorized);
    }

    JsonObject? body;
    try
    {
        body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    }
    catch (JsonException)
    {
        return Results.Json(new { error = "invalid_request", detail = "body is not valid JSON" }, statusCode: StatusCodes.Status400BadRequest);
    }

    R3Operations operations;
    try
    {
        operations = body?["r3_operations"]?.Deserialize<R3Operations>(R3Json.Options)
            ?? throw new InvalidOperationException("missing r3_operations");
        ValidateRequestedOperations(operations);
    }
    catch (Exception ex) when (ex is JsonException or InvalidOperationException)
    {
        return Results.Json(new { error = "invalid_r3_operations", detail = ex.Message }, statusCode: StatusCodes.Status400BadRequest);
    }

    var stored = StoreR3Document(documents, operations.Operations.Select(op => op.Tool));
    var resourceToken = BuildResourceToken(agent.AgentId, agent.ConfirmationKey.ComputeJwkThumbprint(), stored.Uri, stored.S256);
    ctx.Response.Headers[AAuthConstants.Headers.AAuthRequirement] = AAuth.Headers.AAuthRequirementHeader.FormatAuthToken(resourceToken);
    return Results.Ok(new
    {
        resource_token = resourceToken,
        token_type = "aa-resource+jwt",
        aud = accessServerUrl,
        r3_uri = stored.Uri,
        r3_s256 = stored.S256,
        expires_in = 300,
    });
});

app.MapR3Document("/r3/proposals/{hash}", ctx =>
{
    var hash = (string?)ctx.Request.RouteValues["hash"];
    return hash is not null && ctx.RequestServices.GetRequiredService<R3ProposalStore>().TryGet(hash, out var bytes) ? bytes : null;
}, IsTrustedR3Fetcher);

app.MapR3Document("/r3/{hash}", ctx =>
{
    var hash = (string?)ctx.Request.RouteValues["hash"];
    return hash is not null && ctx.RequestServices.GetRequiredService<R3ProposalStore>().TryGet(hash, out var bytes) ? bytes : null;
}, IsTrustedR3Fetcher);

app.MapMethods("/search_trip_options", ["GET", "POST"], async (HttpContext ctx) =>
{
    var auth = await VerifyAuthOrChallengeAsync(ctx, [SearchTripOptions, HoldItinerary, BookTrip]);
    if (auth.Result is not null) { return auth.Result; }
    var decision = R3ClaimReader.ReadAuthToken(auth.Verified!.Payload);
    if (!decision.Granted.ContainsTool(SearchTripOptions))
    {
        return Results.Json(new { error = "r3_denied", detail = "search_trip_options was not granted" }, statusCode: StatusCodes.Status403Forbidden);
    }
    return Results.Ok(new
    {
        accessMode = "four-party-r3",
        tool = SearchTripOptions,
        source = "r3_granted",
        options = new[]
        {
            new { itinerary_id = "itinerary-paris-001", destination = "Paris", depart = "2026-07-12", @return = "2026-07-19", total_usd = 1284, cancellation_policy = "Refundable for 24 hours, then airline fare rules apply." },
            new { itinerary_id = "itinerary-lisbon-002", destination = "Lisbon", depart = "2026-07-13", @return = "2026-07-20", total_usd = 1138, cancellation_policy = "Hotel refundable until 72 hours before arrival." },
        },
        r3_uri = decision.Uri,
        r3_s256 = decision.S256,
    });
});

app.MapMethods("/hold_itinerary", ["GET", "POST"], async (HttpContext ctx) =>
{
    var auth = await VerifyAuthOrChallengeAsync(ctx, [SearchTripOptions, HoldItinerary, BookTrip]);
    if (auth.Result is not null) { return auth.Result; }
    var claims = R3ClaimReader.ReadAuthToken(auth.Verified!.Payload);
    if (!claims.Granted.ContainsTool(HoldItinerary))
    {
        return Results.Json(new { error = "r3_denied", detail = "hold_itinerary was not granted" }, statusCode: StatusCodes.Status403Forbidden);
    }
    return Results.Ok(new
    {
        accessMode = "four-party-r3",
        tool = HoldItinerary,
        source = "r3_granted",
        hold_id = "hold-aria-001",
        itinerary_id = "itinerary-paris-001",
        expires_at = DateTimeOffset.UtcNow.AddMinutes(20),
        r3_uri = claims.Uri,
        r3_s256 = claims.S256,
    });
});

app.MapPost("/book_trip", async (HttpContext ctx, R3ProposalStore proposals) =>
{
    var auth = await VerifyAuthOrChallengeAsync(ctx, [SearchTripOptions, HoldItinerary, BookTrip]);
    if (auth.Result is not null) { return auth.Result; }

    var claims = R3ClaimReader.ReadAuthToken(auth.Verified!.Payload);
    var parameters = await ReadBookingParametersAsync(ctx);

    if (claims.Granted.ContainsTool(BookTrip))
    {
        var retry = VerifyApprovedProposalRetry(claims, parameters, proposals);
        if (retry is not null) { return retry; }
        return Results.Ok(new
        {
            accessMode = "four-party-r3",
            tool = BookTrip,
            source = "per-call-r3_granted",
            status = "booked",
            confirmation = "BK-ARIA-314159",
            itinerary_id = ParameterString(parameters, "itinerary_id"),
            destination = ParameterString(parameters, "destination"),
            total_usd = ParameterNumber(parameters, "total_usd"),
            r3_uri = claims.Uri,
            r3_s256 = claims.S256,
        });
    }

    if (!claims.Conditional?.ContainsTool(BookTrip) ?? true)
    {
        return Results.Json(new { error = "r3_denied", detail = "book_trip was not granted or conditional" }, statusCode: StatusCodes.Status403Forbidden);
    }

    var proposal = new R3ProposalDocument
    {
        Version = "v02",
        Vocabulary = Vocabulary.Mcp,
        Operations = [new McpOperation { Tool = BookTrip }],
        Parameters = parameters,
        Display = BookingDisplay(parameters),
    };
    var stored = proposals.Add(proposal, new Uri(resourceUrl), "/r3/proposals");
    var proposalResourceToken = BuildProposalResourceToken(auth.Verified!, stored.Uri, stored.S256);
    ctx.Response.Headers[AAuthConstants.Headers.AAuthRequirement] = AAuth.Headers.AAuthRequirementHeader.FormatAuthToken(proposalResourceToken);
    return Results.Json(new
    {
        error = "r3_approval_required",
        tool = BookTrip,
        r3_uri = stored.Uri,
        r3_s256 = stored.S256,
    }, statusCode: StatusCodes.Status401Unauthorized);
});

app.Run();

StoredR3Proposal StoreR3Document(R3ProposalStore store, IEnumerable<string> requestedTools)
{
    var requested = requestedTools.ToHashSet(StringComparer.Ordinal);
    var ordered = SupportedTools.Where(requested.Contains).Select(tool => new McpOperation { Tool = tool }).ToArray();
    var doc = new R3Document
    {
        Version = "v02",
        Vocabulary = Vocabulary.Mcp,
        Operations = ordered,
        Display = new R3Display
        {
            Summary = "Search and temporarily hold trip options. Booking a trip may charge your payment method.",
            Implications = "Search and hold are low risk; book_trip is conditional because it purchases a concrete itinerary.",
            DataAccessed = "Traveler itinerary preferences, availability, price, and cancellation terms.",
            Irreversible = false,
        },
    };
    return store.AddBytes(doc.ToUtf8Bytes(), new Uri(resourceUrl), "/r3");
}

string BuildResourceToken(string agentId, string agentJkt, string r3Uri, string r3S256) =>
    new R3Challenge
    {
        ResourceIssuer = resourceUrl,
        Audience = accessServerUrl,
        Key = resourceKey,
        KeyId = ResourceKid,
    }.BuildResourceToken(agentId, agentJkt, r3Uri, r3S256);

string BuildProposalResourceToken(TokenVerifier.VerifiedToken verifiedAuthToken, string proposalUri, string proposalS256)
{
    var payload = verifiedAuthToken.Payload;
    var agentId = (string?)payload["agent"]
        ?? throw new InvalidOperationException("auth token missing agent");
    var cnf = payload["cnf"]?["jwk"] as JsonObject
        ?? throw new InvalidOperationException("auth token missing cnf.jwk");
    var agentJkt = KeyFactory.FromJwk(cnf).ComputeJwkThumbprint();
    return BuildResourceToken(agentId, agentJkt, proposalUri, proposalS256);
}

async Task<AuthOutcome> VerifyAuthOrChallengeAsync(HttpContext ctx, IReadOnlyCollection<string> fallbackTools)
{
    R3VerifiedFetcher fetcher;
    try
    {
        fetcher = await R3DocumentEndpoint.VerifyFetcherAsync(ctx);
    }
    catch (Exception ex) when (ex is R3FetchVerificationException or AAuthVerificationException)
    {
        return new AuthOutcome(null, Results.Json(new { error = "invalid_signature", detail = ex.Message }, statusCode: StatusCodes.Status401Unauthorized));
    }

    if (fetcher.Scheme != AAuthConstants.Schemes.Jwt || fetcher.ParsedKey.Jwt is null || fetcher.ParsedKey.Payload is null)
    {
        return new AuthOutcome(null, Results.Json(new { error = "invalid_carrier_token", detail = "expected jwt Signature-Key" }, statusCode: StatusCodes.Status403Forbidden));
    }

    var typ = (string?)fetcher.ParsedKey.Header?["typ"];
    if (typ == AgentTokenBuilder.TokenType)
    {
        try
        {
            var agent = await VerifyAgentAsync(ctx, fetcher);
            var stored = StoreR3Document(ctx.RequestServices.GetRequiredService<R3ProposalStore>(), fallbackTools);
            var resourceToken = BuildResourceToken(agent.AgentId, agent.ConfirmationKey.ComputeJwkThumbprint(), stored.Uri, stored.S256);
            ctx.Response.Headers[AAuthConstants.Headers.AAuthRequirement] = AAuth.Headers.AAuthRequirementHeader.FormatAuthToken(resourceToken);
            return new AuthOutcome(null, Results.Json(new { error = "auth_token_required", r3_uri = stored.Uri, r3_s256 = stored.S256 }, statusCode: StatusCodes.Status401Unauthorized));
        }
        catch (Exception ex) when (ex is TokenVerificationException or InvalidOperationException)
        {
            return new AuthOutcome(null, Results.Json(new { error = "invalid_agent_token", detail = ex.Message }, statusCode: StatusCodes.Status401Unauthorized));
        }
    }

    if (typ != AuthTokenBuilder.TokenType)
    {
        return new AuthOutcome(null, Results.Json(new { error = "invalid_carrier_token", detail = $"expected {AuthTokenBuilder.TokenType}" }, statusCode: StatusCodes.Status403Forbidden));
    }

    var tokenVerifier = ctx.RequestServices.GetRequiredService<TokenVerifier>();
    var metadata = ctx.RequestServices.GetRequiredService<MetadataClient>();
    var jwks = ctx.RequestServices.GetRequiredService<JwksClient>();
    var agentId = (string?)fetcher.ParsedKey.Payload["agent"];
    if (string.IsNullOrWhiteSpace(agentId) || fetcher.ParsedKey.ConfirmationKey is null)
    {
        return new AuthOutcome(null, Results.Json(new { error = "invalid_auth_token", detail = "missing agent or cnf.jwk" }, statusCode: StatusCodes.Status401Unauthorized));
    }

    try
    {
        var verified = await tokenVerifier.VerifyAuthTokenWithJwksAsync(
            fetcher.ParsedKey.Jwt,
            metadata,
            jwks,
            resourceUrl,
            fetcher.ParsedKey.ConfirmationKey,
            agentId,
            cancellationToken: ctx.RequestAborted);
        var issuer = ((string?)verified.Payload["iss"])?.TrimEnd('/');
        if (!string.Equals(issuer, accessServerUrl, StringComparison.OrdinalIgnoreCase))
        {
            return new AuthOutcome(null, Results.Json(new { error = "untrusted_auth_token_issuer", detail = issuer }, statusCode: StatusCodes.Status403Forbidden));
        }
        R3ClaimReader.ReadAuthToken(verified.Payload);
        return new AuthOutcome(verified, null);
    }
    catch (Exception ex) when (ex is TokenVerificationException or InvalidOperationException)
    {
        return new AuthOutcome(null, Results.Json(new { error = "invalid_auth_token", detail = ex.Message }, statusCode: StatusCodes.Status401Unauthorized));
    }
}

async Task<SignedAgent> VerifyAgentAsync(HttpContext ctx, R3VerifiedFetcher? knownFetcher = null)
{
    var fetcher = knownFetcher ?? await R3DocumentEndpoint.VerifyFetcherAsync(ctx);
    if (fetcher.Scheme != AAuthConstants.Schemes.Jwt || fetcher.ParsedKey.Jwt is null || fetcher.ParsedKey.ConfirmationKey is null)
    {
        throw new InvalidOperationException("expected jwt Signature-Key with cnf.jwk");
    }
    var verifier = ctx.RequestServices.GetRequiredService<TokenVerifier>();
    var metadata = ctx.RequestServices.GetRequiredService<MetadataClient>();
    var jwks = ctx.RequestServices.GetRequiredService<JwksClient>();
    var verified = await verifier.VerifyWithJwksAsync(
        fetcher.ParsedKey.Jwt,
        metadata,
        jwks,
        AgentTokenBuilder.TokenType,
        AgentTokenBuilder.AgentDwk,
        expectedAudience: null,
        cancellationToken: ctx.RequestAborted);
    var cnf = verified.Payload["cnf"]?["jwk"] as JsonObject
        ?? throw new TokenVerificationException("agent token missing cnf.jwk");
    var tokenKey = KeyFactory.FromJwk(cnf);
    if (tokenKey.ComputeJwkThumbprint() != fetcher.ParsedKey.ConfirmationKey.ComputeJwkThumbprint())
    {
        throw new TokenVerificationException("agent token cnf.jwk does not match the HTTP signature key");
    }
    var agentId = (string?)verified.Payload["sub"]
        ?? throw new TokenVerificationException("agent token missing sub");
    return new SignedAgent(agentId, fetcher.ParsedKey.ConfirmationKey);
}

void ValidateRequestedOperations(R3Operations operations)
{
    operations.Validate();
    var supported = SupportedTools.ToHashSet(StringComparer.Ordinal);
    foreach (var operation in operations.Operations)
    {
        if (!supported.Contains(operation.Tool))
        {
            throw new InvalidOperationException($"Unsupported MCP tool '{operation.Tool}'.");
        }
    }
}

bool IsTrustedR3Fetcher(R3VerifiedFetcher fetcher) =>
    fetcher.Scheme == AAuthConstants.Schemes.JwksUri
    && fetcher.JwksUri is not null
    && (trustedFetcherSet.Contains($"{fetcher.JwksUri.Scheme}://{fetcher.JwksUri.Authority}")
        || trustedFetcherSet.Contains(fetcher.JwksUri.Authority));

static JsonObject BuildJwks(string kid, AAuthKey key)
{
    var jwk = key.ToPublicJwk();
    jwk["kid"] = kid;
    jwk["use"] = "sig";
    jwk["alg"] = AAuthKey.Algorithm;
    return new JsonObject { ["keys"] = new JsonArray(jwk) };
}

async Task<IReadOnlyDictionary<string, R3Parameter>> ReadBookingParametersAsync(HttpContext ctx)
{
    JsonObject body = [];
    if (ctx.Request.ContentLength != 0)
    {
        try
        {
            body = await ctx.Request.ReadFromJsonAsync<JsonObject>() ?? [];
        }
        catch (JsonException)
        {
            body = [];
        }
    }

    var parameterSource = body["parameters"] as JsonObject ?? body;
    var values = new JsonObject
    {
        ["itinerary_id"] = parameterSource["itinerary_id"]?.DeepClone() ?? JsonValue.Create("itinerary-paris-001"),
        ["destination"] = parameterSource["destination"]?.DeepClone() ?? JsonValue.Create("Paris"),
        ["depart"] = parameterSource["depart"]?.DeepClone() ?? JsonValue.Create("2026-07-12"),
        ["return"] = parameterSource["return"]?.DeepClone() ?? JsonValue.Create("2026-07-19"),
        ["total_usd"] = parameterSource["total_usd"]?.DeepClone() ?? JsonValue.Create(1284),
        ["cancellation_policy"] = parameterSource["cancellation_policy"]?.DeepClone() ?? JsonValue.Create("Refundable for 24 hours, then airline fare rules apply."),
    };

    return values.ToDictionary(
        pair => pair.Key,
        pair => R3Parameter.Inline(pair.Value!),
        StringComparer.Ordinal);
}

IResult? VerifyApprovedProposalRetry(R3ClaimReader.AuthTokenClaims claims, IReadOnlyDictionary<string, R3Parameter> parameters, R3ProposalStore proposals)
{
    if (!proposals.TryGet(claims.S256, out var stored))
    {
        return Results.Json(new { error = "unknown_proposal", r3_s256 = claims.S256 }, statusCode: StatusCodes.Status403Forbidden);
    }
    R3ProposalDocument expected;
    try
    {
        expected = R3ProposalDocument.FromUtf8Bytes(stored);
    }
    catch (InvalidOperationException ex)
    {
        return Results.Json(new { error = "invalid_proposal", detail = ex.Message }, statusCode: StatusCodes.Status403Forbidden);
    }
    if (!expected.Operations.Any(op => string.Equals(op.Tool, BookTrip, StringComparison.Ordinal)))
    {
        return Results.Json(new { error = "proposal_tool_mismatch" }, statusCode: StatusCodes.Status403Forbidden);
    }
    var actual = new R3ProposalDocument
    {
        Version = expected.Version,
        Vocabulary = expected.Vocabulary,
        Operations = expected.Operations,
        Parameters = parameters,
        Display = expected.Display,
    };
    var actualHash = R3Hash.ComputeS256(actual.ToUtf8Bytes());
    return string.Equals(actualHash, claims.S256, StringComparison.Ordinal)
        ? null
        : Results.Json(new { error = "proposal_digest_mismatch" }, statusCode: StatusCodes.Status403Forbidden);
}

static R3Display BookingDisplay(IReadOnlyDictionary<string, R3Parameter> parameters) => new()
{
    Summary = $"Approve booking {ParameterString(parameters, "itinerary_id")} to {ParameterString(parameters, "destination")}",
    Implications = $"This will book travel for {ParameterString(parameters, "depart")} through {ParameterString(parameters, "return")} and may charge the payment method on file.",
    DataAccessed = "Selected itinerary, destination, travel dates, total price, and cancellation policy.",
    Irreversible = false,
    Detail = $"Book itinerary `{ParameterString(parameters, "itinerary_id")}` to **{ParameterString(parameters, "destination")}** for **${ParameterNumber(parameters, "total_usd")}**. Cancellation policy: {ParameterString(parameters, "cancellation_policy")}",
};

static string ParameterString(IReadOnlyDictionary<string, R3Parameter> parameters, string name) =>
    parameters.TryGetValue(name, out var parameter) && parameter.Json is JsonValue value && value.TryGetValue<string>(out var text)
        ? text
        : parameter?.Json.ToJsonString() ?? string.Empty;

static decimal ParameterNumber(IReadOnlyDictionary<string, R3Parameter> parameters, string name) =>
    parameters.TryGetValue(name, out var parameter) && parameter.Json is JsonValue value && value.TryGetValue<decimal>(out var number)
        ? number
        : 0m;

static string? ToOrigin(string value)
{
    if (Uri.TryCreate(value, UriKind.Absolute, out var uri))
    {
        return $"{uri.Scheme}://{uri.Authority}";
    }
    return value;
}

sealed record SignedAgent(string AgentId, IAAuthKey ConfirmationKey);
sealed record AuthOutcome(TokenVerifier.VerifiedToken? Verified, IResult? Result);

namespace Bookings
{
    /// <summary>Marker type for WebApplicationFactory&lt;T&gt;.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
