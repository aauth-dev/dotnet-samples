using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Events;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Events.Resource;
using AAuth.HttpSig;
using AAuth.R3;
using AAuth.R3.Model;
using AAuth.Tokens;
using Bookings.Events;

var builder = WebApplication.CreateBuilder(args);

var resourceKey = AAuthKey.Generate();
const string ResourceKid = "bookings-1";

const string SearchAvailability = "searchAvailability";
const string HoldReservation = "holdReservation";
const string ConfirmReservation = "confirmReservation";
string[] SupportedOperations = [SearchAvailability, HoldReservation, ConfirmReservation];

var resourceUrl = (builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5005").TrimEnd('/');
var accessServerUrl = (builder.Configuration["AAuth:AccessServer"] ?? "http://localhost:5501").TrimEnd('/');
var personServerUrl = (builder.Configuration["AAuth:PersonServer"] ?? "http://localhost:5100").TrimEnd('/');
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;
var missionAware = builder.Configuration.GetValue("Bookings:MissionAware", false);
var eventsSignatureWindowSeconds = builder.Configuration.GetValue<int?>("Events:SignatureWindow") ?? signatureWindowSeconds;
var eventsFutureSkewSeconds = builder.Configuration.GetValue<int?>("Events:FutureSkew") ?? 5;
var eventsMaxBodyBytes = builder.Configuration.GetValue<int?>("Events:MaxBodyBytes") ?? AAuthEventsConstants.DefaultMaxBodyBytes;
var ticketLifetime = TimeSpan.FromSeconds(builder.Configuration.GetValue<int?>("Events:TicketLifetimeSeconds") ?? 300);
var subscriptionLifetime = TimeSpan.FromSeconds(builder.Configuration.GetValue<int?>("Events:SubscriptionLifetimeSeconds") ?? 3600);
var eventLifetime = TimeSpan.FromSeconds(builder.Configuration.GetValue<int?>("Events:EventLifetimeSeconds") ?? 300);
var asyncApiPath = Path.Combine(builder.Environment.ContentRootPath, "asyncapi.json");
var asyncApiDocument = JsonNode.Parse(File.ReadAllText(asyncApiPath)) as JsonObject
    ?? throw new InvalidOperationException("Bookings asyncapi.json must contain a JSON object.");
AsyncApiAAuthValidator.EnsureValid(asyncApiDocument);
var vocabularies = AAuthEventsMetadata.WithAsyncApiVocabulary(
    new Dictionary<string, string>(StringComparer.Ordinal)
    {
        [Vocabulary.OpenApi] = $"{resourceUrl}/openapi.json",
    },
    $"{resourceUrl}/asyncapi.json");
var r3Vocabularies = AAuthEventsMetadata.ToVocabulariesJson(vocabularies);
var trustedFetcherAuthorities = builder.Configuration
    .GetSection("Bookings:TrustedR3Fetchers")
    .Get<string[]>() ?? [accessServerUrl, personServerUrl];
var trustedFetcherSet = trustedFetcherAuthorities
    .Select(ToOrigin)
    .Where(static origin => origin is not null)
    .Select(static origin => origin!)
    .ToHashSet(StringComparer.OrdinalIgnoreCase);

// Resource DI via the one-call helper: registers the AAuth verifier, the shared
// discovery clients (MetadataClient + JwksClient) behind an SDK-owned pooled handler,
// and the well-known metadata options — no manual HttpClient wiring (2026-06-27
// server-api-surface). R3's r3_vocabularies (and the mission_aware flag) ride the
// generic AdditionalMetadata seam, so Bookings uses the high-level MapAAuthWellKnown
// instead of hand-rolling the well-known + JWKS.
builder.Services.AddAAuthResource(o =>
{
    o.Issuer = resourceUrl;
    o.MaxSignatureAge = TimeSpan.FromSeconds(signatureWindowSeconds);
    o.SigningKeys[ResourceKid] = resourceKey;
    o.Name = "Aria Reservations";
    o.Description = "R3 dining & experiences reservations demo resource.";
    o.AccessMode = AAuthConstants.AccessModes.AuthToken;
    o.AuthorizationEndpoint = $"{resourceUrl}/authorize";
    o.AdditionalMetadata = new Dictionary<string, JsonNode?>
    {
        // Bookings is deliberately not mission-aware (advertised for discovery only).
        ["mission_aware"] = missionAware,
        ["r3_vocabularies"] = r3Vocabularies,
    };
});
var eventsUrlPolicy = new DefaultEventsUrlPolicy();
builder.Services.AddAAuthEventsResource(options =>
{
    options.SignatureMaxAge = TimeSpan.FromSeconds(eventsSignatureWindowSeconds);
    options.SignatureFutureSkew = TimeSpan.FromSeconds(eventsFutureSkewSeconds);
    options.MaxBodyBytes = eventsMaxBodyBytes;
});
builder.Services.AddSingleton<IEventsUrlPolicy>(eventsUrlPolicy);
builder.Services.AddSingleton<EventEndpointResolver>(_ =>
    new EventEndpointResolver(urlPolicy: eventsUrlPolicy, cacheTtl: TimeSpan.FromMinutes(2)));
builder.Services.AddSingleton<EventDeliveryClient>(sp =>
    new EventDeliveryClient(
        sp.GetRequiredService<EventEndpointResolver>(),
        resourceKey,
        ResourceKid,
        EventsHttpClientFactory.Create(eventsUrlPolicy)));
builder.Services.AddSingleton(new TokenVerifier());
builder.Services.AddSingleton<R3ProposalStore>();
builder.Services.AddSingleton(new BookingsEventSubscriptions(ticketLifetime, subscriptionLifetime));

var app = builder.Build();

// Resource well-known (aauth-resource.json + jwks.json) from the DI-registered
// metadata options — including R3's r3_vocabularies via the AdditionalMetadata seam.
// Bookings does not read or enforce AAuth-Mission; mission_aware is advertised false.
app.MapAAuthWellKnown();

app.MapGet("/", () => Results.Ok(new
{
    resource = "Aria Reservations",
    accessMode = "four-party-r3",
    missionAware,
    authorization_endpoint = $"{resourceUrl}/authorize",
    r3_vocabularies = vocabularies,
    flows = new[]
    {
        new { path = "/search_availability", operationId = SearchAvailability, grant = "r3_granted" },
        new { path = "/hold_reservation", operationId = HoldReservation, grant = "r3_granted" },
        new { path = "/confirm_reservation", operationId = ConfirmReservation, grant = "r3_conditional + per-call proposal" },
    },
}));

// OpenAPI discovery document — the OpenAPI vocabulary's discovery endpoint (r3
// §OpenAPI Vocabulary). A minimal but valid OpenAPI 3.1 spec whose operationIds are
// the R3 operation identifiers the AS grants and the resource enforces.
app.MapGet("/openapi.json", () => Results.Json(new JsonObject
{
    ["openapi"] = "3.1.0",
    ["info"] = new JsonObject { ["title"] = "Aria Reservations", ["version"] = "1.0.0" },
    ["paths"] = new JsonObject
    {
        ["/search_availability"] = OpenApiPath(SearchAvailability, "Search dining & experience availability."),
        ["/hold_reservation"] = OpenApiPath(HoldReservation, "Place a temporary hold on a reservation."),
        ["/confirm_reservation"] = OpenApiPath(ConfirmReservation, "Confirm a reservation; may charge a non-refundable deposit."),
    },
}, contentType: "application/json"));

app.MapGet("/asyncapi.json", () => Results.Json(asyncApiDocument, contentType: AAuthEventsConstants.JsonMediaType));

app.MapPost("/waitlist/request", async (HttpContext ctx, BookingsEventSubscriptions subscriptions) =>
{
    var auth = await VerifyAuthOrChallengeAsync(ctx, [SearchAvailability]);
    if (auth.Result is not null) return auth.Result;
    var claims = R3ClaimReader.ReadAuthToken(auth.Verified!.Payload);
    if (!claims.Granted.Contains(SearchAvailability))
    {
        return Results.Json(
            new { error = "r3_denied", detail = "searchAvailability was not granted" },
            statusCode: StatusCodes.Status403Forbidden);
    }

    var agentId = (string?)auth.Verified.Payload["agent"];
    if (string.IsNullOrWhiteSpace(agentId))
    {
        return Results.Json(
            new { error = "invalid_auth_token", detail = "auth token is missing agent identity" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    var ticket = subscriptions.IssueTicket(agentId, "waitlist-subscriptions");
    return Results.Ok(new
    {
        status = "unavailable",
        waitlist = new
        {
            subscribe_url = ticket.SubscribeUrl(resourceUrl),
            event_types = new[] { BookingsEventSubscriptions.SlotAvailable },
            offer_window_seconds = (int)ticketLifetime.TotalSeconds,
        },
    });
});

var waitlistChannel = new SubscriptionChannel(
    "waitlist-subscriptions",
    "/waitlist/subscriptions/{subscriptionTicket}",
    true,
    [BookingsEventSubscriptions.SlotAvailable],
    resourceUrl,
    "subscriptionTicket");
// The Events mapper performs the subscribe-token, ticket, signature, and
// registration-body verification before invoking the sample's atomic handler.
app.MapAAuthProtectedSubscription(
    waitlistChannel,
    app.Services.GetRequiredService<BookingsEventSubscriptions>());

app.MapPost("/waitlist/subscriptions/{eid}/trigger", async (
    HttpContext ctx,
    string eid,
    BookingsEventSubscriptions subscriptions,
    EventDeliveryClient delivery) =>
{
    var auth = await VerifyAuthOrChallengeAsync(ctx, [SearchAvailability]);
    if (auth.Result is not null) return auth.Result;

    if (!subscriptions.TryGet(eid, out var stored))
    {
        return Results.Json(new { error = "subscription_not_found" }, statusCode: StatusCodes.Status404NotFound);
    }

    var agentId = (string?)auth.Verified!.Payload["agent"];
    if (!string.Equals(agentId, stored.Subscription.AgentSubject, StringComparison.Ordinal))
    {
        return Results.Json(
            new { error = "agent_mismatch" },
            statusCode: StatusCodes.Status403Forbidden);
    }

    var now = DateTimeOffset.UtcNow;
    if (stored.ExpiresAt <= now)
    {
        subscriptions.Remove(eid);
        return Results.Json(new { error = "subscription_expired" }, statusCode: StatusCodes.Status404NotFound);
    }

    var payload = JsonSerializer.SerializeToUtf8Bytes(new
    {
        reservation_id = "dining-lumiere-001",
        venue = "Le Lumière (dinner for 2)",
        date = "2026-07-14T19:30:00Z",
        party_size = 2,
        available = true,
        offer_expires_at = now.AddSeconds(60),
    });
    var configuredEventExpiresAt = now.Add(eventLifetime);
    var eventExpiresAt = stored.ExpiresAt <= configuredEventExpiresAt
        ? stored.ExpiresAt
        : configuredEventExpiresAt;
    if (eventExpiresAt <= now)
    {
        subscriptions.Remove(eid);
        return Results.Json(new { error = "subscription_expired" }, statusCode: StatusCodes.Status404NotFound);
    }

    try
    {
        var prepared = delivery.Prepare(
            stored.Subscription,
            payload,
            eventExpiresAt,
            AAuthEventsConstants.JsonMediaType,
            issuedAt: now);
        var outcome = await delivery.SendAsync(prepared, ctx.RequestAborted);
        if (outcome.IsExhausted || outcome.RemainingUses == 0)
            subscriptions.Remove(eid);

        return Results.Json(
            new
            {
                eid,
                outcome = outcome.Outcome.ToString().ToLowerInvariant(),
                remaining_uses = outcome.RemainingUses,
                status_code = (int)outcome.StatusCode,
            },
            statusCode: (int)outcome.StatusCode);
    }
    catch (Exception ex) when (ex is HttpRequestException or EventDeliveryProtocolException or EventsVerificationException)
    {
        return Results.Json(
            new { error = "event_delivery_failed", detail = ex.Message },
            statusCode: StatusCodes.Status502BadGateway);
    }
});

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
        // Resource-token issuance is gated by the authoritative operation set this
        // resource supports (its OpenAPI operationIds, advertised at /openapi.json):
        // an unknown operationId is rejected.
        ValidateRequestedOperations(operations);
    }
    catch (Exception ex) when (ex is JsonException or InvalidOperationException)
    {
        return Results.Json(new { error = "invalid_r3_operations", detail = ex.Message }, statusCode: StatusCodes.Status400BadRequest);
    }

    var stored = StoreR3Document(documents, operations.Operations.Select(op => op.Id));
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

app.MapMethods("/search_availability", ["GET", "POST"], async (HttpContext ctx) =>
{
    var auth = await VerifyAuthOrChallengeAsync(ctx, [SearchAvailability, HoldReservation, ConfirmReservation]);
    if (auth.Result is not null) { return auth.Result; }
    var decision = R3ClaimReader.ReadAuthToken(auth.Verified!.Payload);
    if (!decision.Granted.Contains(SearchAvailability))
    {
        return Results.Json(new { error = "r3_denied", detail = "searchAvailability was not granted" }, statusCode: StatusCodes.Status403Forbidden);
    }
    return Results.Ok(new
    {
        accessMode = "four-party-r3",
        operationId = SearchAvailability,
        source = "r3_granted",
        options = new[]
        {
            new { reservation_id = "dining-lumiere-001", venue = "Le Lumière (dinner for 2)", date = "2026-07-14T19:30", party_size = 2, deposit_usd = 40, cancellation_policy = "Deposit refundable up to 48 hours before the reservation." },
            new { reservation_id = "experience-tour-002", venue = "Old Town Walking Tour", date = "2026-07-15T10:00", party_size = 2, deposit_usd = 25, cancellation_policy = "Non-refundable within 24 hours of the tour." },
        },
        r3_uri = decision.Uri,
        r3_s256 = decision.S256,
    });
});

app.MapMethods("/hold_reservation", ["GET", "POST"], async (HttpContext ctx) =>
{
    var auth = await VerifyAuthOrChallengeAsync(ctx, [SearchAvailability, HoldReservation, ConfirmReservation]);
    if (auth.Result is not null) { return auth.Result; }
    var claims = R3ClaimReader.ReadAuthToken(auth.Verified!.Payload);
    if (!claims.Granted.Contains(HoldReservation))
    {
        return Results.Json(new { error = "r3_denied", detail = "holdReservation was not granted" }, statusCode: StatusCodes.Status403Forbidden);
    }
    return Results.Ok(new
    {
        accessMode = "four-party-r3",
        operationId = HoldReservation,
        source = "r3_granted",
        hold_id = "hold-aria-001",
        reservation_id = "dining-lumiere-001",
        expires_at = DateTimeOffset.UtcNow.AddMinutes(20),
        r3_uri = claims.Uri,
        r3_s256 = claims.S256,
    });
});

app.MapPost("/confirm_reservation", async (HttpContext ctx, R3ProposalStore proposals) =>
{
    var auth = await VerifyAuthOrChallengeAsync(ctx, [SearchAvailability, HoldReservation, ConfirmReservation]);
    if (auth.Result is not null) { return auth.Result; }

    var claims = R3ClaimReader.ReadAuthToken(auth.Verified!.Payload);
    var parameters = await ReadReservationParametersAsync(ctx);

    if (claims.Granted.Contains(ConfirmReservation))
    {
        var retry = VerifyApprovedProposalRetry(claims, parameters, proposals);
        if (retry is not null) { return retry; }
        return Results.Ok(new
        {
            accessMode = "four-party-r3",
            operationId = ConfirmReservation,
            source = "per-call-r3_granted",
            status = "confirmed",
            confirmation = "RSV-ARIA-314159",
            reservation_id = ParameterString(parameters, "reservation_id"),
            venue = ParameterString(parameters, "venue"),
            deposit_usd = ParameterNumber(parameters, "deposit_usd"),
            r3_uri = claims.Uri,
            r3_s256 = claims.S256,
        });
    }

    if (!claims.Conditional?.Contains(ConfirmReservation) ?? true)
    {
        return Results.Json(new { error = "r3_denied", detail = "confirmReservation was not granted or conditional" }, statusCode: StatusCodes.Status403Forbidden);
    }

    var proposal = new R3ProposalDocument
    {
        Version = "v02",
        Vocabulary = Vocabulary.OpenApi,
        Operations = [R3Operation.OpenApi(ConfirmReservation)],
        Parameters = parameters,
        Display = ReservationDisplay(parameters),
    };
    var stored = proposals.Add(proposal, new Uri(resourceUrl), "/r3/proposals");
    var proposalResourceToken = BuildProposalResourceToken(auth.Verified!, stored.Uri, stored.S256);
    ctx.Response.Headers[AAuthConstants.Headers.AAuthRequirement] = AAuth.Headers.AAuthRequirementHeader.FormatAuthToken(proposalResourceToken);
    return Results.Json(new
    {
        error = "r3_approval_required",
        operationId = ConfirmReservation,
        r3_uri = stored.Uri,
        r3_s256 = stored.S256,
    }, statusCode: StatusCodes.Status401Unauthorized);
});

app.Run();

StoredR3Proposal StoreR3Document(R3ProposalStore store, IEnumerable<string> requestedOperations)
{
    var requested = requestedOperations.ToHashSet(StringComparer.Ordinal);
    var ordered = SupportedOperations.Where(requested.Contains).Select(R3Operation.OpenApi).ToArray();
    var doc = new R3Document
    {
        Version = "v02",
        Vocabulary = Vocabulary.OpenApi,
        Operations = ordered,
        Display = new R3Display
        {
            Summary = "Search and temporarily hold reservations. Confirming a reservation may charge a deposit.",
            Implications = "Search and hold are low risk; confirmReservation is conditional because it commits a booking and may charge a deposit.",
            DataAccessed = "Reservation availability, venue, date, party size, deposit, and cancellation terms.",
            Irreversible = ordered.Any(op => string.Equals(op.Id, ConfirmReservation, StringComparison.Ordinal))
                ? "Calling confirmReservation may charge a non-refundable deposit; cancellation and refundability depend on the selected venue's policy."
                : null,
        },
        // The R3 document carries only spec fields (operations + display). The R3
        // Access Server — not the resource — decides which operations are conditional
        // (r3 §Auth Token Extensions); Bookings signals irreversibility via `display`.
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
    var supported = SupportedOperations.ToHashSet(StringComparer.Ordinal);
    foreach (var operation in operations.Operations)
    {
        if (!supported.Contains(operation.Id))
        {
            throw new InvalidOperationException($"Unsupported operation '{operation.Id}'.");
        }
    }
}

bool IsTrustedR3Fetcher(R3VerifiedFetcher fetcher) =>
    fetcher.Scheme == AAuthConstants.Schemes.JwksUri
    && fetcher.JwksUri is not null
    && (trustedFetcherSet.Contains($"{fetcher.JwksUri.Scheme}://{fetcher.JwksUri.Authority}")
        || trustedFetcherSet.Contains(fetcher.JwksUri.Authority));

static JsonObject OpenApiPath(string operationId, string summary) => new()
{
    ["post"] = new JsonObject { ["operationId"] = operationId, ["summary"] = summary },
};

async Task<IReadOnlyDictionary<string, R3Parameter>> ReadReservationParametersAsync(HttpContext ctx)
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
        ["reservation_id"] = parameterSource["reservation_id"]?.DeepClone() ?? JsonValue.Create("dining-lumiere-001"),
        ["venue"] = parameterSource["venue"]?.DeepClone() ?? JsonValue.Create("Le Lumière (dinner for 2)"),
        ["date"] = parameterSource["date"]?.DeepClone() ?? JsonValue.Create("2026-07-14T19:30"),
        ["party_size"] = parameterSource["party_size"]?.DeepClone() ?? JsonValue.Create(2),
        ["deposit_usd"] = parameterSource["deposit_usd"]?.DeepClone() ?? JsonValue.Create(40),
        ["cancellation_policy"] = parameterSource["cancellation_policy"]?.DeepClone() ?? JsonValue.Create("Deposit refundable up to 48 hours before the reservation."),
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
    if (!expected.Operations.Any(op => string.Equals(op.Id, ConfirmReservation, StringComparison.Ordinal)))
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

static R3Display ReservationDisplay(IReadOnlyDictionary<string, R3Parameter> parameters) => new()
{
    Summary = $"Approve reservation {ParameterString(parameters, "reservation_id")} at {ParameterString(parameters, "venue")}",
    Implications = $"This will confirm a reservation on {ParameterString(parameters, "date")} for {ParameterNumber(parameters, "party_size")} guest(s) and may charge a deposit.",
    DataAccessed = "Selected reservation, venue, date, party size, deposit, and cancellation policy.",
    Irreversible = "Confirming this reservation may charge a non-refundable deposit; cancellation and refundability depend on the displayed policy.",
    Detail = $"Confirm reservation `{ParameterString(parameters, "reservation_id")}` at **{ParameterString(parameters, "venue")}** with a **${ParameterNumber(parameters, "deposit_usd")}** deposit. Cancellation policy: {ParameterString(parameters, "cancellation_policy")}",
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
