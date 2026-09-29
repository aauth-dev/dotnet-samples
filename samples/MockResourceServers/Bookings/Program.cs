using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.R3;
using AAuth.R3.Model;
using AAuth.Tokens;
using AAuth.Server;
using AAuth.Server.Verification;
using AAuth.Events;
using AAuth.Samples.Events;

var builder = WebApplication.CreateBuilder(args);

const string ResourceKid = "bookings-1";
var resourceKey = new FileKeyStore(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
    ".aauth", "bookings-keys")).LoadOrCreate(ResourceKid);

const string SearchAvailability = "searchAvailability";
const string HoldReservation = "holdReservation";
const string ConfirmReservation = "confirmReservation";
var openApiDocument = new JsonObject
{
    ["openapi"] = "3.1.0",
    ["info"] = new JsonObject { ["title"] = "Aria Reservations", ["version"] = "1.0.0" },
    ["paths"] = new JsonObject
    {
        ["/search_availability"] = OpenApiPath(SearchAvailability, "Search dining & experience availability.", allowGet: true),
        ["/hold_reservation"] = OpenApiPath(HoldReservation, "Place a temporary hold on a reservation.", allowGet: true),
        ["/confirm_reservation"] = OpenApiPath(ConfirmReservation, "Confirm a reservation; may charge a non-refundable deposit."),
    },
};
// Tell agents up front that confirming blocks on a person for every call (R3 #operation-access-annotations).
R3AccessAnnotations.Annotate(openApiDocument["paths"]!["/confirm_reservation"]!["post"]!.AsObject(), Vocabulary.OpenApi,
    new R3OperationAccess(AAuthConstants.AccessModes.PerCall));
var supportedOperations = openApiDocument["paths"]!.AsObject().SelectMany(path => path.Value!.AsObject())
    .Select(method => method.Value!["operationId"]!.GetValue<string>()).ToArray();

var resourceUrl = (builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5005").TrimEnd('/');
var accessServerUrl = (builder.Configuration["AAuth:AccessServer"] ?? "http://localhost:5501").TrimEnd('/');
var personServerUrl = (builder.Configuration["AAuth:PersonServer"] ?? "http://localhost:5100").TrimEnd('/');
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;
var accounts = builder.Configuration.GetSection("Bookings:Accounts").Get<Dictionary<string, string>>()
    ?? new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["personal"] = "Personal reservations",
        ["work"] = "Work reservations",
    };
var readerPolicy = new R3DocumentReaderPolicy(accessServerUrl,
    builder.Configuration.GetSection("Bookings:PersonServerEvaluators").Get<string[]>(), SampleEgress.Policy)
{
    IsEntitledPersonServer = (ctx, personServer) => ctx.Request.RouteValues["hash"] is string hash
        && ctx.RequestServices.GetRequiredService<R3ProposalStore>().IsEntitled(hash, personServer),
};
var discoveryMetadata = R3Metadata.AddVocabularies(new JsonObject(), new Dictionary<string, string>
{
    [Vocabulary.OpenApi] = $"{resourceUrl}/openapi.json",
    [Vocabulary.AsyncApi] = $"{resourceUrl}/asyncapi.json",
});
var authoritativeOperations = supportedOperations.Select(R3OperationIdentity.OpenApi).ToArray();

// Resource DI via the one-call helper: registers the AAuth verifier, the shared
// discovery clients (MetadataClient + JwksClient) behind an SDK-owned pooled handler,
// and the well-known metadata options — no manual HttpClient wiring (2026-06-27
// server-api-surface). R3's r3_vocabularies ride the
// generic AdditionalMetadata seam, so Bookings uses the high-level MapAAuthWellKnown
// instead of hand-rolling the well-known + JWKS.
builder.Services.AddAAuthResource(o =>
{
    o.EgressPolicy = SampleEgress.Policy;
    o.Issuer = resourceUrl;
    o.RevocationEndpoint = $"{resourceUrl}/revoke";
    o.MaxSignatureAge = TimeSpan.FromSeconds(signatureWindowSeconds);
    o.SigningKeys[ResourceKid] = resourceKey;
    o.Name = "Aria Reservations";
    o.Description = "R3 dining & experiences reservations demo resource.";
    o.AccessMode = AAuthConstants.AccessModes.AuthToken;
    o.AuthorizationEndpoint = $"{resourceUrl}/authorize";
    o.AdditionalMetadata = new Dictionary<string, JsonNode?>
    {
        ["r3_vocabularies"] = discoveryMetadata["r3_vocabularies"]!.DeepClone(),
    };
});
builder.Services.AddSingleton(new TokenVerifier { EgressPolicy = SampleEgress.Policy });
builder.Services.AddSingleton<R3ProposalStore>();
builder.Services.AddAAuthEvents();

var app = builder.Build();
using var eventHttp = new SampleHttpClient();
var eventProtocol = new EventsProtocol(eventHttp, app.Services.GetServices<ISignatureTokenVerifier>());
var eventStore = new SqliteEventStore(builder.Configuration["Events:Database"] ?? Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".aauth", "bookings-events.db"));
var bookingEvents = new BookingsEvents(resourceUrl, resourceKey, ResourceKid, eventProtocol, eventStore);
bookingEvents.Map(app);
// R3 per-call single use: a proposal-approved auth token executes once, and a repeat
// of the same token (even freshly signed) gets the retained result.
var perCallGrants = new AAuthSingleUseGrants();

// Resource well-known (aauth-resource.json + jwks.json) from the DI-registered
// metadata options — including R3's r3_vocabularies via the AdditionalMetadata seam.
app.MapAAuthWellKnown();
var tokenInventory = app.MapAAuthIssuerRevocation(resourceUrl, ResourceTokenBuilder.ResourceDwk,
    new AAuthSigningKeySet(ResourceKid, resourceKey), "/revoke", SampleEgress.Policy, TimeProvider.System,
    options => options.IsAcceptedIssuer = caller => caller == personServerUrl || caller == accessServerUrl);

app.MapGet("/", () => Results.Ok(new
{
    resource = "Aria Reservations",
    accessMode = "four-party-r3",
    authorization_endpoint = $"{resourceUrl}/authorize",
    r3_vocabularies = new Dictionary<string, string> { [Vocabulary.OpenApi] = $"{resourceUrl}/openapi.json" },
    flows = new[]
    {
        new { path = "/search_availability", operationId = SearchAvailability, grant = "r3_granted" },
        new { path = "/hold_reservation", operationId = HoldReservation, grant = "r3_granted" },
        new { path = "/confirm_reservation", operationId = ConfirmReservation, grant = "r3_per_call + per-call proposal" },
    },
}));

app.MapGet("/accounts", () => Results.Json(accounts.Select(account => new { id = account.Key, name = account.Value })));

// OpenAPI discovery document — the OpenAPI vocabulary's discovery endpoint (r3
// §OpenAPI Vocabulary). A minimal but valid OpenAPI 3.1 spec whose operationIds are
// the R3 operation identifiers the AS grants and the resource enforces.
app.MapGet("/openapi.json", () => Results.Json(openApiDocument, contentType: "application/json"));

app.MapPost("/authorize", async (HttpContext ctx, R3ProposalStore documents) =>
{
    SignedPresenter presenter;
    try
    {
        presenter = await VerifyPresenterAsync(ctx);
    }
    catch (Exception ex) when (ex is R3FetchVerificationException or AAuthVerificationException or TokenVerificationException or InvalidOperationException)
    {
        return AAuth.Server.AAuthProblemDetails.Create("invalid_agent_signature", ex.Message, statusCode: StatusCodes.Status401Unauthorized);
    }
    if (presenter.Person is null) return PersonTokenRequired(ctx);

    JsonObject? body;
    try
    {
        body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    }
    catch (JsonException)
    {
        return AAuth.Server.AAuthProblemDetails.Create("invalid_request", "body is not valid JSON", statusCode: StatusCodes.Status400BadRequest);
    }

    if (body is null || !AccountBinding.TryRead(body, out var account))
        return AAuthProblemDetails.Create("invalid_request", "account must be a non-empty string when present", statusCode: 400);
    if (account is not null && !accounts.ContainsKey(account))
        return AAuthProblemDetails.Create("invalid_account", "The selected account is not connected at this resource.", statusCode: 400);

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
        return AAuth.Server.AAuthProblemDetails.Create("invalid_r3_operations", ex.Message, statusCode: StatusCodes.Status400BadRequest);
    }

    var stored = StoreR3Document(documents, operations.Operations.Select(op => op.Id), account, presenter.Person.Issuer);
    var resourceToken = await BuildResourceTokenAsync(presenter.Person, presenter.ConfirmationKey.ComputeJwkThumbprint(), stored.Uri, stored.S256, account);
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
}, readerPolicy);

app.MapR3Document("/r3/{hash}", ctx =>
{
    var hash = (string?)ctx.Request.RouteValues["hash"];
    return hash is not null && ctx.RequestServices.GetRequiredService<R3ProposalStore>().TryGet(hash, out var bytes) ? bytes : null;
}, readerPolicy);

app.MapMethods("/search_availability", ["GET", "POST"], async (HttpContext ctx) =>
{
    var auth = await VerifyAuthOrChallengeAsync(ctx, supportedOperations);
    if (auth.Result is not null) { return auth.Result; }
    var decision = R3ClaimReader.ReadAuthToken(auth.Verified!.Payload);
    var enforcement = await EnforceOperationAsync(ctx, auth.Verified, SearchAvailability);
    if (enforcement.Result is not null) return enforcement.Result;
    return await CompleteAsync(auth.Verified!, enforcement.IsProposal, () => new
    {
        accessMode = "four-party-r3",
        operationId = HttpMethods.IsGet(ctx.Request.Method) ? SearchAvailability : SearchAvailability + "Post",
        account = auth.Verified!.Account,
        account_name = AccountName(auth.Verified.Account),
        subject = (string?)auth.Verified.Payload["sub"],
        ps = (string?)auth.Verified.Payload["ps"],
        source = "r3_granted",
        notifications = bookingEvents.IssueTicket(auth.Verified),
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
    var auth = await VerifyAuthOrChallengeAsync(ctx, supportedOperations);
    if (auth.Result is not null) { return auth.Result; }
    var claims = R3ClaimReader.ReadAuthToken(auth.Verified!.Payload);
    var enforcement = await EnforceOperationAsync(ctx, auth.Verified, HoldReservation);
    if (enforcement.Result is not null) return enforcement.Result;
    return await CompleteAsync(auth.Verified!, enforcement.IsProposal, () => new
    {
        accessMode = "four-party-r3",
        operationId = HttpMethods.IsGet(ctx.Request.Method) ? HoldReservation : HoldReservation + "Post",
        account = auth.Verified!.Account,
        source = "r3_granted",
        hold_id = "hold-aria-001",
        reservation_id = ParameterString(enforcement.Parameters!, "reservation_id"),
        expires_at = DateTimeOffset.UtcNow.AddMinutes(20),
        r3_uri = claims.Uri,
        r3_s256 = claims.S256,
    });
});

app.MapPost("/confirm_reservation", async (HttpContext ctx) =>
{
    var auth = await VerifyAuthOrChallengeAsync(ctx, supportedOperations);
    if (auth.Result is not null) { return auth.Result; }

    var claims = R3ClaimReader.ReadAuthToken(auth.Verified!.Payload);
    var enforcement = await EnforceOperationAsync(ctx, auth.Verified, ConfirmReservation);
    if (enforcement.Result is not null) return enforcement.Result;
    var parameters = enforcement.Parameters!;
    return await CompleteAsync(auth.Verified!, enforcement.IsProposal, () => new
        {
            accessMode = "four-party-r3",
            operationId = ConfirmReservation,
            account = auth.Verified!.Account,
            account_name = AccountName(auth.Verified.Account),
            source = enforcement.IsProposal ? "per-call-r3_granted" : "r3_granted",
            status = "confirmed",
            notifications = bookingEvents.IssueTicket(auth.Verified),
            confirmation = "RSV-ARIA-314159",
            reservation_id = ParameterString(parameters, "reservation_id"),
            venue = ParameterString(parameters, "venue"),
            deposit_usd = ParameterNumber(parameters, "deposit_usd"),
            r3_uri = claims.Uri,
            r3_s256 = claims.S256,
        });
});

app.Run();

async Task<IResult> CompleteAsync(TokenVerifier.VerifiedToken token, bool perCall, Func<object> execute) => !perCall
    ? Results.Ok(execute())
    : (await perCallGrants.ExecuteOnceAsync((string)token.Payload["jti"]!, token.ExpiresAt,
        _ => Task.FromResult(HeldInvocationResult.Json(execute())))).ToResult();

StoredR3Proposal StoreR3Document(R3ProposalStore store, IEnumerable<string> requestedOperations, string? account, string personServer)
{
    var requested = requestedOperations.ToHashSet(StringComparer.Ordinal);
    var ordered = supportedOperations.Where(requested.Contains).Select(R3Operation.OpenApi).ToArray();
    var doc = new R3Document
    {
        Account = account,
        Vocabulary = Vocabulary.OpenApi,
        Operations = ordered,
        Display = new R3Display
        {
            Summary = $"{AccountName(account)}: search and temporarily hold reservations. Confirming a reservation may charge a deposit.",
            Implications = "Search and hold are low risk; confirmReservation requires per-call approval because it commits a booking and may charge a deposit.",
            DataAccessed = "Reservation availability, venue, date, party size, deposit, and cancellation terms.",
            Irreversible = ordered.Any(op => string.Equals(op.Id, ConfirmReservation, StringComparison.Ordinal))
                ? "Calling confirmReservation may charge a non-refundable deposit; cancellation and refundability depend on the selected venue's policy."
                : null,
        },
        // The R3 document carries only spec fields (operations + display). The R3
        // Access Server — not the resource — decides which operations are per-call
        // (r3 §Auth Token Extensions); Bookings signals irreversibility via `display`.
    };
    var stored = store.AddBytes(doc.ToUtf8Bytes(), new Uri(resourceUrl), "/r3");
    // Only the PS the resource token names may read the document (besides the AS).
    store.Entitle(stored.S256, personServer);
    return stored;
}

R3Challenge Challenger() => new()
{
    EgressPolicy = SampleEgress.Policy,
    ResourceIssuer = resourceUrl,
    Audience = accessServerUrl,
    Key = resourceKey,
    KeyId = ResourceKid,
};

// The resource token names the presented person token (draft-11 §Resource Token Structure).
ValueTask<string> BuildResourceTokenAsync(TokenVerifier.VerifiedToken presented, string agentJkt, string r3Uri, string r3S256, string? account) =>
    Challenger().BuildResourceTokenAsync(presented, agentJkt, r3Uri, r3S256, account: account);

// Per-call proposals name the auth token the agent already presented.
ValueTask<string> BuildProposalResourceTokenAsync(TokenVerifier.VerifiedToken verifiedAuthToken, string proposalUri, string proposalS256, CancellationToken ct) =>
    Challenger().BuildResourceTokenAsync(verifiedAuthToken, proposalUri, proposalS256, cancellationToken: ct);

IResult PersonTokenRequired(HttpContext ctx)
{
    ctx.Response.Headers[AAuthConstants.Headers.AAuthRequirement] = AAuth.Headers.AAuthRequirementHeader.FormatPersonToken();
    return AAuthProblemDetails.Create("person_token_required", statusCode: StatusCodes.Status401Unauthorized);
}

async Task<AuthOutcome> VerifyAuthOrChallengeAsync(HttpContext ctx, IReadOnlyCollection<string> fallbackTools)
{
    var values = ctx.Request.Query["account"];
    var account = values.Count == 0 ? null : values.ToString();
    if (values.Count > 1 || !AccountBinding.IsValid(account))
        return new AuthOutcome(null, AAuthProblemDetails.Create("invalid_request", "invalid account selection", statusCode: 400));
    if (account is not null && !accounts.ContainsKey(account))
        return new AuthOutcome(null, AAuthProblemDetails.Create("invalid_account", "The selected account is not connected at this resource.", statusCode: 400));
    R3VerifiedFetcher fetcher;
    try
    {
        var discoveryMetadata = ctx.RequestServices.GetRequiredService<AAuth.Discovery.MetadataClient>();
        var discoveryKeys = ctx.RequestServices.GetRequiredService<AAuth.Discovery.JwksClient>();
        var authenticated = false;
        var middleware = new AAuthVerificationMiddleware(_ => { authenticated = true; return Task.CompletedTask; },
            ctx.RequestServices.GetRequiredService<AAuthVerifier>(), new DefaultSignatureKeyResolver(discoveryKeys, discoveryMetadata), discoveryMetadata, discoveryKeys,
            new AAuthVerificationOptions { EgressPolicy = SampleEgress.Policy, AcceptedSchemes = ["jwt"], ResourceIdentifier = resourceUrl,
                ExpectedAccount = _ => account });
        await middleware.InvokeAsync(ctx);
        if (!authenticated) throw new R3FetchVerificationException("Agent signature verification failed.");
        var parsed = ctx.GetAAuthParsedKey()!;
        fetcher = new R3VerifiedFetcher(parsed.Scheme, parsed.Identifier ?? string.Empty, parsed.Kid,
            ctx.GetAAuthVerification()!.Jkt, parsed);
    }
    catch (Exception ex) when (ex is R3FetchVerificationException or AAuthVerificationException)
    {
        return new AuthOutcome(null, AAuth.Server.AAuthProblemDetails.Create("invalid_signature", ex.Message, statusCode: StatusCodes.Status401Unauthorized));
    }

    if (fetcher.Scheme != AAuthConstants.Schemes.Jwt || fetcher.ParsedKey.Jwt is null || fetcher.ParsedKey.Payload is null)
    {
        return new AuthOutcome(null, AAuth.Server.AAuthProblemDetails.Create("invalid_carrier_token", "expected jwt Signature-Key", statusCode: StatusCodes.Status403Forbidden));
    }

    var typ = (string?)fetcher.ParsedKey.Header?["typ"];
    if (typ is AgentTokenBuilder.TokenType or PersonTokenBuilder.TokenType)
    {
        try
        {
            var presenter = await VerifyPresenterAsync(ctx, fetcher);
            if (presenter.Person is null) return new AuthOutcome(null, PersonTokenRequired(ctx));
            var stored = StoreR3Document(ctx.RequestServices.GetRequiredService<R3ProposalStore>(), fallbackTools, account, presenter.Person.Issuer);
            var resourceToken = await BuildResourceTokenAsync(presenter.Person, presenter.ConfirmationKey.ComputeJwkThumbprint(), stored.Uri, stored.S256, account);
            ctx.Response.Headers[AAuthConstants.Headers.AAuthRequirement] = AAuth.Headers.AAuthRequirementHeader.FormatAuthToken(resourceToken);
            return new AuthOutcome(null, AAuth.Server.AAuthProblemDetails.Create("auth_token_required",
                statusCode: StatusCodes.Status401Unauthorized,
                extensions: new Dictionary<string, object?> { ["r3_uri"] = stored.Uri, ["r3_s256"] = stored.S256 }));
        }
        catch (Exception ex) when (ex is TokenVerificationException or InvalidOperationException)
        {
            return new AuthOutcome(null, AAuth.Server.AAuthProblemDetails.Create("invalid_token", ex.Message, statusCode: StatusCodes.Status401Unauthorized));
        }
    }

    if (typ != AuthTokenBuilder.TokenType)
    {
        return new AuthOutcome(null, AAuth.Server.AAuthProblemDetails.Create("invalid_carrier_token", $"expected {AuthTokenBuilder.TokenType}", statusCode: StatusCodes.Status403Forbidden));
    }

    var tokenVerifier = ctx.RequestServices.GetRequiredService<TokenVerifier>();
    var metadata = ctx.RequestServices.GetRequiredService<MetadataClient>();
    var jwks = ctx.RequestServices.GetRequiredService<JwksClient>();
    if (fetcher.ParsedKey.ConfirmationKey is null)
    {
        return new AuthOutcome(null, AAuth.Server.AAuthProblemDetails.Create("invalid_auth_token", "missing cnf.jwk", statusCode: StatusCodes.Status401Unauthorized));
    }

    try
    {
        var verified = await tokenVerifier.VerifyAuthTokenWithJwksAsync(
            fetcher.ParsedKey.Jwt,
            metadata,
            jwks,
            resourceUrl,
            fetcher.ParsedKey.ConfirmationKey,
            cancellationToken: ctx.RequestAborted,
            accountExpectation: new AccountExpectation(account));
        var issuer = ((string?)verified.Payload["iss"])?.TrimEnd('/');
        if (!string.Equals(issuer, accessServerUrl, StringComparison.OrdinalIgnoreCase))
        {
            return new AuthOutcome(null, AAuth.Server.AAuthProblemDetails.Create("untrusted_auth_token_issuer", issuer, statusCode: StatusCodes.Status403Forbidden));
        }
        R3ClaimReader.ReadAuthToken(verified.Payload);
        await TokenRegistration.RegisterAsync(tokenInventory, [TokenRegistration.FromVerified(verified)], ctx.RequestAborted);
        return new AuthOutcome(verified, null);
    }
    catch (Exception ex) when (ex is TokenVerificationException or InvalidOperationException)
    {
        return new AuthOutcome(null, AAuth.Server.AAuthProblemDetails.Create("invalid_auth_token", ex.Message, statusCode: StatusCodes.Status401Unauthorized));
    }
}

// Verifies the signing token: an agent token yields no person token (the caller
// answers with requirement=person-token); a person token is verified against its PS.
async Task<SignedPresenter> VerifyPresenterAsync(HttpContext ctx, R3VerifiedFetcher? knownFetcher = null)
{
    var fetcher = knownFetcher;
    if (fetcher is null)
    {
        var metadataClient = ctx.RequestServices.GetRequiredService<MetadataClient>();
        var keys = ctx.RequestServices.GetRequiredService<JwksClient>();
        var authenticated = false;
        var middleware = new AAuthVerificationMiddleware(_ => { authenticated = true; return Task.CompletedTask; },
            ctx.RequestServices.GetRequiredService<AAuthVerifier>(), new DefaultSignatureKeyResolver(keys, metadataClient), metadataClient, keys,
            new AAuthVerificationOptions { EgressPolicy = SampleEgress.Policy, AcceptedSchemes = ["jwt"], ResourceIdentifier = resourceUrl });
        await middleware.InvokeAsync(ctx);
        if (!authenticated) throw new R3FetchVerificationException("Agent signature verification failed.");
        var parsed = ctx.GetAAuthParsedKey()!;
        fetcher = new R3VerifiedFetcher(parsed.Scheme, parsed.Identifier ?? string.Empty, parsed.Kid, ctx.GetAAuthVerification()!.Jkt, parsed);
    }
    if (fetcher.Scheme != AAuthConstants.Schemes.Jwt || fetcher.ParsedKey.Jwt is null || fetcher.ParsedKey.ConfirmationKey is null)
    {
        throw new InvalidOperationException("expected jwt Signature-Key with cnf.jwk");
    }
    var typ = (string?)fetcher.ParsedKey.Header?["typ"];
    if (typ == AgentTokenBuilder.TokenType) return new SignedPresenter(null, fetcher.ParsedKey.ConfirmationKey);
    if (typ != PersonTokenBuilder.TokenType) throw new InvalidOperationException("expected an agent token or a person token");
    var verified = await ctx.RequestServices.GetRequiredService<TokenVerifier>().VerifyPersonTokenWithJwksAsync(
        fetcher.ParsedKey.Jwt,
        ctx.RequestServices.GetRequiredService<MetadataClient>(),
        ctx.RequestServices.GetRequiredService<JwksClient>(),
        resourceUrl,
        fetcher.ParsedKey.ConfirmationKey,
        ctx.RequestAborted);
    await TokenRegistration.RegisterAsync(tokenInventory, [TokenRegistration.FromVerified(verified)], ctx.RequestAborted);
    return new SignedPresenter(verified, fetcher.ParsedKey.ConfirmationKey);
}

void ValidateRequestedOperations(R3Operations operations)
{
    R3Metadata.ValidateOperations(operations, discoveryMetadata, authoritativeOperations);
}

static JsonObject OpenApiPath(string operationId, string summary, bool allowGet = false)
{
    JsonObject Definition(string identifier) => new()
    {
        ["operationId"] = identifier, ["summary"] = summary,
        ["responses"] = new JsonObject { ["200"] = new JsonObject { ["description"] = "Authorized operation result." } },
    };
    var path = new JsonObject { ["post"] = Definition(allowGet ? operationId + "Post" : operationId) };
    if (allowGet) path["get"] = Definition(operationId);
    return path;
}

async Task<IReadOnlyDictionary<string, R3Parameter>> ReadReservationParametersAsync(HttpContext ctx, string operation)
{
    JsonObject body = [];
    if (ctx.Request.ContentLength > 0 || ctx.Request.Headers.ContainsKey("Transfer-Encoding") || ctx.Request.ContentType is not null)
    {
        body = await ctx.Request.ReadFromJsonAsync<JsonObject>() ?? throw new JsonException("Request body must be an object.");
    }

    if (body.ContainsKey("parameters") && (body.Count != 1 || body["parameters"] is not JsonObject))
        throw new JsonException("parameters must be the sole wrapper object.");
    var parameterSource = (body["parameters"] as JsonObject ?? body).DeepClone().AsObject();
    foreach (var query in ctx.Request.Query.Where(query => query.Key != "account"))
    {
        if (query.Value.Count != 1 || parameterSource.ContainsKey(query.Key)) throw new JsonException("Ambiguous request parameter.");
        parameterSource[query.Key] = query.Key is "party_size" or "deposit_usd"
            ? JsonNode.Parse(query.Value.ToString()) : JsonValue.Create(query.Value.ToString());
    }
    if (operation == SearchAvailability)
    {
        if (parameterSource.Any(member => member.Key is not ("venue" or "date" or "party_size")))
            throw new JsonException("Unknown search parameter.");
        foreach (var name in new[] { "venue", "date" })
            if (parameterSource.ContainsKey(name) && (parameterSource[name] is not JsonValue text ||
                !text.TryGetValue<string>(out var value) || string.IsNullOrWhiteSpace(value)))
                throw new JsonException($"{name} must be a nonempty string.");
        if (parameterSource.ContainsKey("party_size") && (parameterSource["party_size"] is not JsonValue number ||
            !number.TryGetValue<int>(out var searchPartySize) || searchPartySize <= 0)) throw new JsonException("Invalid party size.");
        parameterSource["request_method"] = ctx.Request.Method;
        return parameterSource.ToDictionary(member => member.Key,
            member => R3Parameter.Inline(member.Value ?? throw new JsonException("Null parameter.")), StringComparer.Ordinal);
    }
    string[] names = ["reservation_id", "venue", "date", "party_size", "deposit_usd", "cancellation_policy"];
    if (parameterSource.Any(member => !names.Contains(member.Key, StringComparer.Ordinal)))
        throw new JsonException("Unknown reservation parameter.");
    if (operation == ConfirmReservation && names.Any(name => !parameterSource.ContainsKey(name)))
        throw new JsonException("Confirmation requires all reservation parameters.");
    var values = new JsonObject
    {
        ["reservation_id"] = parameterSource["reservation_id"]?.DeepClone() ?? JsonValue.Create("dining-lumiere-001"),
        ["venue"] = parameterSource["venue"]?.DeepClone() ?? JsonValue.Create("Le Lumière (dinner for 2)"),
        ["date"] = parameterSource["date"]?.DeepClone() ?? JsonValue.Create("2026-07-14T19:30"),
        ["party_size"] = parameterSource["party_size"]?.DeepClone() ?? JsonValue.Create(2),
        ["deposit_usd"] = parameterSource["deposit_usd"]?.DeepClone() ?? JsonValue.Create(40),
        ["cancellation_policy"] = parameterSource["cancellation_policy"]?.DeepClone() ?? JsonValue.Create("Deposit refundable up to 48 hours before the reservation."),
    };

    foreach (var name in new[] { "reservation_id", "venue", "date", "cancellation_policy" })
        if (values[name] is not JsonValue text || !text.TryGetValue<string>(out var content) || string.IsNullOrWhiteSpace(content))
            throw new JsonException($"{name} must be a nonempty string.");
    if (values["party_size"] is not JsonValue party || !party.TryGetValue<int>(out var size) || size <= 0 ||
        values["deposit_usd"] is not JsonValue deposit || !deposit.TryGetValue<decimal>(out var amount) || amount < 0)
        throw new JsonException("Invalid party size or deposit.");
    values["request_method"] = ctx.Request.Method;

    return values.ToDictionary(
        pair => pair.Key,
        pair => R3Parameter.Inline(pair.Value!),
        StringComparer.Ordinal);
}

async Task<OperationOutcome> EnforceOperationAsync(HttpContext context, TokenVerifier.VerifiedToken token, string operation)
{
    var claims = R3ClaimReader.ReadAuthToken(token.Payload);
    var proposals = context.RequestServices.GetRequiredService<R3ProposalStore>();
    try
    {
        var parameters = await ReadReservationParametersAsync(context, operation);
        if (!proposals.TryGet(claims.S256, out var stored))
            return new(null, false, AAuthProblemDetails.Create("unknown_r3_document", statusCode: 403));
        R3Hash.Verify(stored, claims.S256);
        if (!AccountBinding.Matches(AccountBinding.Read(JsonNode.Parse(stored)!.AsObject()), claims.Account))
            return new(null, false, AAuthProblemDetails.Create("r3_account_mismatch", statusCode: 403));
        var isProposal = JsonNode.Parse(stored)!.AsObject().ContainsKey("parameters");
        var expectedUri = $"{resourceUrl}/r3/{(isProposal ? "proposals/" : string.Empty)}{claims.S256}";
        if (claims.Uri != expectedUri) return new(null, false, AAuthProblemDetails.Create("r3_uri_mismatch", statusCode: 403));
        var enforcement = new R3Enforcement(proposals, new Uri(resourceUrl));
        var operationId = operation != ConfirmReservation && HttpMethods.IsPost(context.Request.Method) ? operation + "Post" : operation;
        var decision = enforcement.Evaluate(claims, R3OperationIdentity.OpenApi(operationId), parameters,
            (_, values) => operation == ConfirmReservation ? ReservationDisplay(values, token.Account) :
                new R3Display { Summary = $"{AccountName(token.Account)}: approve {operation}", Detail = JsonSerializer.Serialize(values, R3Json.Options) },
            approvedProposalS256: isProposal ? claims.S256 : null, expectedAccount: token.Account);
        if (decision.Kind == R3EnforcementDecisionKind.Granted) return new(parameters, isProposal, null);
        if (decision.Kind == R3EnforcementDecisionKind.PerCall)
        {
            proposals.Entitle(decision.ProposalS256!, (string)token.Payload["ps"]!);
            var resourceToken = await BuildProposalResourceTokenAsync(token, decision.ProposalUri!, decision.ProposalS256!, context.RequestAborted);
            context.Response.Headers[AAuthConstants.Headers.AAuthRequirement] = AAuth.Headers.AAuthRequirementHeader.FormatAuthToken(resourceToken);
            return new(parameters, false, AAuthProblemDetails.Create("r3_approval_required", statusCode: 401,
                extensions: new Dictionary<string, object?> { ["operationId"] = operation, ["r3_uri"] = decision.ProposalUri, ["r3_s256"] = decision.ProposalS256 }));
        }
        return new(parameters, isProposal, decision.ToResult());
    }
    catch (Exception exception) when (exception is JsonException or InvalidOperationException or R3HashMismatchException)
    {
        return new(null, false, AAuthProblemDetails.Create("invalid_r3_request", exception.Message, statusCode: 400));
    }
}

string AccountName(string? account) => account is null ? "Reservations" : accounts[account];

R3Display ReservationDisplay(IReadOnlyDictionary<string, R3Parameter> parameters, string? account) => new()
{
    Summary = $"{AccountName(account)}: approve reservation {ParameterString(parameters, "reservation_id")} at {ParameterString(parameters, "venue")}",
    Implications = $"This will confirm a reservation on {ParameterString(parameters, "date")} for {ParameterNumber(parameters, "party_size")} guest(s) and may charge a deposit.",
    DataAccessed = "Selected reservation, venue, date, party size, deposit, and cancellation policy.",
    Irreversible = "Confirming this reservation may charge a non-refundable deposit; cancellation and refundability depend on the displayed policy.",
    Detail = $"Confirm reservation `{ParameterString(parameters, "reservation_id")}` at **{ParameterString(parameters, "venue")}** with a **${ParameterNumber(parameters, "deposit_usd")}** deposit. Cancellation policy: {ParameterString(parameters, "cancellation_policy")}",
};

static string ParameterString(IReadOnlyDictionary<string, R3Parameter> parameters, string name) =>
    parameters.TryGetValue(name, out var parameter) && parameter.Json is JsonValue value && value.TryGetValue<string>(out var text)
        ? text
        : parameter?.Json?.ToJsonString() ?? string.Empty;

static decimal ParameterNumber(IReadOnlyDictionary<string, R3Parameter> parameters, string name) =>
    parameters.TryGetValue(name, out var parameter) && parameter.Json is JsonValue value && value.TryGetValue<decimal>(out var number)
        ? number
        : 0m;

sealed record SignedPresenter(TokenVerifier.VerifiedToken? Person, IAAuthKey ConfirmationKey);
sealed record AuthOutcome(TokenVerifier.VerifiedToken? Verified, IResult? Result);
sealed record OperationOutcome(IReadOnlyDictionary<string, R3Parameter>? Parameters, bool IsProposal, IResult? Result);

namespace Bookings
{
    /// <summary>Marker type for WebApplicationFactory&lt;T&gt;.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
