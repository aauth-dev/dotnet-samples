using System.Collections.Concurrent;
using AAuth;
using AAuth.Crypto;
using AAuth.Headers;
using AAuth.Server;
using AAuth.Server.Challenge;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.WebUtilities;

var builder = WebApplication.CreateBuilder(args);
var issuer = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5007";
var person = builder.Configuration["AAuth:PersonServer"] ?? "http://localhost:5100";
builder.WebHost.UseUrls(issuer);
var key = AAuthKey.Generate();
const string kid = "documents-1";
var scopes = new Dictionary<string, string> { ["documents.read"] = "Read the released travel document" };
builder.Services.AddAAuthResource(options =>
{
    options.EgressPolicy = SampleEgress.Policy;
    options.Issuer = issuer;
    options.Name = "Document Release";
    options.SigningKeys[kid] = key;
    options.ScopeDescriptions = scopes;
});
var app = builder.Build();
app.MapAAuthWellKnown();
var permissions = new ConcurrentDictionary<string, Permission>();
var callbacks = new ConcurrentDictionary<string, string>();
var sessions = new BrowserConsentSessions("AAuth.Documents.Consent",
    builder.Configuration.GetValue<bool>("AAuth:EnableIsolatedDemoConsent") ? "document-owner-demo" : null);
app.UseWhen(context => context.Request.Path == "/document", branch => branch.UseAAuthVerification(new AAuthVerificationOptions
{
    EgressPolicy = SampleEgress.Policy, ResourceIdentifier = issuer, AcceptedSchemes = ["jwt"],
    ExpectedAccount = _ => "work",
    TrustedAuthTokenIssuers = new HashSet<string> { person },
}));
var challenge = new ChallengeOptions
{
    EgressPolicy = SampleEgress.Policy, ResourceIdentifier = issuer, ResourceSigningKey = key, ResourceKeyId = kid,
};
app.MapGet("/document", (HttpContext context) =>
{
    foreach (var expired in permissions.Where(pair => pair.Value.ExpiresAt <= DateTimeOffset.UtcNow)) permissions.TryRemove(expired.Key, out _);
    var identity = context.GetAAuthVerification()!;
    // §Person Token Required: learn who the agent acts for before issuing anything.
    if (identity.TokenType == AAuthTokenType.AgentToken)
    {
        context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatPersonToken();
        return AAuthProblemDetails.Create("person_token_required", statusCode: 401);
    }
    var personKey = $"{identity.PersonServer}|{identity.Subject}";
    if (identity.TokenType == AAuthTokenType.PersonToken)
    {
        var permission = new Permission(personKey, identity.Jkt!);
        permissions[permission.Id] = permission;
        var token = AAuthChallengeMiddleware.BuildResourceToken(challenge, context.GetAAuthVerifiedAssertion()!,
            "documents.read", account: "work", scopeDescriptions: scopes,
            interaction: new Interaction(issuer + "/permission", permission.Browser.Code));
        context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatAuthToken(token);
        return AAuthProblemDetails.Create("auth_token_required", statusCode: 401);
    }
    var payload = context.GetAAuthParsedKey()!.Payload!;
    if ((string?)payload["scope"] != "documents.read" || (string?)payload["account"] != "work"
        || !permissions.Values.Any(permission => permission.Allowed && permission.Person == personKey && permission.Key == identity.Jkt))
        return AAuthProblemDetails.Create("denied", statusCode: 403);
    return Results.Json(new { title = "Travel document", released = true, account = "work", content = "Confirmed itinerary: Kyoto, 14 September.", sub = identity.Subject });
});
app.MapMethods("/permission", ["GET", "POST"], async (HttpContext context) =>
{
    var entered = await sessions.EnterAsync(context, code => permissions.Values.FirstOrDefault(permission => permission.Browser.Code == code) is { } permission
        ? new BrowserPendingRequest(permission.Id, permission.ExpiresAt, permission.Browser, permission.Lifecycle) : null);
    if (entered.Error is Microsoft.AspNetCore.Http.HttpResults.RedirectHttpResult redirect && redirect.Url is { } url
        && QueryHelpers.ParseQuery(new Uri(new Uri(issuer), url).Query).TryGetValue("session", out var session))
    {
        var callback = context.Request.Query["callback"].ToString();
        try { await SampleEgress.Policy.ValidateDestinationAsync(callback, context.RequestAborted); }
        catch (Exception exception) when (exception is HttpRequestException or System.Net.Sockets.SocketException or ArgumentException)
        { return AAuthProblemDetails.Create("invalid_callback", statusCode: 400); }
        callbacks[session.ToString()] = callback;
    }
    if (entered.Error is not null) return entered.Error;
    return Results.Content("<!doctype html><meta charset=utf-8><title>Release travel document</title>"
        + "<main><h1>Release travel document</h1><p>Work account</p>"
        + "<form method=post action='/permission/approve'>" + sessions.Fields(context, entered.Decision!)
        + "<button type=submit>Release document</button></form><form method=post action='/permission/deny'>"
        + sessions.Fields(context, entered.Decision!) + "<button type=submit>Decline release</button></form></main>", "text/html");
});
foreach (var action in new[] { "approve", "deny" })
    app.MapPost("/permission/" + action, async (HttpContext context) =>
    {
        var decision = await sessions.DecideAsync(context);
        if (decision.Error is not null) return decision.Error;
        if (!callbacks.TryRemove(context.Request.Form["session"].ToString(), out var callback)
            || !permissions.TryGetValue(decision.Decision!.Id, out var permission))
            return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
        return await decision.Decision.ApplyAsync(context, () =>
        {
            permission.Allowed = action == "approve";
            permission.Lifecycle.Cancel();
            return Results.Redirect(action == "approve" ? callback : QueryHelpers.AddQueryString(callback, "error", "access_denied"));
        });
    }).DisableAntiforgery();
app.Run();

sealed class Permission(string person, string key)
{
    public string Id { get; } = Guid.NewGuid().ToString("N");
    public string Person { get; } = person;
    public string Key { get; } = key;
    public bool Allowed { get; set; }
    public DateTimeOffset ExpiresAt { get; } = DateTimeOffset.UtcNow.AddMinutes(5);
    public BrowserInteraction Browser { get; } = new();
    public DeferredState Lifecycle { get; } = new();
}