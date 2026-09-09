using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Headers;
using AAuth.R3;
using AAuth.R3.Model;
using AAuth.Server;
using AAuth.Server.Verification;

var builder = WebApplication.CreateBuilder(args);
var issuer = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5006";
var access = builder.Configuration["AAuth:AccessServer"] ?? "http://localhost:5501";
var person = builder.Configuration["AAuth:PersonServer"] ?? "http://localhost:5100";
builder.WebHost.UseUrls(issuer);
var key = AAuthKey.Generate();
const string kid = "catalog-1";
var catalog = new Dictionary<string, string[]>(StringComparer.Ordinal)
{
    ["destinations"] = ["Kyoto", "Lisbon", "Montreal"],
    ["experiences"] = ["Museum visit", "City walking tour", "Cooking class"],
};
var metadata = R3Metadata.AddVocabularies(new JsonObject(), new Dictionary<string, JsonNode?>
{
    [Vocabulary.OpenApiGateway] = new JsonObject(catalog.Keys.Select(service =>
        KeyValuePair.Create<string, JsonNode?>(service, JsonValue.Create($"{issuer}/definitions/{service}")))),
});
var documents = new R3ProposalStore();
var descriptions = catalog.Keys.ToDictionary(service => service, service => documents.AddBytes(new R3Document
{
    Vocabulary = Vocabulary.OpenApiGateway,
    Operations = [R3Operation.OpenApiGateway(service, "list")],
    Display = new R3Display { Summary = $"Read the {service} travel catalog" },
}.ToUtf8Bytes(), new Uri(issuer), "/r3"));
builder.Services.AddAAuthResource(options =>
{
    options.EgressPolicy = SampleEgress.Policy; options.Issuer = issuer;
    options.Name = "Travel Catalog"; options.SigningKeys[kid] = key;
    options.AdditionalMetadata = metadata.ToDictionary(field => field.Key, field => field.Value);
});
var app = builder.Build();
app.MapAAuthWellKnown();
app.MapGet("/definitions/{service}", (string service) => catalog.ContainsKey(service)
    ? Results.Json(new JsonObject
    {
        ["openapi"] = "3.1.0", ["info"] = new JsonObject { ["title"] = service, ["version"] = "1.0.0" },
        ["paths"] = new JsonObject
        {
            [$"/catalog/{service}"] = new JsonObject { ["get"] = new JsonObject
            {
                ["operationId"] = "list", ["responses"] = new JsonObject { ["200"] = new JsonObject { ["description"] = "Catalog entries" } },
            } },
        },
    }) : Results.NotFound());
app.MapR3Document("/r3/{hash}", context => documents.TryGet((string)context.Request.RouteValues["hash"]!, out var bytes) ? bytes : null,
    new R3DocumentReaderPolicy(access, [person], SampleEgress.Policy));
app.UseWhen(context => context.Request.Path.StartsWithSegments("/catalog"), branch => branch.UseAAuthVerification(new AAuthVerificationOptions
{
    EgressPolicy = SampleEgress.Policy, ResourceIdentifier = issuer, AcceptedSchemes = ["jwt"],
    TrustedAuthTokenIssuers = new HashSet<string> { access },
}));
app.MapGet("/catalog/{service}", (string service, HttpContext context) =>
{
    if (!catalog.TryGetValue(service, out var entries)) return Results.NotFound();
    var identity = context.GetAAuthVerification()!;
    if (identity.TokenType == AAuthTokenType.AgentToken)
    {
        var request = new R3Operations { Vocabulary = Vocabulary.OpenApiGateway, Operations = [R3Operation.OpenApiGateway(service, "list")] };
        var definitions = catalog.Keys.Select(name => new R3OperationIdentity(Vocabulary.OpenApiGateway, R3Operation.OpenApiGateway(name, "list")));
        R3Metadata.ValidateOperations(request, metadata, definitions);
        var document = descriptions[service];
        var token = new R3Challenge { EgressPolicy = SampleEgress.Policy, ResourceIssuer = issuer, Audience = access, Key = key, KeyId = kid }
            .BuildResourceToken(identity.Agent!, identity.Jkt!, document.Uri, document.S256);
        context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatAuthToken(token);
        return AAuthProblemDetails.Create("auth_token_required", statusCode: 401);
    }
    var payload = context.GetAAuthParsedKey()!.Payload!;
    var decision = new R3Enforcement(documents, new Uri(issuer)).Evaluate(payload,
        new R3OperationIdentity(Vocabulary.OpenApiGateway, R3Operation.OpenApiGateway(service, "list")));
    return decision.Kind == R3EnforcementDecisionKind.Granted
        ? Results.Json(new { service, operationId = "list", entries, agent = identity.Agent, issuer = identity.Issuer,
            grant = payload["r3_granted"] })
        : decision.ToResult();
});
app.Run();

namespace Catalog { public sealed class Entry { private Entry() { } } }