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
// Both backends expose `list`; R3 -11 requires one merged definition with unique operationIds.
static string OperationId(string service) => "list" + char.ToUpperInvariant(service[0]) + service[1..];
var metadata = R3Metadata.AddVocabularies(new JsonObject(), new Dictionary<string, string>
{
    [Vocabulary.OpenApi] = $"{issuer}/openapi.json",
});
var documents = new R3ProposalStore();
var descriptions = catalog.Keys.ToDictionary(service => service, service => documents.AddBytes(new R3Document
{
    Vocabulary = Vocabulary.OpenApi,
    Operations = [R3Operation.OpenApi(OperationId(service))],
    Display = new R3Display { Summary = $"Read the {service} travel catalog" },
}.ToUtf8Bytes(), new Uri(issuer), "/r3"));
var authoritativeDefinitions = new StaticR3AuthoritativeDefinitionProvider(
    catalog.Keys.Select(name => new R3OperationIdentity(Vocabulary.OpenApi, R3Operation.OpenApi(OperationId(name)))));
var operationValidator = new R3OperationValidator(documents, authoritativeDefinitions);
builder.Services.AddAAuthResource(options =>
{
    options.EgressPolicy = SampleEgress.Policy; options.Issuer = issuer;
    options.AccessServer = access;
    options.RevocationEndpoint = $"{issuer}/revoke";
    options.ConfigureRevocation = revocation =>
        revocation.IsAcceptedIssuer = caller => caller == access || caller == person;
    options.Name = "Travel Catalog"; options.SigningKeys[kid] = key;
    options.AdditionalMetadata = metadata.ToDictionary(field => field.Key, field => field.Value);
});
// The reader policy for MapR3Document; R3Challenge mints entitle the aud and ps to read each document.
builder.Services.AddAAuthR3Documents(_ => new R3DocumentReaderPolicy(access, [person], SampleEgress.Policy));
var app = builder.Build();
app.MapAAuthWellKnown();
app.MapAAuthResourceRevocation();
app.MapGet("/openapi.json", () => Results.Json(new JsonObject
{
    ["openapi"] = "3.1.0", ["info"] = new JsonObject { ["title"] = "Travel Catalog", ["version"] = "1.0.0" },
    ["paths"] = new JsonObject(catalog.Keys.Select(service => KeyValuePair.Create<string, JsonNode?>(
        $"/catalog/{service}", new JsonObject { ["get"] = new JsonObject
        {
            ["operationId"] = OperationId(service),
            ["responses"] = new JsonObject { ["200"] = new JsonObject { ["description"] = $"{service} entries" } },
        } }))),
}));
app.MapR3Document("/r3/{hash}", context => documents.TryGet((string)context.Request.RouteValues["hash"]!, out var bytes) ? bytes : null);
app.UseWhen(context => context.Request.Path.StartsWithSegments("/catalog"), branch => branch.UseAAuthVerification(options =>
{
    options.EgressPolicy = SampleEgress.Policy;
    options.ResourceIdentifier = issuer;
    options.AcceptedSchemes = ["jwt"];
    options.ExpectedAuthTokenDwk = AAuthConstants.DwkFiles.Access;
    options.Trust.AuthTokenIssuers.Allowed = new HashSet<string> { access };
    options.Trust.PersonServers.Allowed = new HashSet<string> { person };
}));
app.MapGet("/catalog/{service}", async (string service, HttpContext context) =>
{
    if (!catalog.TryGetValue(service, out var entries)) return Results.NotFound();
    var identity = context.GetAAuthVerification()!;
    var operation = new R3OperationIdentity(Vocabulary.OpenApi, R3Operation.OpenApi(OperationId(service)));
    if (identity.TokenType is AAuthTokenType.AgentToken or AAuthTokenType.PersonToken)
    {
        var request = new R3Operations { Vocabulary = Vocabulary.OpenApi, Operations = [operation.Operation] };
        var definitions = catalog.Keys.Select(name => new R3OperationIdentity(Vocabulary.OpenApi, R3Operation.OpenApi(OperationId(name))));
        R3Metadata.ValidateOperations(request, metadata, definitions);
        var document = descriptions[service];
        // Agent token -> person-token requirement; person token -> R3 resource token naming it.
        return await new R3Challenge { EgressPolicy = SampleEgress.Policy, ResourceIssuer = issuer, Audience = access,
                Key = key, KeyId = kid, OperationValidator = operationValidator }
            .ChallengeAsync(context, document.Uri, document.S256);
    }
    var payload = context.GetAAuthParsedKey()!.Payload!;
    var decision = new R3Enforcement(documents, new Uri(issuer), egressPolicy: SampleEgress.Policy).Evaluate(payload, operation);
    return decision.Kind == R3EnforcementDecisionKind.Granted
        ? Results.Json(new { service, operationId = OperationId(service), entries, sub = identity.Subject, issuer = identity.Issuer,
            grant = payload["r3_granted"] })
        : decision.ToResult();
});
app.Run();

namespace Catalog { public sealed class Entry { private Entry() { } } }