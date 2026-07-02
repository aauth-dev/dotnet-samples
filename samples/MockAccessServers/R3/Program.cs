using AAuth.Crypto;
using AAuth.R3;

var builder = WebApplication.CreateBuilder(args);

var asKey = AAuthKey.Generate();
const string AsKid = "r3-as-1";

var issuer = (builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5501").TrimEnd('/');
// Person Servers this AS brokers for. draft-08 PS-AS trust (2026-06-29 narrative):
// an UNSET list is open (broker any *verifiable* PS — the spec default); an explicit
// list narrows (empty ⇒ deny-all), composed by AND with an optional IsTrustedPersonServer
// policy. This sample pins the demo PS (:5100) as the documented four-party pattern;
// set R3AccessServer:TrustedPersonServers to override.
var trustedPersonServers = builder.Configuration
    .GetSection("R3AccessServer:TrustedPersonServers")
    .Get<string[]>() ?? ["http://localhost:5100"];

// AS policy: which operations require per-call approval (r3_conditional) vs are
// granted outright (r3_granted). Per r3 §Auth Token Extensions the AS — not the
// resource — decides this, from the document's operations and its own policy. This
// dedicated Bookings AS treats confirmReservation (charges a deposit) as conditional;
// override via R3AccessServer:ConditionalOperations. Values are OpenAPI operationIds.
var conditionalOperations = (builder.Configuration
    .GetSection("R3AccessServer:ConditionalOperations")
    .Get<string[]>() ?? ["confirmReservation"])
    .ToHashSet(StringComparer.Ordinal);

builder.Services.AddSingleton(asKey);
// Shared discovery clients (MetadataClient + JwksClient) with an SDK-owned pooled
// handler; no manual HttpClient wiring (2026-06-27 server-api-surface convention).
builder.Services.AddAAuthDiscovery();

var app = builder.Build();

// Dedicated R3 Access Server (four-party). It fetches the resource's R3 document
// (AS-signed), hash-verifies it, splits granted vs conditional per its OWN policy
// (r3 §Auth Token Extensions — the AS decides, not the resource), mints the R3 auth
// token, and audits issuance. It guards the Bookings resource. The sibling `Federated`
// AS stays the scope-based AS for Wallet: one server per concept, mirroring MockResourceServers.
app.MapR3AccessTokenEndpoint(new R3AccessTokenEndpointOptions
{
    Issuer = issuer,
    SigningKeys = new Dictionary<string, AAuthKey> { [AsKid] = asKey },
    TrustedPersonServers = trustedPersonServers,
    // AS policy decides the granted-vs-conditional split (r3 §Auth Token Extensions).
    IsConditionalOperation = op => conditionalOperations.Contains(op.Id),
    // Diagnostic-only in-memory sink; a production R3 AS should configure a durable IR3AuditSink.
    AuditSink = new InMemoryR3AuditSink(),
});

app.Run();

namespace R3AccessServer
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c> in tests.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
