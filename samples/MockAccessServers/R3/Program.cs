using AAuth.Crypto;
using AAuth.R3;

var builder = WebApplication.CreateBuilder(args);

var asKey = AAuthKey.Generate();
const string AsKid = "r3-as-1";

var issuer = (builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5501").TrimEnd('/');
var trustedPersonServers = builder.Configuration
    .GetSection("R3AccessServer:TrustedPersonServers")
    .Get<string[]>() ?? ["http://localhost:5100"];

builder.Services.AddSingleton(asKey);
// Shared discovery clients (MetadataClient + JwksClient) with an SDK-owned pooled
// handler; no manual HttpClient wiring (2026-06-27 server-api-surface convention).
builder.Services.AddAAuthDiscovery();

var app = builder.Build();

// Dedicated R3 Access Server (four-party). It fetches the resource's R3 document
// (AS-signed), hash-verifies it, splits granted vs conditional from the document's
// own `conditional` list — no per-server tool config — mints the R3 auth token, and
// audits issuance. It guards the Bookings resource. The sibling `Federated` AS stays
// the scope-based AS for Wallet: one server per concept, mirroring MockResourceServers.
app.MapR3AccessTokenEndpoint(new R3AccessTokenEndpointOptions
{
    Issuer = issuer,
    SigningKeys = new Dictionary<string, AAuthKey> { [AsKid] = asKey },
    TrustedPersonServers = trustedPersonServers,
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
