using AAuth.Crypto;
using AAuth.Server.Verification;

// ---------------------------------------------------------------------------
// Wallet — Aria's federated resource server (Federated / four-party).
//
// The Wallet is the bank: it has its OWN Access Server that enforces payment
// policy. Aria cannot get a token from the user's Person Server directly — the
// resource token's `aud` is the Access Server, so the PS federates to the AS,
// which evaluates policy and mints the auth token.
//
//   PATH             SCOPE          POLICY (enforced by the Access Server)
//   /wallet          wallet.read    view balance + cards — any authenticated user
//   /wallet/charge   wallet.charge  initiate a payment — ONLY users carrying the
//                                   `wallet.payer` role at the Access Server
//
// /wallet/charge is where the four-party model earns its keep: a real-world
// "only an authorised payer can spend money" gate, decided by the bank's own
// Access Server rather than the resource. (Keycloak: `demo` has wallet.payer
// and can charge; `guest` does not and is denied 403.)
// ---------------------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);

var resourceKey = AAuthKey.Generate();
const string ResourceKid = "wallet-1";

const string ScopeRead = "wallet.read";
const string ScopeCharge = "wallet.charge";

var resourceUrl = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5003";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;

// Access Server for the four-party flow. The resource issues a resource token
// whose `aud` is this AS (not the PS); the PS federates to the AS, which mints
// the auth token (iss = AS, dwk = aauth-access.json). The resource trusts the
// AS as the auth-token issuer.
var accessServerUrl = builder.Configuration["AAuth:AccessServer"] ?? "http://localhost:5500";
var trustedAccessServers = new HashSet<string> { accessServerUrl };
var trustedPersonServers = builder.Configuration.GetSection("AAuth:TrustedPersonServers").Get<string[]>() ?? ["http://localhost:5100"];

// One DI call: verifier, discovery clients (pooled handler), JTI store, and the
// published metadata — no manual HttpClient/discovery wiring.
builder.Services.AddAAuthResource(o =>
{
    o.EgressPolicy = SampleEgress.Policy;
    o.Issuer = resourceUrl;
    o.RevocationEndpoint = $"{resourceUrl}/revoke";
    o.SigningKeys[ResourceKid] = resourceKey;
    o.MaxSignatureAge = TimeSpan.FromSeconds(signatureWindowSeconds);
    o.SignatureWindow = signatureWindowSeconds;
    o.Name = "Aria Wallet";
    o.ScopeDescriptions = new Dictionary<string, string>
    {
        [ScopeRead] = "See your balance and saved cards",
        [ScopeCharge] = "Charge your wallet to pay for travel",
        ["wallet.review"] = "Review the wallet after explaining the travel purpose",
    };
});
builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();

var app = builder.Build();

// Well-known metadata + JWKS from the DI-registered resource metadata.
app.MapAAuthWellKnown();
// Revocations are keyed by (verified caller, jti): the AS revokes the auth tokens
// it issued, a PS the person tokens it issued. Other callers get unsupported_iss.
AAuth.Server.RevocationEndpoint.MapAAuthRevocationEndpoint(app,
    app.Services.GetRequiredService<AAuth.Server.IJtiStore>(), options =>
        options.IsAcceptedIssuer = caller => caller == accessServerUrl || trustedPersonServers.Contains(caller, StringComparer.Ordinal));

// One declarative pipeline. Four-party: the resource token's `aud` is the AS,
// routing the PS to federate; the AS is the trusted auth-token issuer
// (iss = AS, dwk = aauth-access.json) and the PS the trusted person-token issuer.
app.UseRouting();
app.UseAAuth(o =>
{
    o.Trust.AuthTokenIssuers.Allowed = trustedAccessServers;
    o.Trust.PersonServers.Allowed = trustedPersonServers.ToHashSet();
    o.AccessServer = accessServerUrl;
});

app.UseAuthentication();
app.UseAuthorization();

// GET / — Flow index. No AAuth required.
app.MapGet("/", () => Results.Ok(new
{
    resource = "Aria Wallet",
    accessMode = "four-party",
    flows = new[]
    {
        new { path = "/wallet", auth = "AAuth.Scope.wallet.read" },
        new { path = "/wallet/charge", auth = "AAuth.Scope.wallet.charge" },
    },
}));

// GET /wallet — four-party baseline read. The AS grants `wallet.read` to any
// authenticated user.
app.MapGet("/wallet", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;

    return Results.Ok(new
    {
        accessMode = "four-party",
        scheme = "jwt",
        access = "read",
        ps = result.PersonServer,
        sub = result.Subject,
        scope = result.Scopes,
        // In four-party the auth-token issuer is the Access Server, not the PS.
        iss = result.Issuer,
        userKey = result.PersonServer is null ? null : $"{result.PersonServer}|{result.Subject}",
    });
}).RequireAAuth(scope: ScopeRead);

// GET /wallet/charge — four-party payment. The AS grants `wallet.charge` ONLY
// to users carrying the `wallet.payer` role; everyone else is denied 403 by the
// Access Server's policy.
app.MapGet("/wallet/charge", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;

    return Results.Ok(new
    {
        accessMode = "four-party",
        scheme = "jwt",
        access = "charge",
        ps = result.PersonServer,
        sub = result.Subject,
        scope = result.Scopes,
        iss = result.Issuer,
    });
}).RequireAAuth(scope: ScopeCharge);

app.MapGet("/wallet/review", (HttpContext context) => Results.Ok(new
{
    access = "review", ps = context.GetAAuthVerification()!.PersonServer,
    iss = context.GetAAuthVerification()!.Issuer, scope = "wallet.review",
    review = "Wallet is available for the approved travel review.",
})).RequireAAuth(scope: "wallet.review");

app.Run();

// Marker type for `WebApplicationFactory<Wallet.Entry>` in integration tests.
namespace Wallet
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
