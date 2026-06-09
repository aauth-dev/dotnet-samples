using AAuth.Crypto;
using AAuth;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
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

builder.Services.AddSingleton(resourceKey);
builder.Services.AddSingleton(new AAuthVerifier
{
    MaxAge = TimeSpan.FromSeconds(signatureWindowSeconds),
});
builder.Services.AddSingleton<IJtiStore, InMemoryJtiStore>();
builder.Services.AddSingleton<MetadataClient>(sp =>
    new MetadataClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-metadata")));
builder.Services.AddSingleton<JwksClient>(sp =>
    new JwksClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-jwks")));
builder.Services.AddSingleton<ISignatureKeyResolver>(sp =>
    new DefaultSignatureKeyResolver(sp.GetRequiredService<JwksClient>()));
builder.Services.AddHttpClient("aauth-metadata");
builder.Services.AddHttpClient("aauth-jwks");

builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();
builder.Services.AddAAuthScopePolicy("AAuth.Scope.wallet.read", ScopeRead);
builder.Services.AddAAuthScopePolicy("AAuth.Scope.wallet.charge", ScopeCharge);

var app = builder.Build();

app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = resourceUrl,
    ClientName = "Aria Wallet",
    SigningKeys = new Dictionary<string, AAuthKey> { [ResourceKid] = resourceKey },
    ScopeDescriptions = new Dictionary<string, string>
    {
        [ScopeRead] = "See your balance and saved cards",
        [ScopeCharge] = "Charge your wallet to pay for travel",
    },
    SignatureWindow = signatureWindowSeconds,
});

// Four-party verification: the auth token is issued by the AS (iss = AS,
// dwk = aauth-access.json), so the AS is the trusted auth-token issuer here —
// not the PS.
AAuthVerificationOptions FederatedVerification() => new()
{
    ResourceIdentifier = resourceUrl,
    RequireIssuerVerification = true,
    TrustedAuthTokenIssuers = trustedAccessServers,
};

// Four-party challenge: the resource token's `aud` is the AS (via
// PersonServerAudience), which routes the PS to federate to the AS rather than
// asserting access itself.
ChallengeOptions ChallengeForFederated(string scope) => new()
{
    AccessMode = AAuthAccessMode.RequireAuthToken,
    ResourceSigningKey = resourceKey,
    ResourceKeyId = ResourceKid,
    ResourceIdentifier = resourceUrl,
    PersonServerAudience = accessServerUrl,
    DefaultScopes = scope,
};

// Declare the more specific /wallet/charge before the general /wallet.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/wallet/charge"),
    branch =>
    {
        branch.UseAAuthVerification(FederatedVerification());
        branch.UseAAuthChallenge(ChallengeForFederated(ScopeCharge));
    });
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/wallet")
        && !ctx.Request.Path.StartsWithSegments("/wallet/charge"),
    branch =>
    {
        branch.UseAAuthVerification(FederatedVerification());
        branch.UseAAuthChallenge(ChallengeForFederated(ScopeRead));
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
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        accessMode = "four-party",
        scheme = "jwt",
        access = "read",
        agent = result.Agent,
        sub = result.Subject,
        scope = result.Scopes,
        // In four-party the auth-token issuer is the Access Server, not the PS.
        iss = result.Issuer,
        userKey = result.Issuer is null ? null : $"{result.Issuer}|{result.Subject}",
        act = parsed.Payload?["act"],
    });
}).RequireAuthorization("AAuth.Scope.wallet.read");

// GET /wallet/charge — four-party payment. The AS grants `wallet.charge` ONLY
// to users carrying the `wallet.payer` role; everyone else is denied 403 by the
// Access Server's policy.
app.MapGet("/wallet/charge", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        accessMode = "four-party",
        scheme = "jwt",
        access = "charge",
        agent = result.Agent,
        sub = result.Subject,
        scope = result.Scopes,
        iss = result.Issuer,
        act = parsed.Payload?["act"],
    });
}).RequireAuthorization("AAuth.Scope.wallet.charge");

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
