// Live test: hit whoami.aauth.dev demonstrating all protocol modes.
// Parity with the reference agent at https://github.com/aauth-dev/web-agent-demo
//
// Mode 1:  No signature        → 401 + Accept-Signature header
// Mode 2a: aa-agent+jwt (no scope) → 200 + agent identity (sub echoed back)
// Mode 2b: aa-agent+jwt (scope)    → 401 + AAuth-Requirement (resource token)
// Mode 3:  Full 3-party flow       → 200 + identity claims (via PS exchange)
//
// Architecture:
//   - Local Kestrel server on port 5199 serving agent metadata + JWKS
//   - cloudflared quick tunnel exposes it publicly
//   - Uses the live Person Server at https://person.hello.coop
//   - Our SDK's SelfIssuing builder + WithChallengeHandling drives the 3-party flow
//
// The live PS has a user-consent interaction — the agent will print the
// interaction URL for you to approve in your browser.
//
// Usage: dotnet run --project samples/LiveWhoAmITest

using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AAuth.Crypto;
using AAuth.Errors;
using AAuth.HttpSig;
using AAuth.Server;

const string WhoAmIUrl = "https://whoami.aauth.dev/";
const string PersonServer = "https://person.hello.coop";
const string Subject = "aauth:live-test@dotnet-samples";
const int LocalPort = 5199;

Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
Console.WriteLine("║   Live WhoAmI Test — All 3 Protocol Modes                   ║");
Console.WriteLine("║   Resource: whoami.aauth.dev                                 ║");
Console.WriteLine("║   Person Server: person.hello.coop                           ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
Console.WriteLine();

// ── 1. Generate agent key ───────────────────────────────────────────────────
var agentKey = AAuthKey.Generate();
var agentKid = agentKey.ComputeJwkThumbprint();
Console.WriteLine($"Generated agent key (kid: {agentKid[..12]}...)");
Console.WriteLine();

// ── 2. Start local agent metadata server ────────────────────────────────────
var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args });
builder.WebHost.UseUrls($"http://localhost:{LocalPort}");
builder.Logging.SetMinimumLevel(LogLevel.Warning);
var app = builder.Build();

string? tunnelUrl = null;

// Agent well-known metadata (whoami fetches {iss}/.well-known/aauth-agent.json)
app.MapGet("/.well-known/aauth-agent.json", () => Results.Json(new JsonObject
{
    ["issuer"] = tunnelUrl,
    ["jwks_uri"] = $"{tunnelUrl}/.well-known/jwks.json",
    ["client_name"] = "AAuth .NET SDK Live Test",
}, contentType: "application/json"));

app.MapGet("/.well-known/jwks.json", () =>
{
    var jwk = agentKey.ToPublicJwk();
    jwk["kid"] = agentKid;
    jwk["key_ops"] = new JsonArray("verify");
    return Results.Json(new JsonObject { ["keys"] = new JsonArray(jwk) }, contentType: "application/json");
});

app.MapGet("/health", () => Results.Ok("ok"));

await app.StartAsync();
Console.WriteLine($"Local agent metadata server on http://localhost:{LocalPort}");

// ── 3. Start cloudflared tunnel ─────────────────────────────────────────────
Console.WriteLine("Starting cloudflared quick tunnel...");

var tunnelProcess = new Process
{
    StartInfo = new ProcessStartInfo
    {
        FileName = "cloudflared",
        Arguments = $"tunnel --url http://localhost:{LocalPort} --no-autoupdate",
        RedirectStandardError = true,
        RedirectStandardOutput = true,
        UseShellExecute = false,
        CreateNoWindow = true,
    },
};
tunnelProcess.Start();

tunnelUrl = await WaitForTunnelUrl(tunnelProcess);
if (tunnelUrl is null)
{
    Console.Error.WriteLine("ERROR: Failed to get tunnel URL from cloudflared.");
    tunnelProcess.Kill();
    return 1;
}

Console.WriteLine($"Tunnel URL (agent issuer): {tunnelUrl}");

// Wait for tunnel readiness
Console.WriteLine("Waiting for tunnel to become reachable...");
using var verifyClient = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
for (int attempt = 1; attempt <= 15; attempt++)
{
    try
    {
        var healthResp = await verifyClient.GetAsync($"{tunnelUrl}/health");
        if (healthResp.IsSuccessStatusCode)
        {
            Console.WriteLine($"Tunnel ready (attempt {attempt})");
            break;
        }
        Console.WriteLine($"  Attempt {attempt}: HTTP {(int)healthResp.StatusCode}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Attempt {attempt}: {ex.GetType().Name}");
    }
    await Task.Delay(3000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODE 1: No signature — raw GET, expect 401 + Accept-Signature
// ═══════════════════════════════════════════════════════════════════════════════
Console.WriteLine();
Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
Console.WriteLine("MODE 1: No signature → 401 + Accept-Signature");
Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
Console.WriteLine();

using var rawClient = new HttpClient();
var rawResp = await rawClient.GetAsync(WhoAmIUrl);

Console.WriteLine($"  Status: {(int)rawResp.StatusCode} {rawResp.ReasonPhrase}");
if (rawResp.Headers.TryGetValues("Accept-Signature", out var acceptSigValues))
    Console.WriteLine($"  Accept-Signature: {string.Join(", ", acceptSigValues)}");
var rawBody = await rawResp.Content.ReadAsStringAsync();
Console.WriteLine($"  Body: {rawBody}");
Console.WriteLine();
Console.WriteLine("  → Resource tells the agent: sign with these components, use JWT key scheme.");

// ═══════════════════════════════════════════════════════════════════════════════
// MODE 2a: aa-agent+jwt (no scope) — agent identity returned directly
// ═══════════════════════════════════════════════════════════════════════════════
Console.WriteLine();
Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
Console.WriteLine("MODE 2a: aa-agent+jwt (no scope) → 200 + agent identity");
Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
Console.WriteLine();

// Build a client without challenge handling — unscoped requests get 200 directly
using var mode2aClient = AAuthClientBuilder.SelfIssuing(agentKey)
    .As(tunnelUrl!, Subject)
    .WithKid(agentKid)
    .WithPersonServer(PersonServer)
    .Build();

var mode2aResp = await mode2aClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, WhoAmIUrl));

Console.WriteLine($"  Status: {(int)mode2aResp.StatusCode} {mode2aResp.ReasonPhrase}");
var mode2aBody = await mode2aResp.Content.ReadAsStringAsync();
if (mode2aResp.IsSuccessStatusCode)
{
    Console.WriteLine($"  Body: {mode2aBody}");
    Console.WriteLine();
    Console.WriteLine("  → Resource verified agent token via JWKS, returned agent's self-asserted sub.");
    Console.WriteLine("    No PS involvement needed — whoami echoes the agent identity for unscoped requests.");
}
else
{
    Console.WriteLine($"  Body: {mode2aBody}");
    Console.WriteLine();
    Console.WriteLine($"  ⚠ Expected 200 but got {(int)mode2aResp.StatusCode}.");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODE 2b: aa-agent+jwt (with scope) — agent introduces itself, gets resource_token
// ═══════════════════════════════════════════════════════════════════════════════
Console.WriteLine();
Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
Console.WriteLine("MODE 2b: aa-agent+jwt (scope=email) → 401 + AAuth-Requirement");
Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
Console.WriteLine();

// Build a client WITHOUT challenge handling so we see the raw 401 + resource_token
using var mode2bClient = AAuthClientBuilder.SelfIssuing(agentKey)
    .As(tunnelUrl!, Subject)
    .WithKid(agentKid)
    .WithPersonServer(PersonServer)
    .Build();

var mode2bResp = await mode2bClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"{WhoAmIUrl}?scope=email"));

Console.WriteLine($"  Status: {(int)mode2bResp.StatusCode} {mode2bResp.ReasonPhrase}");
if (mode2bResp.Headers.TryGetValues("AAuth-Requirement", out var reqValues))
{
    var reqHeader = string.Join(", ", reqValues);
    Console.WriteLine($"  AAuth-Requirement: {(reqHeader.Length > 100 ? reqHeader[..100] + "..." : reqHeader)}");
}
var mode2bBody = await mode2bResp.Content.ReadAsStringAsync();
Console.WriteLine($"  Body: {mode2bBody}");
Console.WriteLine();
Console.WriteLine("  → Resource verified our agent token via our tunneled JWKS,");
Console.WriteLine("    read the 'ps' claim (person.hello.coop), and minted a resource_token");
Console.WriteLine("    audienced to the PS. Agent takes this to the PS to get an auth_token.");

// ═══════════════════════════════════════════════════════════════════════════════
// MODE 3: Full 3-party flow — WithChallengeHandling does it automatically
// ═══════════════════════════════════════════════════════════════════════════════
Console.WriteLine();
Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
Console.WriteLine("MODE 3: aa-auth+jwt — full 3-party flow (automated)");
Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
Console.WriteLine();
Console.WriteLine("  Flow: agent_token → 401/resource_token → PS exchange → auth_token → 200");
Console.WriteLine("  Using live PS at person.hello.coop (may require user consent)");
Console.WriteLine();

using var mode3Client = AAuthClientBuilder.SelfIssuing(agentKey)
    .As(tunnelUrl!, Subject)
    .WithKid(agentKid)
    .WithPersonServer(PersonServer)
    .WithChallengeHandling(opts =>
    {
        opts.PreferWaitSeconds = 45;
        opts.MinPollInterval = TimeSpan.FromSeconds(2);
        opts.OnInteractionRequired = (interaction, ct) =>
        {
            Console.WriteLine();
            Console.WriteLine("  ┌─────────────────────────────────────────────────────────┐");
            Console.WriteLine("  │  USER ACTION REQUIRED                                   │");
            Console.WriteLine("  │  Open this URL in your browser to approve:              │");
            Console.WriteLine($"  │  {interaction.BuildUserUrl()}");
            Console.WriteLine("  └─────────────────────────────────────────────────────────┘");
            Console.WriteLine();

            // Also try to open in browser
            try { Process.Start(new ProcessStartInfo(interaction.BuildUserUrl()) { UseShellExecute = true }); }
            catch { /* not critical */ }

            return Task.CompletedTask;
        };
        opts.OnPoll = response =>
        {
            Console.WriteLine($"    [poll] {(int)response.StatusCode} {response.ReasonPhrase}");
        };
    })
    .Build();

HttpResponseMessage? mode3Resp = null;
try
{
    mode3Resp = await mode3Client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"{WhoAmIUrl}?scope=email"));
}
catch (AAuthTokenExchangeException ex)
{
    Console.WriteLine();
    Console.WriteLine($"  Token exchange error: {ex.ErrorCode} (HTTP {ex.StatusCode}, terminal={ex.IsTerminal})");
    if (!string.IsNullOrEmpty(ex.ErrorDescription))
    {
        Console.WriteLine($"    {ex.ErrorDescription}");
    }
    Console.WriteLine();
    Console.WriteLine("  This is expected if:");
    Console.WriteLine("    - The user has no Hellō account / registered devices");
    Console.WriteLine("    - The agent has no callback_endpoint for interaction");
    Console.WriteLine("  The PS couldn't reach the user to obtain consent.");
    Console.WriteLine();
    Console.WriteLine("  To complete Mode 3, you need a Hellō account linked to");
    Console.WriteLine("  person.hello.coop. The PS would then send you a push/redirect");
    Console.WriteLine("  for consent, and return an auth_token with your identity claims.");
}
catch (HttpRequestException ex)
{
    Console.WriteLine();
    Console.WriteLine($"  Token exchange error: {ex.Message}");
    Console.WriteLine();
    Console.WriteLine("  This is expected if:");
    Console.WriteLine("    - The user has no Hellō account / registered devices");
    Console.WriteLine("    - The agent has no callback_endpoint for interaction");
    Console.WriteLine("  The PS couldn't reach the user to obtain consent.");
    Console.WriteLine();
    Console.WriteLine("  To complete Mode 3, you need a Hellō account linked to");
    Console.WriteLine("  person.hello.coop. The PS would then send you a push/redirect");
    Console.WriteLine("  for consent, and return an auth_token with your identity claims.");
}

if (mode3Resp is not null)
{
    Console.WriteLine();
    Console.WriteLine($"  Status: {(int)mode3Resp.StatusCode} {mode3Resp.ReasonPhrase}");
    var mode3Body = await mode3Resp.Content.ReadAsStringAsync();
    if (mode3Resp.IsSuccessStatusCode)
    {
        Console.WriteLine("  Identity claims returned by whoami.aauth.dev:");
        try
        {
            var formatted = JsonSerializer.Serialize(
                JsonSerializer.Deserialize<JsonElement>(mode3Body),
                new JsonSerializerOptions { WriteIndented = true });
            foreach (var line in formatted.Split('\n'))
                Console.WriteLine($"    {line}");
        }
        catch { Console.WriteLine($"    {mode3Body}"); }
        Console.WriteLine();
        Console.WriteLine("  ✓ Full three-party flow complete!");
        Console.WriteLine("    Agent → whoami (agent_token) → PS (resource_token) → auth_token → whoami → claims");
    }
    else
    {
        Console.WriteLine($"  Body: {mode3Body}");
        Console.WriteLine();
        Console.WriteLine("  Response headers:");
        foreach (var h in mode3Resp.Headers)
            Console.WriteLine($"    {h.Key}: {string.Join(", ", h.Value)}");
    }
}

// ── Cleanup ─────────────────────────────────────────────────────────────────
Console.WriteLine();
Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
Console.WriteLine("Done. Shutting down...");
tunnelProcess.Kill();
await app.StopAsync();
return 0;

// ── Helpers ─────────────────────────────────────────────────────────────────
static async Task<string?> WaitForTunnelUrl(Process process)
{
    var regex = new Regex(@"https://[a-z0-9\-]+\.trycloudflare\.com", RegexOptions.IgnoreCase);
    var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

    try
    {
        while (!cts.Token.IsCancellationRequested)
        {
            var line = await process.StandardError.ReadLineAsync(cts.Token);
            if (line is null) break;

            var match = regex.Match(line);
            if (match.Success)
                return match.Value;
        }
    }
    catch (OperationCanceledException) { }

    return null;
}
