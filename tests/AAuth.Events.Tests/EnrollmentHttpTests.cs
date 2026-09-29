using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Samples.Events;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace AAuth.Events.Tests;

public class EnrollmentHttpTests
{
    [Fact]
    public async Task EnrollmentRequiresProofAndProviderAssignedIdentitySurvivesRestart()
    {
        var directory = Path.Combine(Path.GetTempPath(), "enrollment-http-" + Guid.NewGuid().ToString("N"));
        var database = Path.Combine(directory, "agents.db");
        var owner = AAuthKey.Generate();
        var attacker = AAuthKey.Generate();
        string? identity = null;
        string? kid = null;
        string? origin = null;
        try
        {
            for (var restart = 0; restart < 2; restart++)
            {
                var builder = WebApplication.CreateBuilder();
                builder.WebHost.UseUrls(origin ?? "http://127.0.0.1:0");
                builder.Logging.ClearProviders();
                await using var app = builder.Build();
                app.MapGet("/health", () => "ready");
                await app.StartAsync();
                origin = app.Urls.Single();
                var policy = new AAuthEgressPolicy([origin]);
                var registry = new SampleAgentRegistry(database);
                app.MapSampleAgentEnrollment(origin, AAuthKey.Generate(), "ap", policy, registry);
                using var http = AAuthHttpTransport.CreateClient(policy);
                async Task<HttpResponseMessage> Enrol(IAAuthSigner signingKey, IAAuthKey bodyKey, string? requested = null, bool signed = true)
                {
                    using var request = new HttpRequestMessage(HttpMethod.Post, origin + "/enrol")
                    { Content = JsonContent.Create(new { agent_id = requested, jwk = bodyKey.ToPublicJwk() }) };
                    if (signed)
                    {
                        request.Options.Set(AAuthSigningHandler.AdditionalComponentsKey, ["content-type", "content-digest"]);
                        using var signer = new AAuthSigningHandler(signingKey, new HwkSignatureKeyProvider(signingKey));
                        await signer.SignAsync(request);
                    }
                    return await http.SendAsync(request);
                }
                using var unsigned = await Enrol(owner, owner, identity, false);
                Assert.False(unsigned.IsSuccessStatusCode);
                using var hostile = await Enrol(attacker, attacker, identity ?? "aauth:administrator@victim.example");
                Assert.Equal(HttpStatusCode.Conflict, hostile.StatusCode);
                using var forged = await Enrol(attacker, owner, identity);
                Assert.Equal(HttpStatusCode.Forbidden, forged.StatusCode);
                using var accepted = await Enrol(owner, owner, identity);
                Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
                var result = (await accepted.Content.ReadFromJsonAsync<JsonObject>())!;
                if (identity is not null)
                {
                    Assert.Equal(identity, result["agent_id"]!.GetValue<string>());
                    Assert.Equal(kid, result["key_id"]!.GetValue<string>());
                }
                identity = result["agent_id"]!.GetValue<string>();
                kid = result["key_id"]!.GetValue<string>();
                var reenrolled = await AAuthClientBuilder.Bootstrap(origin + "/enrol")
                    .WithEgressPolicy(policy)
                    .WithKey(owner).WithKeyStore(new InMemoryKeyStore()).EnrolAsync();
                Assert.Equal(identity, reenrolled.AgentId);
                Assert.Equal(kid, reenrolled.AgentTokenKid);
                Assert.EndsWith("@127.0.0.1", identity);
                Assert.Single(registry.List());
                Assert.Equal(owner.ComputeJwkThumbprint(), registry.Find(identity)!.PublicKey.ComputeJwkThumbprint());
                await app.StopAsync();
            }
        }
        finally { Directory.Delete(directory, true); }
    }
}