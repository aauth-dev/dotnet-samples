using System;
using System.Linq;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using static AAuth.Conformance.Discovery.RevocationLifecycleTests;

namespace AAuth.Conformance.Discovery;

public class BackgroundRevocationTests
{
    private const string Person = RevocationLifecycleTests.Person;

    [Fact(DisplayName = "§Revocation Cascade — app code revokes through the role's service with no HttpContext")]
    public async Task RevokeToken_FromBackgroundWork_WithoutHttpContext()
    {
        await using var graph = await Graph.CreateAsync();
        var agent = await graph.AgentTokenAsync(FirstProvider, "background-agent");
        var person = await graph.IssuePersonTokenAsync(agent, FirstResource);
        var jti = (string)Decode(person)["jti"]!;
        var accessor = new HttpContextAccessor();

        var result = await Task.Run(async () =>
        {
            Assert.Null(accessor.HttpContext);
            return await graph.PersonRevocation.RevokeTokenAsync(jti);
        });

        Assert.Equal(FirstResource, Assert.Single(result.Downstream).Recipient);
        Assert.Null(result.Downstream[0].Error);
        Assert.Contains(graph.Revocations, entry => entry.Resource == FirstResource && entry.Token == new TokenKey(Person, jti));
    }

    [Fact(DisplayName = "§Token Revocation — the role's service signs downstream revocations as the role identity")]
    public async Task RevokeAt_SignsAsRoleIdentity()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var recipient = builder.Build();
        string? signatureKey = null, signatureInput = null;
        recipient.MapPost("/revoke", (HttpContext context) =>
        {
            signatureKey = context.Request.Headers["Signature-Key"];
            signatureInput = context.Request.Headers["Signature-Input"];
            return Results.Ok();
        });
        await recipient.StartAsync();
        var origin = recipient.Urls.Single().Replace("127.0.0.1", "localhost", StringComparison.Ordinal);

        const string issuer = "https://person.example";
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAAuthPersonServer(configure: options =>
        {
            options.Issuer = issuer;
            options.EgressPolicy = AAuthEgressPolicy.ForDevelopmentLoopback(origin);
            options.SigningKeys = new AAuthSigningKeySet { ["ps-key"] = AAuthKey.Generate() };
        });
        await using var provider = services.BuildServiceProvider();
        var revocation = provider.GetRequiredKeyedService<IAAuthRevocationService>(AAuthPersonServerBuilder.DefaultName);

        var result = await revocation.RevokeAtAsync(new Uri(origin + "/revoke"), "person-token", DateTimeOffset.UtcNow.AddMinutes(5));

        Assert.Null(result.Error);
        Assert.NotNull(signatureKey);
        Assert.Contains("jwks_uri", signatureKey);
        Assert.Contains($"id=\"{issuer}\"", signatureKey);
        Assert.Contains("dwk=\"aauth-person.json\"", signatureKey);
        Assert.Contains("kid=\"ps-key\"", signatureKey);
        Assert.Contains("\"content-digest\"", signatureInput);
    }
}
