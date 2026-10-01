using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AAuth.Tests.Configuration;

/// <summary>The options convention: named options, a shape validator, and failure at host start.</summary>
public class AAuthOptionsValidatorTests
{
    private sealed class RoleOptions
    {
        public string? Issuer { get; set; }
    }

    private sealed class RoleOptionsValidator : AAuthOptionsValidator<RoleOptions>
    {
        protected override void Validate(string? name, RoleOptions options, List<string> failures)
        {
            if (string.IsNullOrEmpty(options.Issuer)) failures.Add($"RoleOptions '{name}': Issuer is required.");
        }
    }

    private static IHost Build(string? issuer)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Services.AddValidatedAAuthOptions<RoleOptions, RoleOptionsValidator>("ps")
            .Configure(o => o.Issuer = issuer);
        return builder.Build();
    }

    [Fact(DisplayName = "invalid named options fail when the host starts")]
    public async Task InvalidOptions_FailAtStart()
    {
        using var host = Build(issuer: null);
        var failure = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync());
        Assert.Contains("RoleOptions 'ps': Issuer is required.", failure.Failures);
    }

    [Fact(DisplayName = "valid named options start and resolve by name")]
    public async Task ValidOptions_Start()
    {
        using var host = Build("https://ps.example");
        await host.StartAsync();
        Assert.Equal("https://ps.example", host.Services.GetRequiredService<IOptionsMonitor<RoleOptions>>().Get("ps").Issuer);
        await host.StopAsync();
    }
}
