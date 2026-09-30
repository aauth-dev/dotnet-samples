using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.DependencyInjection;

/// <summary>
/// Every public configuration method of the builder primitive maps to an
/// <see cref="AAuthAgentOptions"/> member or an <see cref="AAuthAgentBuilder"/> method,
/// or to a justified exclusion. A new builder method fails here until it is mapped.
/// </summary>
public class AgentBuilderParityTests
{
    private const string Terminal = "exclude: builds the pipeline; the DI path builds it lazily (IAAuthAgentFactory, IHttpClientFactory)";

    private static readonly Dictionary<string, string[]> Map = new(StringComparer.Ordinal)
    {
        ["WithEgressPolicy"] = ["EgressPolicy"],
        ["WithDevelopmentLoopback"] = ["DevelopmentLoopbackOrigins"],
        ["Bootstrap"] = ["exclude: enrolment is a one-time imperative step; its result feeds AgentToken or AgentProvider"],
        ["From"] = ["AgentToken", "Signer"],
        ["SelfIssuing"] = ["SelfIssued"],
        ["As"] = ["SelfIssued:Issuer", "SelfIssued:Subject"],
        ["WithKid"] = ["SelfIssued:KeyId"],
        ["Enrolled"] = ["AgentProvider", "builder:WithAgentProvider"],
        ["RefreshingFrom"] = ["AgentProvider:RefreshEndpoint", "KeyHandle"],
        ["WithKeyStore"] = ["exclude: the key store is the DI IKeyStore"],
        ["WithRefreshMode"] = ["exclude: Enrolled supports single-key refresh only; two-key refresh is AgentProviderClient.RefreshTwoKeyAsync (builder:WithAgentProvider)"],
        ["UseHwk"] = ["SignatureKeyProvider"],
        ["UseJwt"] = ["AgentToken", "AgentTokenFactory"],
        ["UseJwksUri"] = ["JwksUri"],
        ["UseJwks"] = ["SignatureKeyProvider"],
        ["UseSelfJwt"] = ["SignatureKeyProvider"],
        ["UseJktJwt"] = ["SignatureKeyProvider"],
        ["UseProvider"] = ["SignatureKeyProvider"],
        ["WithInnerHandler"] = ["InnerHandler", "TransportContract"],
        ["WithCapabilities"] = ["Capabilities"],
        ["OnSignatureBase"] = ["OnSignatureBase"],
        ["WithChallengeHandling"] = ["HandleChallenges", "Challenge", "PersonServer"],
        ["WithCallChaining"] = ["UpstreamTokenProvider", "ChainFromHttpContext"],
        ["WithMission"] = ["Mission"],
        ["WithPersonServer"] = ["PersonServer"],
        ["WithTokenRefresh"] = ["TokenRefresher", "TokenRefreshThreshold"],
        ["WithInteractionHandling"] = ["HandleInteractions", "Interaction"],
        ["WithResourceManagedAccess"] = ["EnableResourceManagedAccess", "AAuthAccessStore"],
        ["WithTokenCache"] = ["TokenCache"],
        ["BuildGovernance"] = ["builder:WithGovernance"],
        ["Build"] = [Terminal],
        ["BuildHandler"] = [Terminal],
        ["ToBuilder"] = [Terminal],
    };

    [Fact]
    public void EveryBuilderConfigurationMethod_IsMappedOrExcluded()
    {
        var methods = new[] { typeof(AAuthClientBuilder), typeof(SelfIssuingBuilder), typeof(EnrolledBuilder) }
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Where(method => !method.IsSpecialName)
            .Select(method => method.Name)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal([], methods.Where(name => !Map.ContainsKey(name)).Order().ToArray());
        Assert.Equal([], Map.Keys.Where(name => !methods.Contains(name)).Order().ToArray());
        foreach (var (method, targets) in Map)
            foreach (var target in targets.Where(target => !target.StartsWith("exclude: ", StringComparison.Ordinal)))
                Assert.True(Exists(target), $"{method} maps to missing {target}.");
    }

    [Fact]
    public async Task ConsoleWithoutGenericHost_UsesTheBuilderOnly()
    {
        var key = AAuthKey.Generate();
        var capture = new CaptureHandler();
        using var client = new AAuthClientBuilder(key).UseHwk()
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(capture, AAuthTransportContract.InProcessOnly)
            .Build();

        using var response = await client.GetAsync("https://resource.example/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.StartsWith("sig=hwk", capture.SignatureKey);
    }

    private static bool Exists(string target)
    {
        if (target.StartsWith("builder:", StringComparison.Ordinal))
            return typeof(AAuthAgentBuilder).GetMethod(target["builder:".Length..]) is not null;
        var type = typeof(AAuthAgentOptions);
        foreach (var segment in target.Split(':'))
        {
            var property = type.GetProperty(segment);
            if (property is null || !property.CanWrite) return false;
            type = property.PropertyType;
        }
        return true;
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public string SignatureKey { get; private set; } = "";

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            SignatureKey = string.Join(",", request.Headers.GetValues("Signature-Key"));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
