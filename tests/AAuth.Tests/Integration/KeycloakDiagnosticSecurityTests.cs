using System.Net;
using System.Net.Http.Json;
using AAuth.Access;
using MockAccessServer.Policy;
using Xunit;

namespace AAuth.Tests.Integration;

public class KeycloakDiagnosticSecurityTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedIdpResponsesDoNotExposeTokensOrUntrustedBodies(bool decisionFailure)
    {
        using var http = new HttpClient(new SecretResponseHandler(decisionFailure));
        var policy = new KeycloakAccessPolicy(http, new KeycloakOptions());
        var error = await Assert.ThrowsAsync<HttpRequestException>(() => policy.CompleteAsync("code",
            "https://as.example/callback", new AccessPolicyRequest
            {
                AgentId = "aauth:demo@ap.example", ResourceUrl = "https://wallet.example", Scope = "wallet.read",
            }));
        Assert.DoesNotContain("PRIVATE-IDP-TOKEN", error.Message);
        Assert.DoesNotContain("access_token", error.Message);
        Assert.Contains("500", error.Message);
    }

    private sealed class SecretResponseHandler(bool decisionFailure) : HttpMessageHandler
    {
        private int _calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(decisionFailure && Interlocked.Increment(ref _calls) == 1
                ? HttpStatusCode.OK : HttpStatusCode.InternalServerError)
            {
                Content = JsonContent.Create(new { access_token = "PRIVATE-IDP-TOKEN", detail = "untrusted body" }),
            });
    }
}