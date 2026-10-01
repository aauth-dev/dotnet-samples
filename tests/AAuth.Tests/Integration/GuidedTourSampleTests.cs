using System.Net;
using System.Reflection;
using AAuth;
using AAuth.Headers;
using GuidedTour;

namespace AAuth.Tests.Integration;

public class GuidedTourSampleTests
{
    [Fact]
    public void PendingLocationResolver_RejectsCrossOriginLocations()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.Accepted)
        {
            Headers = { Location = new Uri("https://evil.example/pending/1") },
        };

        var ex = Assert.Throws<TargetInvocationException>(() => ResolvePending(response, "http://localhost:5100/token"));
        Assert.IsType<HttpRequestException>(ex.InnerException);
    }

    [Fact]
    public void PendingLocationResolver_AllowsRelativeSameOriginLocations()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.Accepted)
        {
            Headers = { Location = new Uri("/pending/1", UriKind.Relative) },
        };

        Assert.Equal("http://localhost:5100/pending/1", ResolvePending(response, "http://localhost:5100/token"));
    }

    [Fact]
    public async Task CaptureHandler_RedactsProtocolCredentialsByDefault()
    {
        var jwt = "aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb.cccccccccccccccc";
        var capture = new CapturingMessageHandler
        {
            InnerHandler = new StaticHandler(jwt),
        };
        using var client = new HttpClient(capture);
        using var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost/data");
        request.Headers.Authorization = new("AAuth", "opaque-token");
        request.Headers.TryAddWithoutValidation(AAuthConstants.Headers.SignatureKey, $"sig=jwt;jwt=\"{jwt}\"");

        using var response = await client.SendAsync(request);
        Assert.Contains("redacted protocol credential", capture.Last!.RequestHeaders);
        Assert.DoesNotContain(jwt, capture.Last.RequestHeaders);
        Assert.DoesNotContain(jwt, capture.Last.ResponseBody);
        Assert.Contains("redacted compact JWT", capture.Last.ResponseBody);
    }

    private static string ResolvePending(HttpResponseMessage response, string issuingEndpoint)
        => (string)typeof(TourSession)
            .GetMethod("ResolvePendingLocation", BindingFlags.Static | BindingFlags.NonPublic)!
            .Invoke(null, [response, issuingEndpoint])!;

    private sealed class StaticHandler(string jwt) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""{"auth_token":"{{jwt}}"}"""),
            };
            response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name, $"requirement=auth-token;resource-token=\"{jwt}\"");
            return Task.FromResult(response);
        }
    }
}
