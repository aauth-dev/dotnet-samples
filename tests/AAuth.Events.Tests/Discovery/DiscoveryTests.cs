using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.R3;
using AAuth.R3.Model;

namespace AAuth.Events.Tests.Discovery;

public sealed class DiscoveryTests
{
    [Fact]
    public void Metadata_composition_preserves_typed_members_and_is_idempotent()
    {
        var metadata = new JsonObject
        {
            ["issuer"] = "https://ap.example",
            ["jwks_uri"] = "https://ap.example/.well-known/jwks.json",
        };

        AAuthEventsMetadata.AddEventEndpoint(metadata, "https://events.example/inbox");
        AAuthEventsMetadata.AddEventEndpoint(metadata, "https://events.example/inbox");

        Assert.Equal("https://ap.example", metadata["issuer"]!.GetValue<string>());
        Assert.Equal("https://events.example/inbox", metadata["event_endpoint"]!.GetValue<string>());
        Assert.Throws<EventsMetadataException>(() =>
            AAuthEventsMetadata.AddEventEndpoint(metadata, "https://other.example/inbox"));
        Assert.Throws<EventsMetadataException>(() =>
            AAuthEventsMetadata.AddEventEndpoint(new JsonObject(), "http://events.example/inbox"));
    }

    [Fact]
    public void Vocabulary_composition_preserves_openapi_and_serializes_once()
    {
        IReadOnlyDictionary<string, string> openApi = new Dictionary<string, string>(
            StringComparer.Ordinal)
        {
            [Vocabulary.OpenApi] = "/openapi.json",
        };

        var completed = AAuthEventsMetadata.WithAsyncApiVocabulary(
            openApi, "/asyncapi.json");
        var metadata = new JsonObject { ["issuer"] = "https://resource.example" };
        R3Metadata.AddVocabularies(metadata, completed);

        var values = (JsonObject)metadata["r3_vocabularies"]!;
        Assert.Equal("/openapi.json", values[Vocabulary.OpenApi]!.GetValue<string>());
        Assert.Equal("/asyncapi.json",
            values[AAuthEventsConstants.AsyncApiVocabulary]!.GetValue<string>());
        Assert.Equal(completed,
            AAuthEventsMetadata.WithAsyncApiVocabulary(completed, "/asyncapi.json"));
        Assert.Throws<EventsMetadataException>(() =>
            AAuthEventsMetadata.WithAsyncApiVocabulary(completed, "/different.json"));
        Assert.Throws<EventsMetadataException>(() =>
            AAuthEventsMetadata.WithAsyncApiVocabulary(
                new Dictionary<string, string> { [""] = "/openapi.json" },
                "/asyncapi.json"));
    }

    [Fact]
    public async Task Resolver_reads_current_metadata_honors_cache_and_invalidation()
    {
        var handler = new MutableMetadataHandler(
            """{"issuer":"https://ap.example","event_endpoint":"https://events.example/one"}""");
        var resolver = new EventEndpointResolver(
            new DefaultEventsUrlPolicy(), handler, TimeSpan.FromHours(1));

        Assert.Equal("https://events.example/one", (await resolver.ResolveAsync("https://ap.example")).AbsoluteUri);
        handler.Json = """{"issuer":"https://ap.example","event_endpoint":"https://events.example/two"}""";
        Assert.Equal("https://events.example/one", (await resolver.ResolveAsync("https://ap.example")).AbsoluteUri);

        resolver.Invalidate("https://ap.example");
        Assert.Equal("https://events.example/two", (await resolver.ResolveAsync("https://ap.example")).AbsoluteUri);
        Assert.Equal(2, handler.CallCount);
    }

    [Theory]
    [InlineData("http://127.0.0.1:5000/events", true)]
    [InlineData("http://192.168.1.10/events", false)]
    [InlineData("ftp://events.example/inbox", false)]
    [InlineData("https://events.example/inbox", true)]
    public async Task Resolver_applies_endpoint_policy(string endpoint, bool allowed)
    {
        var handler = new MutableMetadataHandler(
            $$"""{"issuer":"https://ap.example","event_endpoint":"{{endpoint}}"}""");
        var resolver = new EventEndpointResolver(
            new DefaultEventsUrlPolicy(), handler);

        if (allowed)
            Assert.Equal(endpoint, (await resolver.ResolveAsync("https://ap.example")).AbsoluteUri);
        else
        {
            var error = await Assert.ThrowsAsync<EventsVerificationException>(
                () => resolver.ResolveAsync("https://ap.example"));
            Assert.Equal(EventsVerificationErrorCode.UrlPolicyRejected, error.Error.Code);
        }
    }

    [Fact]
    public void AsyncApi_validator_checks_aauth_declarations_but_ignores_action()
    {
        var valid = JsonNode.Parse(
            """
            {
              "asyncapi":"3.0.0",
              "channels":{"public":{"address":"/events"}},
              "operations":{"receive":{"action":"send","channel":{"$ref":"#/channels/public"},"security":[{"aauth_subscribe":[]}] }},
              "components":{"securitySchemes":{"aauth_subscribe":{"type":"http","scheme":"aauth-subscribe"}}}
            }
            """)!.AsObject();
        Assert.True(AsyncApiAAuthValidator.Validate(valid).IsValid);

        valid["components"]!["securitySchemes"]!["aauth_subscribe"]!["scheme"] = "bearer";
        var invalid = AsyncApiAAuthValidator.Validate(valid);
        Assert.Contains(invalid.Diagnostics, d =>
            d.Code == AsyncApiAAuthDiagnosticCode.WrongSubscribeSecurityScheme);
    }

    [Fact]
    public void AsyncApi_validator_requires_protected_ticket_annotation()
    {
        var document = JsonNode.Parse(
            """
            {
              "asyncapi":"3.0.0",
              "channels":{"protected":{"address":"/events/{ticket}"}},
              "operations":{"receive":{"action":"receive","channel":{"$ref":"#/channels/protected"}}},
              "components":{"securitySchemes":{"aauth_subscribe":{"type":"http","scheme":"aauth-subscribe"}}}
            }
            """)!.AsObject();

        var invalid = AsyncApiAAuthValidator.Validate(document);
        Assert.Contains(invalid.Diagnostics, d =>
            d.Code == AsyncApiAAuthDiagnosticCode.MissingProtectedTicketAnnotation);

        document["channels"]!["protected"]!["description"] =
            "The ticket is returned by a prior authenticated API call.";
        Assert.True(AsyncApiAAuthValidator.Validate(document).IsValid);
    }

    private sealed class MutableMetadataHandler : HttpMessageHandler
    {
        public MutableMetadataHandler(string json) => Json = json;

        public string Json { get; set; }
        public int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(Json, Encoding.UTF8, "application/json"),
                RequestMessage = request,
            });
        }
    }
}
