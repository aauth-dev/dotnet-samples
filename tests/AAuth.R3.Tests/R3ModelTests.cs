using System.Text.Json;
using AAuth.R3.Model;

namespace AAuth.R3.Tests;

public class R3ModelTests
{
    [Fact]
    public void Document_RoundTripsAndSerializesByteStable()
    {
        var doc = R3TestData.Document();
        var bytes = doc.ToUtf8Bytes();

        var roundTrip = R3Document.FromUtf8Bytes(bytes);
        var bytesAgain = roundTrip.ToUtf8Bytes();

        Assert.Equal(bytes, bytesAgain);
        Assert.Equal(Vocabulary.OpenApi, roundTrip.Vocabulary);
        Assert.Contains(roundTrip.Operations, op => op.Id == "book_trip");
    }

    [Fact]
    public void Operation_RoundTripsMcpAndOpenApiShapesByteStably()
    {
        var mcpBytes = JsonSerializer.SerializeToUtf8Bytes(R3Operation.Mcp("create_event"), R3Json.Options);
        var openApiBytes = JsonSerializer.SerializeToUtf8Bytes(R3Operation.OpenApi("createEvent"), R3Json.Options);

        Assert.Equal("{\"tool\":\"create_event\"}", System.Text.Encoding.UTF8.GetString(mcpBytes));
        Assert.Equal("{\"operationId\":\"createEvent\"}", System.Text.Encoding.UTF8.GetString(openApiBytes));

        var mcpBack = JsonSerializer.Deserialize<R3Operation>(mcpBytes, R3Json.Options)!;
        var openApiBack = JsonSerializer.Deserialize<R3Operation>(openApiBytes, R3Json.Options)!;

        Assert.Equal(R3Operation.McpField, mcpBack.Field);
        Assert.Equal("create_event", mcpBack.Id);
        Assert.Equal(R3Operation.OpenApiField, openApiBack.Field);
        Assert.Equal("createEvent", openApiBack.Id);
    }

    [Fact]
    public void Document_RequiresDisplaySummaryWhenDisplayPresent()
    {
        var doc = new R3Document
        {
            Vocabulary = Vocabulary.Mcp,
            Operations = [R3Operation.Mcp("search_trip_options")],
            Display = new R3Display { Detail = "missing summary" },
        };

        Assert.Throws<InvalidOperationException>(() => doc.ToUtf8Bytes());
    }

    [Fact]
    public void Display_IrreversibleSerializesAndRoundTripsAsString()
    {
        const string irreversible = "Submitting the booking may create cancellation fees.";
        var doc = new R3Document
        {
            Version = "v02",
            Vocabulary = Vocabulary.Mcp,
            Operations = [R3Operation.Mcp("book_trip")],
            Display = new R3Display
            {
                Summary = "Book trip",
                Irreversible = irreversible,
            },
        };

        var bytes = doc.ToUtf8Bytes();
        using var json = JsonDocument.Parse(bytes);
        var irreversibleJson = json.RootElement
            .GetProperty("display")
            .GetProperty("irreversible");
        var roundTrip = R3Document.FromUtf8Bytes(bytes);

        Assert.Equal(JsonValueKind.String, irreversibleJson.ValueKind);
        Assert.Equal(irreversible, irreversibleJson.GetString());
        Assert.Equal(irreversible, roundTrip.Display!.Irreversible);
        Assert.Equal(bytes, roundTrip.ToUtf8Bytes());
    }

    [Fact]
    public void Proposal_RoundTripsParametersAndRequiresSingleOperationAndParameters()
    {
        var proposal = new R3ProposalDocument
        {
            Version = "v02",
            Vocabulary = Vocabulary.Mcp,
            Operations = [R3Operation.Mcp("book_trip")],
            Parameters = new Dictionary<string, R3Parameter>
            {
                ["itinerary_id"] = R3Parameter.Inline(JsonSerializer.SerializeToNode("it-123")!),
                ["policy"] = R3Parameter.Digest("digest-value", excerpt: "non refundable", mediaType: "text/markdown"),
            },
            Display = new R3Display { Summary = "Book trip", Detail = "Approve concrete itinerary." },
        };

        var bytes = proposal.ToUtf8Bytes();
        var parsed = R3ProposalDocument.FromUtf8Bytes(bytes);

        Assert.Equal(bytes, parsed.ToUtf8Bytes());
        Assert.Equal("Approve concrete itinerary.", parsed.Display!.Detail);
        Assert.True(parsed.Parameters["policy"].IsDigest);
        Assert.Throws<InvalidOperationException>(() => (proposal with { Parameters = new Dictionary<string, R3Parameter>() }).ToUtf8Bytes());
        Assert.Throws<InvalidOperationException>(() => (proposal with
        {
            Operations =
            [
                R3Operation.Mcp("book_trip"),
                R3Operation.Mcp("hold_itinerary"),
            ],
        }).ToUtf8Bytes());
    }
}
