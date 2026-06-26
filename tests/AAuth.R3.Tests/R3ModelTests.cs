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
        Assert.Equal(Vocabulary.Mcp, roundTrip.Vocabulary);
        Assert.Contains(roundTrip.Operations, op => op.Tool == "book_trip");
    }

    [Fact]
    public void Document_RequiresDisplaySummaryWhenDisplayPresent()
    {
        var doc = new R3Document
        {
            Vocabulary = Vocabulary.Mcp,
            Operations = [new McpOperation { Tool = "search_trip_options" }],
            Display = new R3Display { Detail = "missing summary" },
        };

        Assert.Throws<InvalidOperationException>(() => doc.ToUtf8Bytes());
    }

    [Fact]
    public void Proposal_RoundTripsParametersAndRequiresSingleOperationAndParameters()
    {
        var proposal = new R3ProposalDocument
        {
            Version = "v02",
            Vocabulary = Vocabulary.Mcp,
            Operations = [new McpOperation { Tool = "book_trip" }],
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
                new McpOperation { Tool = "book_trip" },
                new McpOperation { Tool = "hold_itinerary" },
            ],
        }).ToUtf8Bytes());
    }
}
