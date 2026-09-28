using System.Text;
using System.Text.Json.Nodes;
using AAuth.R3.Model;

namespace AAuth.R3.Tests;

/// <summary>Draft-11 R3 wire fixtures: the spec's document example, per-call claims and access annotations.</summary>
public class R3Draft11FixtureTests
{
    // R3 draft-11 #r3-document example, byte for byte (no `version`).
    private const string SpecDocument = """
        {
          "vocabulary": "urn:aauth:vocabulary:mcp",
          "operations": [
            { "tool": "create_calendar_event" },
            { "tool": "modify_calendar_event" }
          ],
          "account": "dick@example.com",
          "display": {
            "summary": "Create and modify events on your work calendar (dick@example.com)",
            "implications": "Meetings can be scheduled or rescheduled. Existing events can be modified.",
            "data_accessed": "Event titles, times, attendees, and descriptions in the work calendar",
            "irreversible": "Sent meeting invitations cannot be unsent"
          }
        }
        """;

    [Fact]
    public void SpecDocument_RoundTripsWithPinnedHashAndPerCallClaims()
    {
        var bytes = Encoding.UTF8.GetBytes(SpecDocument.ReplaceLineEndings("\n"));
        const string s256 = "DB_rCyQ4eWAg8LYhNyyKl-Ze3_hmuGK3zf-AnoK4WOU";
        Assert.Equal(s256, R3Hash.ComputeS256(bytes));
        R3Hash.Verify(bytes, s256);

        var document = R3Document.FromUtf8Bytes(bytes);
        Assert.Equal(Vocabulary.Mcp, document.Vocabulary);
        Assert.Equal("dick@example.com", document.Account);
        Assert.Equal("Sent meeting invitations cannot be unsent", document.Display!.Irreversible);

        var payload = new JsonObject(R3AuthClaims.AuthToken("https://calendar.example/r3/doc", s256,
            R3Grant.Mcp("create_calendar_event"), R3Grant.Mcp("modify_calendar_event")));
        Assert.Equal("modify_calendar_event", (string?)payload["r3_per_call"]!["operations"]![0]!["tool"]);
        var claims = R3ClaimReader.ReadAuthToken(payload);
        Assert.True(claims.PerCall!.Contains(R3OperationIdentity.Mcp("modify_calendar_event")));
        Assert.False(claims.Granted.Contains(R3OperationIdentity.Mcp("modify_calendar_event")));
    }

    [Fact]
    public void SpecAnnotationExamples_ReadAsPerCallWithBudget()
    {
        var openApi = JsonNode.Parse("""
            { "operationId": "purchaseDataset", "x-aauth-access-mode": "per-call", "x-aauth-budget": true }
            """)!.AsObject();
        var mcp = JsonNode.Parse("""
            { "name": "purchase_dataset", "_meta": { "aauth.dev/access-mode": "per-call", "aauth.dev/budget": true } }
            """)!.AsObject();

        var expected = new R3OperationAccess(AAuthConstants.AccessModes.PerCall, Budget: true);
        Assert.Equal(expected, R3AccessAnnotations.Read(openApi, Vocabulary.OpenApi));
        Assert.Equal(expected, R3AccessAnnotations.Read(openApi, Vocabulary.AsyncApi));
        Assert.Equal(expected, R3AccessAnnotations.Read(mcp, Vocabulary.Mcp));
        Assert.Equal("per-call", R3AccessAnnotations.EffectiveAccessMode(expected, AAuthConstants.AccessModes.AuthToken));
    }

    [Theory]
    [InlineData(Vocabulary.OpenApi)]
    [InlineData(Vocabulary.AsyncApi)]
    [InlineData(Vocabulary.Mcp)]
    public void Annotate_WritesTheVocabularyEncodingAndReadsBack(string vocabulary)
    {
        var definition = new JsonObject { ["operationId"] = "read" };
        var access = new R3OperationAccess(AAuthConstants.AccessModes.PersonToken);
        R3AccessAnnotations.Annotate(definition, vocabulary, access);
        Assert.Equal(access, R3AccessAnnotations.Read(definition, vocabulary));
        var target = vocabulary == Vocabulary.Mcp ? definition["_meta"]!.AsObject() : definition;
        Assert.Equal("person-token", (string?)target[vocabulary == Vocabulary.Mcp ? "aauth.dev/access-mode" : "x-aauth-access-mode"]);
        Assert.False(target.ContainsKey(vocabulary == Vocabulary.Mcp ? "aauth.dev/budget" : "x-aauth-budget"));
    }

    [Fact]
    public void Annotations_ApplySpecRules()
    {
        var operation = new JsonObject();
        Assert.Throws<InvalidOperationException>(() => R3AccessAnnotations.Annotate(operation, Vocabulary.OpenApi,
            new R3OperationAccess(AAuthConstants.AccessModes.SessionToken)));
        Assert.Throws<InvalidOperationException>(() => R3AccessAnnotations.Annotate(operation, Vocabulary.OpenApi,
            new R3OperationAccess(AAuthConstants.AccessModes.PersonToken, Budget: true)));
        Assert.Throws<InvalidOperationException>(() => R3AccessAnnotations.Annotate(operation, Vocabulary.Grpc,
            new R3OperationAccess(AAuthConstants.AccessModes.AuthToken)));
        Assert.Empty(operation);

        // Sparse: no annotation takes the resource's access_mode, whose default is agent-token.
        Assert.Null(R3AccessAnnotations.Read(new JsonObject { ["operationId"] = "read" }, Vocabulary.OpenApi));
        Assert.Equal("auth-token", R3AccessAnnotations.EffectiveAccessMode(null, "auth-token"));
        Assert.Equal("agent-token", R3AccessAnnotations.EffectiveAccessMode(null, null));
        // An annotation replaces the default rather than intersecting with it.
        Assert.Equal("person-token", R3AccessAnnotations.EffectiveAccessMode(new("person-token"), "auth-token"));
        // A budget without a mode, or with a mode too weak to carry one, means auth-token.
        Assert.Equal("auth-token", R3AccessAnnotations.EffectiveAccessMode(new(null, Budget: true), "agent-token"));
        var invalid = JsonNode.Parse("""{ "x-aauth-access-mode": "person-token", "x-aauth-budget": true }""")!.AsObject();
        Assert.Equal("auth-token", R3AccessAnnotations.EffectiveAccessMode(R3AccessAnnotations.Read(invalid, Vocabulary.OpenApi), null));
        // session-token and unknown values in a published annotation are ignored.
        Assert.Null(R3AccessAnnotations.Read(JsonNode.Parse("""{ "x-aauth-access-mode": "session-token" }""")!.AsObject(), Vocabulary.OpenApi));
    }
}
