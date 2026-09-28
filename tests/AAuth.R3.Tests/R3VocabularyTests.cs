using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.R3.Model;

namespace AAuth.R3.Tests;

public class R3VocabularyTests
{
    [Fact]
    public void ExplicitNullParameterRoundTripsAndBindsExactRetry()
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes("{\"vocabulary\":\"urn:aauth:vocabulary:mcp\",\"operations\":[{\"tool\":\"update\"}],\"parameters\":{\"description\":null}}");
        var document = R3ProposalDocument.FromUtf8Bytes(bytes);
        var parameter = document.Parameters["description"];
        Assert.NotNull(parameter);
        Assert.Null(parameter.Json);
        Assert.False(parameter.IsDigest);
        Assert.Null(parameter.DeepClone().Json);
        Assert.Null(R3Parameter.Inline(null).Json);
        Assert.Equal(parameter, R3Parameter.Inline(null));
        Assert.NotEqual(parameter, R3Parameter.Digest("hash"));
        Assert.Throws<ArgumentException>(() => new R3PresentedParameters(new Dictionary<string, R3Parameter> { ["description"] = null! }));
        Assert.Throws<InvalidOperationException>(() => (document with { Parameters = new Dictionary<string, R3Parameter> { ["description"] = null! } }).Validate());
        Assert.Throws<InvalidOperationException>(() => (document with { Parameters = new Dictionary<string, R3Parameter> { [""] = parameter } }).Validate());
        Assert.Equal("null", JsonSerializer.Serialize(parameter));
        Assert.NotNull(R3ProposalDocument.FromUtf8Bytes(document.ToUtf8Bytes()).Parameters["description"]);
        var store = new R3ProposalStore();
        var enforcement = new R3Enforcement(store, new Uri("https://resource.test"));
        var identity = R3OperationIdentity.Mcp("update");
        var claims = new R3ClaimReader.AuthTokenClaims("https://resource.test/r3/doc", "hash", R3Grant.Mcp(), R3Grant.Mcp("update"));
        var perCall = enforcement.Evaluate(claims, identity, document.Parameters);
        Assert.Equal(R3EnforcementDecisionKind.PerCall, perCall.Kind);
        var approved = new R3ClaimReader.AuthTokenClaims(perCall.ProposalUri!, perCall.ProposalS256!, claims.PerCall!, null);
        Assert.Equal(R3EnforcementDecisionKind.Granted, enforcement.Evaluate(approved, identity, document.Parameters, approvedProposalS256: approved.S256).Kind);
        Assert.Equal("proposal_digest_mismatch", enforcement.Evaluate(approved, identity,
            new Dictionary<string, R3Parameter>(), approvedProposalS256: approved.S256).Error);
        Assert.Equal("proposal_digest_mismatch", enforcement.Evaluate(approved, identity,
            new Dictionary<string, R3Parameter> { ["description"] = R3Parameter.Inline(JsonValue.Create("not-null")!) }, approvedProposalS256: approved.S256).Error);
        Assert.Equal("proposal_digest_mismatch", enforcement.Evaluate(approved, identity,
            new Dictionary<string, R3Parameter> { ["description"] = R3Parameter.Digest(R3Hash.ComputeS256("null"u8)) }, approvedProposalS256: approved.S256).Error);
    }

    [Theory]
    [InlineData("{\"description\":null,\"description\":null}")]
    [InlineData("{\"description\":{\"s256\":\"hash\",\"s256\":\"hash\"}}")]
    [InlineData("{\"description\":[{\"text\":null,\"text\":1}]}")]
    public void DuplicateParameterMembersRejectStructurally(string parameters)
    {
        var json = "{\"vocabulary\":\"urn:aauth:vocabulary:mcp\",\"operations\":[{\"tool\":\"update\"}],\"parameters\":" + parameters + "}";
        Assert.Throws<JsonException>(() => R3ProposalDocument.FromUtf8Bytes(System.Text.Encoding.UTF8.GetBytes(json)));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<R3Parameter>(parameters));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OData_MultiMethodGrantCoversIndividualCallWithoutWidening(bool perCall)
    {
        var grant = new R3Grant { Vocabulary = Vocabulary.OData, Operations = [R3Operation.OData("Events", "GET", "POST")] };
        var claims = new R3ClaimReader.AuthTokenClaims("https://resource.test/r3/doc", "hash",
            perCall ? grant with { Operations = [] } : grant, perCall ? grant : null);
        var store = new R3ProposalStore();
        var enforcement = new R3Enforcement(store, new Uri("https://resource.test"));
        var parameters = new Dictionary<string, R3Parameter> { ["id"] = R3Parameter.Inline(JsonValue.Create(1)!) };
        var get = new R3OperationIdentity(Vocabulary.OData, R3Operation.OData("Events", "GET"));
        var decision = enforcement.Evaluate(claims, get, parameters);
        Assert.Equal(perCall ? R3EnforcementDecisionKind.PerCall : R3EnforcementDecisionKind.Granted, decision.Kind);
        foreach (var denied in new[] { R3Operation.OData("Events"), R3Operation.OData("Events", "DELETE"), R3Operation.OData("Other", "GET") })
            Assert.Equal("operation_not_granted", enforcement.Evaluate(claims, new(Vocabulary.OData, denied), parameters).Error);
        Assert.False((grant with { Operations = [R3Operation.OData("Events")] }).Contains(get));
        Assert.False((grant with { Operations = [get.Operation] }).Contains(new(Vocabulary.OData, grant.Operations[0])));
        if (!perCall) return;
        Assert.True(store.TryGet(decision.ProposalS256!, out var bytes));
        var proposal = R3ProposalDocument.FromUtf8Bytes(bytes);
        Assert.True(get.Matches(proposal.Vocabulary, Assert.Single(proposal.Operations)));
        var approved = new R3ClaimReader.AuthTokenClaims(decision.ProposalUri!, decision.ProposalS256!,
            grant with { Operations = proposal.Operations }, null);
        Assert.Equal(R3EnforcementDecisionKind.Granted, enforcement.Evaluate(approved, get, parameters, approvedProposalS256: approved.S256).Kind);
        var post = new R3OperationIdentity(Vocabulary.OData, R3Operation.OData("Events", "POST"));
        Assert.Equal("operation_not_granted", enforcement.Evaluate(approved, post, parameters, approvedProposalS256: approved.S256).Error);
        Assert.Equal("proposal_tool_mismatch", enforcement.Evaluate(approved with { Granted = grant }, post, parameters, approvedProposalS256: approved.S256).Error);
    }

    [Fact]
    public void ParameterlessPerCallOperation_RequiresPresentEmptyObjectAndBindsRetry()
    {
        var identity = R3OperationIdentity.Mcp("ping");
        var claims = new R3ClaimReader.AuthTokenClaims("https://resource.test/r3/doc", "hash", R3Grant.Mcp(), R3Grant.Mcp("ping"));
        var store = new R3ProposalStore();
        var enforcement = new R3Enforcement(store, new Uri("https://resource.test"));
        var empty = new Dictionary<string, R3Parameter>();
        Assert.Equal("parameters_required", enforcement.Evaluate(claims, identity).Error);
        var decision = enforcement.Evaluate(claims, identity, empty);
        Assert.Equal(R3EnforcementDecisionKind.PerCall, decision.Kind);
        Assert.True(store.TryGet(decision.ProposalS256!, out var bytes));
        Assert.Empty(R3ProposalDocument.FromUtf8Bytes(bytes).Parameters);
        var approved = new R3ClaimReader.AuthTokenClaims(decision.ProposalUri!, decision.ProposalS256!, claims.PerCall!, null);
        Assert.Equal(R3EnforcementDecisionKind.Granted, enforcement.Evaluate(approved, identity, empty, approvedProposalS256: approved.S256).Kind);
        Assert.Equal("unknown_proposal", enforcement.Evaluate(approved, identity, approvedProposalS256: approved.S256).Error);
        Assert.Equal("proposal_digest_mismatch", enforcement.Evaluate(approved, identity,
            new Dictionary<string, R3Parameter> { ["extra"] = R3Parameter.Inline(JsonValue.Create(1)!) }, approvedProposalS256: approved.S256).Error);
    }

    [Theory]
    [InlineData("{}", true)]
    [InlineData("null", false)]
    [InlineData(null, false)]
    public void ParameterlessProposalSchema_DistinguishesEmptyFromMissing(string? parameters, bool valid)
    {
        var json = new JsonObject { ["vocabulary"] = Vocabulary.Mcp, ["operations"] = new JsonArray(new JsonObject { ["tool"] = "ping" }) };
        if (parameters is not null) json["parameters"] = JsonNode.Parse(parameters);
        var bytes = System.Text.Encoding.UTF8.GetBytes(json.ToJsonString());
        if (valid) Assert.Empty(R3ProposalDocument.FromUtf8Bytes(bytes).Parameters);
        else Assert.ThrowsAny<Exception>(() => R3ProposalDocument.FromUtf8Bytes(bytes));
    }

    [Theory]
    [InlineData("{\"s256\":null}")]
    [InlineData("{\"s256\":[]}")]
    [InlineData("{\"s256\":\"hash\",\"excerpt\":[]}")]
    [InlineData("{\"s256\":\"hash\",\"media_type\":null}")]
    public void Proposal_RejectsMalformedParameterShapes(string parameter)
    {
        var json = "{\"vocabulary\":\"urn:aauth:vocabulary:openapi\",\"operations\":[{\"operationId\":\"create\"}],\"parameters\":{\"value\":" + parameter + "}}";
        Assert.Throws<InvalidOperationException>(() => R3ProposalDocument.FromUtf8Bytes(System.Text.Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void PresentedParameter_CannotHaveTwoRepresentations() =>
        Assert.Throws<ArgumentException>(() => new R3PresentedParameters(
            new Dictionary<string, R3Parameter> { ["body"] = R3Parameter.Inline(JsonValue.Create("one")!) },
            new Dictionary<string, byte[]> { ["body"] = [1, 2, 3] }));

    public static TheoryData<string, R3Operation> Shapes => new()
    {
        { Vocabulary.Mcp, R3Operation.Mcp("search") },
        { Vocabulary.OpenApi, R3Operation.OpenApi("search") },
        { Vocabulary.OpenApiGateway, R3Operation.OpenApiGateway("calendar", "search") },
        { Vocabulary.Grpc, R3Operation.Grpc("calendar.Service/Search") },
        { Vocabulary.GraphQl, R3Operation.GraphQl("Search", "query") },
        { Vocabulary.AsyncApi, R3Operation.AsyncApi("search") },
        { Vocabulary.AsyncApi, R3Operation.AsyncApi("search", "receive") },
        { Vocabulary.Wsdl, R3Operation.Wsdl("Search") },
        { Vocabulary.Wsdl, R3Operation.Wsdl("Search", "Calendar") },
        { Vocabulary.OData, R3Operation.OData("Events") },
        { Vocabulary.OData, R3Operation.OData("Events", "GET", "POST") },
    };

    [Theory]
    [MemberData(nameof(Shapes))]
    public void AllVocabularies_MatchReorderedObjectsAndBindPerCallRetries(string vocabulary, R3Operation operation)
    {
        var json = JsonSerializer.SerializeToNode(operation)!.AsObject();
        var reordered = new JsonObject(json.Reverse().Select(member => new KeyValuePair<string, JsonNode?>(member.Key, member.Value?.DeepClone())));
        var parsed = reordered.Deserialize<R3Operation>()!;
        var identity = new R3OperationIdentity(vocabulary, parsed);
        var grant = new R3Grant { Vocabulary = vocabulary, Operations = [operation] };
        var claims = new R3ClaimReader.AuthTokenClaims("https://resource.test/r3/doc", "hash", grant, null);
        var store = new R3ProposalStore();
        var enforcement = new R3Enforcement(store, new Uri("https://resource.test"));
        var parameters = new Dictionary<string, R3Parameter>();
        Assert.True(grant.Contains(identity));
        Assert.False(grant.Contains(new(vocabulary, parsed with { Id = "Other" })));
        Assert.False(grant.Contains(new("https://other.test/vocabulary", parsed)));
        Assert.Equal(R3EnforcementDecisionKind.Granted, enforcement.Evaluate(claims, identity).Kind);
        var challenge = enforcement.Evaluate(claims with { Granted = grant with { Operations = [] }, PerCall = grant }, identity, parameters);
        Assert.Equal(R3EnforcementDecisionKind.PerCall, challenge.Kind);
        var approved = claims with { Uri = challenge.ProposalUri!, S256 = challenge.ProposalS256! };
        Assert.Equal(R3EnforcementDecisionKind.Granted, enforcement.Evaluate(approved, identity, parameters, approvedProposalS256: approved.S256).Kind);
    }

    [Theory]
    [InlineData("task")]
    [InlineData("service")]
    public void CustomSchemas_PreserveAllMembersAcrossConsumersAndReordering(string identifier)
    {
        const string vocabulary = "https://custom.test/vocabulary";
        var schemas = new R3VocabularySchemas(new Dictionary<string, R3VocabularySchema>
        {
            [vocabulary] = new(identifier, operation =>
            {
                if (operation.Id != "read" || operation.Extensions?.Count != 5)
                    throw new InvalidOperationException("Unexpected custom operation.");
            }),
        });
        var original = new JsonObject
        {
            [identifier] = "read", ["operation"] = "qualifier", ["type"] = 123,
            ["action"] = new JsonObject { ["nested"] = true }, ["methods"] = new JsonArray(1, 2), ["region"] = "west",
        };
        var reordered = new JsonObject(original.Reverse().Select(member => new KeyValuePair<string, JsonNode?>(member.Key, member.Value?.DeepClone())));
        var first = original.Deserialize<R3Operation>(schemas.CreateJsonOptions(vocabulary))!;
        foreach (var wire in new[] { original, reordered })
        {
            var root = new JsonObject { ["operations"] = new JsonArray(wire.DeepClone()), ["vocabulary"] = vocabulary };
            var bytes = System.Text.Encoding.UTF8.GetBytes(root.ToJsonString());
            var document = R3Document.FromUtf8Bytes(bytes, schemas: schemas);
            var parsed = Assert.Single(document.Operations);
            Assert.Equal(identifier, parsed.Field);
            Assert.True(JsonNode.DeepEquals(original, JsonSerializer.SerializeToNode(parsed)));
            Assert.True(new R3OperationIdentity(vocabulary, first).Matches(vocabulary, parsed));
            var request = R3Request.ReadOperations(new JsonObject { ["r3_operations"] = root.DeepClone() }, schemas);
            Assert.True(request.ToGrant().Contains(new(vocabulary, first)));
            Assert.NotNull(R3Request.CreateBody(request, schemas: schemas));
            var payload = new JsonObject { ["r3_uri"] = "https://resource.test/r3/doc", ["r3_s256"] = R3Hash.ComputeS256(bytes), ["r3_granted"] = root.DeepClone() };
            var claims = R3ClaimReader.ReadAuthToken(payload, schemas);
            var enforcement = new R3Enforcement(new R3ProposalStore(), new Uri("https://resource.test"), schemas: schemas);
            var identity = new R3OperationIdentity(vocabulary, parsed);
            Assert.Equal(R3EnforcementDecisionKind.Granted, enforcement.Evaluate(claims, identity).Kind);
            var changed = parsed with { Extensions = new Dictionary<string, JsonElement>(parsed.Extensions!) { ["region"] = JsonSerializer.SerializeToElement("east") } };
            Assert.False(claims.Granted.Contains(new(vocabulary, changed)));
            var perCall = claims with { PerCall = claims.Granted, Granted = claims.Granted with { Operations = [] } };
            var challenge = enforcement.Evaluate(perCall, identity, new Dictionary<string, R3Parameter>());
            var approved = claims with { Uri = challenge.ProposalUri!, S256 = challenge.ProposalS256! };
            Assert.Equal(R3EnforcementDecisionKind.Granted, enforcement.Evaluate(approved, identity, new Dictionary<string, R3Parameter>(), approvedProposalS256: approved.S256).Kind);
        }
    }

    [Theory]
    [MemberData(nameof(Shapes))]
    public void Shapes_RoundTripDocumentRequestClaimsAndProposal(string vocabulary, R3Operation operation)
    {
        var identity = new R3OperationIdentity(vocabulary, operation);
        var document = new R3Document { Vocabulary = vocabulary, Operations = [operation], Account = "work" };
        var bytes = document.ToUtf8Bytes();
        Assert.Equal(bytes, R3Document.FromUtf8Bytes(bytes).ToUtf8Bytes());
        var request = new R3Operations { Vocabulary = vocabulary, Operations = [operation] };
        Assert.NotNull(R3Request.CreateBody(request)["r3_operations"]);
        var claims = new JsonObject(R3AuthClaims.AuthToken("https://resource.test/r3/doc", R3Hash.ComputeS256(bytes), request.ToGrant()));
        Assert.True(R3ClaimReader.ReadAuthToken(claims).Granted.Contains(identity));
        var proposal = new R3ProposalDocument { Vocabulary = vocabulary, Operations = [operation],
            Parameters = new Dictionary<string, R3Parameter> { ["value"] = R3Parameter.Inline(JsonValue.Create(1)!) } };
        Assert.Equal(proposal.ToUtf8Bytes(), R3ProposalDocument.FromUtf8Bytes(proposal.ToUtf8Bytes()).ToUtf8Bytes());
    }

    [Theory]
    [InlineData(Vocabulary.OpenApi, "{\"tool\":\"search\"}")]
    [InlineData(Vocabulary.OpenApi, "{\"operationId\":\"search\",\"service\":\"calendar\"}")]
    [InlineData(Vocabulary.OpenApiGateway, "{\"operationId\":\"search\"}")]
    [InlineData(Vocabulary.GraphQl, "{\"operation\":\"search\"}")]
    [InlineData(Vocabulary.Grpc, "{\"method\":\"Search\"}")]
    [InlineData(Vocabulary.OData, "{\"operation\":\"Events/Cancel\",\"methods\":[\"POST\"]}")]
    [InlineData(Vocabulary.Mcp, "{\"tool\":\"search\",\"typo\":\"hidden\"}")]
    public void InvalidVocabularyShapesFail(string vocabulary, string json)
    {
        var operation = JsonSerializer.Deserialize<R3Operation>(json)!;
        Assert.Throws<InvalidOperationException>(() => new R3Grant { Vocabulary = vocabulary, Operations = [operation] }.Validate());
    }

    [Fact]
    public void GatewayDiscoveryAndServiceCollision_AreScoped()
    {
        var metadata = R3Metadata.AddVocabularies(new JsonObject(), new Dictionary<string, JsonNode?>
        {
            [Vocabulary.OpenApiGateway] = new JsonObject { ["calendar"] = "https://gateway.test/calendar.json", ["billing"] = "https://gateway.test/billing.json" },
        });
        var calendar = new R3OperationIdentity(Vocabulary.OpenApiGateway, R3Operation.OpenApiGateway("calendar", "create"));
        var billing = new R3OperationIdentity(Vocabulary.OpenApiGateway, R3Operation.OpenApiGateway("billing", "create"));
        var request = new R3Operations { Vocabulary = calendar.Vocabulary, Operations = [calendar.Operation, billing.Operation] };
        R3Metadata.ValidateOperations(request, metadata, [calendar, billing]);
        var grant = new R3Grant { Vocabulary = calendar.Vocabulary, Operations = [calendar.Operation] };
        Assert.True(grant.Contains(calendar));
        Assert.False(grant.Contains(billing));
        Assert.False(grant.Contains(R3OperationIdentity.OpenApi("create")));
        Assert.Throws<InvalidOperationException>(() => R3Metadata.ValidateOperations(request, metadata, [calendar]));
        var unknown = new R3OperationIdentity(Vocabulary.OpenApiGateway, R3Operation.OpenApiGateway("unknown", "create"));
        Assert.Throws<InvalidOperationException>(() => R3Metadata.ValidateOperations(request with { Operations = [unknown.Operation] }, metadata, [unknown]));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("\"https://gateway.test/openapi.json\"")]
    [InlineData("{\"\":\"https://gateway.test/openapi.json\"}")]
    [InlineData("{\"calendar\":null}")]
    [InlineData("{\"calendar\":[]}")]
    public void MalformedGatewayDiscoveryFails(string json) =>
        Assert.Throws<InvalidOperationException>(() => R3Metadata.AddVocabularies(new JsonObject(),
            new Dictionary<string, JsonNode?> { [Vocabulary.OpenApiGateway] = JsonNode.Parse(json) }));

    [Theory]
    [InlineData("{\"task\":\"read\",\"region\":\"west\"}")]
    [InlineData("{\"region\":\"west\",\"task\":\"read\"}")]
    public void CustomSchemas_AreExplicitAndLocal(string json)
    {
        const string vocabulary = "https://custom.test/vocabulary";
        var schemas = new R3VocabularySchemas(new Dictionary<string, R3VocabularySchema>
        {
            [vocabulary] = new("task", operation =>
            {
                if (operation.Field != "task" || operation.Extensions?.Count != 1 || !operation.Extensions.ContainsKey("region"))
                    throw new InvalidOperationException("Custom task requires region.");
            }),
        });
        var operation = JsonSerializer.Deserialize<R3Operation>(json, schemas.CreateJsonOptions(vocabulary))!;
        var document = new R3Document { Vocabulary = vocabulary, Operations = [operation] };
        Assert.Throws<InvalidOperationException>(() => document.ToUtf8Bytes());
        var bytes = document.ToUtf8Bytes(schemas: schemas);
        Assert.Equal(bytes, R3Document.FromUtf8Bytes(bytes, schemas: schemas).ToUtf8Bytes(schemas: schemas));
        Assert.Throws<InvalidOperationException>(() => R3Document.FromUtf8Bytes(bytes));
        Assert.Throws<ArgumentException>(() => new R3VocabularySchemas(new Dictionary<string, R3VocabularySchema> { [Vocabulary.Mcp] = new("tool", _ => { }) }));
    }

    [Fact]
    public void EmptyRequestsFailButEmptyGrantsAreValid()
    {
        Assert.Throws<InvalidOperationException>(() => R3Request.CreateBody(R3Operations.OpenApi()));
        R3Grant.OpenApi().Validate(allowEmpty: true);
        Assert.Throws<InvalidOperationException>(() => new R3Grant { Vocabulary = "urn:aauth:vocabulary:unknown", Operations = [] }.Validate(allowEmpty: true));
    }

    [Fact]
    public void OptionalMembers_ArePartOfIdentity()
    {
        Assert.False(new R3OperationIdentity(Vocabulary.AsyncApi, R3Operation.AsyncApi("event", "receive"))
            .Matches(Vocabulary.AsyncApi, R3Operation.AsyncApi("event")));
        Assert.False(new R3OperationIdentity(Vocabulary.Wsdl, R3Operation.Wsdl("read", "one"))
            .Matches(Vocabulary.Wsdl, R3Operation.Wsdl("read", "two")));
        var get = new R3OperationIdentity(Vocabulary.OData, R3Operation.OData("Events", "GET"));
        Assert.False(get.Matches(Vocabulary.OData, R3Operation.OData("Events", "POST")));
        Assert.True(new R3OperationIdentity(Vocabulary.OData, R3Operation.OData("Events", "GET", "POST"))
            .Matches(Vocabulary.OData, R3Operation.OData("Events", "POST", "GET")));
    }

    [Fact]
    public void QualifiedPerCallRetry_RejectsOtherServiceAndVocabulary()
    {
        var operation = R3Operation.OpenApiGateway("calendar", "create");
        var identity = new R3OperationIdentity(Vocabulary.OpenApiGateway, operation);
        var initial = new R3ClaimReader.AuthTokenClaims("https://resource.test/r3/doc", "hash",
            new R3Grant { Vocabulary = identity.Vocabulary, Operations = [] },
            new R3Grant { Vocabulary = identity.Vocabulary, Operations = [operation] });
        var store = new R3ProposalStore();
        var enforcement = new R3Enforcement(store, new Uri("https://resource.test"));
        var parameters = new Dictionary<string, R3Parameter> { ["value"] = R3Parameter.Inline(JsonValue.Create(1)!) };
        var billing = new R3OperationIdentity(identity.Vocabulary, R3Operation.OpenApiGateway("billing", "create"));
        Assert.Equal(R3EnforcementDecisionKind.Rejected, enforcement.Evaluate(initial, billing, parameters).Kind);
        Assert.Equal(R3EnforcementDecisionKind.Rejected, enforcement.Evaluate(initial, R3OperationIdentity.OpenApi("create"), parameters).Kind);
        var challenge = enforcement.Evaluate(initial, identity, parameters);
        var approved = new R3ClaimReader.AuthTokenClaims(challenge.ProposalUri!, challenge.ProposalS256!, initial.PerCall!, null);
        Assert.Equal(R3EnforcementDecisionKind.Granted, enforcement.Evaluate(approved, identity, parameters, approvedProposalS256: approved.S256).Kind);
        var forgedGrant = approved with { Granted = new R3Grant { Vocabulary = billing.Vocabulary, Operations = [billing.Operation] } };
        Assert.Equal("proposal_tool_mismatch", enforcement.Evaluate(forgedGrant, billing, parameters, approvedProposalS256: approved.S256).Error);
    }

    [Fact]
    public void StoredBytes_AreIsolatedFromReturnedBuffers()
    {
        var store = new R3ProposalStore();
        var original = R3TestData.Document().ToUtf8Bytes();
        var stored = store.AddBytes(original, new Uri("https://resource.test"));
        stored.Bytes[0] = 0;
        original[0] = 0;
        Assert.True(store.TryGet(stored.S256, out var retrieved));
        R3Hash.Verify(retrieved, stored.S256);
        retrieved[0] = 0;
        Assert.True(store.TryGet(stored.S256, out var next));
        R3Hash.Verify(next, stored.S256);
    }
}