using System.Text.Json.Nodes;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Conformance.AuthTokens;

public class ActChainBuilderTests
{
    [Fact(DisplayName = "§Call Chaining — BuildNestedAct: direct → 2-hop")]
    public void BuildNestedAct_DirectToTwoHop()
    {
        var upstreamAct = new JsonObject { ["sub"] = "aauth:agent@example" };

        var result = ActChainBuilder.BuildNestedAct("aauth:orch@example", upstreamAct);

        Assert.Equal("aauth:orch@example", (string?)result["sub"]);
        var nested = result["act"] as JsonObject;
        Assert.NotNull(nested);
        Assert.Equal("aauth:agent@example", (string?)nested!["sub"]);
    }

    [Fact(DisplayName = "§Call Chaining — BuildNestedAct: 2-hop → 3-hop")]
    public void BuildNestedAct_TwoHopToThreeHop()
    {
        var upstreamAct = new JsonObject
        {
            ["sub"] = "aauth:r1@example",
            ["act"] = new JsonObject { ["sub"] = "aauth:agent@example" },
        };

        var result = ActChainBuilder.BuildNestedAct("aauth:r2@example", upstreamAct);

        Assert.Equal("aauth:r2@example", (string?)result["sub"]);
        var nested1 = result["act"] as JsonObject;
        Assert.NotNull(nested1);
        Assert.Equal("aauth:r1@example", (string?)nested1!["sub"]);
        var nested2 = nested1["act"] as JsonObject;
        Assert.NotNull(nested2);
        Assert.Equal("aauth:agent@example", (string?)nested2!["sub"]);
    }

    [Fact(DisplayName = "§Call Chaining — BuildNestedAct: does not mutate original")]
    public void BuildNestedAct_DoesNotMutateOriginal()
    {
        var upstreamAct = new JsonObject { ["sub"] = "aauth:agent@example" };

        var result = ActChainBuilder.BuildNestedAct("aauth:orch@example", upstreamAct);

        // Modifying the result should not affect the original
        ((JsonObject)result["act"]!)["sub"] = "tampered";
        Assert.Equal("aauth:agent@example", (string?)upstreamAct["sub"]);
    }

    [Fact(DisplayName = "§Call Chaining — ValidateChain: valid 3-level")]
    public void ValidateChain_ValidThreeLevel()
    {
        var act = new JsonObject
        {
            ["sub"] = "aauth:r2@example",
            ["act"] = new JsonObject
            {
                ["sub"] = "aauth:r1@example",
                ["act"] = new JsonObject { ["sub"] = "aauth:agent@example" },
            },
        };

        Assert.True(ActChainBuilder.ValidateChain(act));
    }

    [Fact(DisplayName = "§Call Chaining — ValidateChain: 11 levels returns false")]
    public void ValidateChain_TooDeep()
    {
        JsonObject? current = null;
        for (int i = 11; i >= 1; i--)
        {
            var level = new JsonObject { ["sub"] = $"agent-{i}" };
            if (current is not null)
                level["act"] = current;
            current = level;
        }

        Assert.False(ActChainBuilder.ValidateChain(current!, maxDepth: 10));
    }

    [Fact(DisplayName = "§Call Chaining — ValidateChain: missing sub returns false")]
    public void ValidateChain_MissingSub()
    {
        var act = new JsonObject
        {
            ["sub"] = "aauth:r1@example",
            ["act"] = new JsonObject { /* missing sub */ },
        };

        Assert.False(ActChainBuilder.ValidateChain(act));
    }

    [Fact(DisplayName = "§Call Chaining — ValidateChain: empty sub returns false")]
    public void ValidateChain_EmptySub()
    {
        var act = new JsonObject { ["sub"] = "" };
        Assert.False(ActChainBuilder.ValidateChain(act));
    }

    [Fact(DisplayName = "§Call Chaining — ValidateChain: 10 levels accepted")]
    public void ValidateChain_MaxAccepted()
    {
        JsonObject? current = null;
        for (int i = 10; i >= 1; i--)
        {
            var level = new JsonObject { ["sub"] = $"agent-{i}" };
            if (current is not null)
                level["act"] = current;
            current = level;
        }

        Assert.True(ActChainBuilder.ValidateChain(current!, maxDepth: 10));
    }
}
