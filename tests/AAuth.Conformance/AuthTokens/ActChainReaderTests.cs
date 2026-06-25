using System.Text.Json.Nodes;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Conformance.AuthTokens;

public class ActChainReaderTests
{
    [Fact(DisplayName = "§Call Chaining — GetDelegationChain: direct (1-hop)")]
    public void GetDelegationChain_Direct()
    {
        var payload = new JsonObject
        {
            ["act"] = new JsonObject { ["agent"] = "aauth:agent@example" },
        };

        var chain = ActChainReader.GetDelegationChain(payload);

        Assert.Single(chain);
        Assert.Equal("aauth:agent@example", chain[0]);
    }

    [Fact(DisplayName = "§Call Chaining — GetDelegationChain: 2-hop")]
    public void GetDelegationChain_TwoHop()
    {
        var payload = new JsonObject
        {
            ["act"] = new JsonObject
            {
                ["agent"] = "aauth:orch@example",
                ["act"] = new JsonObject { ["agent"] = "aauth:agent@example" },
            },
        };

        var chain = ActChainReader.GetDelegationChain(payload);

        Assert.Equal(2, chain.Count);
        Assert.Equal("aauth:orch@example", chain[0]);
        Assert.Equal("aauth:agent@example", chain[1]);
    }

    [Fact(DisplayName = "§Call Chaining — GetDelegationChain: 3-hop")]
    public void GetDelegationChain_ThreeHop()
    {
        var payload = new JsonObject
        {
            ["act"] = new JsonObject
            {
                ["agent"] = "aauth:r2@example",
                ["act"] = new JsonObject
                {
                    ["agent"] = "aauth:r1@example",
                    ["act"] = new JsonObject { ["agent"] = "aauth:agent@example" },
                },
            },
        };

        var chain = ActChainReader.GetDelegationChain(payload);

        Assert.Equal(3, chain.Count);
        Assert.Equal("aauth:r2@example", chain[0]);
        Assert.Equal("aauth:r1@example", chain[1]);
        Assert.Equal("aauth:agent@example", chain[2]);
    }

    [Fact(DisplayName = "§Call Chaining — GetDelegationChain: no act returns empty")]
    public void GetDelegationChain_NoAct()
    {
        var payload = new JsonObject { ["iss"] = "https://ps.example" };
        var chain = ActChainReader.GetDelegationChain(payload);
        Assert.Empty(chain);
    }

    [Fact(DisplayName = "§Call Chaining — GetDelegationChain: depth exceeded throws")]
    public void GetDelegationChain_DepthExceeded()
    {
        var payload = BuildDeepChain(12);

        var ex = Assert.Throws<InvalidOperationException>(
            () => ActChainReader.GetDelegationChain(payload, maxDepth: 10));
        Assert.Contains("exceeds maximum", ex.Message);
    }

    [Fact(DisplayName = "§Call Chaining — GetDelegationChain: missing agent throws")]
    public void GetDelegationChain_MissingSub()
    {
        var payload = new JsonObject
        {
            ["act"] = new JsonObject { /* no agent */ },
        };

        Assert.Throws<InvalidOperationException>(
            () => ActChainReader.GetDelegationChain(payload));
    }

    [Fact(DisplayName = "§Call Chaining — GetOriginalActor: 3-hop returns innermost")]
    public void GetOriginalActor_ThreeHop()
    {
        var payload = new JsonObject
        {
            ["act"] = new JsonObject
            {
                ["agent"] = "aauth:r2@example",
                ["act"] = new JsonObject
                {
                    ["agent"] = "aauth:r1@example",
                    ["act"] = new JsonObject { ["agent"] = "aauth:agent@example" },
                },
            },
        };

        Assert.Equal("aauth:agent@example", ActChainReader.GetOriginalActor(payload));
    }

    [Fact(DisplayName = "§Call Chaining — GetOriginalActor: no act returns null")]
    public void GetOriginalActor_NoAct()
    {
        var payload = new JsonObject { ["iss"] = "https://ps.example" };
        Assert.Null(ActChainReader.GetOriginalActor(payload));
    }

    [Fact(DisplayName = "§Call Chaining — GetImmediateActor: 2-hop returns outermost")]
    public void GetImmediateActor_TwoHop()
    {
        var payload = new JsonObject
        {
            ["act"] = new JsonObject
            {
                ["agent"] = "aauth:orch@example",
                ["act"] = new JsonObject { ["agent"] = "aauth:agent@example" },
            },
        };

        Assert.Equal("aauth:orch@example", ActChainReader.GetImmediateActor(payload));
    }

    [Fact(DisplayName = "§Call Chaining — GetChainDepth: various depths")]
    public void GetChainDepth_Various()
    {
        Assert.Equal(0, ActChainReader.GetChainDepth(new JsonObject()));
        Assert.Equal(1, ActChainReader.GetChainDepth(new JsonObject
        {
            ["act"] = new JsonObject { ["agent"] = "a" },
        }));
        Assert.Equal(2, ActChainReader.GetChainDepth(new JsonObject
        {
            ["act"] = new JsonObject
            {
                ["agent"] = "a",
                ["act"] = new JsonObject { ["agent"] = "b" },
            },
        }));
    }

    [Fact(DisplayName = "§Call Chaining — GetChainDepth: 10 levels accepted")]
    public void GetChainDepth_MaxAccepted()
    {
        var payload = BuildDeepChain(10);
        Assert.Equal(10, ActChainReader.GetChainDepth(payload));
    }

    [Fact(DisplayName = "§Call Chaining — GetChainDepth: 11 levels rejected")]
    public void GetChainDepth_ElevenRejected()
    {
        var payload = BuildDeepChain(11);
        Assert.Throws<InvalidOperationException>(
            () => ActChainReader.GetChainDepth(payload, maxDepth: 10));
    }

    private static JsonObject BuildDeepChain(int depth)
    {
        JsonObject? current = null;
        for (int i = depth; i >= 1; i--)
        {
            var level = new JsonObject { ["agent"] = $"agent-{i}" };
            if (current is not null)
                level["act"] = current;
            current = level;
        }
        return new JsonObject { ["act"] = current! };
    }
}
