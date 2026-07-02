using System.Text;

namespace AAuth.R3.Tests;

public class R3HashTests
{
    [Fact]
    public void ComputeS256_UsesExactPinnedBytes()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"version\":\"v02\",\"vocabulary\":\"urn:aauth:vocabulary:mcp\",\"operations\":[{\"tool\":\"search_trip_options\"}]}");

        var hash = R3Hash.ComputeS256(bytes);

        Assert.Equal("IxqNcEdUIcZFkxNHcDuGZVbT0MI9tpW1oUODXXwYe88", hash);
        Assert.True(R3Hash.Matches(bytes, hash));
    }

    [Fact]
    public void Verify_RejectsSimilarButDifferentBytesAndTamperedDigest()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"a\":1}");
        var similar = Encoding.UTF8.GetBytes("{ \"a\": 1 }");
        var hash = R3Hash.ComputeS256(bytes);

        Assert.NotEqual(hash, R3Hash.ComputeS256(similar));
        Assert.Throws<R3HashMismatchException>(() => R3Hash.Verify(similar, hash));
        Assert.Throws<R3HashMismatchException>(() => R3Hash.Verify(bytes, hash[..^1] + "A"));
    }
}
