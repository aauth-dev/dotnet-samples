using AAuth.Agent;
using Xunit;

namespace AAuth.Tests.Agent;

public class AAuthTokenHolderTests
{
    [Fact]
    public void Update_ReplacesCurrentToken()
    {
        var holder = new AAuthTokenHolder("first");
        Assert.Equal("first", holder.Current);
        holder.Update("second");
        Assert.Equal("second", holder.Current);
    }
}
