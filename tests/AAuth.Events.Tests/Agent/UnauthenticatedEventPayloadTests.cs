using System.Text;
using AAuth.Events.Agent;

namespace AAuth.Events.Tests.Agent;

public sealed class UnauthenticatedEventPayloadTests
{
    [Fact]
    public void ConstructorAndAccessorsDefensivelyOwnBytes()
    {
        var original = Encoding.UTF8.GetBytes("""{"value":1}""");
        var payload = new UnauthenticatedEventPayload(original, "application/json");
        original[0] = 0;

        var returned = payload.Bytes;
        returned[0] = 0;

        Assert.Equal((byte)'{', payload.Bytes[0]);
        Assert.False(payload.IsAuthenticated);
        Assert.False(payload.IsEndToEndAuthenticated);
        Assert.Equal("Unauthenticated", payload.TrustLabel);
        Assert.Equal("application/json", payload.ContentType);
    }
}
