namespace AAuth.Events.Tests.TestSupport;

internal sealed class TestClock
{
    public TestClock(DateTimeOffset now) => Now = now;

    public DateTimeOffset Now { get; set; }

    public DateTimeOffset GetUtcNow() => Now;
}
