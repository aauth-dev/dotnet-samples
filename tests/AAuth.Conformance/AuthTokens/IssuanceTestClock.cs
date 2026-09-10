using System;

namespace AAuth.Conformance.AuthTokens;

internal sealed class IssuanceTestClock(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}