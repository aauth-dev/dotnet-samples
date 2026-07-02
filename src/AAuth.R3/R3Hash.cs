using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.R3;

/// <summary>Computes R3 v02 <c>r3_s256</c> over verbatim served bytes.</summary>
public static class R3Hash
{
    public static string ComputeS256(ReadOnlySpan<byte> bytes) =>
        Base64UrlEncoder.Encode(SHA256.HashData(bytes));

    public static bool Matches(ReadOnlySpan<byte> bytes, string expectedS256) =>
        string.Equals(ComputeS256(bytes), expectedS256, StringComparison.Ordinal);

    public static void Verify(ReadOnlySpan<byte> bytes, string expectedS256)
    {
        if (!Matches(bytes, expectedS256))
        {
            throw new R3HashMismatchException(expectedS256, ComputeS256(bytes));
        }
    }
}

public sealed class R3HashMismatchException : Exception
{
    public R3HashMismatchException(string expected, string actual)
        : base($"R3 hash mismatch. Expected r3_s256 '{expected}', actual '{actual}'.")
    {
        Expected = expected;
        Actual = actual;
    }

    public string Expected { get; }
    public string Actual { get; }
}
