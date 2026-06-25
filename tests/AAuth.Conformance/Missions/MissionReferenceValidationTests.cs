using AAuth.Agent;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for §Mission Reference validation of the <c>AAuth-Mission</c>
/// header: <c>approver</c> MUST be a Server Identifier (https, scheme+host only)
/// and <c>s256</c> MUST be the unpadded base64url encoding of a 32-byte SHA-256
/// digest. A malformed reference is rejected by <see cref="AAuthMissionHeader.TryParseStructured"/>.
/// </summary>
public class MissionReferenceValidationTests
{
    // Unpadded base64url of a 32-byte SHA-256 digest (43 chars).
    private const string ValidS256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

    [Fact(DisplayName = "§Mission Reference — well-formed approver + s256 parse")]
    public void Accepts_WellFormedReference()
    {
        var header = AAuthMissionHeader.FormatStructured("https://ps.example", ValidS256);
        Assert.True(AAuthMissionHeader.TryParseStructured(header, out var approver, out var s256));
        Assert.Equal("https://ps.example", approver);
        Assert.Equal(ValidS256, s256);
    }

    [Fact(DisplayName = "§Mission Reference — loopback approver (dev) parses")]
    public void Accepts_LoopbackApprover()
    {
        var header = AAuthMissionHeader.FormatStructured("http://localhost:5100", ValidS256);
        Assert.True(AAuthMissionHeader.TryParseStructured(header, out _, out _));
    }

    [Theory(DisplayName = "§Mission Reference — non-conformant approver is rejected")]
    [InlineData("http://ps.example")]                    // non-loopback http
    [InlineData("https://ps.example/path")]              // has a path
    [InlineData("https://ps.example/")]                  // trailing slash
    [InlineData("https://ps.example?x=1")]               // has a query
    [InlineData("ps.example")]                            // not absolute
    public void Rejects_NonConformantApprover(string approver)
    {
        var header = $"approver=\"{approver}\"; s256=\"{ValidS256}\"";
        Assert.False(AAuthMissionHeader.TryParseStructured(header, out var a, out var s));
        Assert.Null(a);
        Assert.Null(s);
    }

    [Theory(DisplayName = "§Mission Reference — non-conformant s256 is rejected")]
    [InlineData("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=")] // padded
    [InlineData("47DEQpj8HBSa")]                                  // too short (not 32 bytes)
    [InlineData("47DEQpj8HBSa+_TImW/5JCeuQeRkm5NMpJWZG3hSuFU")]   // standard base64 (+,/)
    [InlineData("not valid base64url!!")]                          // junk
    public void Rejects_NonConformantS256(string s256)
    {
        var header = $"approver=\"https://ps.example\"; s256=\"{s256}\"";
        Assert.False(AAuthMissionHeader.TryParseStructured(header, out var a, out var s));
        Assert.Null(a);
        Assert.Null(s);
    }
}
