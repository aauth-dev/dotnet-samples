using AAuth.Errors;
using Xunit;

namespace AAuth.Conformance.Errors;

/// <summary>
/// Conformance tests for token endpoint error codes per §Token Endpoint Error Codes.
/// </summary>
public class TokenErrorTests
{
    [Theory(DisplayName = "§Token Endpoint Errors — each error code parses correctly")]
    [InlineData("invalid_request", TokenErrorCode.InvalidRequest)]
    [InlineData("invalid_resource_token", TokenErrorCode.InvalidResourceToken)]
    [InlineData("expired_resource_token", TokenErrorCode.ExpiredResourceToken)]
    [InlineData("revoked_resource_token", TokenErrorCode.RevokedResourceToken)]
    [InlineData("invalid_presented_token", TokenErrorCode.InvalidPresentedToken)]
    [InlineData("expired_presented_token", TokenErrorCode.ExpiredPresentedToken)]
    [InlineData("revoked_presented_token", TokenErrorCode.RevokedPresentedToken)]
    [InlineData("invalid_upstream_token", TokenErrorCode.InvalidUpstreamToken)]
    [InlineData("expired_upstream_token", TokenErrorCode.ExpiredUpstreamToken)]
    [InlineData("revoked_upstream_token", TokenErrorCode.RevokedUpstreamToken)]
    [InlineData("invalid_subagent_token", TokenErrorCode.InvalidSubagentToken)]
    [InlineData("expired_subagent_token", TokenErrorCode.ExpiredSubagentToken)]
    [InlineData("revoked_subagent_token", TokenErrorCode.RevokedSubagentToken)]
    [InlineData("clock_skew", TokenErrorCode.ClockSkew)]
    [InlineData("user_unreachable", TokenErrorCode.UserUnreachable)]
    [InlineData("as_unreachable", TokenErrorCode.AsUnreachable)]
    [InlineData("server_error", TokenErrorCode.ServerError)]
    public void ParsesAllErrorCodes(string wireCode, TokenErrorCode expected)
    {
        Assert.True(TokenErrorResponse.TryParseCode(wireCode, out var result));
        Assert.Equal(expected, result);
        Assert.Equal(wireCode, new TokenErrorResponse(result).ErrorCode);
    }

    [Fact(DisplayName = "§Token Endpoint Errors — every code round-trips")]
    public void EveryCode_RoundTrips()
    {
        foreach (var code in Enum.GetValues<TokenErrorCode>())
        {
            Assert.True(TokenErrorResponse.TryParseCode(new TokenErrorResponse(code).ErrorCode, out var parsed));
            Assert.Equal(code, parsed);
        }
        Assert.False(TokenErrorResponse.TryParseCode("interaction_required", out _));
    }

    [Fact(DisplayName = "§Token Endpoint Errors — unknown code returns false")]
    public void UnknownCode_ReturnsFalse()
    {
        Assert.False(TokenErrorResponse.TryParseCode("unknown_code", out _));
    }

    [Fact(DisplayName = "§Token Endpoint Errors — ErrorCode property returns correct wire format")]
    public void ErrorCode_ReturnsWireFormat()
    {
        var resp = new TokenErrorResponse(TokenErrorCode.ExpiredPresentedToken, "stale person token");
        Assert.Equal("expired_presented_token", resp.ErrorCode);
        Assert.Equal("stale person token", resp.Detail);
    }

    [Fact(DisplayName = "§Token Endpoint Errors — null code returns false")]
    public void NullCode_ReturnsFalse()
    {
        Assert.False(TokenErrorResponse.TryParseCode(null, out _));
    }

    [Fact(DisplayName = "draft-02 §Token Endpoint Errors — user_unreachable is terminal")]
    public void UserUnreachable_IsTerminal()
    {
        // Per published draft-02 §Token Endpoint Error Codes: user_unreachable
        // (HTTP 403) is a distinct terminal error, not retryable.
        Assert.Equal("user_unreachable",
            new TokenErrorResponse(TokenErrorCode.UserUnreachable).ErrorCode);
        Assert.True(AAuthTokenExchangeException.IsTerminalCode("user_unreachable"));
    }

    [Theory(DisplayName = "§Token Revocation — revocation error codes and statuses")]
    [InlineData("invalid_request", RevocationErrorCode.InvalidRequest, 400)]
    [InlineData("unsupported_iss", RevocationErrorCode.UnsupportedIss, 403)]
    [InlineData("rate_limited", RevocationErrorCode.RateLimited, 429)]
    [InlineData("server_error", RevocationErrorCode.ServerError, 500)]
    public void RevocationCodes_RoundTrip(string wireCode, RevocationErrorCode expected, int status)
    {
        Assert.True(RevocationError.TryParseCode(wireCode, out var parsed));
        Assert.Equal(expected, parsed);
        Assert.Equal(wireCode, RevocationError.ToWireCode(parsed));
        Assert.Equal(status, RevocationError.StatusCode(parsed));
        Assert.False(RevocationError.TryParseCode("not_found", out _));
    }

    [Theory(DisplayName = "§Token Revocation — downstream outcome errors")]
    [InlineData("revocation_unavailable", RevocationDownstreamError.RevocationUnavailable)]
    [InlineData("revocation_unsupported", RevocationDownstreamError.RevocationUnsupported)]
    public void DownstreamErrors_RoundTrip(string wireCode, RevocationDownstreamError expected)
    {
        Assert.True(RevocationError.TryParseDownstream(wireCode, out var parsed));
        Assert.Equal(expected, parsed);
        Assert.Equal(wireCode, RevocationError.ToWireCode(parsed));
        Assert.False(RevocationError.TryParseDownstream("revocation_incomplete", out _));
    }
}
