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
    [InlineData("invalid_agent_token", TokenErrorCode.InvalidAgentToken)]
    [InlineData("expired_agent_token", TokenErrorCode.ExpiredAgentToken)]
    [InlineData("invalid_resource_token", TokenErrorCode.InvalidResourceToken)]
    [InlineData("expired_resource_token", TokenErrorCode.ExpiredResourceToken)]
    [InlineData("interaction_required", TokenErrorCode.InteractionRequired)]
    [InlineData("user_unreachable", TokenErrorCode.UserUnreachable)]
    [InlineData("server_error", TokenErrorCode.ServerError)]
    public void ParsesAllErrorCodes(string wireCode, TokenErrorCode expected)
    {
        Assert.True(TokenErrorResponse.TryParseCode(wireCode, out var result));
        Assert.Equal(expected, result);
    }

    [Fact(DisplayName = "§Token Endpoint Errors — unknown code returns false")]
    public void UnknownCode_ReturnsFalse()
    {
        Assert.False(TokenErrorResponse.TryParseCode("unknown_code", out _));
    }

    [Fact(DisplayName = "§Token Endpoint Errors — ErrorCode property returns correct wire format")]
    public void ErrorCode_ReturnsWireFormat()
    {
        var resp = new TokenErrorResponse(TokenErrorCode.InvalidAgentToken, "bad token");
        Assert.Equal("invalid_agent_token", resp.ErrorCode);
        Assert.Equal("bad token", resp.ErrorDescription);
    }

    [Fact(DisplayName = "§Token Endpoint Errors — null code returns false")]
    public void NullCode_ReturnsFalse()
    {
        Assert.False(TokenErrorResponse.TryParseCode(null, out _));
    }

    [Fact(DisplayName = "draft-02 §Token Endpoint Errors — user_unreachable is terminal")]
    public void UserUnreachable_IsTerminal()
    {
        // Per upcoming-changes-02 item 2: user_unreachable (HTTP 400) is a
        // distinct terminal error, not retryable.
        Assert.Equal("user_unreachable",
            new TokenErrorResponse(TokenErrorCode.UserUnreachable).ErrorCode);
        Assert.True(AAuthTokenExchangeException.IsTerminalCode("user_unreachable"));
    }
}
