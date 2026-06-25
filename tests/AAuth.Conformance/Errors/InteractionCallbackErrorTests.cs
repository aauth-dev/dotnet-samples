using AAuth.Errors;
using Xunit;

namespace AAuth.Conformance.Errors;

/// <summary>
/// Conformance for the §Interaction Callback Errors mapping — the <c>?error=</c>
/// wire codes a server returns on a failed callback redirect and their mapping to
/// the polling errors surfaced to the agent.
/// </summary>
public class InteractionCallbackErrorTests
{
    [Theory(DisplayName = "§Interaction Callback Errors — each code maps to its polling error")]
    [InlineData(InteractionCallbackError.AccessDenied, PollingErrorCode.Denied)]
    [InlineData(InteractionCallbackError.UserAbandoned, PollingErrorCode.Abandoned)]
    [InlineData(InteractionCallbackError.InteractionExpired, PollingErrorCode.Expired)]
    [InlineData(InteractionCallbackError.ServerError, PollingErrorCode.ServerError)]
    [InlineData(InteractionCallbackError.TemporarilyUnavailable, PollingErrorCode.ServerError)]
    public void MapsEachCallbackErrorToPollingError(string callbackError, PollingErrorCode expected)
    {
        Assert.Equal(expected, InteractionCallbackError.ToPollingError(callbackError));
    }

    [Fact(DisplayName = "§Interaction Callback Errors — an unknown error fails closed to server_error")]
    public void UnknownErrorDefaultsToServerError()
    {
        Assert.Equal(PollingErrorCode.ServerError, InteractionCallbackError.ToPollingError("not_a_real_code"));
    }

    [Theory(DisplayName = "§Interaction Callback Errors — a present error surfaces as a non-completable polling error")]
    [InlineData(InteractionCallbackError.AccessDenied, PollingErrorCode.Denied)]
    [InlineData("temporarily_unavailable", PollingErrorCode.ServerError)]
    [InlineData("something_else", PollingErrorCode.ServerError)]
    public void TryGetPollingError_PresentError_Maps(string callbackError, PollingErrorCode expected)
    {
        Assert.True(InteractionCallbackError.TryGetPollingError(callbackError, out var mapped));
        Assert.Equal(expected, mapped);
    }

    [Theory(DisplayName = "§Interaction Callback Errors — a missing error is a non-error (success) redirect")]
    [InlineData(null)]
    [InlineData("")]
    public void TryGetPollingError_NoError_IsSuccessRedirect(string? errorCode)
    {
        Assert.False(InteractionCallbackError.TryGetPollingError(errorCode, out _));
    }
}
