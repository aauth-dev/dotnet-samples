using AAuth.Server;
using Microsoft.AspNetCore.Http;

namespace AAuth.Tests.Server;

public class DeferredStateTests
{
    [Fact]
    public async Task TypedMissionBlobIsDeliveredOnce()
    {
        var state = new DeferredState();
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        var blob = Results.Bytes("{}"u8.ToArray(), "application/json");
        var result = await state.ExecuteAsync(context, DateTimeOffset.UtcNow.AddMinutes(5), TimeProvider.System,
            () => Task.FromResult(blob));
        Assert.Same(blob, result);
        Assert.True(state.Delivered);
    }

    [Theory]
    [InlineData(202, false)]
    [InlineData(204, true)]
    [InlineData(429, false)]
    [InlineData(503, false)]
    [InlineData(200, true)]
    [InlineData(400, true)]
    [InlineData(500, true)]
    public async Task TypedPollResponseControlsTerminalState(int status, bool terminal)
    {
        var state = new DeferredState();
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        await state.ExecuteAsync(context, DateTimeOffset.UtcNow.AddMinutes(5), TimeProvider.System,
            () => Task.FromResult<IResult>(Results.StatusCode(status)));
        Assert.Equal(terminal, state.Delivered);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OperationFailureIsTerminal(bool cancellation)
    {
        var state = new DeferredState();
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);
        var result = await state.ExecuteAsync(context, expiry, TimeProvider.System,
            () => throw (cancellation ? new OperationCanceledException() : new InvalidOperationException("sensitive failure")));
        Assert.Equal(cancellation ? 408 : 500, Assert.IsAssignableFrom<IStatusCodeHttpResult>(result).StatusCode);
        var replay = await state.ExecuteAsync(context, expiry, TimeProvider.System,
            () => Task.FromResult<IResult>(Results.Ok()));
        Assert.Equal(410, Assert.IsAssignableFrom<IStatusCodeHttpResult>(replay).StatusCode);
    }

    [Fact]
    public async Task CancellationBeforeGateDoesNotConsumeResult()
    {
        var state = new DeferredState();
        var context = new DefaultHttpContext { RequestAborted = new CancellationToken(true) };
        context.Request.Method = "GET";
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => state.ExecuteAsync(context,
            DateTimeOffset.UtcNow.AddMinutes(5), TimeProvider.System, () => Task.FromResult<IResult>(Results.Ok())));
        Assert.False(state.Delivered);
        Assert.False(state.Cancelled);
    }

    [Fact]
    public async Task CancellationDuringOperationCannotLaterGrant()
    {
        var state = new DeferredState();
        using var cancellation = new CancellationTokenSource();
        var context = new DefaultHttpContext { RequestAborted = cancellation.Token };
        context.Request.Method = "GET";
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => state.ExecuteAsync(context,
            DateTimeOffset.UtcNow.AddMinutes(5), TimeProvider.System, () =>
            {
                cancellation.Cancel();
                throw new OperationCanceledException(cancellation.Token);
            }));
        Assert.True(state.Cancelled);
        Assert.False(state.Delivered);
    }
}