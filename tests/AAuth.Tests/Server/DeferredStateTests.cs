using AAuth.Server;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Tests.Server;

public class DeferredStateTests
{
    private static async Task<(int? Status, string? Error)> ExecuteAsync(IResult result)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider(),
        };
        context.Response.Body = new MemoryStream();
        await result.ExecuteAsync(context);
        context.Response.Body.Position = 0;
        var text = await new StreamReader(context.Response.Body).ReadToEndAsync();
        return ((result as IStatusCodeHttpResult)?.StatusCode ?? context.Response.StatusCode,
            text.Length == 0 ? null : (string?)JsonNode.Parse(text)?["error"]);
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("0123456789abcdef0123456789abcdef")]
    public async Task MissingMalformedAndUnknown_Are410InvalidCode(string id)
    {
        var result = await ExecuteAsync(DeferredState.Missing(id));

        Assert.Equal((410, "invalid_code"), result);
    }

    [Fact]
    public async Task InvalidCode_Is410()
    {
        var state = new DeferredState { InvalidCode = true };
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";

        var result = await ExecuteAsync(await state.ExecuteAsync(context, DateTimeOffset.UtcNow.AddMinutes(5), TimeProvider.System,
            () => Task.FromResult<IResult>(Results.Ok())));

        Assert.Equal((410, "invalid_code"), result);
    }

    [Fact]
    public async Task ExpiredFirstPollIs408ThenReplayIs410InvalidCode()
    {
        var state = new DeferredState();
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";

        var first = await ExecuteAsync(await state.ExecuteAsync(context, DateTimeOffset.UtcNow.AddSeconds(-1), TimeProvider.System,
            () => Task.FromResult<IResult>(Results.Ok())));
        var replay = await ExecuteAsync(await state.ExecuteAsync(context, DateTimeOffset.UtcNow.AddMinutes(5), TimeProvider.System,
            () => Task.FromResult<IResult>(Results.Ok())));

        Assert.Equal((408, "expired"), first);
        Assert.Equal((410, "invalid_code"), replay);
    }

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