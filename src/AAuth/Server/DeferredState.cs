using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Errors;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

public sealed class DeferredState
{
    public static IResult Missing(string id)
        => AAuthProblemDetails.Polling(PollingErrorCode.InvalidCode);

    public SemaphoreSlim Gate { get; } = new(1, 1);
    public bool Delivered { get; private set; }
    public bool Cancelled { get; private set; }
    public bool InvalidCode { get; set; }

    public void Cancel() => Cancelled = true;

    public async Task<IResult> ExecuteAsync(HttpContext context, DateTimeOffset expiry,
        TimeProvider timeProvider, Func<Task<IResult>> operation,
        Func<Task<IResult?>>? beforeExpiry = null)
    {
        await Gate.WaitAsync(context.RequestAborted);
        try
        {
            context.Response.Headers.CacheControl = "no-store";
            if (Delivered || Cancelled)
                return AAuthProblemDetails.Polling(PollingErrorCode.InvalidCode);
            if (beforeExpiry is not null && await beforeExpiry().ConfigureAwait(false) is { } preExpiry)
                return Complete(context, preExpiry);
            if (expiry <= timeProvider.GetUtcNow())
            {
                Delivered = true;
                return AAuthProblemDetails.Polling(PollingErrorCode.Expired);
            }
            if (InvalidCode)
            {
                Delivered = true;
                return AAuthProblemDetails.Polling(PollingErrorCode.InvalidCode);
            }
            IResult result;
            try
            {
                result = await operation();
                context.RequestAborted.ThrowIfCancellationRequested();
                if (result is not IStatusCodeHttpResult and not IFileHttpResult)
                    throw new InvalidOperationException("Deferred operations require an explicit HTTP result status.");
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                Cancel();
                throw;
            }
            catch (OperationCanceledException)
            {
                result = AAuthProblemDetails.Polling(PollingErrorCode.Expired);
            }
            catch (Exception)
            {
                result = AAuthProblemDetails.Polling(PollingErrorCode.ServerError);
            }
            return Complete(context, result);
        }
        finally { Gate.Release(); }
    }

    private IResult Complete(HttpContext context, IResult result)
    {
        var status = (result as IStatusCodeHttpResult)?.StatusCode ?? StatusCodes.Status200OK;
        if (status is not (StatusCodes.Status202Accepted
                or StatusCodes.Status429TooManyRequests or StatusCodes.Status503ServiceUnavailable)
            && !(status == StatusCodes.Status204NoContent && HttpMethods.IsPost(context.Request.Method))
            && (HttpMethods.IsGet(context.Request.Method) || status is 200 or 402 or 403 or 408 || status >= 500))
            Delivered = true;
        return result;
    }
}