using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

public sealed class DeferredState
{
    public static IResult Missing(string id)
        => Guid.TryParseExact(id, "N", out _)
            ? AAuthProblemDetails.Create("expired", statusCode: StatusCodes.Status410Gone)
            : AAuthProblemDetails.Create("unknown_pending", statusCode: StatusCodes.Status404NotFound);

    public SemaphoreSlim Gate { get; } = new(1, 1);
    public bool Delivered { get; private set; }
    public bool Cancelled { get; private set; }
    public bool InvalidCode { get; set; }

    public void Cancel() => Cancelled = true;

    public async Task<IResult> ExecuteAsync(HttpContext context, DateTimeOffset expiry,
        TimeProvider timeProvider, Func<Task<IResult>> operation)
    {
        await Gate.WaitAsync(context.RequestAborted);
        try
        {
            context.Response.Headers.CacheControl = "no-store";
            if (Delivered || Cancelled)
                return AAuthProblemDetails.Create("expired", statusCode: StatusCodes.Status410Gone);
            if (expiry <= timeProvider.GetUtcNow())
            {
                Delivered = true;
                return AAuthProblemDetails.Create("expired", statusCode: StatusCodes.Status408RequestTimeout);
            }
            if (InvalidCode)
            {
                Delivered = true;
                return AAuthProblemDetails.Create("invalid_code", statusCode: StatusCodes.Status400BadRequest);
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
                result = AAuthProblemDetails.Create("expired", statusCode: StatusCodes.Status408RequestTimeout);
            }
            catch (Exception)
            {
                result = AAuthProblemDetails.Create("server_error", statusCode: StatusCodes.Status500InternalServerError);
            }
            var status = (result as IStatusCodeHttpResult)?.StatusCode ?? StatusCodes.Status200OK;
                if (status is not (StatusCodes.Status202Accepted
                    or StatusCodes.Status429TooManyRequests or StatusCodes.Status503ServiceUnavailable)
                    && !(status == StatusCodes.Status204NoContent && HttpMethods.IsPost(context.Request.Method))
                && (HttpMethods.IsGet(context.Request.Method) || status is 200 or 402 or 403 or 408 || status >= 500))
                Delivered = true;
            return result;
        }
        finally { Gate.Release(); }
    }
}