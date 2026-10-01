using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;
using AAuth.Server;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AAuth.Person;

internal sealed class PersonResourceInteraction
{
    public required Interaction Request { get; init; }
    public required JsonObject Context { get; init; }
    public required string ResourceToken { get; init; }
    public bool Complete { get; private set; }
    public string? Error { get; private set; }
    public int ErrorStatus { get; private set; }
    private string? _state;
    private string? _browser;
    public TaskCompletionSource<bool> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public static async Task<PersonResourceInteraction?> CreateAsync(JsonObject payload, string token,
        AAuthEgressPolicy policy, CancellationToken cancellationToken)
    {
        if (!payload.ContainsKey("interaction")) return null;
        if (payload["interaction"] is not JsonObject interaction
            || interaction["url"] is not JsonValue urlValue || !urlValue.TryGetValue<string>(out var url)
            || interaction["code"] is not JsonValue codeValue || !codeValue.TryGetValue<string>(out var code)
            || string.IsNullOrWhiteSpace(code))
            throw new TokenVerificationException("Invalid resource interaction.");
        try
        {
            Interaction.Format(url, code, policy);
            await policy.ValidateDestinationAsync(url, cancellationToken);
        }
        catch (Exception exception) when (exception is System.Net.Http.HttpRequestException or ArgumentException or System.Net.Sockets.SocketException
            || exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            throw new TokenVerificationException("Resource interaction destination is not admitted.");
        }
        return new() { Request = new(url, code), Context = (JsonObject)payload.DeepClone(), ResourceToken = token };
    }

    public static void Map(Microsoft.AspNetCore.Routing.IEndpointRouteBuilder app, IPersonPendingStore pending, AAuthPersonServerOptions options)
    {
        var sessions = options.ResourceInteractionSessions ?? new BrowserConsentSessions("AAuth.ResourceInteraction");
        var path = "/" + options.InteractionPath.Trim('/') + "/resource";
        var callbackPath = path + "/callback";
        app.MapMethods(path, ["GET", "POST"], async (HttpContext context) =>
        {
            var entered = await sessions.EnterAsync(context, code => pending.GetByCode(code) is { ResourceInteraction: { Complete: false, Error: null } } entry
                ? new BrowserPendingRequest(entry.Id, entry.PendingExpiresAt, entry.Browser, entry.Lifecycle) : null);
            if (entered.Error is not null) return entered.Error;
            var entry = pending.Get(entered.Id!)!;
            if (entry.ResourceInteraction is not { Complete: false, Error: null })
                return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
            return Results.Content("<!doctype html><meta charset=utf-8><title>Resource permissions</title>"
                + "<main><h1>Resource permissions</h1><p>" + WebUtility.HtmlEncode(entry.ResourceUrl)
                + " requires additional permissions.</p><form method=post action='" + path + "/continue'>"
                + sessions.Fields(context, entered.Decision!) + "<button type=submit>Continue to resource</button></form></main>", "text/html");
        });
        app.MapPost(path + "/continue", async (HttpContext context) =>
        {
            var decision = await sessions.DecideAsync(context);
            if (decision.Error is not null) return decision.Error;
            var entry = pending.Get(decision.Decision!.Id)!;
            return await decision.Decision.ApplyAsync(context, async () =>
            {
                if (entry.ResourceInteraction is not { Complete: false, Error: null } flow || flow._state is not null)
                    return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
                try { await options.EgressPolicy.ValidateDestinationAsync(flow.Request.Url, context.RequestAborted); }
                catch (Exception exception) when (exception is System.Net.Http.HttpRequestException or System.Net.Sockets.SocketException
                    || exception is OperationCanceledException && !context.RequestAborted.IsCancellationRequested)
                { return AAuthProblemDetails.Create("denied", statusCode: 403); }
                flow._state = Secret();
                flow._browser = Secret();
                context.Response.Cookies.Append("AAuth.Resource." + entry.Id, flow._browser, new CookieOptions
                {
                    HttpOnly = true, Secure = context.Request.IsHttps, SameSite = SameSiteMode.Lax,
                    Path = callbackPath, Expires = entry.PendingExpiresAt, IsEssential = true,
                });
                context.Response.Headers.CacheControl = "no-store";
                context.Response.Headers["Referrer-Policy"] = "no-referrer";
                var callback = options.Issuer + callbackPath + "/" + entry.Id + "?state=" + flow._state;
                return Results.Redirect(flow.Request.BuildUserUrl(callback));
            });
        }).DisableAntiforgery();
        app.MapGet(callbackPath + "/{id}", async (HttpContext context, string id) =>
        {
            var entry = pending.Get(id);
            if (entry is null) return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
            await entry.Lifecycle.Gate.WaitAsync(context.RequestAborted);
            try
            {
                context.Response.Headers.CacheControl = "no-store";
                context.Response.Headers["Referrer-Policy"] = "no-referrer";
                if (BrowserConsentSessions.Unavailable(new(entry.Id, entry.PendingExpiresAt, entry.Browser, entry.Lifecycle)) is { } unavailable)
                    return unavailable;
                if (entry.ResourceInteraction is not { Complete: false, Error: null } flow
                    || !Equal(flow._state, context.Request.Query["state"].ToString())
                    || !Equal(flow._browser, context.Request.Cookies["AAuth.Resource." + id])
                    || flow.ResourceToken != entry.ResourceToken || !JsonNode.DeepEquals(flow.Context, entry.ResourceContext))
                    return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
                flow._state = null;
                flow._browser = null;
                context.Response.Cookies.Delete("AAuth.Resource." + id, new CookieOptions { Path = callbackPath });
                if (context.Request.Query.ContainsKey("error"))
                {
                    var error = context.Request.Query["error"].ToString();
                    var mapped = InteractionCallbackError.ToPollingError(string.IsNullOrEmpty(error) ? "server_error" : error);
                    flow.Error = PollingErrorException.ToWireCode(mapped);
                    flow.ErrorStatus = mapped == PollingErrorCode.Expired ? 408 : mapped == PollingErrorCode.ServerError ? 500 : 403;
                    entry.Status = PersonPendingStatus.Denied;
                    flow.Completion.TrySetResult(false);
                    return Results.Content("<!doctype html><title>Authorization stopped</title><h1>Authorization stopped</h1>", "text/html");
                }
                flow.Complete = true;
                entry.Status = PersonPendingStatus.Pending;
                entry.InteractionUrl = null;
                entry.InteractionCode = null;
                entry.Browser.Renew();
                flow.Completion.TrySetResult(true);
                return Results.Redirect(options.Issuer + "/" + options.InteractionPath.Trim('/') + "?code=" + entry.Browser.Code);
            }
            finally { entry.Lifecycle.Gate.Release(); }
        });
    }

    private static string Secret() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    private static bool Equal(string? expected, string? actual) => expected is not null && actual is not null
        && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(actual));
}