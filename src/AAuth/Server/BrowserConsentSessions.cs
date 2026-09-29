using System;
using System.Collections.Concurrent;
using System.Net;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Headers;
using Microsoft.AspNetCore.Http;

namespace AAuth.Server;

public sealed class BrowserInteraction
{
    internal SemaphoreSlim Gate { get; } = new(1, 1);
    internal bool Consumed { get; set; }
    public string Code { get; private set; } = InteractionCode.Generate(26);
    internal int Generation { get; private set; }

    public void Renew()
    {
        Gate.Wait();
        try
        {
            Code = InteractionCode.Generate(26);
            Generation++;
            Consumed = false;
        }
        finally { Gate.Release(); }
    }

    /// <summary>
    /// Consume the code after an out-of-band decision (#interaction-code-format):
    /// the code stops opening the consent page and in-flight page decisions fail.
    /// </summary>
    public void Consume()
    {
        Gate.Wait();
        try
        {
            Generation++;
            Consumed = true;
        }
        finally { Gate.Release(); }
    }
}

public sealed record BrowserPendingRequest(string Id, DateTimeOffset ExpiresAt,
    BrowserInteraction Browser, DeferredState Lifecycle);

public sealed record BrowserConsentIdentity(string AuthenticationType, string Issuer, string Subject);

public sealed class BrowserConsentDecision
{
    private readonly BrowserPendingRequest _pending;
    private readonly int _generation;
    private bool _applied;

    internal BrowserConsentDecision(BrowserPendingRequest pending, int generation)
    {
        _pending = pending;
        _generation = generation;
    }

    public string Id => _pending.Id;

    public Task<IResult> ApplyAsync(HttpContext context, Func<IResult> mutation)
        => ApplyAsync(context, () => Task.FromResult(mutation()));

    public async Task<IResult> ApplyAsync(HttpContext context, Func<Task<IResult>> mutation)
    {
        await _pending.Lifecycle.Gate.WaitAsync(context.RequestAborted);
        try
        {
            await _pending.Browser.Gate.WaitAsync(context.RequestAborted);
            try
            {
                if (_applied || _generation != _pending.Browser.Generation)
                    return AAuthProblemDetails.Create("invalid_code", statusCode: 400);
                if (BrowserConsentSessions.Unavailable(_pending) is { } unavailable) return unavailable;
                context.RequestAborted.ThrowIfCancellationRequested();
                _applied = true;
                return await mutation();
            }
            finally { _pending.Browser.Gate.Release(); }
        }
        finally { _pending.Lifecycle.Gate.Release(); }
    }
}

public sealed class BrowserConsentSessions
{
    private sealed class Session
    {
        public string Csrf { get; } = Secret();
        public DateTimeOffset ExpiresAt { get; } = DateTimeOffset.UtcNow.AddMinutes(30);
        public BrowserConsentIdentity? Identity { get; set; }
        public int Failures { get; set; }
    }

    private sealed record Decision(Session Browser, BrowserPendingRequest Pending, BrowserConsentIdentity? Identity, int Generation)
    {
        public int Failures { get; set; }
    }
    private readonly ConcurrentDictionary<string, Session> _sessions = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Decision> _decisions = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, (DateTimeOffset Window, int Failures)> _addresses = new(StringComparer.Ordinal);
    private readonly string _cookieName;
    private readonly Func<HttpContext, BrowserPendingRequest, BrowserConsentIdentity, bool>? _authorizePerson;
    private readonly Func<HttpContext, bool> _isolatedDemoAccess;
    public string? DemoIdentity { get; }

    public BrowserConsentSessions(string cookieName, string? isolatedDemoIdentity = null,
        Func<HttpContext, BrowserPendingRequest, BrowserConsentIdentity, bool>? authorizePerson = null,
        Func<HttpContext, bool>? isolatedDemoAccess = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cookieName);
        _cookieName = cookieName;
        DemoIdentity = isolatedDemoIdentity;
        _authorizePerson = authorizePerson;
        _isolatedDemoAccess = isolatedDemoAccess ?? (context => context.Connection.RemoteIpAddress is { } address
            && IPAddress.IsLoopback(address) && Uri.TryCreate("http://" + context.Request.Host, UriKind.Absolute, out var host) && host.IsLoopback);
    }

    public async Task<(string? Id, string? Decision, IResult? Error)> EnterAsync(HttpContext context,
        Func<string, BrowserPendingRequest?> lookup, bool externalLogin = false)
    {
        Sweep();
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        if (DemoIdentity is not null && !_isolatedDemoAccess(context)) return (null, null, Failure("denied", 403));
        var session = Browser(context, create: true)!;
        var identity = Identity(context, session);
        if (!externalLogin && identity is null)
        {
            if (DemoIdentity is null) return (null, null, Failure("denied", 401));
            if (HttpMethods.IsPost(context.Request.Method))
            {
                var form = await context.Request.ReadFormAsync(context.RequestAborted);
                if (!Equal(session.Csrf, form["csrf"].ToString()) || form["sign_in"] != "demo")
                    return (null, null, Failure("denied", 403));
                session.Identity = new("isolated-demo", _cookieName, DemoIdentity);
                return (null, null, Results.Redirect(context.Request.Path + context.Request.QueryString));
            }
            var html = "<!doctype html><meta charset=utf-8><title>Demo sign-in</title>"
                + "<main style='font-family:system-ui;max-width:34rem;margin:2rem auto;padding:1rem'>"
                + "<h1>Demo sign-in</h1><p>Isolated demo account: " + Enc(DemoIdentity) + "</p>"
                + "<form method=post><input type=hidden name=sign_in value=demo>"
                + "<input type=hidden name=csrf value='" + Enc(session.Csrf) + "'>"
                + "<button type=submit class=demo-login>Sign in as demo user</button></form></main>";
            return (null, null, Results.Content(html, "text/html"));
        }
        var decisionId = context.Request.Query["session"].ToString();
        if (!string.IsNullOrEmpty(decisionId))
        {
            if (!_decisions.TryGetValue(decisionId, out var decision) || !ReferenceEquals(decision.Browser, session)
                || (!externalLogin && decision.Identity != identity))
                return (null, null, Failure("invalid_code", 400));
            await decision.Pending.Lifecycle.Gate.WaitAsync(context.RequestAborted);
            try
            {
                await decision.Pending.Browser.Gate.WaitAsync(context.RequestAborted);
                try
                {
                    if (decision.Generation != decision.Pending.Browser.Generation)
                        return (null, null, Failure("invalid_code", 400));
                    if (Unavailable(decision.Pending) is { } unavailable) return (null, null, unavailable);
                    return (decision.Pending.Id, decisionId, null);
                }
                finally { decision.Pending.Browser.Gate.Release(); }
            }
            finally { decision.Pending.Lifecycle.Gate.Release(); }
        }
        var code = context.Request.Query["code"].ToString();
        var credibleAttempt = HttpMethods.IsPost(context.Request.Method);
        Decision? attemptScope = null;
        if (credibleAttempt)
        {
            if (!context.Request.HasFormContentType) return (null, null, Failure("invalid_request", 400));
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            if (!Equal(session.Csrf, form["csrf"].ToString())) return (null, null, Failure("denied", 403));
            if (!string.IsNullOrEmpty(form["session"]))
            {
                if (!_decisions.TryGetValue(form["session"].ToString(), out attemptScope)
                    || !ReferenceEquals(attemptScope.Browser, session) || attemptScope.Identity != identity
                    || attemptScope.Generation != attemptScope.Pending.Browser.Generation
                    || identity is null || !Authorized(context, attemptScope.Pending, identity))
                    return (null, null, Failure("denied", 403));
            }
        }
        var address = context.Connection.RemoteIpAddress?.ToString() ?? "in-process";
        if (_addresses.TryGetValue(address, out var attempts) && attempts.Window > DateTimeOffset.UtcNow && attempts.Failures >= 20)
            return (null, null, Failure("invalid_code", 400));
        if (code.Length > 128 || InteractionCode.Normalize(code) is not { Length: >= 8 } normalized)
            return (null, null, await FailedCodeAttemptAsync(context, session, address, credibleAttempt, attemptScope));
        var pending = lookup(normalized);
        if (pending is null) return (null, null, await FailedCodeAttemptAsync(context, session, address, credibleAttempt, attemptScope));
        await pending.Lifecycle.Gate.WaitAsync(context.RequestAborted);
        try
        {
            await pending.Browser.Gate.WaitAsync(context.RequestAborted);
            try
            {
                if (!Equal(pending.Browser.Code, normalized)) return (null, null, Failure("invalid_code", 400));
                if (Unavailable(pending) is { } unavailable) return (null, null, unavailable);
                if (!externalLogin && !Authorized(context, pending, identity!)) return (null, null, Failure("denied", 403));
                if (session.Failures < 5 && !pending.Browser.Consumed)
                {
                    pending.Browser.Consumed = true;
                    decisionId = Secret();
                    _decisions[decisionId] = new(session, pending, identity, pending.Browser.Generation);
                    return (null, null, Results.Redirect(context.Request.Path + "?session=" + decisionId));
                }
            }
            finally { pending.Browser.Gate.Release(); }
        }
        finally { pending.Lifecycle.Gate.Release(); }
        return (null, null, await FailedCodeAttemptAsync(context, session, address, credibleAttempt, attemptScope));
    }

    public string Fields(HttpContext context, string decision)
    {
        var session = Browser(context, create: false) ?? throw new InvalidOperationException("No browser session.");
        return "<input type=hidden name=session value='" + Enc(decision) + "'>"
            + "<input type=hidden name=csrf value='" + Enc(session.Csrf) + "'>";
    }

    public async Task<(BrowserConsentDecision? Decision, IResult? Error)> DecideAsync(HttpContext context,
        bool externalLogin = false, string? externalState = null)
    {
        var session = Browser(context, create: false);
        if (session is null) return (null, Failure("denied", 401));
        if (DemoIdentity is not null && !_isolatedDemoAccess(context)) return (null, Failure("denied", 403));
        string decisionId;
        if (externalLogin)
            decisionId = externalState ?? "";
        else
        {
            if (!context.Request.HasFormContentType) return (null, Failure("invalid_request", 400));
            var identity = Identity(context, session);
            if (identity is null) return (null, Failure("denied", 401));
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            if (!Equal(session.Csrf, form["csrf"].ToString())) return (null, Failure("denied", 403));
            decisionId = form["session"].ToString();
        }
        if (!_decisions.TryGetValue(decisionId, out var decision) || !ReferenceEquals(session, decision.Browser))
            return (null, Failure("invalid_code", 400));
        if (decision.Generation != decision.Pending.Browser.Generation) return (null, Failure("invalid_code", 400));
        if (!externalLogin && (decision.Identity != Identity(context, session)
            || decision.Identity is null || !Authorized(context, decision.Pending, decision.Identity)))
            return (null, Failure("denied", 403));
        await decision.Pending.Lifecycle.Gate.WaitAsync(context.RequestAborted);
        try
        {
            await decision.Pending.Browser.Gate.WaitAsync(context.RequestAborted);
            try
            {
                if (decision.Generation != decision.Pending.Browser.Generation) return (null, Failure("invalid_code", 400));
                if (Unavailable(decision.Pending) is { } unavailable) return (null, unavailable);
                if (!_decisions.TryRemove(decisionId, out _)) return (null, Failure("invalid_code", 400));
                return (new BrowserConsentDecision(decision.Pending, decision.Generation), null);
            }
            finally { decision.Pending.Browser.Gate.Release(); }
        }
        finally { decision.Pending.Lifecycle.Gate.Release(); }
    }

    private async Task<IResult> FailedCodeAttemptAsync(HttpContext context, Session session, string address, bool credibleAttempt, Decision? attemptScope)
    {
        var now = DateTimeOffset.UtcNow;
        _addresses.AddOrUpdate(address, (now.AddMinutes(1), 1), (_, current) =>
            current.Window <= now ? (now.AddMinutes(1), 1) : (current.Window, current.Failures + 1));
        if (credibleAttempt)
        {
            lock (session) session.Failures++;
        }
        if (attemptScope is not null)
        {
            await attemptScope.Pending.Lifecycle.Gate.WaitAsync(context.RequestAborted);
            try
            {
                await attemptScope.Pending.Browser.Gate.WaitAsync(context.RequestAborted);
                try
                {
                    if (attemptScope.Generation == attemptScope.Pending.Browser.Generation
                        && Unavailable(attemptScope.Pending) is null && ++attemptScope.Failures >= 5)
                        attemptScope.Pending.Lifecycle.InvalidCode = true;
                }
                finally { attemptScope.Pending.Browser.Gate.Release(); }
            }
            finally { attemptScope.Pending.Lifecycle.Gate.Release(); }
        }
        return Failure("invalid_code", 400);
    }

    internal static IResult? Unavailable(BrowserPendingRequest pending)
    {
        if (pending.ExpiresAt <= DateTimeOffset.UtcNow) return Failure("expired", 408);
        if (pending.Lifecycle.Cancelled || pending.Lifecycle.Delivered || pending.Lifecycle.InvalidCode)
            return Failure("invalid_code", 400);
        return null;
    }

    private Session? Browser(HttpContext context, bool create)
    {
        if (context.Request.Cookies.TryGetValue(_cookieName, out var cookie)
            && _sessions.TryGetValue(cookie, out var existing) && existing.ExpiresAt > DateTimeOffset.UtcNow)
            return existing;
        if (!create) return null;
        var key = Secret();
        var session = new Session();
        _sessions[key] = session;
        context.Response.Cookies.Append(_cookieName, key, new CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            MaxAge = TimeSpan.FromMinutes(30),
            IsEssential = true,
        });
        return session;
    }

    private void Sweep()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var pair in _sessions) if (pair.Value.ExpiresAt <= now) _sessions.TryRemove(pair.Key, out _);
        foreach (var pair in _decisions) if (pair.Value.Pending.ExpiresAt.AddHours(1) <= now) _decisions.TryRemove(pair.Key, out _);
        foreach (var pair in _addresses) if (pair.Value.Window <= now) _addresses.TryRemove(pair.Key, out _);
    }

    private static string Secret() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    private bool Authorized(HttpContext context, BrowserPendingRequest pending, BrowserConsentIdentity identity)
        => identity.AuthenticationType == "isolated-demo" && identity.Issuer == _cookieName && identity.Subject == DemoIdentity
            || _authorizePerson?.Invoke(context, pending, identity) == true;

    private static BrowserConsentIdentity? Identity(HttpContext context, Session session)
    {
        var identities = context.User.Identities.Where(identity => identity.IsAuthenticated).ToArray();
        if (identities.Length == 0) return session.Identity;
        if (identities.Length != 1) return null;
        var principal = identities[0];
        var subjects = principal.Claims.Where(claim => claim.Type is "sub" or ClaimTypes.NameIdentifier).ToArray();
        if (subjects.Length == 0 || subjects.Any(claim => claim.Value != subjects[0].Value || claim.Issuer != subjects[0].Issuer)
            || string.IsNullOrWhiteSpace(subjects[0].Value) || string.IsNullOrWhiteSpace(principal.AuthenticationType)) return null;
        var issuer = principal.FindFirst("iss")?.Value ?? subjects[0].Issuer;
        if (string.IsNullOrWhiteSpace(issuer) || issuer == ClaimsIdentity.DefaultIssuer) return null;
        return new(principal.AuthenticationType, issuer, subjects[0].Value);
    }

    private static bool Equal(string expected, string actual) => CryptographicOperations.FixedTimeEquals(
        Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(actual));
    private static string Enc(string value) => WebUtility.HtmlEncode(value);
    private static IResult Failure(string error, int status) => AAuthProblemDetails.Create(error, statusCode: status);
}