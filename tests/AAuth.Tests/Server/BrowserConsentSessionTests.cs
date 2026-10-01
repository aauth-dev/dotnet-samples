using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json.Nodes;
using AAuth.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.TestHost;

namespace AAuth.Tests.Server;

public class BrowserConsentSessionTests
{
    [Fact]
    public async Task RenewalBetweenCodeLookupAndConsumptionRejectsOldCode()
    {
        var sessions = new BrowserConsentSessions("race", authorizePerson: (_, _, _) => true);
        var store = new AAuth.Person.InMemoryPersonPendingStore();
        var entry = store.Add("https://resource.test", "old-scope", "agent", null, DateTimeOffset.UtcNow.AddMinutes(5));
        var pending = new BrowserPendingRequest(entry.Id, entry.PendingExpiresAt, entry.Browser, entry.Lifecycle);
        var consumed = AuthenticatedContext();
        consumed.Request.QueryString = new QueryString("?code=" + entry.Browser.Code);
        Assert.IsType<RedirectHttpResult>((await sessions.EnterAsync(consumed, _ => pending)).Error);
        var context = AuthenticatedContext();
        context.Request.Headers.Cookie = consumed.Response.Headers.SetCookie.ToString().Split(';')[0];
        context.Request.QueryString = new QueryString("?code=" + pending.Browser.Code);
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var resume = new ManualResetEventSlim();
        var arrival = Task.Run(() => sessions.EnterAsync(context, code =>
        {
            var found = store.GetByCode(code);
            Assert.Same(entry, found);
            reached.SetResult();
            Assert.True(resume.Wait(TimeSpan.FromSeconds(10)));
            return new BrowserPendingRequest(found!.Id, found.PendingExpiresAt, found.Browser, found.Lifecycle);
        }));
        try
        {
            await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
            pending.Browser.Renew();
        }
        finally { resume.Set(); }
        var result = await arrival;
        Assert.Equal(400, Assert.IsAssignableFrom<IStatusCodeHttpResult>(result.Error).StatusCode);
    }

    [Fact]
    public async Task RenewalDuringPersonAuthorizationRejectsOldDecision()
    {
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var resume = new ManualResetEventSlim();
        var pause = false;
        var sessions = new BrowserConsentSessions("race", authorizePerson: (_, _, _) =>
        {
            if (pause)
            {
                reached.SetResult();
                Assert.True(resume.Wait(TimeSpan.FromSeconds(10)));
            }
            return true;
        });
        var pending = new BrowserPendingRequest("pending", DateTimeOffset.UtcNow.AddMinutes(5), new(), new());
        var arrival = AuthenticatedContext();
        arrival.Request.QueryString = new QueryString("?code=" + pending.Browser.Code);
        var entered = await sessions.EnterAsync(arrival, _ => pending);
        var redirect = Assert.IsAssignableFrom<RedirectHttpResult>(entered.Error);
        var page = AuthenticatedContext();
        page.Request.Headers.Cookie = arrival.Response.Headers.SetCookie.ToString().Split(';')[0];
        page.Request.QueryString = new QueryString(new Uri("http://localhost" + redirect.Url).Query);
        var opened = await sessions.EnterAsync(page, _ => pending);
        var fields = sessions.Fields(page, opened.Decision!);
        var context = AuthenticatedContext();
        context.Request.Headers.Cookie = page.Request.Headers.Cookie;
        context.Request.Method = "POST";
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["session"] = TestConsentBrowser.Field(fields, "session"),
            ["csrf"] = TestConsentBrowser.Field(fields, "csrf"),
        });
        pause = true;
        var decision = Task.Run(() => sessions.DecideAsync(context));
        try
        {
            await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
            pending.Browser.Renew();
        }
        finally { resume.Set(); }
        var result = await decision;
        Assert.Equal(400, Assert.IsAssignableFrom<IStatusCodeHttpResult>(result.Error).StatusCode);
    }

    private static DefaultHttpContext AuthenticatedContext() => new()
    {
        User = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim("sub", "person", ClaimValueTypes.String, "https://idp.test")
        ], "test-auth")),
    };

    [Theory]
    [InlineData("approve")]
    [InlineData("deny")]
    [InlineData("cancel")]
    public async Task RenewalAfterDecisionValidationCannotMutateNewGeneration(string action)
    {
        await using var fixture = await Fixture.CreateAsync();
        var fields = await fixture.ArriveAsync("01010101");
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.BeforeApply = async () => { reached.SetResult(); await resume.Task; };
        var responseTask = fixture.Client.PostAsync("/consent/" + action, Form(fields));
        try
        {
            await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await fixture.Pending.Lifecycle.Gate.WaitAsync();
            try { fixture.Pending.Browser.Renew(); }
            finally { fixture.Pending.Lifecycle.Gate.Release(); }
        }
        finally { resume.SetResult(); }
        using var response = await responseTask.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_code", (await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]!.GetValue<string>());
        Assert.Equal(0, fixture.Approvals);
        Assert.False(fixture.Pending.Lifecycle.Cancelled);
        fixture.BeforeApply = null;
        var renewed = await fixture.ArriveAsync("01010101");
        using var approved = await fixture.Client.PostAsync("/consent/approve", Form(renewed));
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        Assert.Equal(1, fixture.Approvals);
    }

    [Theory]
    [InlineData("approve")]
    [InlineData("deny")]
    [InlineData("cancel")]
    public async Task CancellationAfterDecisionValidationPreventsMutation(string action)
    {
        await using var fixture = await Fixture.CreateAsync();
        var fields = await fixture.ArriveAsync("01010101");
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.BeforeApply = async () => { reached.SetResult(); await resume.Task; };
        var responseTask = fixture.Client.PostAsync("/consent/" + action, Form(fields));
        try
        {
            await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await fixture.Pending.Lifecycle.Gate.WaitAsync();
            try { fixture.Pending.Lifecycle.Cancel(); }
            finally { fixture.Pending.Lifecycle.Gate.Release(); }
        }
        finally { resume.SetResult(); }
        using var response = await responseTask.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, fixture.Approvals);
    }

    [Fact]
    public async Task MutationHoldsLifecycleAcrossAwaitAndArtifactAppliesOnce()
    {
        await using var fixture = await Fixture.CreateAsync();
        var fields = await fixture.ArriveAsync("01010101");
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.DuringApply = async () => { reached.SetResult(); await resume.Task; };
        var responseTask = fixture.Client.PostAsync("/consent/approve", Form(fields));
        try
        {
            await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.False(fixture.Pending.Lifecycle.Gate.Wait(0));
        }
        finally { resume.SetResult(); }
        using var response = await responseTask.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var replay = await fixture.LastDecision!.ApplyAsync(new DefaultHttpContext(), () =>
        {
            Interlocked.Increment(ref fixture.Approvals);
            return Results.Ok();
        });
        Assert.Equal(400, Assert.IsAssignableFrom<IStatusCodeHttpResult>(replay).StatusCode);
        Assert.Equal(1, fixture.Approvals);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthenticatedPersonRequiresExplicitPendingAuthorization(bool configureDeny)
    {
        var sessions = new BrowserConsentSessions("test", authorizePerson: configureDeny ? (_, _, _) => false : null);
        var context = new DefaultHttpContext();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim("sub", "person", ClaimValueTypes.String, "https://idp.test")
        ], "test-auth"));
        var pending = new BrowserPendingRequest("pending", DateTimeOffset.UtcNow.AddMinutes(1), new(), new());
        context.Request.QueryString = new QueryString("?code=" + pending.Browser.Code);
        var result = await sessions.EnterAsync(context, _ => pending);
        Assert.Equal(403, Assert.IsAssignableFrom<IStatusCodeHttpResult>(result.Error).StatusCode);
    }

    [Fact]
    public async Task RenewedGenerationRejectsOldDecisionSession()
    {
        await using var fixture = await Fixture.CreateAsync();
        var fields = await fixture.ArriveAsync("01010101");
        fixture.Pending.Browser.Renew();
        using var stale = await fixture.Client.PostAsync("/consent/approve", Form(fields));
        Assert.Equal(HttpStatusCode.BadRequest, stale.StatusCode);
        Assert.Equal(0, fixture.Approvals);
    }

    [Fact]
    public async Task ConsumedCodeRejectsOpenDecisionAndNewArrival()
    {
        await using var fixture = await Fixture.CreateAsync();
        var fields = await fixture.ArriveAsync("01010101");
        var code = fixture.Pending.Browser.Code;
        fixture.Pending.Browser.Consume();
        Assert.Equal(code, fixture.Pending.Browser.Code);
        using var stale = await fixture.Client.PostAsync("/consent/approve", Form(fields));
        Assert.Equal(HttpStatusCode.BadRequest, stale.StatusCode);
        Assert.Equal(0, fixture.Approvals);
        var context = AuthenticatedContext();
        context.Request.QueryString = new QueryString("?code=" + code);
        var pending = new BrowserPendingRequest("consumed", DateTimeOffset.UtcNow.AddMinutes(1), fixture.Pending.Browser, new());
        var arrival = await new BrowserConsentSessions("consumed", authorizePerson: (_, _, _) => true)
            .EnterAsync(context, _ => pending);
        Assert.Equal(400, Assert.IsAssignableFrom<IStatusCodeHttpResult>(arrival.Error).StatusCode);
    }

    [Fact]
    public async Task ProtectedCodeAttemptsTerminateOnlyTheirAuthenticatedDecision()
    {
        await using var fixture = await Fixture.CreateAsync();
        var fields = await fixture.ArriveAsync("01010101");
        for (var attempt = 0; attempt < 5; attempt++)
        {
            using var rejected = await fixture.Client.PostAsync("/consent?code=!", Form(fields));
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        }
        using var decision = await fixture.Client.PostAsync("/consent/approve", Form(fields));
        Assert.Equal(HttpStatusCode.BadRequest, decision.StatusCode);
        Assert.False(fixture.Other.Lifecycle.InvalidCode);
        using var terminal = await fixture.Client.GetAsync("/pending");
        Assert.Equal("invalid_code", (await terminal.Content.ReadFromJsonAsync<JsonObject>())!["error"]!.GetValue<string>());
        using var replay = await fixture.Client.GetAsync("/pending");
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

    [Theory]
    [InlineData(null, "localhost", false)]
    [InlineData("192.0.2.1", "localhost", true)]
    [InlineData("127.0.0.1", "attacker.test", true)]
    [InlineData(null, "localhost", true)]
    public async Task DemoConsentRequiresExplicitIsolation(string? remote, string host, bool enabled)
    {
        var sessions = new BrowserConsentSessions("test", enabled ? "demo" : null);
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString(host);
        context.Connection.RemoteIpAddress = remote is null ? null : IPAddress.Parse(remote);
        var result = await sessions.EnterAsync(context, _ => null);
        Assert.Equal(enabled ? 403 : 401, Assert.IsAssignableFrom<IStatusCodeHttpResult>(result.Error).StatusCode);
    }

    [Theory]
    [InlineData("subject")]
    [InlineData("issuer")]
    [InlineData("scheme")]
    public async Task SameDisplayNameDoesNotAuthorizeDifferentIdentity(string changed)
    {
        await using var fixture = await Fixture.CreateAsync(authenticated: true);
        var fields = await fixture.ArriveAsync("01010101");
        fixture.Client.DefaultRequestHeaders.Add("Test-Identity-Change", changed);
        using var response = await fixture.Client.PostAsync("/consent/approve", Form(fields));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, fixture.Approvals);
    }

    [Fact]
    public async Task CodeAloneCannotApprove()
    {
        await using var fixture = await Fixture.CreateAsync();
        using var response = await fixture.Client.PostAsync("/consent/approve", Form(("code", "01010101")));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, fixture.Approvals);
    }

    [Fact]
    public async Task AliasesConsumeCodeButPreserveAuthenticatedDecision()
    {
        await using var fixture = await Fixture.CreateAsync();
        var fields = await fixture.ArriveAsync("ol-ol-ol-ol");
        using var repeated = await fixture.Client.GetAsync("/consent?code=01010101");
        Assert.Equal(HttpStatusCode.BadRequest, repeated.StatusCode);
        Assert.Equal("invalid_code", (await repeated.Content.ReadFromJsonAsync<JsonObject>())!["error"]!.GetValue<string>());
        using var approved = await fixture.Client.PostAsync("/consent/approve", Form(fields));
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        Assert.Equal(1, fixture.Approvals);
        using var terminal = await fixture.Client.GetAsync("/pending");
        using var replay = await fixture.Client.GetAsync("/pending");
        Assert.Equal(HttpStatusCode.OK, terminal.StatusCode);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

    [Fact]
    public async Task CsrfAndForeignBrowserCannotUseDecisionSession()
    {
        await using var fixture = await Fixture.CreateAsync();
        var fields = await fixture.ArriveAsync("01010101");
        using var csrf = await fixture.Client.PostAsync("/consent/approve", Form(("session", fields[0].Item2), ("csrf", "wrong")));
        Assert.Equal(HttpStatusCode.Forbidden, csrf.StatusCode);
        using var foreign = fixture.App.GetTestClient();
        using var stolen = await foreign.PostAsync("/consent/approve", Form(fields));
        Assert.Equal(HttpStatusCode.Unauthorized, stolen.StatusCode);
        using var valid = await fixture.Client.PostAsync("/consent/approve", Form(fields));
        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
    }

    [Theory]
    [InlineData("/consent?code=!")]
    [InlineData("/consent?session=unknown")]
    public async Task UntrustedGetCannotTerminateBoundInteraction(string path)
    {
        await using var fixture = await Fixture.CreateAsync();
        var fields = await fixture.ArriveAsync("01010101");
        for (var attempt = 0; attempt < 5; attempt++)
        {
            using var response = await fixture.Client.GetAsync(path);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
        using var approved = await fixture.Client.PostAsync("/consent/approve", Form(fields));
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        using var terminal = await fixture.Client.GetAsync("/pending");
        Assert.Equal(HttpStatusCode.OK, terminal.StatusCode);
        using var replay = await fixture.Client.GetAsync("/pending");
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
        Assert.False(fixture.Other.Lifecycle.InvalidCode);
    }

    [Fact]
    public async Task ConcurrentDecisionsRecordOnce()
    {
        await using var fixture = await Fixture.CreateAsync();
        var fields = await fixture.ArriveAsync("01010101");
        var responses = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => fixture.Client.PostAsync("/consent/approve", Form(fields))));
        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
        Assert.Equal(1, fixture.Approvals);
        foreach (var response in responses) response.Dispose();
    }

    [Fact]
    public async Task ExpiredCodeRetainsExpiredError()
    {
        await using var fixture = await Fixture.CreateAsync(expired: true);
        await fixture.SignInAsync();
        using var first = await fixture.Client.GetAsync("/consent?code=" + fixture.Pending.Browser.Code);
        using var second = await fixture.Client.GetAsync("/consent?code=" + fixture.Pending.Browser.Code);
        Assert.Equal(HttpStatusCode.RequestTimeout, first.StatusCode);
        Assert.Equal(HttpStatusCode.RequestTimeout, second.StatusCode);
        Assert.Equal("expired", (await first.Content.ReadFromJsonAsync<JsonObject>())!["error"]!.GetValue<string>());
    }

    private static FormUrlEncodedContent Form(params (string, string)[] fields) =>
        new(fields.Select(field => new KeyValuePair<string, string>(field.Item1, field.Item2)));

    private sealed class Fixture : IAsyncDisposable
    {
        public required WebApplication App { get; init; }
        public required HttpClient Client { get; init; }
        public required BrowserPendingRequest Other { get; init; }
        public required BrowserPendingRequest Pending { get; init; }
        public int Approvals;
        public Func<Task>? BeforeApply;
        public Func<Task>? DuringApply;
        public BrowserConsentDecision? LastDecision;

        public static async Task<Fixture> CreateAsync(bool expired = false, bool authenticated = false)
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            var app = builder.Build();
            if (authenticated) app.Use((context, next) =>
            {
                var changed = context.Request.Headers["Test-Identity-Change"].ToString();
                context.User = new ClaimsPrincipal(new ClaimsIdentity([
                    new Claim(ClaimTypes.Name, "same-display-name"),
                    new Claim(ClaimTypes.NameIdentifier, changed == "subject" ? "other" : "person", ClaimValueTypes.String,
                        changed == "issuer" ? "https://other-idp.test" : "https://idp.test")
                ], changed == "scheme" ? "other-scheme" : "test-auth"));
                return next(context);
            });
            var browser = new BrowserConsentSessions("Test.Consent", "isolated-test", authorizePerson: (_, _, _) => true,
                isolatedDemoAccess: _ => true);
            var pending = new BrowserPendingRequest("01010101", DateTimeOffset.UtcNow.AddMinutes(expired ? -1 : 5), new(), new());
            var other = new BrowserPendingRequest("ABCDEFGH", DateTimeOffset.UtcNow.AddMinutes(5), new(), new());
            Fixture fixture = null!;
            app.MapMethods("/consent", ["GET", "POST"], async (HttpContext context) =>
            {
                var entered = await browser.EnterAsync(context, code => code == pending.Browser.Code ? pending : code == other.Browser.Code ? other : null);
                return entered.Error ?? Results.Content("<form>" + browser.Fields(context, entered.Decision!) + "</form>", "text/html");
            });
            foreach (var action in new[] { "approve", "deny", "cancel" })
            app.MapPost("/consent/" + action, async (HttpContext context) =>
            {
                var decision = await browser.DecideAsync(context);
                if (decision.Error is not null) return decision.Error;
                fixture.LastDecision = decision.Decision;
                if (fixture.BeforeApply is { } before) await before();
                return await decision.Decision!.ApplyAsync(context, async () =>
                {
                    if (fixture.DuringApply is { } during) await during();
                    Interlocked.Increment(ref fixture.Approvals);
                    if (action == "cancel") pending.Lifecycle.Cancel();
                    return Results.Ok();
                });
            });
            app.MapGet("/pending", (Func<HttpContext, Task<IResult>>)(context => pending.Lifecycle.ExecuteAsync(context, pending.ExpiresAt,
                TimeProvider.System, () => Task.FromResult<IResult>(Results.Ok()))));
            await app.StartAsync();
            fixture = new Fixture
            {
                App = app,
                Other = other,
                Pending = pending,
                Authenticated = authenticated,
                Client = new HttpClient(new CookieHandler { InnerHandler = app.GetTestServer().CreateHandler() })
                { BaseAddress = new Uri("http://localhost") },
            };
            return fixture;
        }

        public async Task SignInAsync()
        {
            if (Authenticated || _signedIn) return;
            using var login = await Client.GetAsync("/consent?code=01010101");
            using var signedIn = await Client.PostAsync("/consent?code=01010101", Form(
                ("sign_in", "demo"), ("csrf", TestConsentBrowser.Field(await login.Content.ReadAsStringAsync(), "csrf"))));
            Assert.Equal(HttpStatusCode.Redirect, signedIn.StatusCode);
            _signedIn = true;
        }

        public async Task<(string, string)[]> ArriveAsync(string code)
        {
            await SignInAsync();
            if (AAuth.Headers.InteractionCode.Normalize(code) == Pending.Id)
                code = string.Join('-', Pending.Browser.Code.ToLowerInvariant().Replace('0', 'o').Replace('1', 'l').ToCharArray());
            using var arrival = await Client.GetAsync("/consent?code=" + code);
            Assert.Equal(HttpStatusCode.Redirect, arrival.StatusCode);
            using var page = await Client.GetAsync(arrival.Headers.Location);
            Assert.Equal(HttpStatusCode.OK, page.StatusCode);
            var html = await page.Content.ReadAsStringAsync();
            return [("session", TestConsentBrowser.Field(html, "session")), ("csrf", TestConsentBrowser.Field(html, "csrf"))];
        }

        public async ValueTask DisposeAsync() { Client.Dispose(); await App.DisposeAsync(); }
        private bool Authenticated { get; init; }
        private bool _signedIn;
    }

    private sealed class CookieHandler : DelegatingHandler
    {
        private string? _cookie;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_cookie is not null) request.Headers.TryAddWithoutValidation("Cookie", _cookie);
            var response = await base.SendAsync(request, cancellationToken);
            if (response.Headers.TryGetValues("Set-Cookie", out var cookies)) _cookie = cookies.First().Split(';')[0];
            return response;
        }
    }
}