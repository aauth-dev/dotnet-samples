using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace MockPersonServer;

/// <summary>
/// Signed-in sessions for the PS consent dashboard (#ps-approval-endpoint-auth).
/// Uses the same isolated demo identity and loopback-only guard as the consent
/// page, and is enabled exactly when <c>AAuth:EnableIsolatedDemoConsent</c> is.
/// </summary>
public sealed class ConsentDashboardSessions(IConfiguration configuration)
{
    public const string CookieName = "AAuth.Person.Dashboard";
    public const string CsrfHeader = "X-CSRF-Token";
    private readonly ConcurrentDictionary<string, Session> _sessions = new(StringComparer.Ordinal);

    public string? DemoIdentity { get; } =
        configuration.GetValue<bool>("AAuth:EnableIsolatedDemoConsent") ? "isolated-person-demo" : null;

    public sealed class Session
    {
        public string Csrf { get; } = Secret();
        public DateTimeOffset ExpiresAt { get; } = DateTimeOffset.UtcNow.AddHours(8);
        public string? Person { get; set; }
    }

    /// <summary>Null when the caller may use the dashboard at all; otherwise the refusal.</summary>
    public IResult? Refusal(HttpContext context)
    {
        if (DemoIdentity is null) return Problem("denied", "The dashboard needs AAuth:EnableIsolatedDemoConsent.", 401);
        var loopback = context.Connection.RemoteIpAddress is { } address && IPAddress.IsLoopback(address)
            && Uri.TryCreate("http://" + context.Request.Host, UriKind.Absolute, out var host) && host.IsLoopback;
        return loopback ? null : Problem("denied", null, 403);
    }

    public Session Current(HttpContext context, bool create)
    {
        if (context.Request.Cookies.TryGetValue(CookieName, out var key)
            && _sessions.TryGetValue(key, out var existing) && existing.ExpiresAt > DateTimeOffset.UtcNow)
            return existing;
        var session = new Session();
        if (!create) return session;
        foreach (var pair in _sessions)
            if (pair.Value.ExpiresAt <= DateTimeOffset.UtcNow) _sessions.TryRemove(pair.Key, out _);
        key = Secret();
        _sessions[key] = session;
        context.Response.Cookies.Append(CookieName, key, new CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.Strict,
            Path = "/dashboard",
            MaxAge = TimeSpan.FromHours(8),
            IsEssential = true,
        });
        return session;
    }

    public static bool CsrfMatches(Session session, string? supplied) =>
        supplied is not null && CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(session.Csrf), System.Text.Encoding.UTF8.GetBytes(supplied));

    public static IResult Problem(string error, string? detail, int status) =>
        AAuth.Server.AAuthProblemDetails.Create(error, detail, statusCode: status);

    private static string Secret() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
}

/// <summary>
/// The PS consent dashboard: every pending and historical PS consent request,
/// decided out-of-band by the signed-in person (#user-interaction).
/// </summary>
public static class ConsentDashboard
{
    public static void MapConsentDashboard(this WebApplication app)
    {
        app.MapGet("/dashboard", (HttpContext ctx, ConsentDashboardSessions sessions) =>
        {
            NoStore(ctx);
            if (sessions.Refusal(ctx) is { } refused) return refused;
            var session = sessions.Current(ctx, create: true);
            var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            ctx.Response.Headers.ContentSecurityPolicy =
                $"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; "
                + "form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
            return Results.Content(session.Person is null
                ? SignInPage(nonce, session.Csrf, ctx.Request.QueryString.Value ?? "")
                : DashboardPage(nonce, session.Csrf, session.Person), "text/html");
        });

        app.MapPost("/dashboard/sign-in", async (HttpContext ctx, ConsentDashboardSessions sessions) =>
        {
            NoStore(ctx);
            if (sessions.Refusal(ctx) is { } refused) return refused;
            var session = sessions.Current(ctx, create: false);
            if (!ctx.Request.HasFormContentType) return ConsentDashboardSessions.Problem("invalid_request", null, 400);
            var form = await ctx.Request.ReadFormAsync(ctx.RequestAborted);
            if (!ConsentDashboardSessions.CsrfMatches(session, form["csrf"]) || form["sign_in"] != "demo")
                return ConsentDashboardSessions.Problem("denied", null, 403);
            session.Person = sessions.DemoIdentity;
            var code = form["code"].ToString();
            return Results.Redirect(string.IsNullOrEmpty(code) ? "/dashboard" : "/dashboard?code=" + Uri.EscapeDataString(code));
        });

        app.MapGet("/dashboard/requests", (HttpContext ctx, ConsentDashboardSessions sessions, ConsentRegistry registry,
            string? group, string? code) =>
        {
            NoStore(ctx);
            if (sessions.Refusal(ctx) is { } refused) return refused;
            if (sessions.Current(ctx, create: false).Person is null)
                return ConsentDashboardSessions.Problem("denied", "Sign in to the dashboard.", 401);
            var grouping = group is "mission" or "agent" ? group : "none";
            var records = registry.Snapshot();
            var linked = code is null ? null : registry.FindByCode(code);
            return Results.Json(new JsonObject
            {
                ["group"] = grouping,
                ["highlight"] = linked?.Id,
                // The agent's link names a request with nothing for the person to do now.
                ["settled"] = code is not null && linked is not { IsDecidable: true },
                ["pending"] = Groups(records.Where(record => record.Status == ConsentStatus.Pending), grouping),
                ["history"] = Groups(records.Where(record => record.Status != ConsentStatus.Pending), grouping),
            });
        });

        app.MapPost("/dashboard/requests/{id}/{action:regex(^(approve|deny)$)}", async (HttpContext ctx, string id, string action,
            ConsentDashboardSessions sessions, PersonConsentDecisions decisions) =>
        {
            NoStore(ctx);
            if (sessions.Refusal(ctx) is { } refused) return refused;
            var session = sessions.Current(ctx, create: false);
            if (session.Person is null) return ConsentDashboardSessions.Problem("denied", "Sign in to the dashboard.", 401);
            if (!ConsentDashboardSessions.CsrfMatches(session, ctx.Request.Headers[ConsentDashboardSessions.CsrfHeader]))
                return ConsentDashboardSessions.Problem("denied", "Missing or invalid CSRF token.", 403);
            var outcome = await decisions.DecideAsync(id, action == "approve", ConsentDecider.Dashboard, ctx.RequestAborted);
            return outcome switch
            {
                ConsentOutcome.Applied => Results.Json(new { outcome = "applied" }),
                ConsentOutcome.Unknown => ConsentDashboardSessions.Problem("unknown_request", null, 404),
                ConsentOutcome.Refused => ConsentDashboardSessions.Problem("denied", "The identity provider refused.", 403),
                ConsentOutcome.Expired => ConsentDashboardSessions.Problem("expired", null, 409),
                ConsentOutcome.NotDecidable => ConsentDashboardSessions.Problem("not_decidable",
                    "Complete this request where it is hosted.", 409),
                _ => ConsentDashboardSessions.Problem("already_decided", null, 409),
            };
        });
    }

    private static void NoStore(HttpContext ctx)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        ctx.Response.Headers.XContentTypeOptions = "nosniff";
    }

    private static JsonArray Groups(IEnumerable<ConsentRecord> records, string grouping)
    {
        var groups = new JsonArray();
        foreach (var group in records.GroupBy(record => grouping switch
        {
            "mission" => record.MissionS256 ?? (record.Kind == ConsentKind.MissionCreation ? "new:" + record.Id : ""),
            "agent" => record.AgentId,
            _ => "",
        }))
        {
            var first = group.First();
            groups.Add(new JsonObject
            {
                ["key"] = group.Key,
                ["label"] = grouping switch
                {
                    "mission" when group.Key.Length == 0 => "Not under a mission",
                    "mission" => "Mission: " + (first.MissionDescription ?? group.Key),
                    "agent" => "Agent: " + group.Key,
                    _ => null,
                },
                ["mission_s256"] = grouping == "mission" ? first.MissionS256 : null,
                ["records"] = new JsonArray(group.Select(Describe).ToArray<JsonNode?>()),
            });
        }
        return groups;
    }

    private static JsonObject Describe(ConsentRecord record)
    {
        var asserted = record.PersonEntry?.AgentAsserted;
        return new JsonObject
        {
            ["id"] = record.Id,
            ["kind"] = record.Kind.ToString(),
            ["status"] = record.Status.ToString(),
            ["decidable"] = record.IsDecidable,
            ["agent"] = record.AgentId,
            ["resource"] = record.Resource,
            ["scope"] = record.Scope,
            ["account"] = record.Account,
            ["action"] = record.Action,
            ["mission_s256"] = record.MissionS256,
            ["mission"] = record.MissionDescription,
            ["tools"] = record.ProposedTools.Count == 0 ? null : string.Join(", ", record.ProposedTools),
            // The SDK egress policy already validated this relayed AS URL; only
            // http(s) ever reaches an href.
            ["external_url"] = Uri.TryCreate(record.ExternalInteractionUrl, UriKind.Absolute, out var external)
                && (external.Scheme == Uri.UriSchemeHttps || external.Scheme == Uri.UriSchemeHttp)
                ? record.ExternalInteractionUrl : null,
            ["created_at"] = record.CreatedAt,
            ["expires_at"] = record.ExpiresAt,
            ["decided_at"] = record.DecidedAt,
            ["decided_by"] = record.Decider?.ToString(),
            ["agent_asserted"] = asserted is null ? null : new JsonObject
            {
                ["justification"] = asserted.Justification,
                ["platform"] = asserted.Platform,
                ["device"] = asserted.Device,
            },
        };
    }

    private static string Enc(string value) => WebUtility.HtmlEncode(value);

    private static string SignInPage(string nonce, string csrf, string query)
    {
        var code = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(query).TryGetValue("code", out var value)
            ? value.ToString() : "";
        return "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            + "<title>Sign in — Person Server dashboard</title>"
            + $"<style nonce='{nonce}'>{Styles}</style>"
            + "<main class=narrow><div class=badge><span class=dot></span>Person Server</div>"
            + "<h1>Sign in to review consent requests</h1>"
            + "<p class=muted>The dashboard lists every request agents have made to act on your behalf. "
            + "Sign in as the isolated demo person to decide them.</p>"
            + "<form method=post action='/dashboard/sign-in'><input type=hidden name=sign_in value=demo>"
            + $"<input type=hidden name=csrf value='{Enc(csrf)}'><input type=hidden name=code value='{Enc(code)}'>"
            + "<button type=submit class='primary demo-login'>Sign in as demo user</button></form></main></html>";
    }

    private static string DashboardPage(string nonce, string csrf, string person) =>
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        + "<title>Consent dashboard — Person Server</title>"
        + $"<meta name=csrf content='{Enc(csrf)}'>"
        + $"<style nonce='{nonce}'>{Styles}</style>"
        + "<main><header><div class=badge><span class=dot></span>Person Server</div>"
        + $"<span class=muted>Signed in as <code>{Enc(person)}</code></span></header>"
        + "<h1>Consent requests</h1>"
        + "<p class=muted>Agents asking to act on your behalf. Approve or deny here, or through the link the agent showed you. "
        + "The agent picks up your decision on its next poll.</p>"
        + "<div class=toolbar role=group aria-label='Group by'><span>Group by</span>"
        + "<button type=button data-group=none aria-pressed=true>None</button>"
        + "<button type=button data-group=mission aria-pressed=false>Mission</button>"
        + "<button type=button data-group=agent aria-pressed=false>Agent</button>"
        + "<span id=status class=muted aria-live=polite></span></div>"
        + "<p id=notice class=error role=alert></p>"
        + "<p id=settled class=info role=status hidden>Nothing to decide for this link right now. "
        + "The request it names is not waiting for you; any other pending requests are listed below.</p>"
        + "<section aria-labelledby=pending-h><h2 id=pending-h>Pending <span id=pending-count class=count>0</span></h2>"
        + "<div id=pending><p class=empty>No pending requests.</p></div></section>"
        + "<section aria-labelledby=history-h><h2 id=history-h>History</h2>"
        + "<div id=history><p class=empty>Nothing decided yet.</p></div></section></main>"
        + $"<script nonce='{nonce}'>{Script}</script></html>";

    private const string Styles =
        "*{box-sizing:border-box}body{font-family:system-ui,sans-serif;margin:0;background:#f8fafc;color:#1e293b;line-height:1.5}"
        + "main{max-width:60rem;margin:0 auto;padding:1.5rem 1rem 3rem}main.narrow{max-width:34rem}"
        + "header{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}"
        + ".badge{display:inline-flex;align-items:center;gap:.5rem;background:#1d4ed8;color:#fff;padding:.4rem .8rem;"
        + "border-radius:.4rem;font-weight:600;letter-spacing:.02em}.badge .dot{width:.6rem;height:.6rem;border-radius:50%;background:#bfdbfe}"
        + "h1{font-size:1.4rem;margin:1.25rem 0 .25rem}h2{font-size:1.05rem;margin:1.75rem 0 .6rem;display:flex;align-items:center;gap:.5rem}"
        + ".muted{color:#64748b;font-size:.9rem}.empty{color:#94a3b8;font-style:italic}"
        + ".count{background:#1d4ed8;color:#fff;border-radius:999px;padding:0 .55rem;font-size:.8rem}"
        + ".toolbar{display:flex;align-items:center;gap:.4rem;margin-top:1rem;flex-wrap:wrap}.toolbar>span:first-child{color:#475569;font-size:.9rem}"
        + ".toolbar button{border:1px solid #cbd5e1;background:#fff;border-radius:999px;padding:.2rem .8rem;cursor:pointer;font:inherit;font-size:.85rem}"
        + ".toolbar button[aria-pressed=true]{background:#1d4ed8;border-color:#1d4ed8;color:#fff}#status{margin-left:auto}"
        + ".group{margin:.75rem 0}.group-h{font-weight:600;color:#334155;margin:.25rem 0 .4rem;display:flex;gap:.5rem;align-items:baseline;flex-wrap:wrap}"
        + ".group-h a{font-weight:400;font-size:.85rem}"
        + ".card{background:#fff;border:1px solid #e2e8f0;border-radius:.6rem;padding:.85rem 1rem;margin:.5rem 0;"
        + "display:grid;grid-template-columns:1fr auto;gap:.5rem 1rem;align-items:start}"
        + ".card.highlight{border-color:#f59e0b;box-shadow:0 0 0 3px #fde68a}"
        + ".kind{font-weight:600}.meta{display:grid;grid-template-columns:max-content 1fr;gap:.1rem .75rem;margin-top:.35rem;font-size:.9rem}"
        + ".meta dt{color:#64748b}.meta dd{margin:0;overflow-wrap:anywhere}code{font-size:.85em;background:#f1f5f9;padding:0 .25rem;border-radius:.25rem}"
        + ".asserted{grid-column:1/-1;background:#fffbeb;border:1px dashed #f59e0b;border-radius:.4rem;padding:.4rem .7rem;font-size:.85rem}"
        + ".asserted blockquote{margin:.2rem 0;font-style:italic;white-space:pre-wrap}"
        + ".actions{display:flex;gap:.5rem;flex-wrap:wrap;justify-content:flex-end}"
        + "button.approve,button.deny,button.primary{padding:.45rem 1rem;font:inherit;cursor:pointer;border-radius:.35rem;border:1px solid}"
        + "button.approve,button.primary{background:#16a34a;border-color:#15803d;color:#fff}button.deny{background:#fff;border-color:#dc2626;color:#b91c1c}"
        + "button:disabled{opacity:.6;cursor:progress}button:focus-visible,a:focus-visible{outline:3px solid #93c5fd;outline-offset:2px}"
        + ".pill{display:inline-block;border-radius:999px;padding:0 .6rem;font-size:.8rem;font-weight:600}"
        + ".s-Approved,.s-Delivered{background:#dcfce7;color:#166534}.s-Denied{background:#fee2e2;color:#991b1b}"
        + ".s-Expired,.s-Withdrawn{background:#e2e8f0;color:#475569}.s-Pending{background:#dbeafe;color:#1e40af}"
        + ".note{font-size:.85rem;color:#64748b}.error{color:#b91c1c;font-size:.9rem;margin:.5rem 0 0}.error:empty{display:none}"
        + ".info{background:#eff6ff;border:1px solid #bfdbfe;color:#1e3a8a;border-radius:.4rem;padding:.5rem .8rem;font-size:.9rem;margin:.75rem 0 0}"
        + "@media (max-width:40rem){.card{grid-template-columns:1fr}.actions{justify-content:flex-start}}";

    private const string Script = """
        const csrf = document.querySelector('meta[name=csrf]').content;
        const code = new URLSearchParams(location.search).get('code');
        let group = 'none', highlighted = false, busy = false;
        const decidedHere = new Set();
        const labels = {
          Token: 'Access to a resource', PersonToken: 'Share your identity with a resource',
          MissionToken: 'Extra access under a mission', MissionCreation: 'Start a new mission',
          Permission: 'Run a tool under a mission', FederatedConsent: 'Access through an Access Server',
          AccessServerInteraction: 'Sign-in at an Access Server' };
        const statusLabels = { Delivered: 'Approved · agent has it', Withdrawn: 'Withdrawn by agent' };
        const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
        const when = iso => iso ? new Date(iso).toLocaleString() : '';
        function row(dl, label, value, asCode) {
          if (value == null || value === '') return;
          dl.append(el('dt', null, label));
          const dd = el('dd'); dd.append(asCode ? el('code', null, value) : document.createTextNode(value)); dl.append(dd);
        }
        function card(r, highlight) {
          const c = el('article', 'card' + (highlight ? ' highlight' : ''));
          c.dataset.id = r.id; c.dataset.agent = r.agent;
          if (r.resource) c.dataset.resource = r.resource;
          if (r.scope) c.dataset.scope = r.scope;
          if (r.mission_s256) c.dataset.mission = r.mission_s256;
          const body = el('div');
          const title = el('div'); title.append(el('span', 'kind', labels[r.kind] || r.kind));
          if (r.status !== 'Pending') title.append(' ', el('span', 'pill s-' + r.status, statusLabels[r.status] || r.status));
          body.append(title);
          const dl = el('dl', 'meta');
          row(dl, 'Agent', r.agent, true); row(dl, 'Resource', r.resource, true); row(dl, 'Scope', r.scope, true);
          row(dl, 'Account', r.account, true); row(dl, 'Tool', r.action, true); if (group !== 'mission') row(dl, 'Mission', r.mission); row(dl, 'Tools', r.tools, true);
          if (r.mission_s256 && group !== 'mission') row(dl, 'Mission s256', r.mission_s256, true);
          row(dl, 'Requested', when(r.created_at));
          if (r.status === 'Pending') row(dl, 'Expires', when(r.expires_at));
          if (r.status !== 'Pending') row(dl, 'Decided', [when(r.decided_at), r.decided_by && 'via ' + r.decided_by.toLowerCase()].filter(Boolean).join(' '));
          body.append(dl); c.append(body);
          const actions = el('div', 'actions');
          if (r.decidable) {
            const approve = el('button', 'approve', 'Approve'); approve.type = 'button';
            const deny = el('button', 'deny', 'Deny'); deny.type = 'button';
            approve.addEventListener('click', () => decide(r.id, 'approve', c));
            deny.addEventListener('click', () => decide(r.id, 'deny', c));
            actions.append(approve, deny);
          } else if (r.external_url && r.status === 'Pending') {
            const a = el('a', null, 'Complete at the Access Server'); a.href = r.external_url; a.target = '_blank'; a.rel = 'noopener noreferrer';
            actions.append(a);
          } else if (r.status === 'Pending') {
            actions.append(el('span', 'note', 'Waiting for the agent'));
          }
          c.append(actions);
          if (r.agent_asserted) {
            const a = el('div', 'asserted'); a.append(el('strong', null, 'The agent says (not verified)'));
            if (r.agent_asserted.justification) a.append(el('blockquote', null, r.agent_asserted.justification));
            const dl2 = el('dl', 'meta'); row(dl2, 'Platform', r.agent_asserted.platform); row(dl2, 'Device', r.agent_asserted.device);
            if (dl2.childElementCount) a.append(dl2);
            c.append(a);
          }
          return c;
        }
        function render(target, groups, empty, highlight) {
          const root = document.getElementById(target); root.replaceChildren();
          if (!groups.some(g => g.records.length)) { root.append(el('p', 'empty', empty)); return; }
          for (const g of groups) {
            const wrap = el('div', 'group');
            if (g.label) {
              const h = el('div', 'group-h'); h.append(el('span', null, g.label));
              if (g.mission_s256) { const a = el('a', null, 'Mission log'); a.href = '/admin/mission-log/' + encodeURIComponent(g.mission_s256); a.target = '_blank'; a.rel = 'noopener'; h.append(a); }
              wrap.append(h);
            }
            for (const r of g.records) wrap.append(card(r, r.id === highlight));
            root.append(wrap);
          }
        }
        async function refresh() {
          if (busy) return;
          const query = new URLSearchParams({ group }); if (code) query.set('code', code);
          try {
            const response = await fetch('/dashboard/requests?' + query, { credentials: 'same-origin', cache: 'no-store' });
            if (response.status === 401) { location.reload(); return; }
            const data = await response.json();
            const pending = data.pending.reduce((n, g) => n + g.records.length, 0);
            document.getElementById('pending-count').textContent = pending;
            document.title = (pending ? '(' + pending + ') ' : '') + 'Consent dashboard — Person Server';
            render('pending', data.pending, 'No pending requests.', data.highlight);
            render('history', data.history, 'Nothing decided yet.', data.highlight);
            document.getElementById('settled').hidden = !data.settled || decidedHere.has(data.highlight);
            document.getElementById('status').textContent = 'Updated ' + new Date().toLocaleTimeString();
            if (data.highlight && !highlighted) {
              highlighted = true;
              document.querySelector('.card.highlight')?.scrollIntoView({ block: 'center' });
            }
          } catch { document.getElementById('status').textContent = 'Reconnecting…'; }
        }
        async function decide(id, action, cardEl) {
          busy = true;
          const notice = document.getElementById('notice');
          notice.textContent = '';
          cardEl.querySelectorAll('button').forEach(b => b.disabled = true);
          try {
            const response = await fetch('/dashboard/requests/' + encodeURIComponent(id) + '/' + action,
              { method: 'POST', headers: { 'X-CSRF-Token': csrf }, credentials: 'same-origin' });
            if (!response.ok) {
              const problem = await response.json().catch(() => ({}));
              notice.textContent = problem.error === 'already_decided'
                ? 'That request was already decided elsewhere.'
                : 'Could not ' + action + ' the request: ' + (problem.detail || problem.error || response.status);
            } else decidedHere.add(id);
          } finally { busy = false; await refresh(); }
        }
        document.querySelectorAll('[data-group]').forEach(b => b.addEventListener('click', () => {
          group = b.dataset.group;
          document.querySelectorAll('[data-group]').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
          refresh();
        }));
        refresh();
        setInterval(refresh, 1000);
        """;
}
