# Agent Console

A command-line AAuth agent. It enrols with an Agent Provider, signs requests
with RFC 9421, handles `401` challenges, and — when given a Person Server —
runs the three-party exchange to obtain an auth token.

## What it does

- Enrols (and caches) an agent key with the Agent Provider (`--ap`).
- Signs a `GET` to the target URL and prints the resource's JSON response.
- On a `401` challenge, follows the indicated flow for the chosen
  `--signing-mode`.
- With `--ps`, performs the three-party exchange: agent token → resource
  token → PS `POST /token` → auth token → retried request.

## Run

```bash
dotnet run --project samples/AgentConsole -- <url> --ap <agent-provider-url> [options]
```

| Flag | Default | Purpose |
|------|---------|---------|
| `--ap <url>` | _(required)_ | Agent Provider URL (enrol + refresh endpoints) |
| `--sub <id>` | `aauth:demo@ap.example` | Agent subject identifier |
| `--ps <url>` | _(none)_ | Person Server URL — enables the three-party flow |
| `--signing-mode <mode>` | `jwt` (with `--ps`) / `hwk` (without) | One of `jwt`, `hwk`, `jwks_uri`, `jkt-jwt` |
| `--prefer-wait <seconds>` | _(none)_ | Long-poll hint for deferred PS responses |
| `--upstream-token <jwt>` | _(none)_ | Upstream auth token for call-chaining scenarios |

## Signing-mode → path mapping

When the target URL has no path (or just `/`), AgentConsole appends the path
that routes the WhoAmI sample (port 5000) to the matching verification
pipeline:

| `--signing-mode` | Appended path | WhoAmI endpoint |
|------------------|---------------|-----------------|
| `hwk` | `/hwk` | Pseudonymous (signature only) |
| `jkt-jwt` | `/jkt-jwt` | Pseudonymous, key delegation |
| `jwks_uri` | `/jwks-uri` | Agent identity |
| `jwt` _(default)_ | `/jwt` | Three-party baseline |

To reach the elevated (`/jwt/admin`) or RBAC (`/jwt/roles`) endpoints, pass the
explicit path — these are not auto-appended.

## Validated invocations

Against the running WhoAmI (5000), MockAgentProvider (5301), and
MockPersonServer (5100):

```bash
# Pseudonymous — HTTP signature only (no PS)
dotnet run --project samples/AgentConsole -- \
  http://localhost:5000/hwk --ap http://localhost:5301

# Pseudonymous, key delegation via naming JWT
dotnet run --project samples/AgentConsole -- \
  http://localhost:5000 --ap http://localhost:5301 --signing-mode jkt-jwt

# Agent identity — key verified via JWKS URI
dotnet run --project samples/AgentConsole -- \
  http://localhost:5000 --ap http://localhost:5301 --signing-mode jwks_uri

# Three-party baseline — scope "whoami" (grant consent first)
dotnet run --project samples/AgentConsole -- \
  http://localhost:5000 --ap http://localhost:5301 --ps http://localhost:5100

# Three-party, elevated scope "whoami:admin"
dotnet run --project samples/AgentConsole -- \
  http://localhost:5000/jwt/admin --ap http://localhost:5301 \
  --ps http://localhost:5100 --signing-mode jwt

# Three-party, RBAC — PS asserts roles ["whoami-admin"], groups ["demo-users"]
dotnet run --project samples/AgentConsole -- \
  http://localhost:5000/jwt/roles --ap http://localhost:5301 \
  --ps http://localhost:5100 --signing-mode jwt
```

## Granting consent

MockPersonServer keys consent by `(agent, resource, scope)`. Grant it ahead of
a three-party run (the `scope` field defaults to `whoami` if omitted):

```bash
# Baseline / RBAC endpoints use scope "whoami"
curl -X POST http://localhost:5100/admin/consent \
  -H 'content-type: application/json' \
  -d '{"agent":"aauth:demo@ap.example","resource":"http://localhost:5000","scope":"whoami"}'

# The /jwt/admin endpoint requires the elevated scope
curl -X POST http://localhost:5100/admin/consent \
  -H 'content-type: application/json' \
  -d '{"agent":"aauth:demo@ap.example","resource":"http://localhost:5000","scope":"whoami:admin"}'
```

## Enrollment-cache quirk

AgentConsole caches its enrollment on disk at
`~/.local/share/aauth-agent-console/<sub>.json`, while MockAgentProvider keeps
enrollments in memory. If the AP is restarted, the signed `/refresh` (used by
`jwt` and `jkt-jwt`) and the AP-hosted JWKS (used by `jwks_uri`) return `4xx`
for the now-unknown agent. Delete the cached enrollment file so the console
re-enrols:

```bash
rm ~/.local/share/aauth-agent-console/aauth:demo@ap.example.json
```

The `hwk` mode is unaffected — it performs no refresh.
