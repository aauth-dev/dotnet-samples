# Documents Resource

Documents listens on <http://localhost:5007>. It serves one work-account travel
document and demonstrates resource-initiated interaction, separately from
resource-managed opaque access and AS-initiated consent.

| Endpoint | Contract |
|---|---|
| `GET /document` | Agent JWT produces a resource-token challenge containing `interaction`; an auth JWT requires `documents.read`, account `work` and an agent/key-bound release decision |
| `GET/POST /permission` | Standard `code`/`callback` browser arrival and authenticated local document-owner session |
| `POST /permission/approve` | Session/CSRF-bound release followed by the admitted callback |
| `POST /permission/deny` | Session/CSRF-bound denial followed by callback `error=access_denied` |

Run `make demo` for both apps, or `make resources` for the resource processes.
Direct `dotnet run --project samples/MockResourceServers/Documents` does not
enable isolated demo sign-in. The exact loopback origin is admitted by
[SampleEgress](../../SampleEgress.cs); never expose the demo publicly.

Use `/documents` in either primary app. The [workflow guide](../../../docs/workflows/document-release.md)
describes the four actual steps and callback controls. Release records expire
after five minutes and are lost on restart. No external OAuth flow, file upload,
payment operation or simulated token is involved.