# EventAgent

`EventAgent` is a focused console sample for the experimental AAuth Events
flow. It uses the protected Bookings waitlist, obtains a subscribe token from
the Mock Agent Provider, registers the ticket URL, triggers a deterministic
event, then polls and verifies the event before displaying its JSON payload.

The sample references only `AAuth` and `AAuth.Events`; it does not reference
`AAuth.R3`. The Bookings resource uses R3 claims internally, while the agent
uses the normal AAuth JWT/challenge-handling client.

## Run

Start the focused stack, then run EventAgent in another terminal:

```bash
make events-stack
make agent-events
```

The equivalent direct command is:

```bash
dotnet run --project samples/EventAgent -- \
  --ap http://localhost:5301 \
  --bookings http://localhost:5005 \
  --ps http://localhost:5100
```

Options:

```text
--ap <url>        Agent Provider (default http://localhost:5301)
--bookings <url> Bookings resource (default http://localhost:5005)
--ps <url>        Person Server (default http://localhost:5100)
--sub <subject>   Agent subject (default aauth:event-agent@ap.example)
```

The enrollment key is stored by `FileKeyStore`; the EventAgent metadata cache
is kept separately under:

```text
~/.local/share/aauth-event-agent/<sha256-of-subject>.json
```

To reset enrollment after restarting the in-memory Mock Agent Provider, remove
that file (and rerun the command):

```bash
rm ~/.local/share/aauth-event-agent/*.json
```

## Trust and transport boundary

Event issuer metadata and JWKS are resolved through the Events URL policy. The
sample's AP acquisition, batch polling, and ACK endpoints are deliberately
non-normative sample transport: they use enrolled-agent HTTP signatures,
in-memory AP state, and an explicit ACK. Production agents need a durable
inbox, durable event-context and deduplication storage, and an authenticated
AP-to-agent transport.

The event token authenticates the envelope, not the optional payload. The
sample prints a prominent **UNAUTHENTICATED PAYLOAD** warning, displays JSON
only, performs no consequential action, and ACKs only after successful token
verification, local `eid` lookup, deduplication, and display. Invalid,
unknown-context, duplicate, or display failures are never acknowledged.
