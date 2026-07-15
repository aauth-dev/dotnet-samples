# EventAgent

> **Sample only.** This console app demonstrates the protected Bookings
> waitlist and the AAuth Events envelope-verification boundary.

EventAgent enrolls at the Mock Agent Provider, requests the protected waitlist,
acquires a subscribe token through the sample AP route, registers the ticket,
triggers one event, then uses the sample polling route to retrieve and verify
the receipt.

## Run

Start the focused stack, then run EventAgent in another terminal:

```bash
make events-stack
make agent-events
```

Equivalent direct command:

```bash
dotnet run --project samples/EventAgent -- \
  --ap http://localhost:5301 \
  --bookings http://localhost:5005 \
  --ps http://localhost:5100
```

Options implemented by `Program.cs`:

```text
--ap <url>        Agent Provider (default http://localhost:5301)
--bookings <url> Bookings resource (default http://localhost:5005)
--ps <url>        Person Server (default http://localhost:5100)
--sub <subject>   Agent subject (default aauth:event-agent@ap.example)
```

The enrollment key is held by `FileKeyStore`. EventAgent writes its enrollment
metadata cache below the platform `LocalApplicationData` directory
(`~/.local/share/aauth-event-agent/<sha256-of-subject>.json` on this Linux
sample). After restarting the in-memory AP, reset it with:

```bash
make event-agent-reset
```

## Trust and transport boundary

The resource registration, event-token verification, local `eid` lookup, and
exact-token deduplication use `AAuth.Events`. The AP acquisition,
non-destructive batch polling, and explicit receipt ACK are **non-normative
sample transport**:

- acquisition: `POST /agents/{agentId}/event-subscriptions/bookings`;
- polling: `GET /agents/{agentId}/events?limit=20`;
- ACK: `POST /agents/{agentId}/events/{receiptId}/ack`.

Polling and ACK are not standardized. Production agents need an authenticated,
application-owned AP-to-agent transport plus durable event context and
deduplication state.

The event JWT authenticates the event envelope, not the optional JSON payload.
EventAgent prints an **UNAUTHENTICATED PAYLOAD** warning, displays JSON only,
performs no consequential action, and ACKs only after successful envelope
verification, known local `eid`, deduplication, and display parsing. Invalid,
unknown-context, duplicate, or display failures are never acknowledged.
