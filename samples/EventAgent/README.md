---
title: EventAgent Sample
description: A single-shot AAuth Events console demonstration using the same client as both primary apps.
---

## Run

Start `make demo` in one terminal. Run `make agent-events` in another for a public
availability subscription. Use `make agent-events ARGS="--protected --work"` for
a protected work-account subscription and approve the printed consent URL.

The agent discovers AsyncAPI, obtains a subscription URL, requests an AP subscribe
token, registers, triggers a sample notification and polls the AP inbox. It
verifies the resource JWT before recording the receipt and ignores a repeated
issuer/eid pair. The console prints each executed step and response.

The sample persists its key, context and receipts under `~/.aauth/event-agent`.
Each invocation starts a new single-shot subscription. It does not resume an old
console workflow automatically. AP polling, acknowledgement, subscribe-token
acquisition and the resource trigger are authenticated local sample APIs, not
standard Events endpoints. Recurring-event ambiguity is documented in the
[Events workflow](../../docs/workflows/events.md).