# AAuth.Events

`AAuth.Events` is an experimental preview package for the AAuth asynchronous
subscription and event-token protocol. It provides the token primitives used
by agent providers, resources, and agents; network delivery, persistence, and
payload schemas remain application responsibilities.

The package targets .NET 10 and depends only on `AAuth`. The AP uses
`SubscribeTokenBuilder`, resources use `EventTokenBuilder`, and agents/resources
use the typed claim projections after core JWT verification. Network endpoints,
discovery, payload schemas, and persistence are application responsibilities.

This is a preview implementation of a changing draft. Applications must use
durable, atomic storage for subscriptions and event inboxes and must not treat
an event payload as authenticated by the event JWT.
