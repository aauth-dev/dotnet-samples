# SampleApp

Start the full stack from the repository root with `make demo`, then open
<http://localhost:5240>. `make demo-keycloak` selects the configured live IdP
policy. Isolated demo consent is local-only; do not expose this stack publicly.

Calendar, Inbox, Wallet, Trips, Bookings and Concierge pages execute real signed
requests. Profile pages explicitly demonstrate generic HWK, direct JWKS and
naming-JWT signatures; they are not alternative AAuth resource carriers.

- [Wallet Protocol](../../docs/workflows/wallet-protocol.md): `/wallet-protocol`,
  with AS clarification/cancel, direct-AS chaining and revocation/recovery
- [Catalog Gateway](../../docs/workflows/catalog-gateway.md): `/catalog-gateway`,
  service-qualified grants and sibling-service rejection
- [Document Release](../../docs/workflows/document-release.md): `/documents`,
  resource permission before PS consent, approval/download and denial
- [Events](../../docs/workflows/events.md): `/events`, public/protected account
  subscriptions and verified durable receipts
- [R3](../../docs/workflows/rich-resource-requests.md): `/bookings`, account
  selection and exact-parameter conditional approval
- [Shared setup](../README.md): service URLs, explicit egress policy and consent
- [Playwright specs](playwright-tests/): executed through [the shared configuration](../../tests/e2e/playwright.config.ts)

Displayed C# blocks compile with typed prior-step and host callback inputs in
[SnippetCompilationTests](../../tests/AAuth.Tests/Api/SnippetCompilationTests.cs).
Captured JSON/HTTP results are dynamic views of the running flow. Application
callbacks such as `Surface` and `CancelBookingAsync` are not SDK APIs; key custody,
authenticated person mapping, durable provider contracts and external business
effects remain host responsibilities.