# Document Release

Both apps expose `/documents`: [GuidedTour](../../samples/GuidedTour/Components/Pages/Documents.razor)
and [SampleApp](../../samples/SampleApp/Components/Pages/Documents.razor).
The shared [session](../../samples/CapabilitySupport/DocumentDemoSession.cs) performs
real requests against the AP, PS and [Documents resource](../../samples/MockResourceServers/Documents/README.md).
Start the isolated local stack with `make demo`.

## Four Steps

1. Enroll a document agent with a new key at the local AP.
2. Make a signed `GET /document`. The resource returns a verified resource-token
   challenge for `documents.read`, account `work`, with its `/permission` URL/code.
3. Request authorization through the PS. Open the PS interaction link, sign in
   to the isolated demo, and continue from its interstitial to the resource.
   Release the document there, return through the per-flow PS callback, then
   approve PS consent. The agent polls with its signed agent credential and
   receives the auth token only after these decisions.
4. Download using the auth token and the original agent key. The resource checks
   the issuer, agent/key, account, scope and its own release decision.

Declining release returns `access_denied` to the PS callback. The PS maps this
to `403 denied` on the pending request without asking for its own consent or
issuing a token. Reset starts a new agent and request; it does not alter existing
resource permission records.

## Security Boundary

The [resource-initiated interaction flow](../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#resource-initiated-interaction)
places resource permission before PS consent (L993) and requires abandonment on
callback error (L994). The SDK admits the destination before redirecting. The
interstitial continuation uses authenticated person/session and CSRF checks;
the browser callback uses per-flow state, a browser cookie and the retained
resource-token/context snapshot. Replays and changed context fail. The callback
is a browser redirect, not an invented HTTP-signature requirement for resources.
The agent still requires a signed, verified terminal token response.

Configure `AAuthPersonServerOptions.ResourceInteractionSessions` with the host's
authenticated person authorization policy, normally the same
`BrowserConsentSessions` instance used for PS consent. The default denies
unauthorized people. Hosts must not present or record ordinary consent while
`PersonPendingEntry.AwaitingResourceInteraction` is true. A callback does not
authenticate an external OAuth provider; a resource integrating one must validate
that provider's own state, identity and authorization result before redirecting.

Documents implements a local document-owner permission decision, not a mock
OAuth exchange. Demo sign-in is explicitly local-only, as described in the
[sample deployment constraints](../../samples/README.md#start-the-stack).
The permission records and pending flow are in-memory, not distributed or durable.

## Evidence

The [shared Playwright cases](../../tests/e2e/helpers/documents.ts) run through
both app-local wrappers. They check the real resource/PS order, ordinary-consent
bypass rejection, approval/download, denial without download, token account and
scope, reset, and desktop/mobile layout. PersonServerMapperTests additionally
cover callback replay, browser/state/context mismatches and error mapping;
DeferredFederationTests cover resource completion/denial before AS policy.