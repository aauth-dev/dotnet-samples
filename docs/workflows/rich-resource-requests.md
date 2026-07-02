# Rich Resource Requests (R3)

> [!WARNING]
> R3 is experimental. This repository demonstrates it through the
> extraction-ready `samples/AAuth.R3` preview library. R3-specific models and
> claims live there; `src/AAuth` only gained generic Person Server extensibility
> used by the demo. The preview library currently implements the MCP vocabulary
> only.

Rich Resource Requests replace opaque scope strings with content-addressed
operation documents. In the Guided Tour, Aria asks the `Bookings` resource for
three MCP operations: `search_trip_options`, `hold_itinerary`, and `book_trip`.

Flow #11, **Rich Trip Booking (R3)**, runs against live mock services:

1. Agent discovers Bookings metadata, including `authorization_endpoint` and
   `r3_vocabularies["urn:aauth:vocabulary:mcp"]`.
2. Agent signs `POST /authorize` with `r3_operations`.
3. Bookings returns a resource token whose `aud` is the dedicated R3 AS and
   whose payload carries `r3_uri` and `r3_s256`.
4. The Person Server fetches the R3 document with a `jwks_uri` signature,
   verifies the digest over the exact bytes served, and renders `display`
   consent.
5. After user approval, the PS federates to the R3 AS.
6. The AS fetches and verifies the same R3 document, then mints
   `r3_granted` (`search_trip_options`, `hold_itinerary`) and
   `r3_conditional` (`book_trip`).
7. Bookings serves the granted calls with 200 responses.
8. `book_trip` returns a per-call proposal (`r3_uri`/`r3_s256`) for the concrete
   itinerary.
9. The user approves that proposal; the digest-matched retry commits the booking
   and returns 200.

Run the demo with:

```bash
make demo-tour-r3
```

The target launches Bookings on `:5005`, the dedicated R3 AS on `:5501`, the
MockPersonServer on `:5100`, the Agent Provider on `:5301`, and GuidedTour on
`:5400`.

## Conformance scope

This demo exercises the MCP vocabulary (`urn:aauth:vocabulary:mcp`) only.
Bookings validates incoming `r3_operations` against the same MCP tool set it
publishes from `/mcp` before it issues a resource token. The sample uses one
internal R3 definition for those tools, so multi-definition R3 document
composition is not exercised here; resources that split operations across
multiple internal definitions must compose and persist one content-addressed R3
document before issuing their resource token.

The latest upstream R3 draft drift in this area is limited to future AsyncAPI
and AAuth Events wording. This phase intentionally defers syncing the checked-in
v02 draft and adds no AsyncAPI implementation code while the sample remains
MCP-only.
