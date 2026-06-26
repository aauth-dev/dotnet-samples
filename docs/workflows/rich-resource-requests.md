# Rich Resource Requests (R3)

> [!WARNING]
> R3 is experimental. This repository demonstrates it through the
> extraction-ready `samples/AAuth.R3` preview library; the core `src/AAuth` SDK
> is unchanged.

Rich Resource Requests replace opaque scope strings with content-addressed
operation documents. In the Guided Tour, Aria asks the `Bookings` resource for
three MCP operations: `search_trip_options`, `hold_itinerary`, and `book_trip`.

Flow #10, **Rich Trip Booking (R3)**, runs against live mock services:

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

The target launches Bookings on `:5004`, the dedicated R3 AS on `:5501`, the
MockPersonServer on `:5100`, the Agent Provider on `:5301`, and GuidedTour on
`:5400`.
