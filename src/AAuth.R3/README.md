# AAuth.R3 preview

Experimental helpers for **AAuth Rich Resource Requests (R3)** — resource-declared,
vocabulary-based authorization layered on the [AAuth](https://www.nuget.org/packages/AAuth)
protocol. Resources publish content-addressed R3 documents describing what a class
of access *means*; tokens carry `r3_uri`, `r3_s256`, `r3_granted`, and
`r3_per_call` alongside opaque scopes.

> **Preview.** R3 is an IETF Exploratory Draft (`draft-hardt-aauth-r3`). This package
> ships separately from `AAuth` and may change with the draft. It tracks the `AAuth`
> package version.

Current target: R3 draft-01 from the protocol draft-10 snapshot, alongside
Signature Keys draft-08. Supported vocabulary models do not imply native
protocol hosting; runnable integrations use OpenAPI, OpenAPI Gateway and AsyncAPI.

## What's inside

- R3 models for all eight standard vocabularies: MCP, OpenAPI, OpenAPI Gateway,
  gRPC, GraphQL, AsyncAPI, WSDL, and OData. Required and optional members are
  validated against the selected vocabulary. `R3VocabularySchemas` admits
  third-party URI schemas explicitly per consumer, without global registration.
- Content addressing (`R3Hash`) — SHA-256 over the verbatim served bytes, base64url
  (no canonicalization).
- Claim helpers (`R3AuthClaims`, `R3ClaimReader`) that ride the core token builders'
  `AdditionalClaims` seam.
- Server helpers: designated-AS document readership, signed fetch and hash
  verification, per-call proposal enforcement, and mandatory audit persistence.

## Qualified identity

```csharp
var operation = new R3OperationIdentity(Vocabulary.OpenApiGateway,
    R3Operation.OpenApiGateway("calendar", "createEvent"));
var granted = new R3Grant
{
    Vocabulary = Vocabulary.OpenApiGateway,
    Operations = [operation.Operation],
};
bool authorized = granted.Contains(operation);
```

Identity includes the vocabulary, member names, service qualifier, and optional
members. An omitted optional member is not a wildcard. OData method-array order
does not change identity. `R3Metadata.ValidateOperations` checks an operation
against advertised discovery and a resource-supplied authoritative definition;
it does not fetch or parse arbitrary API definitions on the resource's behalf.
Gateway discovery uses a JSON service-label-to-OpenAPI-URL map.

## Issuance and storage

`R3AccessTokenEndpointOptions.AuditSink` is required. There is no no-op sink.
Completion must mean the token identity/hash and audit provenance are committed
before release. `InMemoryR3AuditSink` is explicitly non-durable and intended for
tests. The R3 sample uses Microsoft.Data.Sqlite 10.0.11 with a transaction joining
issuance and audit rows; bearer token text is not persisted. A post-commit delivery
failure may leave an audited but undelivered token, never an unaudited release.
Pending browser consent remains volatile. `R3ProposalStore` retains exact document
and proposal bytes for its process lifetime, including after consent completes;
an unexpired grant must not lose its approved proposal after ten minutes.
Its `maxEntries` capacity defaults to 1024 distinct hashes. Duplicate content
reuses its entry; new content at capacity fails before a reference is published,
without evicting existing references. The store is not restart-durable. Restart
requires a new authorization request; production document and audit retention
requires durable hosting beyond this in-memory sample store.

`IsPerCallOperation` and `IsOperationAllowed` receive a qualified identity.
`IsProposalAllowed` can evaluate concrete parameters. Resource scopes, when
present, also require `IsScopeAllowed(resourceIssuer, scope)` approval and are
retained independently of R3 grants. Account identifiers must match the resource
token, document/proposal, auth token, and requested resource account.

## Reader and transport policy

`R3DocumentReaderPolicy` defaults to the designated AS using `aauth-access.json`.
Explicit PS evaluators must use `aauth-person.json`. PS evaluation is the logged
Q4 interpretation of conflicting draft readership clauses, not an unconditional
PS entitlement. Agent requests are rejected.

Custom `FetchAndVerifyAsync` callbacks require `FetchTransportContract`. The SDK
still validates the URL, deadline, response size, and hash of returned bytes.
Network callbacks must enforce DNS/connected-address admission and redirect
policy; `InProcessOnly` must never be used for a network callback. Hashes always
cover exact served bytes, including bytes returned from caches.

## Events handoff

`R3Operation.AsyncApi(operationId, "receive")` models a subscription grant.
The `AAuth.Events` companion and shared EventSupport sample implement the
authenticated ticket response, subscribe token, registration and event delivery.
Both primary apps expose public/protected `/events` flows. R3 vocabulary support
alone does not provide an AP transport or durable receipt store.

## Status

Preview. The AAuth samples show a runnable end-to-end R3 flow (the **Bookings**
resource, guarded by a dedicated R3 Access Server, using the OpenAPI vocabulary)
and a Catalog Gateway with service-qualified grants and sibling-service rejection.
