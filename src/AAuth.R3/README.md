# AAuth.R3 preview

Experimental helpers for **AAuth Rich Resource Requests (R3)** — resource-declared,
vocabulary-based authorization layered on the [AAuth](https://www.nuget.org/packages/AAuth)
protocol. Resources publish content-addressed R3 documents describing what a class
of access *means*; tokens carry `r3_uri`, `r3_s256`, `r3_granted`, and
`r3_per_call` alongside opaque scopes.

> **Preview.** R3 is an IETF Exploratory Draft (`draft-hardt-aauth-r3`). This package
> ships separately from `AAuth` and may change with the draft. It tracks the `AAuth`
> package version.

Current target: the R3 editor's copy vendored with protocol draft-11 (aauth-spec/v11),
alongside Signature Keys draft-09. Supported vocabulary models do not imply native
protocol hosting; runnable integrations use OpenAPI and AsyncAPI.

## What's inside

- R3 models for all seven standard vocabularies: MCP, OpenAPI,
  gRPC, GraphQL, AsyncAPI, WSDL, and OData. Required and optional members are
  validated against the selected vocabulary. `R3VocabularySchemas` admits
  third-party URI schemas explicitly per consumer, without global registration.
- Content addressing (`R3Hash`) — SHA-256 over the verbatim served bytes, base64url
  (no canonicalization).
- Claim helpers (`R3AuthClaims`, `R3ClaimReader`) that ride the core token builders'
  `AdditionalClaims` seam.
- Server helpers: designated-AS document readership, signed fetch and hash
  verification, per-call proposal enforcement, and mandatory audit persistence.
- Operation access annotations (`R3AccessAnnotations`): write or read the
  `per-call`/`auth-token`/`person-token`/`agent-token` requirement and the budget
  flag on an OpenAPI or AsyncAPI operation (`x-aauth-access-mode`,
  `x-aauth-budget`) or an MCP tool's `_meta`. `EffectiveAccessMode` applies the
  sparse-default and budget rules. Annotations are advisory; resources still
  enforce `r3_granted` and `r3_per_call` from the auth token.

## Qualified identity

```csharp
var operation = new R3OperationIdentity(Vocabulary.Wsdl,
    R3Operation.Wsdl("Search", "Calendar"));
var granted = new R3Grant
{
    Vocabulary = Vocabulary.Wsdl,
    Operations = [operation.Operation],
};
bool authorized = granted.Contains(operation);
```

Identity includes the vocabulary, member names, and optional members such as the
WSDL `service` qualifier. An omitted optional member is not a wildcard. OData method-array order
does not change identity. `R3Metadata.ValidateOperations` checks an operation
against advertised discovery and a resource-supplied authoritative definition;
it does not fetch or parse arbitrary API definitions on the resource's behalf.

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

`r3_uri` values must be absolute HTTPS URIs (apart from the SDK's explicit
development-loopback exception), and the document origin must match the verified
resource issuer. `R3DocumentReaderPolicy` defaults to the designated AS using
`aauth-access.json`.
Explicit PS evaluators must use `aauth-person.json`. PS evaluation is the logged
Q4 interpretation of conflicting draft readership clauses, not an unconditional
PS entitlement. Agent requests are rejected.

Register the policy with `services.AddAAuthR3Documents(sp => policy)`, which also
adds the in-memory `IR3DocumentEntitlements` default, and map documents with
`MapR3Document(pattern, getBytes)`. Each `R3Challenge` mint validates the
referenced document/proposal through `IR3OperationValidator`, then entitles the
token's `aud` and `ps` to read the exact `r3_uri`/`r3_s256` until the resource
token expires. `ChallengeAsync(context, …)` and
`R3EnforcementDecision.ToResultAsync(context, challenge, …)` use
`R3Challenge.Entitlements` or the DI-registered store. Call
`IR3DocumentEntitlements.EntitleAsync(uri, s256, reader, tokenId, expiresAt)`
yourself for resource tokens minted another way. Register shared validator and
entitlement implementations first to scale out.

Approved per-call retries return `R3EnforcementDecisionKind.SingleUse` with a
`SingleUseGrant` handle. Execute the operation through
`SingleUseGrant.ExecuteOnceAsync`; replays of the same auth-token `(iss, jti)`
receive the retained result. Missing gate, `jti`, or `exp` returns
`single_use_required`.

The R3 Access Server registers its options with
`services.AddR3AccessTokenEndpoint(o => { … })` and maps them with
`app.MapR3AccessTokenEndpoint()`; `Issuer`, `SigningKeys` and `AuditSink` are
validated at map time.

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
and a Travel Catalog whose merged OpenAPI definition renames colliding operations,
with sibling-operation rejection.
