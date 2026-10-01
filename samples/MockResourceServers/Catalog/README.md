# Catalog Resource

Catalog reads destination and experience catalogs on port 5006. Both backends
expose a `list` operation, so the resource publishes one merged OpenAPI definition
that renames them `listDestinations` and `listExperiences`; a grant for one cannot
read the other. The resource has no payment, Events or unrelated administrative behavior.

Run `make demo` from the repository root. Choose Travel Catalog in either
primary app, select a catalog, complete consent, and observe the sibling-operation
403 followed by explicit reauthorization. The stack includes the existing R3 AS
at port 5501 and PS at port 5100. Direct starts use
`dotnet run --project samples/MockResourceServers/Catalog` but require the other
services and explicit isolated consent settings for the complete browser flow.

See the [workflow guide and sequence](../../../docs/workflows/catalog-gateway.md),
[resource source](Program.cs), and [shared browser checks](../../../tests/e2e/helpers/catalog.ts).
Catalog is registered in the solution, `Makefile` and Playwright service list.
Reset belongs to the agent/UI session; catalog data and definitions are immutable.