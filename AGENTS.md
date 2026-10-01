# Agent Instructions

## Documentation inventory snapshot

The documentation inventory test
(`SnippetCompilationTests.Documentation_FrozenSurface`) hashes every file it
covers into
[`tests/AAuth.Tests/Api/DocumentationInventory.snapshot.md`](tests/AAuth.Tests/Api/DocumentationInventory.snapshot.md).
CI fails when that snapshot is stale. Covered files are:

- the root `README.md`;
- every `*.md` under `docs/`, `src/` and `samples/` (including sample READMEs);
- `*.cs`, `*.razor` and `*.ts` under `samples/GuidedTour/`, `samples/SampleApp/`,
  `samples/CapabilitySupport/` and `samples/EventSupport/`.

After changing any of these, regenerate the snapshot, review its diff and commit
it in the same change:

```bash
AAUTH_UPDATE_DOCS_INVENTORY=1 dotnet test tests/AAuth.Tests --filter "FullyQualifiedName~Documentation_FrozenSurface"
```
