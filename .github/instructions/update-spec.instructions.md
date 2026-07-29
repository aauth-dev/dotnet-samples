---
description: "Workflow for vendoring a new AAuth specification draft into aauth-spec/ and updating SPEC-VERSION.md and CHANGELOG.md."
applyTo: "aauth-spec/**"
---

# Update AAuth Spec Workflow

This repo vendors snapshots of the upstream [AAuth](https://github.com/dickhardt/AAuth)
specification under `aauth-spec/` for reference while building the .NET samples.
Follow this workflow when a new upstream draft is published and needs to be pulled
down. Vendoring is a **documentation-only** task: it adds a snapshot folder and
updates the two tracking files. It does **not** change SDK code.

## Scope and golden rules

- **Vendoring is decoupled from migration.** Pulling a new draft into
  `aauth-spec/` never edits `src/`, `samples/`, `tests/`, or `docs/`. The SDK
  keeps targeting whatever draft it already conformed to until a separate
  migration lands. Always state, in both tracking files, which snapshot the code
  currently targets versus which is the latest reference.
- **Snapshots are immutable and self-contained.** Never edit a vendored file after
  download. Each `v<NN>/` folder carries its own copy of every document it needs,
  including the HTTP Signature Keys draft at the version that snapshot references.
- **One folder per protocol draft.** Folder name is `v<NN>/` where `NN` is the
  zero-padded AAuth **protocol** draft number (for example, `draft-08` →
  [`v08/`](../../aauth-spec/v08/)). Skipping intermediate drafts is expected and
  fine — vendor only the snapshots actually pulled.

## Folder layout

```text
aauth-spec/
    SPEC-VERSION.md   # Per-snapshot source commit + metadata (ascending order)
    CHANGELOG.md      # High-fidelity per-snapshot delta (newest first)
    v01/ v02/ v08/    # One self-contained snapshot per vendored protocol draft
```

Each `v<NN>/` snapshot contains:

| File | Source | Notes |
|---|---|---|
| `draft-hardt-oauth-aauth-protocol.md` | AAuth repo | The protocol spec; names the snapshot. |
| `draft-hardt-aauth-bootstrap.md` | AAuth repo | Informational; often unchanged across drafts. |
| `draft-hardt-aauth-r3.md` | AAuth repo | Rich Resource Requests; has its own version. |
| `draft-hardt-aauth-events.md` | AAuth repo | AAuth Events; standalone draft. Include when present upstream. |
| `interop-demo-profile.md` | AAuth repo | Informational; new since draft-06. Include when present upstream. |
| `draft-hardt-httpbis-signature-key-<NN>.txt` | IETF archive | Lives in the separate `dickhardt/signature-key` repo; vendor the IETF `.txt` at the version the protocol references. |

## Procedure

### 1. Identify the new version and pin a commit

Find the latest published protocol tag and its commit; pin to the tag (do not
track a moving branch):

```bash
# Latest protocol tags (highest first)
curl -s "https://api.github.com/repos/dickhardt/AAuth/tags?per_page=100" \
  | grep '"name"' | grep oauth-aauth-protocol | head

# Resolve the chosen tag to its commit SHA + list files at that tag
TAG=draft-hardt-oauth-aauth-protocol-08
curl -s "https://api.github.com/repos/dickhardt/AAuth/git/ref/tags/$TAG" | grep '"sha"'
curl -s "https://api.github.com/repos/dickhardt/AAuth/contents?ref=$TAG" | grep '"name"'
```

Record the commit SHA, commit date, document date, and the tag name — they all go
into `SPEC-VERSION.md`.

> **Take the document date from the published Internet-Draft, not the kramdown
> `date = ` frontmatter.** Upstream routinely leaves the frontmatter stale (both
> draft-08 and draft-09 ship with `date = 2026-06-17` while the published
> revisions are dated 2026-06-24 and 2026-07-04). Read it off the `.txt`:

```bash
curl -s "https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-$NN.txt" \
  | sed -n '1,12p' | grep -oE '[0-9]{1,2} [A-Z][a-z]+ 20[0-9]{2}' | head -1
```

For companion drafts not yet on the Datatracker (currently R3 and AAuth Events),
the frontmatter is the only available source — use it, and say so in the entry.

### 2. Download the snapshot

```bash
cd aauth-spec
NN=08
TAG=draft-hardt-oauth-aauth-protocol-$NN
BASE="https://raw.githubusercontent.com/dickhardt/AAuth/$TAG"
mkdir -p "v$NN"
for f in draft-hardt-oauth-aauth-protocol.md draft-hardt-aauth-bootstrap.md \
         draft-hardt-aauth-r3.md; do
  curl -fsSL "$BASE/$f" -o "v$NN/$f"
done

# Optional standalone/informational docs; include when present upstream.
for f in draft-hardt-aauth-events.md interop-demo-profile.md; do
  if curl -fsSL "$BASE/$f" -o "v$NN/$f"; then
    echo "Downloaded optional $f"
  else
    rm -f "v$NN/$f"
    echo "Optional $f not present upstream; record as absent."
  fi
done
```

For the HTTP Signature Keys dependency, vendor the IETF `.txt` at the version the
protocol's reference points to (check the `I-D.hardt-httpbis-signature-key`
reference target and the `dickhardt/signature-key` tags):

```bash
SK=05   # the signature-key draft the protocol references
curl -fsSL "https://www.ietf.org/archive/id/draft-hardt-httpbis-signature-key-$SK.txt" \
  -o "v$NN/draft-hardt-httpbis-signature-key-$SK.txt"
```

### 3. Diff unchanged documents against the previous snapshot

Confirm which documents actually changed; `diff -q` exit `0` means byte-identical.
Record "unchanged" docs explicitly so each snapshot stays auditable.

```bash
diff -q v02/draft-hardt-aauth-bootstrap.md v08/draft-hardt-aauth-bootstrap.md
diff -q v02/draft-hardt-aauth-r3.md        v08/draft-hardt-aauth-r3.md
if [ -f v02/draft-hardt-aauth-events.md ] && [ -f v08/draft-hardt-aauth-events.md ]; then
  diff -q v02/draft-hardt-aauth-events.md v08/draft-hardt-aauth-events.md
fi
# Protocol structural delta (added/removed sections):
diff <(grep -nE '^#{1,2} ' v02/draft-hardt-oauth-aauth-protocol.md | sed 's/^[0-9]*://') \
     <(grep -nE '^#{1,2} ' v08/draft-hardt-oauth-aauth-protocol.md | sed 's/^[0-9]*://')
```

### 4. Update `SPEC-VERSION.md`

- Add the new snapshot to the intro grouping and to the "SDK currently targets …"
  / "latest upstream snapshot is …" framing.
- Append a `## \`v<NN>/\` — protocol draft-NN` section (sections are in **ascending**
  order). Include a metadata table (source repo, commit SHA, commit date, tagged
  version, document date, IETF draft URL, copied-on date) and a per-file list
  noting which docs are unchanged from the prior snapshot, including AAuth Events
  when present.
- Add a short "Notable changes since draft-XX" highlight list.

### 5. Update `CHANGELOG.md`

- Add a row to the snapshot table (table is **ascending**: oldest first).
- Add a Contents entry and a new `## \`v<NN>/\`` section at the **top** of the
  per-snapshot sections (newest first).
- Summarize the delta by theme, then reproduce the **author's verbatim per-draft
  changelog** from the protocol's `# Document History` section for every draft
  spanned. Note unchanged R3/bootstrap/AAuth Events, any new documents, and the
  signature-key version bump.
- Reference the spec's own kramdown anchors (e.g. `#sub-agents`) rather than line
  numbers where possible — anchors are stable across line shifts.

### 6. Verify and stop

- Run `get_errors` (or markdownlint) on `SPEC-VERSION.md` and `CHANGELOG.md`.
- Confirm any external URLs added (datatracker, editor's copy) resolve.
- Do **not** start an SDK migration. If migration is wanted, open a separate plan
  under `.agent/plans/<YYYY-MM-DD>-aauth-vNN-spec-migration/` per
  [`plan-workflow.instructions.md`](plan-workflow.instructions.md).

## Canonical sources and fallback

The GitHub repo (`dickhardt/AAuth`) is the working source these steps download
from, but it is not the system of record. The **IETF Datatracker** is the canonical,
permanent home and survives the repo being moved, renamed, or deprecated:

- Document page (all revisions) — <https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/>
- Per-revision text — `https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-<NN>.txt`
- Per-revision HTML — `https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol-<NN>`
- AAuth Events editor's copy — <https://github.com/dickhardt/AAuth/blob/main/draft-hardt-aauth-events.md>

If the GitHub repo is unavailable, vendor the Datatracker `.txt` rendering for that
revision instead of the kramdown `.md`, and note the substitution in the snapshot's
`SPEC-VERSION.md` entry. The same applies to the dependencies: HTTP Signature Keys
lives at <https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/>.

## Conventions

- Pin downloads to a **tag**, not `main`. Record the resolved commit SHA.
- Prefer the GitHub `.md` source; fall back to the Datatracker `.txt` rendering if
  the repo is gone (see Canonical sources and fallback).
- Match existing filenames exactly; the signature-key file keeps its draft number
  in the name (`draft-hardt-httpbis-signature-key-<NN>.txt`).
- `SPEC-VERSION.md` and `CHANGELOG.md` are reference docs and intentionally carry
  **no YAML frontmatter** — do not add any.
- Dates are ISO 8601 (`YYYY-MM-DD`).
