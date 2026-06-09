# AAuth Blazor Demo E2E Tests (Playwright)

Browser end-to-end tests for the two Blazor Server demo apps:

- `samples/GuidedTour` — single page, flow + signing-mode dropdowns, step engine.
- `samples/SampleApp` — multi-page, one route per signing mode / consent flow.

Specs live **inside each sample** under `playwright-tests/`; the Node toolchain
and Playwright config live once here under `tests/e2e/`.

## Prerequisites

- **Node.js ≥ 20** and **.NET 10 SDK**. In the dev container, Node and the
  Chromium browser are installed automatically by `.devcontainer/post-create.sh`.
- Manual install:

  ```bash
  cd tests/e2e
  npm ci
  npx playwright install --with-deps chromium
  ```

## Running

From the repo root via `make`:

```bash
make e2e-install   # one-time: npm ci + Chromium (with deps)
make e2e           # both projects (guided-tour + sample-app)
make e2e-tour      # GuidedTour only
make e2e-sample    # SampleApp only
make e2e-report    # open the last HTML report
```

Or directly from `tests/e2e/`:

```bash
npm test            # both projects (guided-tour + sample-app)
npm run test:tour   # GuidedTour only
npm run test:sample # SampleApp only
npm run report      # open the last HTML report
```

> **Ad-hoc `npx playwright test` runs** must be invoked from `tests/e2e/` with
> `NODE_PATH=./node_modules` (the npm scripts and `make` targets set this for
> you). Spec files live under `samples/*/playwright-tests/` but `node_modules`
> exists only here, so the prefix lets the specs resolve `@playwright/test`. Use
> `-g "<title grep>"` (not a filename) to select individual specs.

The Playwright `webServer` block boots every backend the demos need plus both
apps:

| Service | Port |
|---|---|
| Profile (resource) | 5000 |
| Calendar (resource) | 5001 |
| Trips (resource) | 5002 |
| Wallet (resource) | 5003 |
| MockPersonServer (`RequireConsent=true`) | 5100 |
| Orchestrator | 5200 |
| MockAgentProvider | 5301 |
| MockAccessServer | 5500 |
| GuidedTour | 5400 |
| SampleApp | 5240 |

`reuseExistingServer` is on outside CI, so if you already have
`make demo` / `make demo-sample` running, the suite reuses those processes.
Otherwise Playwright starts them and waits on each service's health endpoint.

## Notes

- **Blazor circuit readiness.** Pages render static HTML first; handlers only
  work after the SignalR circuit connects. Specs use `waitForInteractive` (waits
  for an enabled primary button) before interacting — never fixed sleeps.
- **Deferred / consent paths.** MockPersonServer must run with
  `RequireConsent=true` (the config sets this). The deferred specs open the PS
  consent page in a popup and click **Approve** / **Deny**, then assert the
  polling loop resolves. These specs use an extended per-test timeout.
- **Result assertions.** Every result-bearing spec asserts the actual on-page
  outcome — the rendered HTTP status (e.g. `200`) and the returned claims/scheme
  shown in the demo's response panel — not just that a step "completed".
- **Call-chain flow.** The SampleApp call-chain spec exercises the multi-hop
  Agent → Orchestrator → Calendar delegation and asserts the rendered `200` plus
  the nested `act` chain in the payload. It is the first interactive SampleApp
  spec to click its button, so it uses `clickAndConfirm` to absorb the Blazor
  cold-circuit first-click drop.
- **Traces.** On failure, traces/screenshots/video are retained under
  `test-results/`; view with `npm run report`.
