import { Page, Locator, expect } from '@playwright/test';
import { waitForInteractive } from './blazor';

/**
 * GuidedTour (Blazor Server) page-object helpers.
 *
 * The tour is a single page at `/` driven by two <select> pickers (flow +
 * signing mode), a primary action button that either steps or shows a consent
 * link, plus "Run all" / "Reset" buttons. Each executed step is recorded in the
 * left step list; selecting a done step renders its captured request/response
 * payloads in the right `section.payload` inspector.
 *
 * The DoD for these specs is to assert the ACTUAL on-page result — i.e. the
 * status line (e.g. `200`) and representative claims rendered in the selected
 * step's Response panel — not merely that the flow ran.
 */

export const TourMode = {
  Bootstrap: 'Bootstrap',
  Identity: 'Identity',
  ResourceManaged: 'ResourceManaged',
  Autonomous: 'Autonomous',
  Deferred: 'Deferred',
  CallChain: 'CallChain',
  Federated: 'Federated',
  Mission: 'Mission',
  MissionCallChain: 'MissionCallChain',
  SubAgent: 'SubAgent',
  RichRequest: 'RichRequest',
} as const;
export type TourMode = (typeof TourMode)[keyof typeof TourMode];

export const SigningMode = {
  Hwk: 'Hwk',
  JwksUri: 'JwksUri',
  JktJwt: 'JktJwt',
} as const;
export type SigningMode = (typeof SigningMode)[keyof typeof SigningMode];

/** Navigate to the tour page and wait until the Blazor circuit is interactive. */
export async function openTour(page: Page): Promise<void> {
  await page.goto('/tour');
  await expect(page.locator('header.topbar h1')).toHaveText('AAuth Guided Tour');
  await waitForInteractive(page, 'button.primary');
}

/** Planned step counts per flow (AP + PS + Concierge all configured). */
const PLAN_STEPS: Record<TourMode, number> = {
  Bootstrap: 3,
  Identity: 2,
  // Resource-managed (two-party): signed GET → 202 → consent → poll → replay.
  ResourceManaged: 6,
  Autonomous: 6,
  Deferred: 9,
  CallChain: 7,
  // Four-party federated: the plan shows 7 steps at selection time; once the
  // exchange returns 202 (the AS requires consent — its own stub screen or
  // Keycloak) the plan expands to 10 (consent + poll), mirroring deferred.
  Federated: 7,
  // Mission (PS-governed): 20 steps across three consent cycles — mission
  // creation (4/5), the out-of-mission elevated scope token (12/13), and the
  // out-of-scope cancel_booking permission (18/19).
  Mission: 20,
  // Mission + Call Chain: one mission governs a clarified elevated-scope
  // grant (creation 4/5, elevated 10/11 with a clarification chat at 7/8) and
  // a silent mission-forwarded call chain (Agent → Concierge → Trips).
  MissionCallChain: 14,
  // Sub-Agents (parent-mediated worker): 7 in-process steps — parent + worker
  // identities, the worker's resource token, the parent-mediated exchange, the
  // PS token return + handoff, and the worker's resource call. Runs entirely
  // in-process (no live servers).
  SubAgent: 7,
  // Rich Resource Requests (R3): experimental Bookings four-party flow with
  // two PS-rendered approvals (document display, then per-call proposal).
  RichRequest: 12,
};

/** Select a flow in the `#flow-select` picker and wait for the timeline to reset. */
export async function selectFlow(page: Page, mode: TourMode): Promise<void> {
  const flow = page.locator('select#flow-select');
  // The <select> uses one-way Blazor binding and the page runs an async
  // consent-prep on init; a change event fired against a freshly-connected
  // circuit can be dropped or reverted. Retry the selection until the server
  // confirms by rendering this flow's plan length in the step list.
  await expect(async () => {
    await flow.selectOption(mode);
    await expect(steps(page)).toHaveCount(PLAN_STEPS[mode], { timeout: 2_000 });
  }).toPass({ timeout: 20_000 });
  await expect(flow).toBeEnabled();
  await waitForInteractive(page, 'button.primary');
}

/** Select a signing mode (Identity flow only) in the `#signing-mode-select` picker. */
export async function selectSigningMode(page: Page, mode: SigningMode): Promise<void> {
  const select = page.locator('select#signing-mode-select');
  await expect(select).toBeVisible({ timeout: 15_000 });
  await select.selectOption(mode);
  await expect(select).toHaveValue(mode);
  await waitForInteractive(page, 'button.primary');
}

/**
 * Click "Run all" and wait until the flow either completes (Done) or parks on a
 * user-approval / aborted state. Returns when the primary button is no longer
 * "Running…".
 */
export async function runAll(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Run all' }).click();
  // The flow is busy while any control shows "Running…"; it settles to Done /
  // Aborted, or a consent link replaces the primary button. Wait until no
  // "Running…" indicator remains anywhere, which is a single deterministic
  // signal regardless of which control hosted it.
  await expect(page.getByText('Running…')).toHaveCount(0, { timeout: 30_000 });
}

/** The left step-list <li> elements (one per planned step). */
export function steps(page: Page): Locator {
  return page.locator('aside.steps .step-list .step');
}

/** Only the executed (done) step-list entries. */
export function doneSteps(page: Page): Locator {
  return page.locator('aside.steps .step-list .step.done');
}

/** Click the Nth (0-based) done step to inspect its captured payloads. */
export async function selectStep(page: Page, index: number): Promise<void> {
  const step = steps(page).nth(index);
  const header = page.locator('section.payload article.inspector h2');
  // The inspector renders "<Number>. <Title>"; Number is 1-based (index + 1).
  // A click on a freshly settled circuit can be dropped, leaving the inspector
  // on the previously selected step — retry until the header reflects this one.
  await expect(async () => {
    await step.click();
    await expect(header).toHaveText(new RegExp(`^${index + 1}\\.`), {
      timeout: 2_000,
    });
  }).toPass({ timeout: 20_000 });
}

/** The Response `<details>` panel in the inspector for the selected step. */
export function responsePanel(page: Page): Locator {
  return page
    .locator('section.payload article.inspector details')
    .filter({ has: page.locator('summary', { hasText: 'Response' }) });
}

/**
 * Assert the selected step's Response panel renders the given HTTP status code
 * (the DoD result check) and, optionally, that the response body contains each
 * provided substring (e.g. a scheme/claim).
 */
export async function expectResponse(
  page: Page,
  status: number,
  contains: string[] = [],
): Promise<void> {
  const panel = responsePanel(page);
  await expect(panel).toBeVisible();
  const code = panel.locator('pre code');
  // The status lives on the first line of the panel ("200 OK" / "HTTP/1.1 200
  // ..."). Assert it there so a bare "200" elsewhere in the JSON body can't
  // satisfy the check.
  await expect(async () => {
    const text = await code.innerText();
    const statusLine = text.split('\n').find((l) => l.trim().length > 0) ?? '';
    expect(statusLine).toMatch(new RegExp(`\\b${status}\\b`));
  }).toPass({ timeout: 15_000 });
  for (const needle of contains) {
    await expect(code).toContainText(needle);
  }
}

/**
 * Parse the JSON body rendered in the selected step's Response panel.
 *
 * The inspector renders the response as `StatusLine\n\nHeaders\n\nBody`; the
 * body is the trailing JSON object. We grab the panel's text, slice from the
 * first `{` to the last `}`, and `JSON.parse` it so specs can assert exact
 * claim values and structure (not just substrings).
 */
export async function readResponseJson(page: Page): Promise<unknown> {
  const panel = responsePanel(page);
  await expect(panel).toBeVisible();
  const text = await panel.locator('pre code').innerText();
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1 || end < start) {
    throw new Error(`No JSON object found in Response panel:\n${text}`);
  }
  return JSON.parse(text.slice(start, end + 1));
}
