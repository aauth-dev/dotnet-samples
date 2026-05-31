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
  Autonomous: 'Autonomous',
  Deferred: 'Deferred',
  CallChain: 'CallChain',
} as const;
export type TourMode = (typeof TourMode)[keyof typeof TourMode];

export const SigningMode = {
  Hwk: 'Hwk',
  JwksUri: 'JwksUri',
  JktJwt: 'JktJwt',
} as const;
export type SigningMode = (typeof SigningMode)[keyof typeof SigningMode];

/** Navigate to the tour root and wait until the Blazor circuit is interactive. */
export async function openTour(page: Page): Promise<void> {
  await page.goto('/');
  await expect(page.locator('header.topbar h1')).toHaveText('AAuth Guided Tour');
  await waitForInteractive(page, 'button.primary');
}

/** Planned step counts per flow (AP + PS + Orchestrator all configured). */
const PLAN_STEPS: Record<TourMode, number> = {
  Bootstrap: 3,
  Identity: 2,
  Autonomous: 6,
  Deferred: 9,
  CallChain: 7,
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
  // The primary button text settles to Done / Aborted, or a consent link
  // ("Open consent page") replaces it. Wait for the busy state to clear.
  await expect(page.locator('button.primary, a.primary.approve')).not.toHaveText(/Running…/, {
    timeout: 30_000,
  });
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
  await expect(panel.locator('pre code')).toContainText(String(status));
  for (const needle of contains) {
    await expect(panel.locator('pre code')).toContainText(needle);
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

/**
 * Parse the JSON rendered in the selected step's decoded token panel
 * (`details.token` → `pre code`). Used by token-bearing steps (e.g. the
 * decoded auth-token payload) where the claim chain is the assertion target.
 */
export async function readTokenJson(page: Page): Promise<unknown> {
  const panel = page
    .locator('section.payload article.inspector details.token pre code')
    .first();
  await expect(panel).toBeVisible();
  const text = await panel.innerText();
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1 || end < start) {
    throw new Error(`No JSON object found in token panel:\n${text}`);
  }
  return JSON.parse(text.slice(start, end + 1));
}