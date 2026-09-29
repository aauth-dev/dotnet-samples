import { Page, Locator, expect } from '@playwright/test';
import { authenticateConsent } from './consent';
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
  RichRequests: 'RichRequests',
  Mission: 'Mission',
  MissionCallChain: 'MissionCallChain',
  SubAgent: 'SubAgent',
  Events: 'Events',
  WalletProtocol: 'WalletProtocol',
  Documents: 'Documents',
  Catalog: 'Catalog',
} as const;
export type TourMode = (typeof TourMode)[keyof typeof TourMode];

export const SigningMode = {
  Hwk: 'Hwk',
  Jwks: 'Jwks',
  JktJwt: 'JktJwt',
} as const;
export type SigningMode = (typeof SigningMode)[keyof typeof SigningMode];

/** Navigate to the tour page and wait until the Blazor circuit is interactive. */
export async function openTour(page: Page): Promise<void> {
  await page.goto('/tour');
  await expect(page.locator('header.topbar h1')).toHaveText('AAuth Guided Tour');
  await waitForInteractive(page, 'button.primary');
}

/**
 * Planned step counts per flow (AP + PS + Concierge all configured). Every
 * Person Server flow includes the draft-11 person-token leg: signed GET → 401
 * requirement=person-token, POST /person → person token, and the resource's
 * requirement=auth-token challenge naming that token (presented_jti).
 */
const PLAN_STEPS: Record<TourMode, number> = {
  Bootstrap: 3,
  Identity: 2,
  // Resource-managed (two-party): signed GET → 202 → consent → poll → replay.
  ResourceManaged: 6,
  Autonomous: 8,
  Deferred: 11,
  // Call chain: 9 at selection time; the plan expands to 15 once the hop-1
  // exchange returns 202 (two consent + poll cycles).
  CallChain: 9,
  // Four-party federated: the plan shows 9 steps at selection time; once the
  // exchange returns 202 (PS and/or AS consent) the plan expands to 12
  // (consent + poll), mirroring deferred.
  Federated: 9,
  // Rich Resource Requests (R3, four-party): a single, always-full 16-step
  // linear plan (no branch). The R3 Access Server sets RequireProposalConsent,
  // so confirm_reservation always needs a per-call consent; the plan shows 16
  // at selection time and never expands.
  RichRequests: 16,
  // Mission (PS-governed): 21 steps across three consent cycles — mission
  // creation (4/5), the out-of-mission elevated scope token (13/14), and the
  // out-of-scope cancel_booking permission (19/20).
  Mission: 21,
  // Mission + Call Chain: one mission governs a clarified elevated-scope
  // grant (creation 4/5, elevated 11/12 with a clarification chat at 8/9) and
  // a silent mission-governed call chain (Agent → Concierge → Trips).
  MissionCallChain: 15,
  // Sub-Agents (parent-mediated worker): 8 steps against the live PS, AS and
  // Wallet — parent + worker identities, the upstream grant, the worker's
  // person token (via the parent) and resource token, the parent-mediated
  // exchange, the handoff, and the worker's resource call.
  SubAgent: 8,
  // Capability flows plan one consent cycle (direct user, decide, poll) after
  // each exchange; the plan adapts at run time when a server grants at once
  // (200) or asks again (a new interaction or a clarification).
  // Events defaults to the protected channel: AP enrolment, the account-bound
  // grant, subscribe, register, deliver, inbox, verify, acknowledge.
  Events: 19,
  // Wallet Protocol defaults to the AS clarification scenario: PS consent,
  // the AS question, then PS and AS decisions.
  WalletProtocol: 18,
  Documents: 11,
  // Two operation-bound grants; the PS remembers consent for the second.
  Catalog: 16,
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

/**
 * Drive the selected flow to its end, answering every consent link it surfaces.
 * "Run all" parks on each user decision; `decide` handles the popup (PS, AS or
 * resource page) and the loop resumes once the poll resolves. Returns the
 * number of decisions made.
 */
export async function driveTour(
  page: Page,
  decide: (popup: Page, round: number) => Promise<void>,
  maxDecisions = 8,
): Promise<number> {
  const primary = page.locator('button.primary');
  const consent = page.locator('a.primary.approve');
  let rounds = 0;
  for (let turn = 0; turn < 60; turn++) {
    await expect.poll(async () => {
      if (await consent.isVisible()) return 'consent';
      if (await page.getByText('Running…').count()) return 'busy';
      return await primary.isVisible() ? 'ready' : 'busy';
    }, { timeout: 150_000 }).not.toBe('busy');
    if (await consent.isVisible()) {
      if (++rounds > maxDecisions) throw new Error(`More than ${maxDecisions} user decisions were requested.`);
      const [popup] = await Promise.all([page.context().waitForEvent('page'), consent.click()]);
      await decide(popup, rounds);
      await popup.close();
      continue;
    }
    const label = (await primary.innerText()).trim();
    if (label === 'Done' || label === 'Aborted') return rounds;
    await page.getByRole('button', { name: 'Run all' }).click();
    await expect(page.getByText('Running…')).toHaveCount(0, { timeout: 150_000 });
  }
  throw new Error('The flow did not finish.');
}

/**
 * Decide on any consent popup the capability flows open: the Documents
 * resource-permission interstitial and release page, then the PS or AS consent
 * screen. `approve=false` declines at the first decision offered.
 */
export async function decideConsent(popup: Page, approve = true): Promise<void> {
  for (let transition = 0; transition < 8; transition++) {
    let state = 'pending';
    await expect.poll(async () => {
      if (await popup.getByRole('heading', { name: 'Authorization stopped', exact: true }).isVisible()) return state = 'stopped';
      if (await popup.getByText(/^(Approved|Denied)/).first().isVisible()) return state = 'decided';
      if (await popup.locator('button.demo-login').isVisible()) return state = 'login';
      if (await popup.getByRole('button', { name: 'Continue to resource' }).isVisible()) return state = 'interstitial';
      if (await popup.getByRole('button', { name: 'Release document' }).isVisible()) return state = 'release';
      if (await popup.locator('button.approve').isVisible()) return state = 'consent';
      return state = 'pending';
    }, { timeout: 30_000 }).not.toBe('pending');
    if (state === 'stopped' || state === 'decided') return;
    if (state === 'login') await popup.locator('button.demo-login').click();
    else if (state === 'interstitial') await popup.getByRole('button', { name: 'Continue to resource' }).click();
    else if (state === 'release') {
      await popup.getByRole('button', { name: approve ? 'Release document' : 'Decline release', exact: true }).click();
      if (!approve) return;
    } else {
      await authenticateConsent(popup);
      await popup.locator(approve ? 'button.approve' : 'button.deny').click();
    }
  }
  throw new Error(`Consent popup did not settle: ${popup.url()}`);
}

/** Step-list titles of the executed steps, in order. */
export async function doneTitles(page: Page): Promise<string[]> {
  return (await doneSteps(page).locator('.step__title').allInnerTexts()).map((title) => title.trim());
}

/** Select the executed step whose title matches, and return its index. */
export async function selectStepTitled(page: Page, title: RegExp): Promise<number> {
  const titles = await doneTitles(page);
  const index = titles.findIndex((entry) => title.test(entry));
  if (index < 0) throw new Error(`No executed step matches ${title}: ${titles.join(' | ')}`);
  await selectStep(page, index);
  return index;
}

/** Parse the JSON payload rendered in the selected step's decoded-token panel. */
export async function decodedTokenPayload(page: Page): Promise<Record<string, unknown>> {
  const panel = page
    .locator('section.payload article.inspector details.token')
    .filter({ hasText: 'Decoded payload' });
  await expect(panel).toBeVisible();
  const text = await panel.locator('pre code').innerText();
  return JSON.parse(text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1)) as Record<string, unknown>;
}
