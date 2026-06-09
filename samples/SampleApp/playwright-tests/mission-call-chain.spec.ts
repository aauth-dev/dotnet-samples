import type { Page, BrowserContext } from '@playwright/test';
import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { approveInPopup } from '../../../tests/e2e/helpers/consent';

/**
 * Mission Call Chain (SampleApp) — one human-approved mission governs three
 * AAuth seams in a single run on the `/mission-call-chain` page:
 *
 *   1. Mission creation        — PROMPT (the user approves intent + tools).
 *   2. Elevated scope          — a CLARIFICATION round (§Clarification Chat)
 *                                runs first because the scope is out-of-mission,
 *                                then the user approves the prompt.
 *   3. Mission-forwarded chain — SILENT: the same mission is carried
 *                                (WithMission) to the Orchestrator's mission-aware
 *                                "/mission" endpoint, which forwards the
 *                                AAuth-Mission header to the Trips "/trips"
 *                                hop. Both hops are seeded in-scope, so no prompt.
 *
 * The page then fetches the PS-held mission log (§Mission Log) and renders it.
 * Needs PS + AP + Orchestrator + Trips booted (the Playwright webServer array).
 */
test.describe('Mission Call Chain (SampleApp)', () => {
  test.describe.configure({ timeout: 180_000 });

  /** The PS consent link surfaced while a step is parked on user approval. */
  function approvalLink(page: Page) {
    return page.locator('.alert-warning a[target="_blank"]');
  }

  /** A step-outcome card by its 1-based number (cards render in order). */
  function stepCard(page: Page, n: number) {
    return page.locator('.card').nth(n - 1);
  }

  /**
   * Resolve the currently-parked prompt: open the surfaced PS consent page in a
   * popup, click Approve, then wait until the step cards reach `expectedCards`.
   *
   * We assert the just-approved step's card is present (i.e. there are AT LEAST
   * `expectedCards` cards) rather than an EXACT total. Unlike the `/mission`
   * page — where every gate parks on the next prompt, so the card count settles
   * and stays put — here the FINAL step (the silent mission-forwarded chain)
   * advances with no gate after the step-2 approval. It appends its card almost
   * immediately, and Blazor coalesces the step-2 and step-3 render batches into
   * one (the DOM jumps 1 -> 3, never momentarily showing 2). An exact
   * `toHaveCount(2)` here is therefore racy by construction; the page behaviour
   * is correct. The strict final count of 3 is asserted separately below.
   */
  async function approvePrompt(
    page: Page,
    context: BrowserContext,
    expectedCards: number,
  ): Promise<void> {
    await expect(page.locator('.alert-warning')).toBeVisible({ timeout: 60_000 });
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      approvalLink(page).click(),
    ]);
    await approveInPopup(popup);
    await expect(stepCard(page, expectedCards)).toBeVisible({ timeout: 120_000 });
  }

  test('mission governs a clarification round and a forwarded call chain', async ({ page, context }) => {
    await page.goto('/mission-call-chain');
    await expect(page.locator('h2')).toContainText('Mission Call Chain');
    await waitForInteractive(page, 'button.btn-primary');

    // Start the flow; step 1 (mission creation) parks on the first PS prompt.
    await clickAndConfirm(page, 'button.btn-primary', () =>
      page.locator('.alert-warning').isVisible());

    // Step 1: approve the mission's intent + tools (PROMPT) → 1 card.
    await approvePrompt(page, context, 1);

    // Step 2: the elevated scope first triggers a clarification round (the
    // agent answers it automatically), surfaced in the clarification panel.
    await expect(page.locator('[data-test="clarification"]')).toBeVisible({ timeout: 60_000 });
    await expect(page.locator('[data-test="clarification"]')).toContainText('PS asked');
    await expect(page.locator('[data-test="clarification"]')).toContainText('Agent answered');

    // ...then the PS prompts for the out-of-mission scope; approve it → 2 cards.
    await approvePrompt(page, context, 2);

    // Step 3: the mission-forwarded call chain resolves silently → 3 cards.
    await expect(page.locator('.card')).toHaveCount(3, { timeout: 120_000 });

    // The flow finished: the "Running…" button is gone.
    await expect(page.getByRole('button', { name: /Running/ })).toHaveCount(0, { timeout: 30_000 });

    // Step 1 — PROMPT, approved.
    await expect(stepCard(page, 1)).toContainText('Mission creation');
    await expect(stepCard(page, 1).locator('.badge.bg-warning')).toHaveText('prompt');

    // Step 2 — PROMPT, granted, with the clarification round noted.
    await expect(stepCard(page, 2)).toContainText('clarification');
    await expect(stepCard(page, 2).locator('.badge.bg-warning')).toHaveText('prompt');
    await expect(stepCard(page, 2).locator('.badge.bg-success').last()).toHaveText('granted');

    // Step 3 — SILENT, granted: the chain result shows the full delegation.
    await expect(stepCard(page, 3)).toContainText('Mission call chain');
    await expect(stepCard(page, 3).locator('.badge.bg-success').first()).toHaveText('silent');
    const chainJson = await stepCard(page, 3).locator('pre code').innerText();
    const chain = JSON.parse(chainJson) as Record<string, any>;
    expect(chain.downstream.accessMode).toBe('three-party');
    expect(chain.downstream.scope).toEqual(['trips.read']);
    // The downstream Trips hop saw the Orchestrator as the immediate actor.
    expect(chain.downstream.agent).toBe('aauth:orchestrator@localhost:5200');
    // The mission was forwarded: the downstream auth token carries the mission.
    expect(chain.downstream.mission).toBeTruthy();

    // The PS-held mission log/trail is surfaced and records the governed steps.
    await expect(page.locator('[data-test="mission-log"]')).toBeVisible({ timeout: 30_000 });
    const rows = page.locator('[data-test="mission-log"] tbody tr');
    expect(await rows.count()).toBeGreaterThan(0);
    // The log includes the clarification exchange under the mission.
    await expect(page.locator('[data-test="mission-log"]')).toContainText('clarification');
  });
});
