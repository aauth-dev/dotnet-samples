import type { Page, BrowserContext } from '@playwright/test';
import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { approveInPopup, denyInPopup } from '../../../tests/e2e/helpers/consent';

/**
 * Mission (PS-Governed) — the Person Server is the policy-enforcement point for
 * a durable, human-approved mission. The SampleApp `/mission` page runs five
 * gates in order against the same self-issued agent identity (§Missions):
 *
 *   1. Mission creation       — PROMPT (the user approves intent + tools).
 *   2. Resource token trips.read — SILENT (in scope: the seeded `trips.read` fits the
 *                               mission's intent, so the PS mints silently, gate 2a).
 *   3. Resource token elevated— PROMPT (`trips.book` falls OUTSIDE the
 *                               mission's intent, so the PS prompts, gate 3).
 *   4. Permission send_email  — SILENT (a pre-approved tool resolves locally).
 *   5. Permission delete_inbox— PROMPT (a non-approved tool, so the PS asks).
 *
 * On run, the page scripts the PS for an interactive demo and seeds `trips.read`
 * in-scope, so the three out-of-mission gates each surface their own PS consent
 * page while the two in-mission gates resolve without a prompt. Each gate hits
 * the resource with a freshly-minted agent token (a new `jti`) so the resource's
 * replay detection never rejects a second access (§Agent Token).
 *
 * The approval banner (`.alert-warning`) is a single shared element reused for
 * every prompt — between two prompted gates the silent gate resolves and the
 * banner is immediately re-shown for the next prompt, so it never goes hidden
 * mid-flow. Tests therefore sync on the gate-outcome **card count** growing
 * (each resolved gate appends one card) rather than on the banner toggling.
 */
test.describe('Mission (SampleApp)', () => {
  test.describe.configure({ timeout: 180_000 });

  /** The PS consent link surfaced while a gate is parked on user approval. */
  function approvalLink(page: Page) {
    return page.locator('.alert-warning a[target="_blank"]');
  }

  /** A gate-outcome card by its 1-based gate number (cards render in order). */
  function gateCard(page: Page, n: number) {
    return page.locator('.card').nth(n - 1);
  }

  /**
   * Resolve the currently-parked prompt: open the surfaced PS consent page in a
   * popup, click Approve / Deny, then wait until the gate-outcome cards reach
   * `expectedCards` (the prompted gate plus any silent gate that follows it
   * resolve and append cards) so the next gate is ready.
   */
  async function resolvePrompt(
    page: Page,
    context: BrowserContext,
    action: 'approve' | 'deny',
    expectedCards: number,
  ): Promise<void> {
    await expect(page.locator('.alert-warning')).toBeVisible({ timeout: 60_000 });
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      approvalLink(page).click(),
    ]);
    if (action === 'approve') {
      await approveInPopup(popup);
    } else {
      await denyInPopup(popup);
    }
    await expect(page.locator('.card')).toHaveCount(expectedCards, { timeout: 120_000 });
  }

  test('three approvals drive all five gates to their expected outcomes', async ({ page, context }) => {
    await page.goto('/trips');
    await expect(page.locator('h2')).toContainText('Mission');
    await waitForInteractive(page, 'button.btn-primary');

    // Start the flow; gate 1 (mission creation) parks on the first PS prompt.
    await clickAndConfirm(page, 'button.btn-primary', () =>
      page.locator('.alert-warning').isVisible());

    // Gate 1: approve the mission's intent + tools (PROMPT).
    // Gate 1 approve → gate 1 card + silent gate 2 card (2 cards), then gate 3 prompts.
    await resolvePrompt(page, context, 'approve', 2);
    // Gate 3: approve the out-of-mission elevated scope (PROMPT).
    // Gate 3 approve → gate 3 card + silent gate 4 card (4 cards), then gate 5 prompts.
    await resolvePrompt(page, context, 'approve', 4);
    // Gate 5: approve the non-pre-approved delete_inbox action (PROMPT).
    // Gate 5 approve → gate 5 card (5 cards); flow finishes.
    await resolvePrompt(page, context, 'approve', 5);

    // The flow finished: the "Running…" button is gone and all five gate
    // cards are present.
    await expect(page.getByRole('button', { name: /Running/ })).toHaveCount(0, { timeout: 30_000 });
    await expect(page.locator('.card')).toHaveCount(5);

    // Gate 1 — PROMPT, approved.
    await expect(gateCard(page, 1)).toContainText('Mission creation');
    await expect(gateCard(page, 1).locator('.badge.bg-warning')).toHaveText('prompt');
    await expect(gateCard(page, 1).locator('.badge.bg-success').last()).toHaveText('approved');

    // Gate 2 — SILENT, granted (in-scope trips.read).
    await expect(gateCard(page, 2)).toContainText('trips.read');
    await expect(gateCard(page, 2).locator('.badge.bg-success').first()).toHaveText('silent');
    await expect(gateCard(page, 2)).toContainText('trips.read');

    // Gate 3 — PROMPT, granted (out-of-mission elevated scope).
    await expect(gateCard(page, 3)).toContainText('elevated');
    await expect(gateCard(page, 3).locator('.badge.bg-warning')).toHaveText('prompt');
    await expect(gateCard(page, 3).locator('.badge.bg-success').last()).toHaveText('granted');
    await expect(gateCard(page, 3)).toContainText('trips.book');

    // Gate 4 — SILENT, granted (pre-approved tool).
    await expect(gateCard(page, 4)).toContainText('send_email');
    await expect(gateCard(page, 4).locator('.badge.bg-success').first()).toHaveText('silent');

    // Gate 5 — PROMPT, granted (non-pre-approved tool).
    await expect(gateCard(page, 5)).toContainText('delete_inbox');
    await expect(gateCard(page, 5).locator('.badge.bg-warning')).toHaveText('prompt');
    await expect(gateCard(page, 5).locator('.badge.bg-success').last()).toHaveText('granted');
  });

  test('deny at the elevated-scope gate records denied without affecting the prior token', async ({ page, context }) => {
    await page.goto('/trips');
    await expect(page.locator('h2')).toContainText('Mission');
    await waitForInteractive(page, 'button.btn-primary');

    await clickAndConfirm(page, 'button.btn-primary', () =>
      page.locator('.alert-warning').isVisible());

    // Gate 1: approve the mission (2 cards: gate 1 + silent gate 2).
    await resolvePrompt(page, context, 'approve', 2);
    // Gate 3: DENY the out-of-mission elevated scope (4 cards: gate 3 denied + silent gate 4).
    await resolvePrompt(page, context, 'deny', 4);
    // Gate 5: approve the delete_inbox action — the flow continues past the
    // denied gate because each gate is independent (5 cards).
    await resolvePrompt(page, context, 'approve', 5);

    await expect(page.getByRole('button', { name: /Running/ })).toHaveCount(0, { timeout: 30_000 });
    await expect(page.locator('.card')).toHaveCount(5);

    // Gate 2 (the in-scope trips.read token) was issued BEFORE the deny and is
    // unaffected by it (§Missions: a permission/scope decision does not revoke
    // an earlier token).
    await expect(gateCard(page, 2).locator('.badge.bg-success').last()).toHaveText('granted');

    // Gate 3 — PROMPT, denied → denied.
    await expect(gateCard(page, 3).locator('.badge.bg-warning')).toHaveText('prompt');
    await expect(gateCard(page, 3).locator('.badge.bg-danger')).toHaveText('denied');
    await expect(gateCard(page, 3)).toContainText('denied');

    // Gate 5 — PROMPT, granted: denying gate 3 did not abort the mission.
    await expect(gateCard(page, 5).locator('.badge.bg-success').last()).toHaveText('granted');
  });
});
