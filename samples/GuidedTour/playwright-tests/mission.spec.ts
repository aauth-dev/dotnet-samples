import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import {
  openTour,
  selectFlow,
  runAll,
  selectStep,
  expectResponse,
  readResponseJson,
  doneSteps,
  TourMode,
} from '../../../tests/e2e/helpers/tour';
import { approveInPopup, denyInPopup } from '../../../tests/e2e/helpers/consent';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Mission (PS-Governed) — the Person Server acts as the policy-enforcement
 * point for a durable, human-approved mission, 20 steps across three consent
 * cycles. On flow selection the tour seeds the PS for an interactive run with
 * the `whoami` scope in-scope (so the first token gate is silent), while every
 * out-of-mission request surfaces its own PS consent page:
 *
 *   1. Mission creation (steps 4/5): the user approves the durable mission +
 *      its tools; the agent polls for the signed approval blob.
 *   2. Out-of-mission elevated scope (steps 12/13): requesting
 *      `whoami:elevated_scope` falls outside the mission's intent, so the PS
 *      prompts before issuing the elevated auth_token (gate 3).
 *   3. Out-of-scope delete_inbox (steps 18/19): a tool that is NOT pre-approved
 *      prompts the user; the PS returns a decision, not a token.
 *
 * In between, the in-scope `whoami` token (gate 2) and the pre-approved
 * send_email tool (gate 4) resolve silently. Generous timeout covers three
 * poll loops.
 */
test.describe('Mission (Guided Tour)', () => {
  test.describe.configure({ timeout: 240_000 });

  test('three approvals govern the full mission lifecycle to a 200', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Mission);

    // ---- Cycle 1: mission creation (PROMPT) ------------------------------
    await runAll(page);
    // Parked on the mission-approval step (3 done: discover, propose, direct-user).
    await expect(doneSteps(page)).toHaveCount(3);
    const createLink = page.locator('a.primary.approve');
    await expect(createLink).toBeVisible();
    const [createPopup] = await Promise.all([
      context.waitForEvent('page'),
      createLink.click(),
    ]);
    await approveInPopup(createPopup);
    // user-approval + create poll resolve (5 of 20).
    await expect(doneSteps(page)).toHaveCount(5, { timeout: 120_000 });

    // ---- Silent gate 2 token + cycle 2: elevated scope (PROMPT) ----------
    await runAll(page);
    // Steps 6 (challenge), 7 (exchange SILENT), 8 (replay), 9 (elevated
    // challenge), 10 (elevated exchange → 202), 11 (direct-user) run, parking
    // on the elevated-scope approval (11 done).
    await expect(doneSteps(page)).toHaveCount(11, { timeout: 60_000 });
    const elevatedLink = page.locator('a.primary.approve');
    await expect(elevatedLink).toBeVisible();
    const [elevatedPopup] = await Promise.all([
      context.waitForEvent('page'),
      elevatedLink.click(),
    ]);
    await approveInPopup(elevatedPopup);
    // user-approval + elevated poll resolve (13 of 20).
    await expect(doneSteps(page)).toHaveCount(13, { timeout: 120_000 });

    // ---- Silent gate 4 tool + cycle 3: delete_inbox (PROMPT) -------------
    await runAll(page);
    // Steps 14 (elevated replay), 15 (send_email SILENT), 16 (permission →
    // 202), 17 (direct-user) run, parking on the delete_inbox approval (17).
    await expect(doneSteps(page)).toHaveCount(17, { timeout: 60_000 });
    const deleteLink = page.locator('a.primary.approve');
    await expect(deleteLink).toBeVisible();
    const [deletePopup] = await Promise.all([
      context.waitForEvent('page'),
      deleteLink.click(),
    ]);
    await approveInPopup(deletePopup);
    // user-approval + permission poll resolve (19 of 20).
    await expect(doneSteps(page)).toHaveCount(19, { timeout: 120_000 });

    // ---- Final inspect step still needs an explicit "Run all" ------------
    await runAll(page);
    await expect(doneSteps(page)).toHaveCount(20, { timeout: 30_000 });

    // Step 8 ("Replay GET /jwt/mission → 200") is the in-scope resource result.
    await selectStep(page, 7);
    await expectResponse(page, 200, ['mission']);
    const inScope = (await readResponseJson(page)) as Record<string, unknown>;
    expect(inScope.access).toBe('mission');
    expect(inScope.scope).toEqual(['whoami']);
    expect(inScope.iss).toBe(Urls.personServer);
    expect(inScope.agent).toBe(Agents.tour);

    // Step 14 ("Replay GET /jwt/mission/elevated → 200") is the elevated result.
    await selectStep(page, 13);
    await expectResponse(page, 200, ['mission-elevated']);
    const elevated = (await readResponseJson(page)) as Record<string, unknown>;
    expect(elevated.access).toBe('mission-elevated');
    expect(elevated.scope).toEqual(['whoami:elevated_scope']);
  });

  test('deny at the elevated-scope gate yields access_denied', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Mission);

    // Cycle 1: approve the mission.
    await runAll(page);
    const createLink = page.locator('a.primary.approve');
    await expect(createLink).toBeVisible();
    const [createPopup] = await Promise.all([
      context.waitForEvent('page'),
      createLink.click(),
    ]);
    await approveInPopup(createPopup);
    await expect(doneSteps(page)).toHaveCount(5, { timeout: 120_000 });

    // Advance to the elevated-scope gate and DENY it.
    await runAll(page);
    const elevatedLink = page.locator('a.primary.approve');
    await expect(elevatedLink).toBeVisible();
    const [elevatedPopup] = await Promise.all([
      context.waitForEvent('page'),
      elevatedLink.click(),
    ]);
    await denyInPopup(elevatedPopup);

    // The flow aborts: the primary button locks to "Aborted" and the poll loop
    // records a terminal denied step (403 access_denied).
    await expect(page.locator('button.primary')).toHaveText('Aborted', { timeout: 120_000 });
    await expect(doneSteps(page).last()).toContainText(/denied/i);
  });
});
