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

/**
 * Mission + Call Chain — one durable, human-approved mission governs two very
 * different kinds of access across 14 steps:
 *
 *   1. Mission creation (steps 4/5): the user approves the durable mission and
 *      its tools; the agent polls for the signed approval blob.
 *   2. Clarified elevated scope (steps 7/8/10/11): requesting
 *      `trips.book` falls outside the mission's intent, so the PS
 *      first opens a CLARIFICATION CHAT — it asks WHY (step 7, 202), the agent
 *      answers (step 8, 204) — and only then prompts the user (step 10),
 *      issuing the elevated auth_token on the next poll (step 11).
 *   3. Mission-forwarded call chain (step 13): the SAME mission drives an
 *      Agent → Orchestrator → Trips chain. Both hops (`orchestrate`,
 *      `trips.read`) are in mission scope, so the Orchestrator forwards the
 *      `AAuth-Mission` header downstream and the whole chain resolves SILENTLY.
 *
 * The PS's mission log (step 14) records it all — including the clarification
 * round. Generous timeout covers two poll loops.
 */
test.describe('Mission + Call Chain (Guided Tour)', () => {
  test.describe.configure({ timeout: 180_000 });

  test('one mission governs a clarified elevated grant and a silent call chain', async ({
    page,
    context,
  }) => {
    await openTour(page);
    await selectFlow(page, TourMode.MissionCallChain);

    // ---- Cycle 1: mission creation (PROMPT) ------------------------------
    await runAll(page);
    // Parked on the mission-approval step (3 done: discover, propose, direct).
    await expect(doneSteps(page)).toHaveCount(3);
    const createLink = page.locator('a.primary.approve');
    await expect(createLink).toBeVisible();
    const [createPopup] = await Promise.all([
      context.waitForEvent('page'),
      createLink.click(),
    ]);
    await approveInPopup(createPopup);
    // user-approval + create poll resolve (5 of 14).
    await expect(doneSteps(page)).toHaveCount(5, { timeout: 120_000 });

    // ---- Clarification chat + cycle 2: elevated scope (PROMPT) -----------
    await runAll(page);
    // Steps 6 (elevated challenge → 401), 7 (exchange → 202 clarification),
    // 8 (answer → 204), 9 (direct-user) run, parking on the elevated-scope
    // approval (9 done).
    await expect(doneSteps(page)).toHaveCount(9, { timeout: 60_000 });
    const elevatedLink = page.locator('a.primary.approve');
    await expect(elevatedLink).toBeVisible();
    const [elevatedPopup] = await Promise.all([
      context.waitForEvent('page'),
      elevatedLink.click(),
    ]);
    await approveInPopup(elevatedPopup);
    // user-approval + elevated poll resolve (11 of 14).
    await expect(doneSteps(page)).toHaveCount(11, { timeout: 120_000 });

    // ---- Silent replay + mission-forwarded call chain + log --------------
    await runAll(page);
    // Steps 12 (elevated replay → 200), 13 (forwarded chain → 200 SILENT),
    // 14 (mission log) run with no further prompts (14 done).
    await expect(doneSteps(page)).toHaveCount(14, { timeout: 60_000 });

    // Step 7 ("Exchange → 202 clarification"): the PS asked WHY before consent.
    await selectStep(page, 6);
    await expectResponse(page, 202, ['clarification']);
    const clarify = (await readResponseJson(page)) as Record<string, unknown>;
    expect(String(clarify.clarification)).toContain('elevated access');

    // Step 8 ("Answer the clarification → 204"): the agent's answer is recorded.
    await selectStep(page, 7);
    await expectResponse(page, 204);
    await expect(page.locator('section.payload')).toContainText('triage the inbox');

    // Step 12 ("Replay GET /trips/book → 200"): the elevated result.
    await selectStep(page, 11);
    await expectResponse(page, 200, ['mission-elevated']);
    const elevated = (await readResponseJson(page)) as Record<string, unknown>;
    expect(elevated.access).toBe('mission-elevated');
    expect(elevated.scope).toEqual(['trips.book']);

    // Step 13 ("Mission-forwarded call chain → 200 (SILENT)"): one mission
    // governed every hop. The combined result nests Trips' mission-bound
    // downstream object reached via the Orchestrator.
    await selectStep(page, 12);
    await expectResponse(page, 200, ['downstream']);
    const chain = (await readResponseJson(page)) as Record<string, unknown>;
    expect(String(chain.chain)).toContain('Trips');
    const downstream = chain.downstream as Record<string, unknown>;
    expect(downstream.accessMode).toBe('three-party');
    expect(downstream.access).toBe('mission');
    expect(downstream.scope).toEqual(['trips.read']);
    // The mission travelled all the way downstream (silent because in scope).
    expect(downstream.mission).toBeTruthy();

    // Step 14 ("Inspect the mission log"): the PS kept an auditable trail that
    // includes the clarification round.
    await selectStep(page, 13);
    await expectResponse(page, 200, ['entries']);
    const log = (await readResponseJson(page)) as { entries: Array<Record<string, unknown>> };
    expect(Array.isArray(log.entries)).toBe(true);
    expect(log.entries.some((e) => e.kind === 'clarification')).toBe(true);
  });

  test('deny at the clarified elevated-scope gate yields denied', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.MissionCallChain);

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

    // Advance through the clarification chat to the elevated-scope gate, DENY.
    await runAll(page);
    await expect(doneSteps(page)).toHaveCount(9, { timeout: 60_000 });
    const elevatedLink = page.locator('a.primary.approve');
    await expect(elevatedLink).toBeVisible();
    const [elevatedPopup] = await Promise.all([
      context.waitForEvent('page'),
      elevatedLink.click(),
    ]);
    await denyInPopup(elevatedPopup);

    // The flow aborts: the primary button locks to "Aborted" and the poll loop
    // records a terminal denied step.
    await expect(page.locator('button.primary')).toHaveText('Aborted', { timeout: 120_000 });
    await expect(doneSteps(page).last()).toContainText(/denied/i);
  });
});
