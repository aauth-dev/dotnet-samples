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
import { approveInPopup, denyInPopup, directedSubject } from '../../../tests/e2e/helpers/consent';
import { Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Mission + Call Chain — one durable, human-approved mission governs two very
 * different kinds of access across 15 steps:
 *
 *   1. Mission creation (steps 4/5): the user approves the durable mission and
 *      its tools; the agent polls for the approval envelope {s256, mission}.
 *   2. Clarified elevated scope (steps 8/9/11/12): the agent requests a person
 *      token under the mission (step 6) and presents it for `trips.book`
 *      (step 7), which falls outside the mission's intent, so the PS first
 *      opens a CLARIFICATION CHAT — it asks WHY (step 8, 202), the agent
 *      answers (step 9, 204) — and only then prompts the user (step 11),
 *      issuing the elevated auth_token on the next poll (step 12).
 *   3. Mission-governed call chain (step 14): the SAME mission drives an
 *      Agent → Concierge → Trips chain. The agent's Concierge person token and
 *      auth token carry mission_s256; the Concierge chains with that auth token
 *      as upstream_token, both hops (`concierge`, `trips.read`) are in mission
 *      scope, and the whole chain resolves SILENTLY.
 *
 * The PS's mission log (step 15) records it all — including the clarification
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
    // user-approval + create poll resolve (5 of 15).
    await expect(doneSteps(page)).toHaveCount(5, { timeout: 120_000 });

    // ---- Clarification chat + cycle 2: elevated scope (PROMPT) -----------
    await runAll(page);
    // Steps 6 (mission person token), 7 (elevated challenge → 401),
    // 8 (exchange → 202 clarification), 9 (answer → 204), 10 (direct-user)
    // run, parking on the elevated-scope approval (10 done).
    await expect(doneSteps(page)).toHaveCount(10, { timeout: 60_000 });
    const elevatedLink = page.locator('a.primary.approve');
    await expect(elevatedLink).toBeVisible();
    const [elevatedPopup] = await Promise.all([
      context.waitForEvent('page'),
      elevatedLink.click(),
    ]);
    await approveInPopup(elevatedPopup);
    // user-approval + elevated poll resolve (12 of 15).
    await expect(doneSteps(page)).toHaveCount(12, { timeout: 120_000 });

    // ---- Silent replay + mission-governed call chain + log --------------
    await runAll(page);
    // Steps 13 (elevated replay → 200), 14 (call chain → 200 SILENT),
    // 15 (mission log) run with no further prompts (15 done).
    await expect(doneSteps(page)).toHaveCount(15, { timeout: 60_000 });

    // Step 5 ("Poll → 200 mission approval"): the approval envelope's s256.
    await selectStep(page, 4);
    const envelope = (await readResponseJson(page)) as Record<string, unknown>;
    const missionS256 = envelope.s256 as string;
    expect(typeof missionS256).toBe('string');

    // Step 8 ("Exchange → 202 clarification"): the PS asked WHY before consent.
    await selectStep(page, 7);
    await expectResponse(page, 202, ['clarification']);
    const clarify = (await readResponseJson(page)) as Record<string, unknown>;
    expect(String(clarify.clarification)).toContain('book and pay');

    // Step 9 ("Answer the clarification → 204"): the agent's answer is recorded.
    await selectStep(page, 8);
    await expectResponse(page, 204);
    await expect(page.locator('section.payload')).toContainText('reserve and pay');
    await expect(page.locator('section.payload')).toContainText(/Then GET .* -> 202/);
    await expect(page.locator('section.payload')).toContainText(/Interaction code: [0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}/);
    await expect(page.locator('section.payload')).toContainText('signedClient.GetAsync(missionPendingUrl)');

    // Step 13 ("Replay GET /trips/book → 200"): the elevated result.
    await selectStep(page, 12);
    await expectResponse(page, 200, ['mission-elevated']);
    const elevated = (await readResponseJson(page)) as Record<string, unknown>;
    expect(elevated.access).toBe('mission-elevated');
    expect(elevated.scope).toEqual(['trips.book']);
    expect(elevated.mission_s256).toBe(missionS256);

    // Step 14 ("Mission-governed call chain → 200 (SILENT)"): one mission
    // governed every hop. The combined result nests Trips' downstream object
    // reached via the Concierge.
    await selectStep(page, 13);
    await expectResponse(page, 200, ['downstream']);
    const chain = (await readResponseJson(page)) as Record<string, unknown>;
    expect(String(chain.chain)).toContain('Trips');
    const upstream = chain.upstream as Record<string, unknown>;
    expect(upstream.ps).toBe(Urls.personServer);
    expect(upstream.sub).toBe(directedSubject(Urls.concierge));
    expect(upstream.mission_s256).toBe(missionS256);
    const downstream = chain.downstream as Record<string, unknown>;
    expect(downstream.accessMode).toBe('three-party');
    expect(downstream.access).toBe('mission');
    expect(downstream.scope).toEqual(['trips.read']);
    // Same PS, a sub directed at Trips, and no agent/act claims.
    expect(downstream.ps).toBe(upstream.ps);
    expect(downstream.sub).toBe(directedSubject(Urls.trips));
    expect(downstream).not.toHaveProperty('agent');
    expect(downstream).not.toHaveProperty('act');
    // The mission reached the downstream hop (silent because in scope).
    expect(downstream.mission_s256).toBe(missionS256);

    // Step 15 ("Inspect the mission log"): the PS kept an auditable trail that
    // includes the clarification round.
    await selectStep(page, 14);
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
    await expect(doneSteps(page)).toHaveCount(10, { timeout: 60_000 });
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
