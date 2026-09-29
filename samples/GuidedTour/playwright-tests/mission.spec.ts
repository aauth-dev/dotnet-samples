import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import {
  openTour,
  selectFlow,
  runAll,
  selectStep,
  expectResponse,
  readResponseJson,
  doneSteps,
  decidePersonServerPrompt,
  TourMode,
} from '../../../tests/e2e/helpers/tour';
import { directedSubject } from '../../../tests/e2e/helpers/consent';
import { Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Mission (PS-Governed) — the Person Server acts as the policy-enforcement
 * point for a durable, human-approved mission, 21 steps across three consent
 * cycles. On flow selection the tour seeds the PS for an interactive run with
 * the `trips.read` scope in-scope (so the first token gate is silent), while every
 * out-of-mission request surfaces its own PS consent page:
 *
 *   1. Mission creation (steps 4/5): the user approves the durable mission +
 *      its tools; the agent polls for the approval envelope {s256, mission}.
 *   2. Out-of-mission elevated scope (steps 13/14): requesting
 *      `trips.book` falls outside the mission's intent, so the PS
 *      prompts before issuing the elevated auth_token (gate 3).
 *   3. Out-of-scope cancel_booking (steps 19/20): a tool that is NOT pre-approved
 *      prompts the user; the PS returns a decision, not a token.
 *
 * The agent names the mission only through `mission_s256` on its person token
 * request (step 6); the resource and auth tokens carry it from there. In
 * between, the in-scope `trips.read` token (gate 2) and the pre-approved
 * add_to_calendar tool (gate 4) resolve silently. Generous timeout covers three
 * poll loops.
 */
test.describe('Mission (Guided Tour)', () => {
  test.describe.configure({ timeout: 240_000 });

  test('three approvals govern the full mission lifecycle to a 200', async ({ page }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Mission);

    // One "Run all" drives every gate; the agent polls on arrival at each
    // waiting step while the person decides on the PS dashboard.
    await runAll(page);
    // Cycle 1: mission creation (discover, propose, direct-user + waiting step).
    const create = await decidePersonServerPrompt(page, 'approve', { done: 4 });
    // Silent gate 2, then cycle 2: the elevated scope (12 + waiting step).
    const elevatedPrompt = await decidePersonServerPrompt(page, 'approve', { previous: create, done: 13 });
    // Silent gate 4, then cycle 3: cancel_booking (18 + waiting step).
    await decidePersonServerPrompt(page, 'approve', { previous: elevatedPrompt, done: 19 });
    await expect(doneSteps(page)).toHaveCount(21, { timeout: 120_000 });
    await expect(page.locator('button.primary')).toHaveText('Done');

    // Step 5 ("Poll → 200 mission approval"): the approval envelope's s256.
    await selectStep(page, 4);
    await expectResponse(page, 200, ['s256']);
    const envelope = (await readResponseJson(page)) as Record<string, unknown>;
    const missionS256 = envelope.s256 as string;
    expect(typeof missionS256).toBe('string');

    // Step 6 ("POST /person (mission_s256) → person token"): the request names
    // the mission and the person token carries it.
    await selectStep(page, 5);
    await expectResponse(page, 200, ['person_token']);
    await expect(page.locator('section.payload')).toContainText(`"mission_s256": "${missionS256}"`);

    // Step 9 ("Replay GET /trips → 200") is the in-scope resource result.
    await selectStep(page, 8);
    await expectResponse(page, 200, ['mission']);
    const inScope = (await readResponseJson(page)) as Record<string, unknown>;
    expect(inScope.access).toBe('mission');
    expect(inScope.scope).toEqual(['trips.read']);
    expect(inScope.iss).toBe(Urls.personServer);
    expect(inScope.ps).toBe(Urls.personServer);
    expect(inScope.sub).toBe(directedSubject(Urls.trips));
    expect(inScope.mission_s256).toBe(missionS256);
    expect(inScope).not.toHaveProperty('agent');

    // Step 15 ("Replay GET /trips/book → 200") is the elevated result.
    await selectStep(page, 14);
    await expectResponse(page, 200, ['mission-elevated']);
    const elevated = (await readResponseJson(page)) as Record<string, unknown>;
    expect(elevated.access).toBe('mission-elevated');
    expect(elevated.scope).toEqual(['trips.book']);
    expect(elevated.mission_s256).toBe(missionS256);
  });

  test('deny at the elevated-scope gate yields denied', async ({ page }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Mission);

    // Approve the mission, then DENY the elevated-scope gate.
    await runAll(page);
    const create = await decidePersonServerPrompt(page, 'approve', { done: 4 });
    await decidePersonServerPrompt(page, 'deny', { previous: create, done: 13 });

    // The flow aborts: the primary button locks to "Aborted" and the poll loop
    // records a terminal denied step (403 denied).
    await expect(page.locator('button.primary')).toHaveText('Aborted', { timeout: 120_000 });
    await expect(doneSteps(page).last()).toContainText(/denied/i);
  });
});
