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
import { Urls } from '../../../tests/e2e/helpers/agents';
import { directedSubject } from '../../../tests/e2e/helpers/consent';

/**
 * PS Authorization (Deferred) — three-party flow requiring human approval, 11 steps.
 * After the person-token leg (steps 2–6) the agent has no standing consent, so
 * POST /token returns 202 with an interaction URL. The agent starts polling as
 * soon as it surfaces the request (step 9 is recorded on arrival), and "Run all"
 * keeps running while the person decides on the Person Server dashboard.
 * Generous timeout covers the poll loop.
 *
 * This exercises granting consent dynamically at the PS (rather than the admin
 * backdoor).
 */
test.describe('Deferred (Guided Tour)', () => {
  test.describe.configure({ timeout: 150_000 });

  test('approve on the PS dashboard resolves to a three-party 200', async ({ page }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Deferred);

    // "Run all" reaches the waiting step with no error and is already polling.
    await runAll(page);
    await decidePersonServerPrompt(page, 'approve', { done: 9 });

    // "Run all" continues: the poll resolves (10) and the replay runs (11).
    await expect(doneSteps(page)).toHaveCount(11, { timeout: 120_000 });
    await expect(page.locator('button.primary')).toHaveText('Done');

    // Step 4 ("POST /person → person token"): 200 with the aa-person+jwt.
    await selectStep(page, 3);
    await expectResponse(page, 200, ['person_token']);

    // Step 11 ("Replay GET /events with auth_token") is the resource result.
    await selectStep(page, 10);
    await expectResponse(page, 200, ['three-party']);

    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.accessMode).toBe('three-party');
    expect(json.scheme).toBe('jwt');
    expect(json.ps).toBe(Urls.personServer);
    expect(json.sub).toBe(directedSubject(Urls.calendar));
    expect(json.scope).toEqual(['calendar.read']);
    expect(json.iss).toBe(Urls.personServer);
    // The auth token names the person, not the agent; there is no act chain.
    expect(json).not.toHaveProperty('agent');
    expect(json).not.toHaveProperty('act');
  });

  test('stepping onto the consent request starts polling at once', async ({ page }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Deferred);

    // Step 8 surfaces the request; the waiting step 9 is recorded with it.
    for (let step = 1; step <= 8; step++) {
      await page.locator('button.primary').click();
      await expect(doneSteps(page)).toHaveCount(step === 8 ? 9 : step, { timeout: 30_000 });
    }
    await decidePersonServerPrompt(page, 'approve', { done: 9 });

    // The background poll records step 10; the replay still waits for a click.
    await expect(doneSteps(page)).toHaveCount(10, { timeout: 120_000 });
    await page.locator('button.primary').click();
    await expect(doneSteps(page)).toHaveCount(11, { timeout: 30_000 });
  });

  test('deny on the PS dashboard aborts the flow', async ({ page }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Deferred);

    await runAll(page);
    await decidePersonServerPrompt(page, 'deny');

    // The flow aborts: the primary button locks to "Aborted" and the poll loop
    // records a terminal denied step (403 denied).
    await expect(page.locator('button.primary')).toHaveText('Aborted', { timeout: 120_000 });
    await expect(doneSteps(page).last()).toContainText(/denied/i);
  });
});
