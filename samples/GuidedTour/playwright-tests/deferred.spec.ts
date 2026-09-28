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
import { Urls } from '../../../tests/e2e/helpers/agents';
import { directedSubject } from '../../../tests/e2e/helpers/consent';

/**
 * PS-Asserted (Deferred) — three-party flow requiring human approval, 11 steps.
 * After the person-token leg (steps 2–6) the agent has no standing consent, so
 * POST /token returns 202 with an interaction URL. "Run all" parks on step 8
 * and surfaces the consent link; the user opens the PS consent page in a new
 * tab and Approves/Denies while the agent polls the pending URL. Generous
 * timeout covers the poll loop.
 *
 * This exercises granting consent dynamically via the PS consent URL (rather
 * than the admin backdoor).
 */
test.describe('Deferred (Guided Tour)', () => {
  test.describe.configure({ timeout: 150_000 });

  test('approve at the PS consent page resolves to a three-party 200', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Deferred);

    await runAll(page);

    // Parked on the user-approval step: the consent link is shown.
    const link = page.locator('a.primary.approve');
    await expect(link).toBeVisible();
    await expect(doneSteps(page)).toHaveCount(8);

    // Opening the link starts the background poll loop and opens the PS
    // consent page in a new tab.
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await approveInPopup(popup);

    // The poll loop resolves and records the auth_token step (10 of 11). The
    // final replay step (11) still requires an explicit "Run step" click — the
    // consent link is replaced by the primary button again once polling ends.
    await expect(doneSteps(page)).toHaveCount(10, { timeout: 120_000 });
    const primary = page.locator('button.primary');
    await expect(primary).toBeEnabled();
    await primary.click();

    await expect(doneSteps(page)).toHaveCount(11, { timeout: 30_000 });

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

  test('deny at the PS consent page aborts the flow', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Deferred);

    await runAll(page);

    const link = page.locator('a.primary.approve');
    await expect(link).toBeVisible();

    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await denyInPopup(popup);

    // The flow aborts: the primary button locks to "Aborted" and the poll loop
    // records a terminal denied step (403 denied).
    await expect(page.locator('button.primary')).toHaveText('Aborted', { timeout: 120_000 });
    await expect(doneSteps(page).last()).toContainText(/denied/i);
  });
});
