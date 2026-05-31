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
 * PS-Asserted (Deferred) — three-party flow requiring human approval, 9 steps.
 * The agent has no standing consent, so POST /token returns 202 with an
 * interaction URL. "Run all" parks on step 6 and surfaces the consent link; the
 * user opens the PS consent page in a new tab and Approves/Denies while the
 * agent polls the pending URL. Generous timeout covers the poll loop.
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

    // Opening the link starts the background poll loop and opens the PS
    // consent page in a new tab.
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await approveInPopup(popup);

    // The poll loop resolves and records the auth_token step (8 of 9). The
    // final replay step (9) still requires an explicit "Run step" click — the
    // consent link is replaced by the primary button again once polling ends.
    await expect(doneSteps(page)).toHaveCount(8, { timeout: 120_000 });
    const primary = page.locator('button.primary');
    await expect(primary).toBeEnabled();
    await primary.click();

    await expect(doneSteps(page)).toHaveCount(9, { timeout: 30_000 });

    // Step 9 ("Replay GET / with auth_token") is the resource result.
    await selectStep(page, 8);
    await expectResponse(page, 200, ['three-party']);

    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.mode).toBe('three-party');
    expect(json.scheme).toBe('jwt');
    expect(json.agent).toBe(Agents.tour);
    expect(json.sub).toBe('pairwise-sub');
    expect(json.scope).toEqual(['whoami']);
    expect(json.iss).toBe(Urls.personServer);
    const act = json.act as Record<string, unknown>;
    expect(act.sub).toBe(Agents.tour);
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
    // records a terminal denied step (403 access_denied).
    await expect(page.locator('button.primary')).toHaveText('Aborted', { timeout: 120_000 });
    await expect(doneSteps(page).last()).toContainText(/denied/i);
  });
});
