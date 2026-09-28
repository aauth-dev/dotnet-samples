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
import { decideAccessConsent } from '../../../tests/e2e/helpers/consent';
import { Urls } from '../../../tests/e2e/helpers/agents';
import { approvePersonConsent, directedSubject } from '../../../tests/e2e/helpers/consent';

/**
 * Federated (four-party) — Guided Tour, interactive consent path.
 *
 * Runs against a **stub** Access Server with `RequireConsent=true` (no Keycloak
 * / Docker). The agent first gets a person token for the Wallet and presents
 * it; the Wallet's /wallet branch then challenges with a resource_token whose
 * `aud` is the Access Server. The PS asks for its own consent first, then
 * federates to the AS, which returns `202 requirement=interaction`. The PS
 * relays it, the tour surfaces the AS interaction link, and the user clicks
 * **Approve** on the Access Server's own consent screen — exactly like the
 * three-party deferred flow, but the final consent screen is the AS's (badged
 * *Access Server*) rather than the Person Server's.
 *
 * From the agent's perspective the stub AS and Keycloak are identical (same
 * 202 → interaction URL → poll → mint); only the interaction URL's destination
 * differs. The Keycloak login variant is covered by the SampleApp
 * `federated-deferred.spec.ts` (gated on KEYCLOAK_E2E=1).
 */
test.describe('Federated (Guided Tour)', () => {
  test.describe.configure({ timeout: 180_000 });

  test('approve at the AS consent page resolves to a four-party 200', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Federated);

    // The four-party flow shows a distinct Access Server lane (rendered red).
    await expect(page.locator('.lanes .lane.agent')).toContainText('Agent');
    await expect(page.locator('.lanes .lane.ps')).toContainText('Person Server');
    await expect(page.locator('.lanes .lane.as')).toContainText('Access Server');

    // Run all: the exchange returns 202, the plan expands to 12 steps and parks
    // on the user-approval step (8 done); the PS consent comes first, then the
    // AS interaction link is shown.
    await runAll(page);
    await expect(doneSteps(page)).toHaveCount(8);
    await approvePersonConsent(page, 'a.primary.approve');
    const link = page.locator('a.worker-consent');
    await expect(link).toBeVisible();

    // Opening the link starts the background poll loop and opens the Access
    // Server's consent page in a new tab.
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    // The AS consent screen is unmistakably badged "Access Server".
    await decideAccessConsent(popup);

    // The poll loop resolves and records the auth_token step (10 of 12). Running
    // again finishes the replay (11) and inspect (12) steps.
    await expect(doneSteps(page)).toHaveCount(10, { timeout: 120_000 });
    await runAll(page);
    await expect(doneSteps(page)).toHaveCount(12, { timeout: 30_000 });

    // Step 5 ("GET /wallet with person token → 401"): the Wallet verified the
    // person token and issued a resource token for the Access Server.
    await selectStep(page, 4);
    await expectResponse(page, 401);
    await expect(page.locator('section.payload')).toContainText('requirement=auth-token');

    // Step 11 ("Replay GET /wallet with auth_token → 200") holds the result.
    await selectStep(page, 10);
    await expectResponse(page, 200, ['four-party']);

    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.accessMode).toBe('four-party');
    expect(json.scheme).toBe('jwt');
    // The AS copied the person (ps, sub) from the resource token; no agent claim.
    expect(json.ps).toBe(Urls.personServer);
    expect(json.sub).toBe(directedSubject(Urls.wallet));
    expect(json.userKey).toBe(`${Urls.personServer}|${directedSubject(Urls.wallet)}`);
    expect(json.scope).toEqual(['wallet.read']);
    // The auth token is issued by the Access Server, not the Person Server.
    expect(json.iss).toBe(Urls.accessServer);
    expect(json).not.toHaveProperty('agent');
    expect(json).not.toHaveProperty('act');
  });

  test('deny at the AS consent page aborts the flow', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.Federated);

    await runAll(page);
    await approvePersonConsent(page, 'a.primary.approve');
    const link = page.locator('a.worker-consent');
    await expect(link).toBeVisible();

    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await decideAccessConsent(popup, false);

    // The flow aborts: the primary button locks to "Aborted" and the poll loop
    // records a terminal denied step (403 denied).
    await expect(page.locator('button.primary')).toHaveText('Aborted', { timeout: 120_000 });
    await expect(doneSteps(page).last()).toContainText(/denied/i);
  });
});
