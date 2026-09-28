import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { approvePersonConsent } from '../../../tests/e2e/helpers/consent';
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
import { approveInPopup, denyInPopup, authenticateConsent } from '../../../tests/e2e/helpers/consent';
import { Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Rich Resource Requests (R3, four-party) — Guided Tour.
 *
 * Mirrors the SampleApp Bookings page as an explicit, inspectable 16-step
 * walkthrough against the Bookings resource (:5005) and its dedicated R3 Access
 * Server (:5501). The flow is a single linear plan (no branch): Bookings first
 * requires a person token (steps 2–5), then the low-risk
 * `searchAvailability` is granted outright (steps 6–8, `r3_granted`), while
 * `confirmReservation` charges a deposit, so it is `r3_conditional` — the
 * resource challenges with a per-call proposal carrying the concrete
 * parameters and naming the presented class auth token, the R3 AS asks the
 * user to approve that specific booking (202 → consent → poll), and only then
 * does the resource confirm it (steps 9–16).
 *
 * The R3 AS sets `RequireProposalConsent=true`, so confirm ALWAYS needs consent:
 * `runAll` parks on the user-approval step (12 done — the granted path plus the
 * confirm challenge/proposal exchange), the user approves at the R3 AS's own
 * consent screen (badged *R3 Access Server*), the poll resolves the per-call
 * token, and the retry confirms the reservation.
 */
test.describe('Rich Resource Requests (Guided Tour)', () => {
  test.describe.configure({ timeout: 180_000 });

  test('account switch keeps the agent but rejects the previous grant and stale consent', async ({ page, context }, testInfo) => {
    await openTour(page);
    await selectFlow(page, TourMode.RichRequests);
    await page.locator('#bookings-account').selectOption('personal');
    for (let step = 1; step <= 6; step++) {
      await page.locator('button.primary').click();
      await expect(doneSteps(page)).toHaveCount(step);
    }
    // The person token carries no account; the resource token echoes it.
    await selectStep(page, 3);
    await expect(page.locator('section.payload')).not.toContainText('"account"');
    await page.locator('button.primary').click();
    await approvePersonConsent(page, 'a.worker-consent');
    await expect(doneSteps(page)).toHaveCount(7);
    await page.locator('button.primary').click();
    await expect(doneSteps(page)).toHaveCount(8);
    await selectStep(page, 7);
    const personal = await readResponseJson(page) as Record<string, unknown>;
    expect(personal.account).toBe('personal');
    expect(personal.ps).toBe(Urls.personServer);

    await page.locator('#bookings-account').selectOption('work');
    await expect(doneSteps(page)).toHaveCount(0);
    await page.getByRole('button', { name: 'Check previous account grant', exact: true }).click();
    await expect(page.locator('.account-probe')).toContainText('401 Unauthorized: previous account grant rejected');
    for (let step = 1; step <= 6; step++) {
      await page.locator('button.primary').click();
      await expect(doneSteps(page)).toHaveCount(step);
    }
    await page.locator('button.primary').click();
    const link = page.locator('a.worker-consent');
    await expect(link).toBeVisible();
    const [popup] = await Promise.all([context.waitForEvent('page'), link.click()]);
    await authenticateConsent(popup);
    await expect(popup.locator('body')).toContainText('work');
    await denyInPopup(popup);
    await popup.close();
    await expect(page.locator('header.topbar .error')).toContainText(/denied/i);
    await expect(doneSteps(page)).toHaveCount(6);
    await page.locator('button.primary').click();
    await approvePersonConsent(page, 'a.worker-consent');
    await expect(doneSteps(page)).toHaveCount(7);
    await page.locator('button.primary').click();
    await expect(doneSteps(page)).toHaveCount(8);
    await selectStep(page, 7);
    const work = await readResponseJson(page) as Record<string, unknown>;
    expect(work.account).toBe('work');
    // Same person (ps, sub) and same agent key; only the account differs.
    expect(work.subject).toBe(personal.subject);
    expect(work.ps).toBe(personal.ps);
    await page.screenshot({ path: testInfo.outputPath('accounts-desktop.png') });
  });

  test('approve the per-call proposal at the R3 AS resolves both operations', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.RichRequests);
    await page.locator('#bookings-account').selectOption('personal');

    // Four-party R3 shows a distinct Bookings resource lane and a dedicated
    // R3 Access Server lane (rendered on the same red `as` lane as Federated).
    await expect(page.locator('.lanes .lane.agent')).toContainText('Agent');
    await expect(page.locator('.lanes .lane.resource')).toContainText('Bookings');
    await expect(page.locator('.lanes .lane.ps')).toContainText('Person Server');
    await expect(page.locator('.lanes .lane.as')).toContainText('R3 Access Server');

    // Run all: the person-token leg and granted path (search 1–8) and the
    // confirm challenge + proposal exchange (9–11) run, then the flow parks on
    // the user-approval step (12 done) with the R3 AS interaction link shown.
    await page.getByRole('button', { name: 'Run all' }).click();
    await approvePersonConsent(page, 'a.worker-consent');
    const link = page.locator('a.primary.approve[href^="http://localhost:5501/"]');
    await expect(link).toBeVisible();
    await expect(doneSteps(page)).toHaveCount(12);

    // Opening the link starts the background poll loop and opens the R3 Access
    // Server's own per-call consent screen in a new tab.
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    // The R3 AS consent screen is unmistakably badged "R3 Access Server".
    await authenticateConsent(popup);
    await expect(popup.locator('.badge')).toContainText('R3 Access Server');
    await expect(popup.locator('body')).toContainText('Personal reservations');
    await approveInPopup(popup);

    // The poll loop resolves and records the per-call auth_token step (14 done).
    // Running again finishes the confirm replay (15) and inspect (16) steps.
    await expect(doneSteps(page)).toHaveCount(14, { timeout: 120_000 });
    await runAll(page);
    await expect(doneSteps(page)).toHaveCount(16, { timeout: 30_000 });

    // Step 8 ("Replay GET /search_availability → 200 (r3_granted)") — served
    // outright because searchAvailability is in r3_granted.
    await selectStep(page, 7);
    await expectResponse(page, 200, ['four-party-r3']);
    const search = (await readResponseJson(page)) as Record<string, unknown>;
    expect(search.accessMode).toBe('four-party-r3');
    expect(search.operationId).toBe('searchAvailability');
    expect(search.source).toBe('r3_granted');
    expect(search.account).toBe('personal');
    expect(typeof search.r3_uri).toBe('string');
    expect(typeof search.r3_s256).toBe('string');

    // Step 15 ("Replay POST /confirm_reservation → 200 (confirmed)") — served
    // only after the per-call proposal was approved and the digest verified.
    await selectStep(page, 14);
    await expectResponse(page, 200, ['confirmed']);
    const confirm = (await readResponseJson(page)) as Record<string, unknown>;
    expect(confirm.accessMode).toBe('four-party-r3');
    expect(confirm.operationId).toBe('confirmReservation');
    expect(confirm.source).toBe('per-call-r3_granted');
    expect(confirm.status).toBe('confirmed');
    expect(confirm.account).toBe('personal');
    expect(typeof confirm.r3_uri).toBe('string');
    expect(typeof confirm.r3_s256).toBe('string');

    // Step 16 ("Inspect R3 result") — the summary decodes the auth token's
    // object-shaped r3_granted / r3_conditional claims into their operation ids
    // (guards against rendering "(none)" when the claim shape is misread).
    await selectStep(page, 15);
    const inspector = page.locator('section.payload');
    await expect(inspector).toContainText('searchAvailabilityPost');
    await expect(inspector).toContainText('holdReservationPost');
    await expect(inspector).toContainText('searchAvailability');
    await expect(inspector).toContainText('holdReservation');
    await expect(inspector).toContainText('r3_conditional: confirmReservation');
  });

  test('deny the per-call proposal at the R3 AS aborts the flow', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.RichRequests);

    await page.getByRole('button', { name: 'Run all' }).click();
    await approvePersonConsent(page, 'a.worker-consent');
    const link = page.locator('a.primary.approve[href^="http://localhost:5501/"]');
    await expect(link).toBeVisible();

    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await authenticateConsent(popup);
    await expect(popup.locator('.badge')).toContainText('R3 Access Server');
    await denyInPopup(popup);

    // The flow aborts: the primary button locks to "Aborted" and the poll loop
    // records a terminal denied step (403 denied).
    await expect(page.locator('button.primary')).toHaveText('Aborted', { timeout: 120_000 });
    await expect(doneSteps(page).last()).toContainText(/denied/i);
  });
});
