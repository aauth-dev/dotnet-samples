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
 * Rich Resource Requests (R3, four-party) — Guided Tour.
 *
 * Mirrors the SampleApp Bookings page as an explicit, inspectable 14-step
 * walkthrough against the Bookings resource (:5005) and its dedicated R3 Access
 * Server (:5501). The flow is a single linear plan (no branch): the low-risk
 * `searchAvailability` is granted outright (steps 1–6, `r3_granted`), while
 * `confirmReservation` charges a deposit, so it is `r3_conditional` — the
 * resource challenges with a per-call proposal carrying the concrete
 * parameters, the R3 AS asks the user to approve that specific booking (202 →
 * consent → poll), and only then does the resource confirm it (steps 7–14).
 *
 * The R3 AS sets `RequireProposalConsent=true`, so confirm ALWAYS needs consent:
 * `runAll` parks on the user-approval step (10 done — the granted path plus the
 * confirm challenge/proposal exchange), the user approves at the R3 AS's own
 * consent screen (badged *R3 Access Server*), the poll resolves the per-call
 * token, and the retry confirms the reservation.
 */
test.describe('Rich Resource Requests (Guided Tour)', () => {
  test.describe.configure({ timeout: 180_000 });

  test('approve the per-call proposal at the R3 AS resolves both operations', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.RichRequests);

    // Four-party R3 shows a distinct Bookings resource lane and a dedicated
    // R3 Access Server lane (rendered on the same red `as` lane as Federated).
    await expect(page.locator('.lanes .lane.agent')).toContainText('Agent');
    await expect(page.locator('.lanes .lane.resource')).toContainText('Bookings');
    await expect(page.locator('.lanes .lane.ps')).toContainText('Person Server');
    await expect(page.locator('.lanes .lane.as')).toContainText('R3 Access Server');

    // Run all: the granted path (search 1–6) and the confirm challenge +
    // proposal exchange (7–9) run, then the flow parks on the user-approval
    // step (10 done) with the R3 AS interaction link shown.
    await runAll(page);
    const link = page.locator('a.primary.approve');
    await expect(link).toBeVisible();
    await expect(doneSteps(page)).toHaveCount(10);

    // Opening the link starts the background poll loop and opens the R3 Access
    // Server's own per-call consent screen in a new tab.
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    // The R3 AS consent screen is unmistakably badged "R3 Access Server".
    await expect(popup.locator('.badge')).toContainText('R3 Access Server');
    await approveInPopup(popup);

    // The poll loop resolves and records the per-call auth_token step (12 done).
    // Running again finishes the confirm replay (13) and inspect (14) steps.
    await expect(doneSteps(page)).toHaveCount(12, { timeout: 120_000 });
    await runAll(page);
    await expect(doneSteps(page)).toHaveCount(14, { timeout: 30_000 });

    // Step 6 ("Replay GET /search_availability → 200 (r3_granted)") — served
    // outright because searchAvailability is in r3_granted.
    await selectStep(page, 5);
    await expectResponse(page, 200, ['four-party-r3']);
    const search = (await readResponseJson(page)) as Record<string, unknown>;
    expect(search.accessMode).toBe('four-party-r3');
    expect(search.operationId).toBe('searchAvailability');
    expect(search.source).toBe('r3_granted');
    expect(typeof search.r3_uri).toBe('string');
    expect(typeof search.r3_s256).toBe('string');

    // Step 13 ("Replay POST /confirm_reservation → 200 (confirmed)") — served
    // only after the per-call proposal was approved and the digest verified.
    await selectStep(page, 12);
    await expectResponse(page, 200, ['confirmed']);
    const confirm = (await readResponseJson(page)) as Record<string, unknown>;
    expect(confirm.accessMode).toBe('four-party-r3');
    expect(confirm.operationId).toBe('confirmReservation');
    expect(confirm.source).toBe('per-call-r3_granted');
    expect(confirm.status).toBe('confirmed');
    expect(typeof confirm.r3_uri).toBe('string');
    expect(typeof confirm.r3_s256).toBe('string');
  });

  test('deny the per-call proposal at the R3 AS aborts the flow', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.RichRequests);

    await runAll(page);
    const link = page.locator('a.primary.approve');
    await expect(link).toBeVisible();

    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await expect(popup.locator('.badge')).toContainText('R3 Access Server');
    await denyInPopup(popup);

    // The flow aborts: the primary button locks to "Aborted" and the poll loop
    // records a terminal denied step (403 denied).
    await expect(page.locator('button.primary')).toHaveText('Aborted', { timeout: 120_000 });
    await expect(doneSteps(page).last()).toContainText(/denied/i);
  });
});
