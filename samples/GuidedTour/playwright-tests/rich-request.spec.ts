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
import { approveInPopup } from '../../../tests/e2e/helpers/consent';
import { Urls } from '../../../tests/e2e/helpers/agents';

test.describe('Rich Resource Requests (Guided Tour)', () => {
  test.describe.configure({ timeout: 240_000 });

  test('drives rich trip booking through R3 claims and digest-matched retry', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.RichRequest);

    await expect(page.locator('.lanes .lane.resource')).toContainText('Bookings');
    await expect(page.locator('.lanes .lane.as')).toContainText('R3 Access Server');
    await expect(page.locator('details.flow-picker__desc')).toContainText('Experimental');

    // First approval: PS-rendered R3 document display.
    await runAll(page);
    let link = page.locator('a.primary.approve');
    await expect(link).toBeVisible();
    let [popup] = await Promise.all([context.waitForEvent('page'), link.click()]);
    await expect(popup.locator('body')).toContainText(/search|hold|book|R3/i);
    await approveInPopup(popup);

    await expect(doneSteps(page)).toHaveCount(7, { timeout: 120_000 });

    // Continue through granted operations and the conditional proposal.
    await runAll(page);
    await expect(doneSteps(page)).toHaveCount(10, { timeout: 60_000 });

    await selectStep(page, 2);
    await expect(page.locator('section.payload')).toContainText('r3_uri');
    await expect(page.locator('section.payload')).toContainText('r3_s256');
    await expect(page.locator('section.payload')).toContainText(Urls.r3AccessServer);

    await selectStep(page, 6);
    await expect(page.locator('section.payload')).toContainText('r3_granted');
    await expect(page.locator('section.payload')).toContainText('r3_conditional');
    await expect(page.locator('section.payload')).toContainText('book_trip');

    await selectStep(page, 8);
    await expectResponse(page, 401, ['r3_approval_required', 'r3_s256']);

    // Second approval: concrete book_trip per-call proposal.
    link = page.locator('a.primary.approve');
    await expect(link).toBeVisible();
    [popup] = await Promise.all([context.waitForEvent('page'), link.click()]);
    await expect(popup.locator('body')).toContainText(/Seattle|842|itinerary|book/i);
    await approveInPopup(popup);

    await expect(doneSteps(page)).toHaveCount(11, { timeout: 120_000 });
    await runAll(page);
    await expect(doneSteps(page)).toHaveCount(12, { timeout: 120_000 });
    await selectStep(page, 11);
    await expectResponse(page, 200, ['book_trip']);

    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(JSON.stringify(json)).toContain('SEA-2026-09-18-A');
  });
});
