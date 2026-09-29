import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import {
  openTour, selectFlow, driveTour, decideConsent, doneTitles, selectStepTitled,
  expectResponse, TourMode,
} from '../../../tests/e2e/helpers/tour';

/**
 * Bookings Events (flow 12) in the standard tour: AsyncAPI discovery, AP
 * enrolment, an account-bound grant on the protected channel, subscription,
 * self-jwt delivery to the AP inbox, verification with duplicate suppression,
 * and acknowledgement.
 */
test.describe('Bookings Events (Guided Tour)', () => {
  test.describe.configure({ timeout: 180_000 });

  for (const channel of ['public', 'protected'] as const) {
    test(`${channel} channel delivers a verified notification`, async ({ page }) => {
      await openTour(page);
      await selectFlow(page, TourMode.Events);
      const picker = page.locator('select#events-channel-select');
      await expect(async () => {
        await picker.selectOption(channel);
        await expect(page.locator('select#events-account-select')).toHaveCount(channel === 'protected' ? 1 : 0, { timeout: 2_000 });
      }).toPass({ timeout: 20_000 });
      if (channel === 'protected') {
        const account = page.locator('select#events-account-select');
        await expect(async () => {
          await account.selectOption('work');
          await expect(account).toHaveValue('work', { timeout: 2_000 });
        }).toPass({ timeout: 20_000 });
      }
      await expect(page.locator('.lanes .lane')).toHaveText(channel === 'protected'
        ? ['Agent', 'Bookings', 'Agent Provider', 'Person Server', 'R3 Access Server']
        : ['Agent', 'Bookings', 'Agent Provider']);

      await driveTour(page, (popup) => decideConsent(popup, true));
      await expect(page.locator('button.primary')).toHaveText('Done');
      const titles = await doneTitles(page);
      if (channel === 'public') expect(titles).toContain('Select the public channel URL');
      else expect(titles).toContain('Replay search with auth token → subscription ticket');

      await selectStepTitled(page, /^Register the subscription → 2\d\d/);
      await expect(page.locator('section.payload article.inspector')).toContainText('Signature-Key');
      await selectStepTitled(page, /^Trigger a sample notification → 202/);
      await expectResponse(page, 202);

      await selectStepTitled(page, /^Verify and deduplicate the event/);
      const inspector = page.locator('section.payload article.inspector');
      await expect(inspector).toContainText('"duplicate_ignored": true');
      await expect(inspector).toContainText('reservation.available');
      await expect(inspector).toContainText(channel === 'protected' ? 'work reservations' : 'public availability');
      await selectStepTitled(page, /^Acknowledge the event → 204/);
    });
  }
});
