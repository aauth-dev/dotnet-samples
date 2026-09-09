import { test, expect } from './fixtures';
import { clickAndConfirm, waitForInteractive } from './blazor';
import { approvePersonConsent } from './consent';

export function eventsWalkthroughTests() {
  test.describe('Events subscription and delivery', () => {
    test.describe.configure({ timeout: 120_000 });
    for (const protectedChannel of [false, true]) {
      test(`${protectedChannel ? 'protected work account' : 'public channel'} delivers a verified notification`, async ({ page }, testInfo) => {
        if (protectedChannel) await page.setViewportSize({ width: 390, height: 844 });
        await page.goto('/events');
        await waitForInteractive(page, '.events-next');
        await expect(async () => {
          await page.getByLabel(protectedChannel ? 'Protected reservations' : 'Public availability', { exact: true }).check();
          if (protectedChannel) await page.locator('#events-account').selectOption('work');
          await expect(page.getByLabel(protectedChannel ? 'Protected reservations' : 'Public availability', { exact: true })).toBeChecked();
          await expect(page.locator('.events-view')).toHaveAttribute('data-channel', protectedChannel ? 'protected' : 'public');
        }).toPass();
        await clickAndConfirm(page, '.events-next', async () =>
          await page.locator('.events-view').getAttribute('data-step') === '1' || await page.locator('.events-error').isVisible());
        await expect(page.locator('.events-error')).toHaveCount(0);
        await expect(page.locator('.events-view')).toHaveAttribute('data-step', '1');
        await expect(page.locator('.events-evidence')).toContainText('aauth-subscribe');
        await page.locator('.events-next').click();
        if (protectedChannel) await approvePersonConsent(page, '.events-consent a');
        await expect(page.locator('.events-view')).toHaveAttribute('data-step', '2', { timeout: 60_000 });
        for (const step of [3, 4, 5, 6]) {
          await page.locator('.events-next').click();
          await expect(page.locator('.events-error')).toHaveCount(0);
          await expect(page.locator('.events-view')).toHaveAttribute('data-step', String(step), { timeout: 30_000 });
        }
        await expect(page.getByTestId('event-payload')).toContainText('reservation.available');
        await expect(page.getByTestId('event-payload')).toContainText(protectedChannel ? '"account":"work"' : '"account":null');
        await expect(page.locator('.events-receipt')).toContainText(protectedChannel ? 'work reservations' : 'public availability');
        await expect(page.locator('.events-evidence')).toContainText('"duplicate_ignored": true');
        await expect(page.locator('.events-evidence')).toContainText('HTTP 202');
        await expect(page.locator('.events-next')).toBeDisabled();
        const images = page.locator('.events-view img');
        for (let index = 0; index < await images.count(); index++) {
          expect(await images.nth(index).evaluate(image => (image as HTMLImageElement).naturalWidth)).toBeGreaterThan(0);
        }
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
        await page.locator('.events-receipt').scrollIntoViewIfNeeded();
        await page.screenshot({ path: testInfo.outputPath(protectedChannel ? 'events-mobile.png' : 'events-desktop.png') });
      });
    }
  });
}