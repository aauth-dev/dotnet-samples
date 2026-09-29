import { test, expect } from './fixtures';
import { clickAndConfirm, waitForInteractive } from './blazor';
import { approvePersonConsent } from './consent';
import { expectRequestResponseArrows } from './sequence';
import { expectReadableLinks, expectSyntaxHighlighted } from './visual-style';

export function eventsWalkthroughTests() {
  test.describe('Events subscription and delivery', () => {
    test.describe.configure({ timeout: 120_000 });
    for (const protectedChannel of [false, true]) {
      test(`${protectedChannel ? 'protected work account' : 'public channel'} delivers a verified notification`, async ({ page }, testInfo) => {
        test.setTimeout(180_000);
        if (protectedChannel) await page.setViewportSize({ width: 390, height: 844 });
        await page.goto('/events');
        await waitForInteractive(page, '.events-next');
        const root = page.locator('.events-view');
        await expect(root.locator('.scenario-narrative')).toContainText('Aria');
        await expect(root.locator('.scenario-narrative')).toContainText('Bookings');
        await expectSyntaxHighlighted(root.locator('[data-code-step="1"] code'));
        await expectReadableLinks(page);
        await expect(root.locator('[data-protocol-step]')).toHaveCount(6);
        const methods = ['DiscoverChannelsAsync', 'ObtainSubscriptionUrlAsync', 'AcquireSubscribeTokenAsync', 'RegisterSubscriptionAsync', 'DeliverResourceEventAsync', 'VerifyInboxAsync'];
        for (const step of [1, 2, 3, 4, 5, 6]) {
          await expect(root.locator(`[data-code-step="${step}"] summary`)).toContainText(`${step}.`);
          await expect(root.locator(`[data-code-step="${step}"] code`)).toContainText(methods[step - 1]);
        }
        const diagram = root.getByRole('region', { name: 'Sequence diagram' });
        for (const step of [1, 2, 3, 4, 5, 6])
          expect(await diagram.locator(`[data-sequence-step="${step}"]`).count()).toBeGreaterThan(0);
        await expect(diagram.locator('.sequence-participant')).toHaveText([
          'Agent', 'Bookings', 'Agent Provider', 'Person Server', 'User / Browser',
        ]);
        let previousReceipt: string | null = null;
        for (const cycle of [0, 1]) {
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
        if (protectedChannel) {
          const consent = page.locator('.events-consent-action');
          await expect(consent).toHaveCSS('display', /^(inline-)?flex$/);
          await approvePersonConsent(page, '.events-consent-action');
        }
        await expect(page.locator('.events-view')).toHaveAttribute('data-step', '2', { timeout: 60_000 });
        for (const step of [3, 4, 5, 6]) {
          await expect(root.locator(`[data-protocol-step="${step}"]`)).toHaveAttribute('aria-current', 'step');
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
        for (let step = 1; step <= 6; step++)
          expect(await diagram.locator(`[data-sequence-step="${step}"]`).count()).toBeGreaterThan(0);
        const localMessages = (await diagram.locator('[data-kind="local"] .sequence-label').allTextContents()).join(' ');
        expect(localMessages).toContain('Verify and deduplicate event');
        if (!protectedChannel) expect(localMessages).toContain('Select public channel URL');
        await expectRequestResponseArrows(diagram);
        const receipt = await root.locator('.events-receipt dd').nth(1).innerText();
        expect(receipt).not.toBe(previousReceipt);
        previousReceipt = receipt;
        const images = page.locator('.events-view img');
        for (let index = 0; index < await images.count(); index++) {
          expect(await images.nth(index).evaluate(image => (image as HTMLImageElement).naturalWidth)).toBeGreaterThan(0);
        }
        for (const width of [1280, 390]) {
          await page.setViewportSize({ width, height: 844 });
          expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
          await page.locator('.events-receipt').scrollIntoViewIfNeeded();
          await page.screenshot({ path: testInfo.outputPath(`events-${cycle}-${width}.png`) });
          await diagram.screenshot({ path: testInfo.outputPath(`events-diagram-${cycle}-${width}.png`) });
          const code = root.locator('[data-code-step="6"]');
          if (!await code.evaluate(element => (element as HTMLDetailsElement).open)) await code.locator('summary').click();
          await code.screenshot({ path: testInfo.outputPath(`events-code-${cycle}-${width}.png`) });
        }
        await page.getByRole('button', { name: 'Start a new subscription' }).click();
        await expect(root).toHaveAttribute('data-step', '0');
        await expect(root.locator('.events-evidence details')).toHaveCount(0);
        await expect(page.getByTestId('event-payload')).toHaveCount(0);
        await expect(root.locator('.events-consent')).toHaveCount(0);
        }
      });
    }
  });
}