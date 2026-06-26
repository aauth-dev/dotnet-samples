import { test, expect } from '../../../tests/e2e/helpers/fixtures';

/**
 * SampleApp landing page: demo cards, each linking to a flow page with the
 * right badges. Static content — no circuit interaction required.
 */
test.describe('Home', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('renders the demo cards with correct links', async ({ page }) => {
    await expect(page.locator('h1')).toHaveText('AAuth SDK — Sample App');

    const expected: Array<[string, string]> = [
      ['HWK', 'pseudonymous'],
      ['JWKS URI', 'identified'],
      ['JWT', 'calendar'],
      ['Deferred', 'calendar-deferred'],
      ['JKT-JWT', 'anchored'],
      ['Call Chain', 'call-chain'],
      ['Rich Trip Booking', 'rich-request'],
    ];

    for (const [title, href] of expected) {
      const card = page.locator('.card', { hasText: title }).first();
      await expect(card).toBeVisible();
      await expect(card.locator(`a[href="${href}"]`)).toBeVisible();
    }
  });

  test('introduces Aria and the Sample App role', async ({ page }) => {
    const intro = page.locator('.alert-primary');
    await expect(intro).toContainText('Meet Aria');
    await expect(intro).toContainText('AI travel assistant');
    // The Aria servers and the golden-example role are explained.
    await expect(intro).toContainText('Profile');
    await expect(intro).toContainText('Wallet');
    await expect(intro).toContainText('Bookings');
    await expect(intro).toContainText('golden example');
  });

  test('shows the prerequisites block', async ({ page }) => {
    await expect(page.getByText('make demo')).toBeVisible();
    await expect(page.locator('body')).toContainText('Bookings');
    await expect(page.locator('body')).toContainText(':5004');
    await expect(page.locator('body')).toContainText('R3 Access Server');
    await expect(page.locator('body')).toContainText(':5501');
  });
});
