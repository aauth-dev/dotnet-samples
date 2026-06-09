import { test, expect } from '../../../tests/e2e/helpers/fixtures';

/**
 * SampleApp landing page: six demo cards, each linking to a flow page with the
 * right badges. Static content — no circuit interaction required.
 */
test.describe('Home', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('renders the six demo cards with correct links', async ({ page }) => {
    await expect(page.locator('h1')).toHaveText('AAuth SDK — Sample App');

    const expected: Array<[string, string]> = [
      ['HWK', 'pseudonymous'],
      ['JWKS URI', 'identified'],
      ['JWT', 'calendar'],
      ['Deferred', 'calendar-deferred'],
      ['JKT-JWT', 'anchored'],
      ['Call Chain', 'call-chain'],
    ];

    for (const [title, href] of expected) {
      const card = page.locator('.card', { hasText: title }).first();
      await expect(card).toBeVisible();
      await expect(card.locator(`a[href="${href}"]`)).toBeVisible();
    }
  });

  test('shows the prerequisites block', async ({ page }) => {
    await expect(page.getByText('make demo')).toBeVisible();
  });
});
