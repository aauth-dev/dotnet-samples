import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { expectReadableLinks } from '../../../tests/e2e/helpers/visual-style';

/**
 * SampleApp landing page: every demo card links to a flow page with the
 * right badges. Static content — no circuit interaction required.
 */
test.describe('Home', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('renders every demo card with correct links', async ({ page }) => {
    await expect(page.locator('h1')).toHaveText('AAuth SDK — Sample App');
    await expectReadableLinks(page);

    const expected: Array<[string, string]> = [
      ['HWK', 'pseudonymous'],
      ['Direct JWKS', 'identified'],
      ['Inbox', 'inbox'],
      ['JWT', 'calendar'],
      ['Deferred', 'calendar-deferred'],
      ['JKT-JWT', 'anchored'],
      ['Call Chain', 'call-chain'],
      ['Sub-Agents', 'sub-agent'],
      ['Federated', 'wallet'],
      ['Rich Resource Requests', 'bookings'],
      ['Mission —', 'trips'],
      ['Mission Call Chain', 'mission-call-chain'],
      ['Bookings Events', 'events'],
      ['Wallet Protocol', 'wallet-protocol'],
      ['Document Release', 'documents'],
      ['Travel Catalog', 'catalog-gateway'],
    ];

    await expect(page.locator('.card')).toHaveCount(expected.length);

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
    for (const entity of [
      'Profile', 'Inbox', 'Calendar', 'Trips', 'Wallet', 'Bookings', 'Catalog', 'Documents',
      'Concierge', 'Agent Provider', 'Person Server', 'Access Server', 'R3 Access Server',
      'User / Browser', 'Original Caller', 'Parent', 'Worker',
    ]) await expect(intro).toContainText(entity);
    await expect(intro).toContainText('golden example');
  });

  test('shows the prerequisites block', async ({ page }) => {
    await expect(page.getByText('make demo')).toBeVisible();
    await expect(page.getByText('eight Aria resource servers')).toBeVisible();
  });

  test('navigation gives each new flow its own styled item', async ({ page }) => {
    for (const href of ['events', 'documents', 'wallet-protocol', 'catalog-gateway']) {
      const link = page.locator(`nav .nav-item > a.nav-link[href="${href}"]`);
      await expect(link).toHaveCount(1);
      await expect(link.locator('.bi')).toHaveCount(1);
    }
  });
});
