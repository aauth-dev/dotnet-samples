import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive } from '../../../tests/e2e/helpers/blazor';

/**
 * Smoke test: the GuidedTour `/tour` page loads, the flow picker renders, and the
 * Blazor circuit becomes interactive (primary button enabled). Proves the
 * toolchain + server lifecycle + circuit-wait helper end-to-end before the full
 * specs are added.
 */
test('guided tour loads and circuit is interactive', async ({ page }) => {
  await page.goto('/tour');

  await expect(page.locator('header.topbar h1')).toHaveText('AAuth Guided Tour');
  await expect(page.locator('select#flow-select')).toBeVisible();

  await waitForInteractive(page, 'button.primary');
  await expect(page.locator('button.primary')).toBeEnabled();
});
