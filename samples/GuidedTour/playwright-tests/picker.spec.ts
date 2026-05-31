import { test, expect } from '@playwright/test';
import { openTour } from '../../../tests/e2e/helpers/tour';

/**
 * Flow picker structure: all five flows are offered, the signing-mode picker is
 * Identity-only, and the description text reacts to the selected flow. This is a
 * UI-structure spec (no protocol result), guarding the entry point every other
 * spec depends on.
 */
test('flow picker offers all five flows and reacts to selection', async ({ page }) => {
  await openTour(page);

  const flow = page.locator('select#flow-select');
  await expect(flow.locator('option')).toHaveCount(5);
  await expect(flow.locator('option')).toContainText([
    'Bootstrap',
    'Identity-based',
    'PS-Asserted (Direct Grant)',
    'PS-Asserted (Deferred)',
    'Call Chain',
  ]);

  // Signing-mode picker only appears for the Identity flow.
  await expect(page.locator('select#signing-mode-select')).toHaveCount(0);
  await flow.selectOption('Identity');
  await expect(page.locator('select#signing-mode-select')).toBeVisible();
  await expect(page.locator('p.flow-picker__desc')).toContainText('access control');

  // Switching to a three-party flow hides the signing-mode picker again.
  await flow.selectOption('Autonomous');
  await expect(page.locator('select#signing-mode-select')).toHaveCount(0);
  await expect(page.locator('p.flow-picker__desc')).toContainText('standing consent');
});
