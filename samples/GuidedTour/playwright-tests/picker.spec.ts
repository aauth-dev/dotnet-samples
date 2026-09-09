import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { openTour } from '../../../tests/e2e/helpers/tour';

/**
 * Flow picker structure: all fifteen flows are offered, the signing-mode picker is
 * Identity-only, and the description text reacts to the selected flow. This is a
 * UI-structure spec (no protocol result), guarding the entry point every other
 * spec depends on.
 */
test('flow picker offers all fifteen flows and reacts to selection', async ({ page }) => {
  await openTour(page);

  const flow = page.locator('select#flow-select');
  await expect(flow.locator('option')).toHaveCount(15);
  await expect(flow.locator('option')).toContainText([
    'Bootstrap',
    'Generic Signature Keys',
    'Resource-Managed',
    'PS-Asserted (Direct Grant)',
    'PS-Asserted (Deferred)',
    'Call Chain',
    'Federated (Four-Party)',
    'Rich Resource Requests',
    'Mission (PS-Governed)',
    'Mission + Call Chain',
    'Sub-Agents',
    'Bookings Events',
    'Wallet Protocol',
    'Document Release',
    'Travel Catalog',
  ]);

  // Signing-mode picker only appears for the Identity flow.
  await expect(page.locator('select#signing-mode-select')).toHaveCount(0);
  // The <select> uses one-way Blazor binding; a change event fired against a
  // freshly-connected circuit can be dropped. Retry until the server confirms
  // by rendering the Identity-only signing-mode picker.
  await expect(async () => {
    await flow.selectOption('Identity');
    await expect(page.locator('select#signing-mode-select')).toBeVisible({ timeout: 2_000 });
  }).toPass({ timeout: 20_000 });
  await expect(page.locator('details.flow-picker__desc')).toContainText('access control');

  // Switching to a three-party flow hides the signing-mode picker again.
  await expect(async () => {
    await flow.selectOption('Autonomous');
    await expect(page.locator('select#signing-mode-select')).toHaveCount(0, { timeout: 2_000 });
  }).toPass({ timeout: 20_000 });
  await expect(page.locator('details.flow-picker__desc')).toContainText('standing consent');

  await flow.selectOption('/events');
  await expect(page).toHaveURL(/\/events$/);
  await expect(page.locator('select#flow-select')).toHaveValue('/events');
  await expect(page.locator('select#flow-select option')).toHaveCount(15);
});
