import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';

/**
 * HWK — pseudonymous 2-party flow. One button, one signed GET /pseudonymous → 200.
 * Needs only Profile.
 */
test('hwk sends a signed request and returns a pseudonymous identity', async ({ page }) => {
  await page.goto('/pseudonymous');
  await expect(page.locator('h2')).toHaveText('HWK — Pseudonymous Signing');
  await waitForInteractive(page, 'button.btn-primary');

  await page.locator('button.btn-primary').click();

  await expectStatus(page, 200);
  const json = (await readResponseJson(page)) as Record<string, unknown>;
  expect(json.signingMode).toBe('pseudonymous');
  expect(json.scheme).toBe('hwk');
  // The resource sees only the key thumbprint (jkt), never an agent identity.
  expect(json.jkt).toMatch(/^[A-Za-z0-9_-]{43}$/); // base64url SHA-256 thumbprint
  expect(json.agent).toBeUndefined();
  expect(json.note).toContain('key thumbprint only');
});
