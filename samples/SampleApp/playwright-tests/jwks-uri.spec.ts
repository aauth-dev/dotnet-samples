import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';

/**
 * JWKS URI — agent-identity 2-party flow. Step 1 enrols with the AP, step 2
 * sends a signed GET /identified → 200. Needs MockAgentProvider + Profile.
 */
test('jwks-uri enrols then sends a signed request', async ({ page }) => {
  await page.goto('/identified');
  await expect(page.locator('h2')).toHaveText('JWKS URI — Agent Identity');
  await waitForInteractive(page, 'button');

  // Step 1 — enrol (button only present when not yet enrolled this circuit).
  const enrol = page.getByRole('button', { name: /Enrol with Agent Provider/ });
  if (await enrol.isVisible().catch(() => false)) {
    await enrol.click();
  }
  await expect(page.locator('.alert-info')).toContainText('JWKS URI');

  // Step 2 — signed request.
  await page.getByRole('button', { name: /Send Signed Request/ }).click();

  await expectStatus(page, 200);
  const json = (await readResponseJson(page)) as Record<string, unknown>;
  expect(json.signingMode).toBe('agent-identity');
  expect(json.scheme).toBe('jwks_uri');
  // Agent identity is established by a published JWKS — both the URI and the
  // key id the resource resolved must be present and well-formed.
  expect(json.kid).toBeTruthy();
  expect(typeof json.kid).toBe('string');
  expect(String(json.jwks_uri)).toMatch(/^https?:\/\/.+\/.+/);
  expect(json.note).toContain('JWKS URI');
});
