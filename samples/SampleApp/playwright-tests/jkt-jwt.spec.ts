import { test, expect } from '@playwright/test';
import { waitForInteractive } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';

/**
 * JKT-JWT — key-rotation 2-party flow. Three steps: enrol, two-key refresh
 * (generates an ephemeral key), then signed GET /jkt-jwt → 200.
 * Needs MockAgentProvider + WhoAmI.
 */
test('jkt-jwt enrols, refreshes to an ephemeral key, then sends', async ({ page }) => {
  await page.goto('/jkt-jwt');
  await expect(page.locator('h2')).toContainText('JKT-JWT');
  await waitForInteractive(page, 'button');

  const enrol = page.getByRole('button', { name: /Enrol with Agent Provider/ });
  if (await enrol.isVisible().catch(() => false)) {
    await enrol.click();
  }
  await expect(page.locator('.alert-info')).toContainText('Durable key thumbprint');

  await page.getByRole('button', { name: /Two-Key Refresh/ }).click();
  await expect(page.locator('.alert-success')).toContainText('Ephemeral key');

  await page.getByRole('button', { name: /Send Signed Request/ }).click();

  await expectStatus(page, 200);
  const json = (await readResponseJson(page)) as Record<string, unknown>;
  expect(json.mode).toBe('pseudonymous');
  expect(json.scheme).toBe('jkt-jwt');
  // The resource identifies the agent by the DURABLE key thumbprint carried in
  // the naming JWT, even though the request was signed by the ephemeral key.
  expect(json.jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(json.note).toContain('naming JWT');
});
