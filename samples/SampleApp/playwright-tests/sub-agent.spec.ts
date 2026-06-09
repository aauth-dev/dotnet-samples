import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';

/**
 * Sub-Agents — parent-mediated workers. Unlike the other SampleApp pages this
 * one runs the token lifecycle in-process with the real SDK builders, so it
 * needs no mock servers or standing consent. The spec asserts the wire
 * artifacts the page surfaces: the sub-agent's `parent_agent` claim, the
 * sub-agent-bound `cnf`, the nested `act`, and single-level depth enforcement.
 */
test('sub-agent flow shows parent_agent, sub-agent-bound cnf, and nested act', async ({ page }) => {
  await page.goto('/sub-agent');
  await expect(page.locator('h2')).toHaveText('Sub-Agents — Parent-Mediated Workers');
  await waitForInteractive(page, 'button.btn-primary');

  // Blazor InteractiveServer can drop the first click on a cold circuit; retry
  // until the flow list renders.
  await clickAndConfirm(
    page,
    'button.btn-primary',
    async () => (await page.locator('.list-group-item').count()) > 0,
  );

  // The flow list records each step of the parent-mediated exchange, including
  // the PS returning the token to the parent, the parent handing it down, and
  // the sub-agent calling the resource itself.
  await expect(page.locator('.list-group-item')).toHaveCount(7);
  await expect(page.getByText('PS returns the auth token to the parent')).toBeVisible();
  await expect(page.getByText('Parent hands the token to the worker')).toBeVisible();
  await expect(page.getByText('Sub-agent calls the resource with the token')).toBeVisible();

  // The sub-agent token carries the parent_agent claim (the authoritative marker).
  const subClaims = page.locator('pre code.language-json').first();
  await expect(subClaims).toContainText('parent_agent');
  await expect(subClaims).toContainText('aauth:aria+worker1@');

  // The issued auth token binds cnf to the sub-agent (success alert) and nests act.
  await expect(page.locator('.alert-success')).toContainText('matches');
  const authClaims = page.locator('pre code.language-json').nth(1);
  await expect(authClaims).toContainText('"agent": "aauth:aria+worker1@');
  await expect(authClaims).toContainText('"act"');

  // Single-level depth is enforced by the AP builder.
  await expect(page.getByRole('heading', { name: 'Single-level depth enforcement' })).toBeVisible();
});
