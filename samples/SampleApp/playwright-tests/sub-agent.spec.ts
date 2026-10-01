import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { completeWorkerConsent } from '../../../tests/e2e/helpers/worker-consent';
import { Urls } from '../../../tests/e2e/helpers/agents';
import { CONSENT_ACTION } from '../../../tests/e2e/helpers/dashboard';

/**
 * Sub-Agents — parent-mediated workers. Unlike the other SampleApp pages this
 * one runs the token lifecycle in-process with the real SDK builders, so it
 * needs no mock servers or standing consent. The spec asserts the wire
 * artifacts the page surfaces: the sub-agent's `parent_agent` claim, the
 * sub-agent-bound `cnf`, and the person-named (ps, sub) auth token.
 */
test('sub-agent flow shows parent_agent and a worker-bound auth token', async ({ page }) => {
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
  await completeWorkerConsent(page, `.alert-warning ${CONSENT_ACTION}`, async () => (await page.locator('.list-group-item').count()) === 7);
  await expect(page.locator('.list-group-item')).toHaveCount(7);
  await expect(page.getByText('PS returns the AS auth token to the parent')).toBeVisible();
  await expect(page.getByText('Parent hands the token to the worker')).toBeVisible();
  await expect(page.getByText('Sub-agent calls the resource with the token')).toBeVisible();

  // The sub-agent token carries the parent_agent claim (the authoritative marker).
  const json = page.locator('pre code.language-json');
  const worker = JSON.parse(await json.nth(1).innerText()) as Record<string, any>;
  expect(worker.sub).toMatch(/^aauth:aria\+worker1@/);
  expect(worker.parent_agent).toBe('aauth:aria@localhost');

  // The issued AS auth token binds cnf to the worker's key and names the person
  // (ps, sub) — no agent claim and no act chain.
  await expect(page.locator('.alert-success')).toContainText('matches');
  const auth = JSON.parse(await json.nth(2).innerText()) as Record<string, any>;
  expect(auth.cnf.jwk).toEqual(worker.cnf.jwk);
  expect(auth.iss).toBe(Urls.accessServer);
  expect(auth.ps).toBe(Urls.personServer);
  expect(auth.dwk).toBe('aauth-access.json');
  expect(typeof auth.sub).toBe('string');
  expect(auth).not.toHaveProperty('agent');
  expect(auth).not.toHaveProperty('act');

  // The Wallet served the worker the same person the auth token names.
  const wallet = JSON.parse(await json.first().innerText()) as Record<string, any>;
  expect(wallet.ps).toBe(Urls.personServer);
  expect(wallet.sub).toBe(auth.sub);
  expect(wallet.iss).toBe(Urls.accessServer);
  await expect(page.getByText('Actual signed HTTP responses: worker 200, parent 401.')).toBeVisible();
});
