import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';
import { grantConsent } from '../../../tests/e2e/helpers/consent';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

/**
 * JWT — three-party direct grant. The page has no interaction UI, so standing
 * consent must already exist or the SDK would block on the deferred path. We
 * pre-grant consent for the SampleApp's self-issued agent (OQ1).
 */
test.beforeEach(async ({ request }) => {
  await grantConsent(request, Agents.sampleApp, Urls.whoami);
});

test('jwt direct grant returns a three-party identity', async ({ page }) => {
  await page.goto('/jwt');
  await expect(page.locator('h2')).toHaveText('JWT — Agent Token (Three-Party)');
  await waitForInteractive(page, 'button.btn-primary');

  await page.locator('button.btn-primary').click();

  await expectStatus(page, 200);
  const json = (await readResponseJson(page)) as Record<string, unknown>;
  expect(json.mode).toBe('three-party');
  expect(json.scheme).toBe('jwt');
  // The auth token was minted by the Person Server for the WhoAmI audience.
  expect(json.agent).toBe(Agents.sampleApp);
  expect(json.sub).toBe('pairwise-sub');
  expect(json.scope).toEqual(['whoami']);
  expect(json.iss).toBe(Urls.personServer);
  // Direct grant — single-hop act chain naming the calling agent, no nesting.
  const act = json.act as Record<string, unknown>;
  expect(act.sub).toBe(Agents.sampleApp);
  expect(act.act).toBeUndefined();
});
