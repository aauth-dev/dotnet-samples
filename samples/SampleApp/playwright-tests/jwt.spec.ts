import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';
import { grantConsent } from '../../../tests/e2e/helpers/consent';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';
import { directedSubject } from '../../../tests/e2e/helpers/consent';

/**
 * JWT — three-party direct grant. The page has no interaction UI, so standing
 * consent must already exist or the SDK would block on the deferred path. We
 * pre-grant consent for the SampleApp's self-issued agent (OQ1).
 */
test.beforeEach(async ({ request }) => {
  await grantConsent(request, Agents.sampleApp, Urls.calendar);
});

test('jwt direct grant returns a three-party identity', async ({ page }) => {
  await page.goto('/calendar');
  await expect(page.locator('h2')).toHaveText('JWT — Agent Token (Three-Party)');
  await waitForInteractive(page, 'button.btn-primary');

  await page.locator('button.btn-primary').click();

  await expectStatus(page, 200);
  const json = (await readResponseJson(page)) as Record<string, unknown>;
  expect(json.accessMode).toBe('three-party');
  expect(json.scheme).toBe('jwt');
  // The auth token was minted by the Person Server for the Calendar audience and
  // names the person as the (ps, sub) pair, not the agent.
  expect(json.ps).toBe(Urls.personServer);
  expect(json.sub).toBe(directedSubject(Urls.calendar));
  expect(json.userKey).toBe(`${Urls.personServer}|${directedSubject(Urls.calendar)}`);
  expect(json.scope).toEqual(['calendar.read']);
  expect(json.iss).toBe(Urls.personServer);
  expect(json).not.toHaveProperty('agent');
  expect(json).not.toHaveProperty('act');
});
