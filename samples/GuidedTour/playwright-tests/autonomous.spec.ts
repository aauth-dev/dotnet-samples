import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import {
  openTour,
  selectFlow,
  runAll,
  selectStep,
  expectResponse,
  readResponseJson,
  TourMode,
} from '../../../tests/e2e/helpers/tour';
import { Urls } from '../../../tests/e2e/helpers/agents';
import { directedSubject } from '../../../tests/e2e/helpers/consent';

/**
 * PS-Asserted (Direct Grant) — autonomous three-party flow, 8 steps, no human.
 * The agent token meets requirement=person-token; the agent gets a person token
 * from POST /person and presents it for a resource token. It has standing
 * consent at the Person Server (the page pre-seeds it via
 * PrepareConsentStateAsync), so POST /token returns an auth_token immediately and
 * the replayed GET returns 200 with a three-party identity. Assert the actual
 * 200 result and the full claim set on the final step.
 */
test.describe.configure({ timeout: 60_000 });

test('autonomous flow exchanges and replays to a three-party 200', async ({ page }) => {
  await openTour(page);
  await selectFlow(page, TourMode.Autonomous);

  await runAll(page);

  // Step 2 ("Signed GET → 401 person-token"): the agent token alone names no person.
  await selectStep(page, 1);
  await expectResponse(page, 401);
  await expect(page.locator('section.payload')).toContainText('requirement=person-token');

  // Step 8 ("Replay GET /events with auth_token") is the resource result.
  await selectStep(page, 7);
  await expectResponse(page, 200, ['three-party']);

  const json = (await readResponseJson(page)) as Record<string, unknown>;
  expect(json.accessMode).toBe('three-party');
  expect(json.scheme).toBe('jwt');
  // The auth token names the person as the (ps, sub) pair, not the agent.
  expect(json.ps).toBe(Urls.personServer);
  expect(json.sub).toBe(directedSubject(Urls.calendar));
  expect(json.userKey).toBe(`${Urls.personServer}|${directedSubject(Urls.calendar)}`);
  expect(json.scope).toEqual(['calendar.read']);
  expect(json.iss).toBe(Urls.personServer);
  expect(json).not.toHaveProperty('agent');
  expect(json).not.toHaveProperty('act');
});
