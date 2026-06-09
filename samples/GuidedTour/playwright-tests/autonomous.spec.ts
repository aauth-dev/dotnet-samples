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
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

/**
 * PS-Asserted (Direct Grant) — autonomous three-party flow, 6 steps, no human.
 * The agent has standing consent at the Person Server (the page pre-seeds it via
 * PrepareConsentStateAsync), so POST /token returns an auth_token immediately and
 * the replayed GET / returns 200 with a three-party identity. Assert the actual
 * 200 result and the full claim set on the final step.
 */
test.describe.configure({ timeout: 60_000 });

test('autonomous flow exchanges and replays to a three-party 200', async ({ page }) => {
  await openTour(page);
  await selectFlow(page, TourMode.Autonomous);

  await runAll(page);

  // Step 6 ("Replay GET /events with auth_token") is the resource result.
  await selectStep(page, 5);
  await expectResponse(page, 200, ['three-party']);

  const json = (await readResponseJson(page)) as Record<string, unknown>;
  expect(json.accessMode).toBe('three-party');
  expect(json.scheme).toBe('jwt');
  expect(json.agent).toBe(Agents.tour);
  expect(json.sub).toBe('pairwise-sub');
  expect(json.scope).toEqual(['calendar.read']);
  expect(json.iss).toBe(Urls.personServer);
  // Standing-consent single-hop grant — act names the tour agent, no nesting.
  const act = json.act as Record<string, unknown>;
  expect(act.sub).toBe(Agents.tour);
  expect(act.act).toBeUndefined();
});
