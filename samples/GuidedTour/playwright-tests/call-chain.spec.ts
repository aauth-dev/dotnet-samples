import { test, expect } from '@playwright/test';
import {
  openTour,
  selectFlow,
  runAll,
  selectStep,
  expectResponse,
  readResponseJson,
  TourMode,
} from '../../../tests/e2e/helpers/tour';
import { grantConsent } from '../../../tests/e2e/helpers/consent';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Call Chain — multi-agent delegation Agent → Orchestrator → WhoAmI, 7 steps,
 * no human. The tour self-seeds hop-1 consent (tour-agent → Orchestrator) via
 * PrepareConsentStateAsync; this spec also pre-grants hop-2 (Orchestrator →
 * WhoAmI) so the Orchestrator's downstream chaining mints immediately. The
 * retry step renders the combined 200 with a three-party downstream identity,
 * and the inspect step surfaces the nested `act` delegation chain.
 */
test.describe.configure({ timeout: 90_000 });

test.beforeEach(async ({ request }) => {
  // Hop 2: the Orchestrator chains downstream to WhoAmI on the user's behalf.
  await grantConsent(request, 'aauth:orchestrator@localhost:5200', Urls.whoami);
});

test('call chain replays through the orchestrator to a three-party 200', async ({ page }) => {
  await openTour(page);
  await selectFlow(page, TourMode.CallChain);

  await runAll(page);

  // Step 6 ("Retry Orchestrator with auth_token → 200") holds the combined
  // resource result: a three-party downstream identity with a nested act chain.
  await selectStep(page, 5);
  await expectResponse(page, 200, ['three-party', 'act']);

  const json = (await readResponseJson(page)) as Record<string, unknown>;

  // Upstream: how the tour agent authenticated to the Orchestrator.
  const upstream = json.upstream as Record<string, unknown>;
  expect(upstream.agent).toBe(Agents.tour);

  // Orchestrator: the intermediary's own identity.
  const orchestrator = json.orchestrator as Record<string, unknown>;
  expect(orchestrator.identity).toBe('aauth:orchestrator@localhost:5200');

  // Downstream: WhoAmI's three-party identity with the nested act chain.
  const downstream = json.downstream as Record<string, unknown>;
  expect(downstream.mode).toBe('three-party');
  expect(downstream.scheme).toBe('jwt');
  expect(downstream.agent).toBe('aauth:orchestrator@localhost:5200');
  expect(downstream.sub).toBe('pairwise-sub');
  expect(downstream.scope).toEqual(['whoami']);
  expect(downstream.iss).toBe(Urls.personServer);

  // The act chain proves the full delegation path:
  //   act.sub      = the Orchestrator (immediate actor)
  //   act.act.sub  = the original calling agent (the tour agent)
  const act = downstream.act as Record<string, unknown>;
  expect(act.sub).toBe('aauth:orchestrator@localhost:5200');
  const innerAct = act.act as Record<string, unknown>;
  expect(innerAct.sub).toBe(Agents.tour);

  // Step 7 ("Inspect multi-agent chain result") renders the decoded chain
  // summary showing the full Agent → Orchestrator → WhoAmI delegation.
  await selectStep(page, 6);
  await expect(
    page.locator('section.payload article.inspector details.token pre code'),
  ).toContainText('Call Chain Summary');
});
