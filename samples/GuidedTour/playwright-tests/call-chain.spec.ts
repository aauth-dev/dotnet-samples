import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import {
  openTour,
  selectFlow,
  runAll,
  selectStep,
  expectResponse,
  readResponseJson,
  doneSteps,
  TourMode,
} from '../../../tests/e2e/helpers/tour';
import { approveInPopup } from '../../../tests/e2e/helpers/consent';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Call Chain — multi-agent delegation Agent → Concierge → Calendar with two
 * human approvals, 13 steps. The tour wipes the PS consent store on init
 * (PrepareConsentStateAsync), so BOTH hops surface their own interaction:
 *
 *   1. Agent → Concierge: POST /token returns 202; the user approves at the
 *      PS consent page and the agent polls the PS pending URL for the
 *      Concierge-audience auth_token.
 *   2. Concierge → Calendar: the agent retries the Concierge, which drives
 *      its own downstream exchange, hits the SAME no-consent wall, and re-emits
 *      a chained 202 pointing at its OWN pending URL. The user approves the
 *      second hop at the PS and the agent polls the Concierge pending URL for
 *      the combined 200.
 *
 * The internal Concierge → PS → Calendar hops are shown as grouped sub-steps,
 * never as separate agent-visible steps. The final poll renders the combined
 * 200 with a three-party downstream identity and a nested `act` delegation
 * chain. Generous timeout covers two poll loops.
 */
test.describe('Call Chain (Guided Tour)', () => {
  test.describe.configure({ timeout: 180_000 });

  test('two approvals replay through the concierge to a three-party 200', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.CallChain);

    await runAll(page);

    // Hop 1 — parked on the Agent → Concierge approval (6 steps done).
    const hop1Link = page.locator('a.primary.approve');
    await expect(hop1Link).toBeVisible();
    const [hop1Popup] = await Promise.all([
      context.waitForEvent('page'),
      hop1Link.click(),
    ]);
    await approveInPopup(hop1Popup);

    // The background poll resolves the Concierge-audience auth_token (8 of
    // 13 steps done: user-approval + poll).
    await expect(doneSteps(page)).toHaveCount(8, { timeout: 120_000 });

    // "Run all" advances the hop-2 retry (the Concierge re-emits its own
    // 202) and the direct-user step, then parks on the second approval.
    await runAll(page);

    // Hop 2 — parked on the Concierge → Calendar approval (10 steps done).
    const hop2Link = page.locator('a.primary.approve');
    await expect(hop2Link).toBeVisible();
    const [hop2Popup] = await Promise.all([
      context.waitForEvent('page'),
      hop2Link.click(),
    ]);
    await approveInPopup(hop2Popup);

    // The background poll of the Concierge pending URL resolves the chained
    // 200 (12 of 13 steps done: user-approval + poll).
    await expect(doneSteps(page)).toHaveCount(12, { timeout: 120_000 });

    // The final inspect step still needs an explicit "Run all" click.
    await runAll(page);
    await expect(doneSteps(page)).toHaveCount(13, { timeout: 30_000 });

    // Step 12 ("Poll Concierge pending → 200") holds the combined result:
    // a three-party downstream identity with a nested act chain.
    await selectStep(page, 11);
    await expectResponse(page, 200, ['three-party', 'act']);

    const json = (await readResponseJson(page)) as Record<string, unknown>;

    // Upstream: how the tour agent authenticated to the Concierge.
    const upstream = json.upstream as Record<string, unknown>;
    expect(upstream.agent).toBe(Agents.tour);

    // Concierge: the intermediary's own identity.
    const concierge = json.concierge as Record<string, unknown>;
    expect(concierge.identity).toBe('aauth:concierge@localhost:5200');

    // Downstream: Calendar's three-party identity with the nested act chain.
    const downstream = json.downstream as Record<string, unknown>;
    expect(downstream.accessMode).toBe('three-party');
    expect(downstream.scheme).toBe('jwt');
    expect(downstream.agent).toBe('aauth:concierge@localhost:5200');
    expect(downstream.sub).toBe('pairwise-sub');
    expect(downstream.scope).toEqual(['calendar.read']);
    expect(downstream.iss).toBe(Urls.personServer);

    // The act chain proves the full delegation path:
    //   act.sub      = the Concierge (immediate actor)
    //   act.act.sub  = the original calling agent (the tour agent)
    const act = downstream.act as Record<string, unknown>;
    expect(act.sub).toBe('aauth:concierge@localhost:5200');
    const innerAct = act.act as Record<string, unknown>;
    expect(innerAct.sub).toBe(Agents.tour);

    // Step 13 ("Inspect multi-agent chain result") renders the decoded chain
    // summary showing the full Agent → Concierge → Calendar delegation.
    await selectStep(page, 12);
    await expect(
      page.locator('section.payload article.inspector details.token pre code'),
    ).toContainText('Call Chain Summary');
  });
});
