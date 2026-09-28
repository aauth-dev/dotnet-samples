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
import { Urls } from '../../../tests/e2e/helpers/agents';
import { directedSubject } from '../../../tests/e2e/helpers/consent';

/**
 * Call Chain — multi-agent delegation Agent → Concierge → Calendar with two
 * human approvals, 15 steps. The agent first meets the Concierge's
 * requirement=person-token, gets a person token directed at the Concierge and
 * presents it for a resource token. The tour wipes the PS consent store on init
 * (PrepareConsentStateAsync), so BOTH hops surface their own interaction:
 *
 *   1. Agent → Concierge: POST /token returns 202; the user approves at the
 *      PS consent page and the agent polls the PS pending URL for the
 *      Concierge-audience auth_token.
 *   2. Concierge → Calendar: the agent retries the Concierge, which requests
 *      its own Calendar person token and auth token with our auth token as
 *      upstream_token, hits the SAME no-consent wall, and re-emits a chained
 *      202 pointing at its OWN pending URL. The user approves the second hop
 *      at the PS and the agent polls the Concierge pending URL for the
 *      combined 200.
 *
 * The internal Concierge → PS → Calendar hops are shown as grouped sub-steps,
 * never as separate agent-visible steps. The final poll renders the combined
 * 200: both grants name the same person's PS with a sub directed at each
 * resource, and neither carries an agent or act claim. Generous timeout covers
 * two poll loops.
 */
test.describe('Call Chain (Guided Tour)', () => {
  test.describe.configure({ timeout: 180_000 });

  test('two approvals replay through the concierge to a three-party 200', async ({ page, context }) => {
    await openTour(page);
    await selectFlow(page, TourMode.CallChain);

    await runAll(page);

    // Hop 1 — parked on the Agent → Concierge approval (8 steps done).
    const hop1Link = page.locator('a.primary.approve');
    await expect(hop1Link).toBeVisible();
    await expect(doneSteps(page)).toHaveCount(8);
    const [hop1Popup] = await Promise.all([
      context.waitForEvent('page'),
      hop1Link.click(),
    ]);
    await approveInPopup(hop1Popup);

    // The background poll resolves the Concierge-audience auth_token (10 of
    // 15 steps done: user-approval + poll).
    await expect(doneSteps(page)).toHaveCount(10, { timeout: 120_000 });

    // "Run all" advances the hop-2 retry (the Concierge re-emits its own
    // 202) and the direct-user step, then parks on the second approval.
    await runAll(page);

    // Hop 2 — parked on the Concierge → Calendar approval (12 steps done).
    const hop2Link = page.locator('a.primary.approve');
    await expect(hop2Link).toBeVisible();
    await expect(doneSteps(page)).toHaveCount(12);
    const [hop2Popup] = await Promise.all([
      context.waitForEvent('page'),
      hop2Link.click(),
    ]);
    await approveInPopup(hop2Popup);

    // The background poll of the Concierge pending URL resolves the chained
    // 200 (14 of 15 steps done: user-approval + poll).
    await expect(doneSteps(page)).toHaveCount(14, { timeout: 120_000 });

    // The final inspect step still needs an explicit "Run all" click.
    await runAll(page);
    await expect(doneSteps(page)).toHaveCount(15, { timeout: 30_000 });

    // Step 14 ("Poll Concierge pending → 200") holds the combined result.
    await selectStep(page, 13);
    await expectResponse(page, 200, ['three-party']);

    const json = (await readResponseJson(page)) as Record<string, unknown>;

    // Upstream: the auth token we presented names the person at the Concierge.
    const upstream = json.upstream as Record<string, unknown>;
    expect(upstream.ps).toBe(Urls.personServer);
    expect(upstream.sub).toBe(directedSubject(Urls.concierge));
    expect(upstream).not.toHaveProperty('agent');
    expect(upstream.tokenType).toBe('aa-auth+jwt');

    // Concierge: the intermediary's own identity.
    const concierge = json.concierge as Record<string, unknown>;
    expect(concierge.identity).toBe('aauth:concierge@localhost');

    // Downstream: Calendar's three-party identity. Same PS, but the PS directs
    // a fresh sub at the Calendar (§Directed Identifiers Across a Chain).
    const downstream = json.downstream as Record<string, unknown>;
    expect(downstream.accessMode).toBe('three-party');
    expect(downstream.scheme).toBe('jwt');
    expect(downstream.iss).toBe(Urls.personServer);
    expect(downstream.ps).toBe(upstream.ps);
    expect(downstream.sub).toBe(directedSubject(Urls.calendar));
    expect(downstream.sub).not.toBe(upstream.sub);
    expect(downstream.scope).toEqual(['calendar.read']);
    expect(downstream).not.toHaveProperty('agent');
    expect(downstream).not.toHaveProperty('act');

    // Step 15 ("Inspect multi-agent chain result") renders the decoded chain
    // summary: both hops name the same ps with their own directed sub.
    await selectStep(page, 14);
    const summary = page.locator('section.payload article.inspector details.token pre code');
    await expect(summary).toContainText('Call Chain Summary');
    await expect(summary).toContainText(directedSubject(Urls.concierge));
    await expect(summary).toContainText(directedSubject(Urls.calendar));
  });
});
