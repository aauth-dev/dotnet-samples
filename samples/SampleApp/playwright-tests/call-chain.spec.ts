import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';
import { grantConsent } from '../../../tests/e2e/helpers/consent';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Call Chain — multi-hop delegation Agent → Concierge → Calendar. The test
 * pre-grants consent at the PS for both hops, then a single chained GET → 200
 * with a nested `act` delegation chain. Needs PS + AP + Concierge + Calendar.
 *
 * This is the first interactive test in the SampleApp suite to click the
 * `/call-chain` button, so it is exposed to the Blazor cold-circuit
 * first-click drop (the freshly connected SignalR circuit can silently discard
 * the very first event even after the button reports enabled). We use
 * `clickAndConfirm` to re-click until the page reflects the request, then
 * assert the rendered 200 status and the nested `act` chain in the payload.
 */
test.describe.configure({ timeout: 60_000 });

test.beforeEach(async ({ request }) => {
  // Hop 1 (agent → Concierge) needs the Concierge's `concierge` scope;
  // hop 2 (Concierge → Calendar) needs the default `calendar.read` scope.
  await grantConsent(request, Agents.sampleApp, Urls.concierge, 'concierge');
  await grantConsent(request, 'aauth:concierge@localhost:5200', Urls.calendar);
});

test('call chain returns a nested act delegation chain', async ({ page }) => {
  await page.goto('/call-chain');
  await expect(page.locator('h2')).toContainText('Call Chain');
  await waitForInteractive(page, 'button.btn-primary');

  // The first click on a cold circuit can be dropped — confirm the handler
  // actually fired (button enters "Sending…" or a result/error renders).
  await clickAndConfirm(page, 'button.btn-primary', async () => {
    const sending = await page
      .locator('button.btn-primary', { hasText: 'Sending' })
      .isVisible()
      .catch(() => false);
    const done = await page
      .locator('pre code.language-json')
      .first()
      .isVisible()
      .catch(() => false);
    const err = await page
      .locator('div.alert.alert-danger')
      .isVisible()
      .catch(() => false);
    return sending || done || err;
  });

  await expectStatus(page, 200, 30_000);
  const json = (await readResponseJson(page)) as Record<string, unknown>;

  // Upstream: how *we* (the calling agent) authenticated to the Concierge.
  const upstream = json.upstream as Record<string, unknown>;
  expect(upstream.scheme).toBe('jwt');
  expect(upstream.agent).toBe(Agents.sampleApp);

  // Concierge: the intermediary's own identity + what it did.
  const concierge = json.concierge as Record<string, unknown>;
  expect(concierge.identity).toBe('aauth:concierge@localhost:5200');

  // Downstream: Calendar's three-party identity with the nested act chain.
  const downstream = json.downstream as Record<string, unknown>;
  expect(downstream.accessMode).toBe('three-party');
  expect(downstream.scheme).toBe('jwt');
  // The resource sees the Concierge as the immediate actor.
  expect(downstream.agent).toBe('aauth:concierge@localhost:5200');
  expect(downstream.iss).toBe(Urls.personServer);
  expect(downstream.scope).toEqual(['calendar.read']);

  // The act chain proves the full delegation path end to end:
  //   act.sub      = the Concierge (immediate actor)
  //   act.act.sub  = the original calling agent (us)
  const act = downstream.act as Record<string, unknown>;
  expect(act.sub).toBe('aauth:concierge@localhost:5200');
  const innerAct = act.act as Record<string, unknown>;
  expect(innerAct.sub).toBe(Agents.sampleApp);
});
