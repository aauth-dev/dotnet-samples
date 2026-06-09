import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus, expectError } from '../../../tests/e2e/helpers/json';
import { approveInPopup, denyInPopup } from '../../../tests/e2e/helpers/consent';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Call Chain (deferred) — genuine Interaction Chaining with two human consent
 * hops. The global fixture wipes consent, so NOTHING is pre-granted:
 *
 *   Hop 1: Agent → Orchestrator. The PS returns 202; the SDK surfaces the
 *          consent URL via WithChallengeHandling. The user approves.
 *   Hop 2: Orchestrator → Calendar. The Orchestrator's downstream client throws
 *          AAuthInteractionChainedException, so the Orchestrator parks the
 *          flow and re-emits its OWN 202 to the agent. The agent's top-level
 *          InteractionHandler (WithInteractionHandling) surfaces the second
 *          consent URL. The user approves again, and the chain resolves to a
 *          200 with the full nested `act` delegation chain.
 *
 * Needs PS + AP + Orchestrator + Calendar. Extended timeout for the two poll
 * loops.
 */
test.describe('Call Chain (deferred)', () => {
  test.describe.configure({ timeout: 180_000 });

  test('two interactive consent hops resolve to a nested act chain', async ({ page, context }) => {
    await page.goto('/call-chain');
    await expect(page.locator('h2')).toContainText('Call Chain');
    await waitForInteractive(page, 'button.btn-primary');

    const link = page.locator('a[target="_blank"]', { hasText: /interaction/ });
    const heading = page.locator('.alert .badge', { hasText: /Approval/ });

    // First click on a cold circuit can be dropped — confirm hop 1 surfaced.
    await clickAndConfirm(page, 'button.btn-primary', () => link.isVisible());

    // --- Hop 1: Agent → Orchestrator (orchestrate) ---
    await expect(heading).toContainText('Approval 1 of 2', { timeout: 30_000 });
    await expect(link).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('.spinner-border')).toBeVisible();

    const [popup1] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await approveInPopup(popup1);

    // --- Hop 2: Orchestrator → Calendar (calendar.read, chained) ---
    await expect(heading).toContainText('Approval 2 of 2', { timeout: 60_000 });
    await expect(link).toBeVisible({ timeout: 30_000 });

    const [popup2] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await approveInPopup(popup2);

    // --- Chain resolves ---
    await expectStatus(page, 200, 60_000);
    const json = (await readResponseJson(page)) as Record<string, unknown>;

    // Upstream: how the calling agent authenticated to the Orchestrator.
    const upstream = json.upstream as Record<string, unknown>;
    expect(upstream.scheme).toBe('jwt');
    expect(upstream.agent).toBe(Agents.sampleApp);

    // Orchestrator: the intermediary's own identity.
    const orchestrator = json.orchestrator as Record<string, unknown>;
    expect(orchestrator.identity).toBe('aauth:orchestrator@localhost:5200');

    // Downstream: Calendar's three-party identity with the nested act chain.
    const downstream = json.downstream as Record<string, unknown>;
    expect(downstream.accessMode).toBe('three-party');
    expect(downstream.scheme).toBe('jwt');
    expect(downstream.agent).toBe('aauth:orchestrator@localhost:5200');
    expect(downstream.iss).toBe(Urls.personServer);
    expect(downstream.scope).toEqual(['calendar.read']);

    // act.sub = the Orchestrator; act.act.sub = the original calling agent.
    const act = downstream.act as Record<string, unknown>;
    expect(act.sub).toBe('aauth:orchestrator@localhost:5200');
    const innerAct = act.act as Record<string, unknown>;
    expect(innerAct.sub).toBe(Agents.sampleApp);

    // Both hops should be recorded as approved.
    await expect(page.locator('text=Approved:')).toContainText('Hop 1');
    await expect(page.locator('text=Approved:')).toContainText('Hop 2');
  });

  test('denying the first hop surfaces an access-denied error', async ({ page, context }) => {
    await page.goto('/call-chain');
    await waitForInteractive(page, 'button.btn-primary');

    const link = page.locator('a[target="_blank"]', { hasText: /interaction/ });
    const heading = page.locator('.alert .badge', { hasText: /Approval/ });

    await clickAndConfirm(page, 'button.btn-primary', () => link.isVisible());
    await expect(heading).toContainText('Approval 1 of 2', { timeout: 30_000 });
    await expect(link).toBeVisible({ timeout: 30_000 });

    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await denyInPopup(popup);

    await expectError(page, 'denied');
  });
});
