import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';
import { grantConsent, approveInPopup, directedSubject } from '../../../tests/e2e/helpers/consent';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';
import { CONSENT_ACTION } from '../../../tests/e2e/helpers/dashboard';

/**
 * Call Chain — multi-hop delegation Agent → Concierge → Calendar, asserting the
 * page RESETS standing consent so BOTH hops always surface their own approval.
 *
 * We deliberately pre-grant consent for both hops. The page's SendChainedRequest
 * POSTs `/admin/reset` before running, so the grants are wiped and the user must
 * still approve hop 1 (Agent → Concierge) and hop 2 (the Concierge's chained
 * Concierge → Calendar). This guards the bug where a prior run — or the Guided
 * Tour's call-chain flow — left the Concierge-keyed hop-2 consent
 * (`Concierge → Calendar`, independent of the calling agent) in place and
 * silently skipped the second approval. Needs PS + AP + Concierge + Calendar.
 */
test.describe.configure({ timeout: 180_000 });

test.beforeEach(async ({ request }) => {
  // Pre-grant BOTH hops; the page must reset these so each hop still prompts.
  await grantConsent(request, Agents.sampleApp, Urls.concierge, 'concierge');
  await grantConsent(request, 'aauth:concierge@localhost', Urls.calendar);
});

test('the page resets standing consent so both hops still prompt', async ({ page, context }) => {
  await page.goto('/call-chain');
  await expect(page.locator('h2')).toContainText('Call Chain');
  await waitForInteractive(page, 'button.btn-primary');

  const link = page.locator(CONSENT_ACTION);
  const heading = page.locator('.alert .badge', { hasText: /Approval/ });

  // First click on a cold circuit can be dropped — confirm hop 1 surfaced. The
  // reset wiped the pre-granted consent, so hop 1 MUST prompt.
  await clickAndConfirm(page, 'button.btn-primary', () => link.isVisible());

  // --- Hop 1: Agent → Concierge (concierge) ---
  await expect(heading).toContainText('Approval 1 of 2', { timeout: 30_000 });
  await expect(link).toBeVisible({ timeout: 30_000 });
  const [popup1] = await Promise.all([
    context.waitForEvent('page'),
    link.click(),
  ]);
  await approveInPopup(popup1);

  // --- Hop 2: Concierge → Calendar (calendar.read, chained) ---
  // This is the hop the bug skipped: its consent is keyed by the Concierge, so a
  // pre-existing grant would have resolved silently without the reset.
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

  // Upstream: how *we* (the calling agent) authenticated to the Concierge. The
  // auth token names the person (ps, sub directed at the Concierge), not us.
  const upstream = json.upstream as Record<string, unknown>;
  expect(upstream.scheme).toBe('jwt');
  expect(upstream.ps).toBe(Urls.personServer);
  expect(upstream.sub).toBe(directedSubject(Urls.concierge));
  expect(upstream).not.toHaveProperty('agent');
  // The token type renders as its protocol `typ` string, not the enum's integer.
  expect(upstream.tokenType).toBe('aa-auth+jwt');

  // Concierge: the intermediary's own identity.
  const concierge = json.concierge as Record<string, unknown>;
  expect(concierge.identity).toBe('aauth:concierge@localhost');

  // Downstream: Calendar's three-party identity. The chain keeps the same PS but
  // the PS mints a fresh directed sub for the Calendar (§Directed Identifiers
  // Across a Chain); there is no act chain and no agent claim.
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
});
