import { APIRequestContext, Page } from '@playwright/test';
import { Urls } from './agents';

/**
 * MockPersonServer consent control helpers.
 *
 * The PS exposes demo-only unauthenticated admin endpoints to flip consent
 * deterministically (see samples/MockPersonServer/Program.cs):
 *   POST /admin/consent  { agent, resource, scope? }  → grant standing consent
 *   POST /admin/reset                                  → wipe all consent/pending
 *
 * The user-facing consent page lives at GET /interaction?code={id} and renders
 * two forms with button.approve / button.deny.
 */

/**
 * Grant standing consent for (agent, resource[, scope]) so /token issues
 * immediately. The PS keys consent by (agent, resource, scope); pass `scope`
 * when the resource requires something other than the default `calendar.read` (e.g.
 * the Orchestrator's `orchestrate` scope on the first call-chain hop).
 */
export async function grantConsent(
  request: APIRequestContext,
  agent: string,
  resource: string,
  scope?: string,
): Promise<void> {
  const data: Record<string, string> = { agent, resource: resource.replace(/\/$/, '') };
  if (scope) {
    data.scope = scope;
  }
  const res = await request.post(`${Urls.personServer}/admin/consent`, {
    data,
  });
  if (!res.ok()) {
    throw new Error(
      `grantConsent failed: ${res.status()} ${res.statusText()} — ${await res.text()}`,
    );
  }
}

/**
 * Reset the PS to an empty baseline (no standing consent, no pending
 * interactions). Call from a global beforeEach so each spec is hermetic
 * regardless of order or what a previous spec granted.
 */
export async function resetConsent(request: APIRequestContext): Promise<void> {
  const res = await request.post(`${Urls.personServer}/admin/reset`);
  if (!res.ok()) {
    throw new Error(
      `resetConsent failed: ${res.status()} ${res.statusText()} — ${await res.text()}`,
    );
  }
}

/** On the PS interaction popup, click Approve. */
export async function approveInPopup(popup: Page): Promise<void> {
  await popup.locator('button.approve').click();
  await popup.getByText('Approved', { exact: false }).first().waitFor();
}

/** On the PS interaction popup, click Deny. */
export async function denyInPopup(popup: Page): Promise<void> {
  await popup.locator('button.deny').click();
  await popup.getByText('Denied', { exact: false }).first().waitFor();
}

/**
 * Complete a Keycloak login on the four-party (federated) interaction popup.
 *
 * In federated mode the surfaced interaction URL is the Access Server's
 * login-start endpoint, which 302-redirects to the Keycloak OIDC login form.
 * The realm ships two demo users (samples/MockAccessServer/keycloak):
 *   demo / demo   → has the `wallet.payer` role (full access)
 *   guest / guest → no admin role (limited access)
 * After login Keycloak may render a consent/grant screen; approve it if shown.
 */
export async function keycloakLogin(
  popup: Page,
  username = 'demo',
  password = 'demo',
): Promise<void> {
  await popup.locator('#username').waitFor({ timeout: 30_000 });
  await popup.locator('#username').fill(username);
  await popup.locator('#password').fill(password);
  await popup.locator('#kc-login, input[type="submit"]').first().click();

  // Optional OAuth consent/grant screen.
  const grant = popup.locator('#kc-login, input[name="accept"]');
  if (await grant.first().isVisible().catch(() => false)) {
    await grant.first().click();
  }
}
