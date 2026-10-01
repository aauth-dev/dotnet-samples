import { APIRequestContext, Page, expect } from '@playwright/test';
import { Agents, Urls } from './agents';
import { createHash } from 'node:crypto';
import { decideHighlighted, isDashboard, signInToDashboard } from './dashboard';

export function directedSubject(resource: string): string {
  return createHash('sha256').update('isolated-demo-person\0' + resource).digest('hex');
}

export async function approvePersonConsent(page: Page, selector: string): Promise<void> {
  const link = page.locator(selector);
  await expect(link).toBeVisible({ timeout: 30_000 });
  const [popup] = await Promise.all([page.context().waitForEvent('page'), link.click()]);
  await authenticateConsent(popup);
  await expect(popup.locator('.badge')).toContainText('Person Server');
  await approveInPopup(popup);
  await popup.close();
}

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
 * the Concierge's `concierge` scope on the first call-chain hop).
 */
export async function grantConsent(
  request: APIRequestContext,
  agent: string,
  resource: string,
  scope?: string,
): Promise<void> {
  const data: Record<string, string> = { agent, resource: resource.replace(/\/$/, '') };
  const issuers: Record<string, string> = {
    [Agents.sampleApp]: 'http://localhost:5240',
    [Agents.tour]: 'http://localhost:5400',
    'aauth:concierge@localhost': Urls.concierge,
  };
  const issuer = issuers[agent];
  if (!issuer) throw new Error(`No explicit development issuer for ${agent}`);
  const keys = await (await request.get(`${issuer}/.well-known/jwks.json`)).json();
  const key = keys.keys[0];
  const canonical = key.kty === 'EC'
    ? { crv: key.crv, kty: key.kty, x: key.x, y: key.y }
    : { crv: key.crv, kty: key.kty, x: key.x };
  data.key = createHash('sha256').update(JSON.stringify(canonical)).digest('base64url');
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

/** Explicit approve/deny helpers expect the dashboard link to name a decidable request. */
function requireDecision(decided: boolean): void {
  if (!decided) throw new Error('The dashboard link named a request with nothing to decide.');
}

/** On the PS interaction popup (or the PS dashboard it deep-linked to), approve. */
export async function approveInPopup(popup: Page): Promise<void> {
  if (await isDashboard(popup)) return requireDecision(await decideHighlighted(popup, 'approve'));
  await authenticateConsent(popup);
  await popup.locator('button.approve').click();
  await popup.getByText('Approved', { exact: false }).first().waitFor();
}

/** On the PS interaction popup (or the PS dashboard it deep-linked to), deny. */
export async function denyInPopup(popup: Page): Promise<void> {
  if (await isDashboard(popup)) return requireDecision(await decideHighlighted(popup, 'deny'));
  await authenticateConsent(popup);
  await popup.locator('button.deny').click();
  await popup.getByText('Denied', { exact: false }).first().waitFor();
}

export async function authenticateConsent(popup: Page): Promise<void> {
  if (await isDashboard(popup)) return signInToDashboard(popup);
  let state = 'pending';
  await expect.poll(async () => {
    if (await popup.locator('button.demo-login, button.approve').first().isVisible()) return state = 'ready';
    const body = await popup.locator('body').innerText().catch(() => '');
    if (/"error"\s*:\s*"[^"]+"/.test(body)) return state = `error:${body}`;
    return state = 'pending';
  }, { timeout: 30_000 }).not.toBe('pending');
  if (state.startsWith('error:'))
    throw new Error(`Consent endpoint rejected ${popup.url()}: ${state.slice('error:'.length)}`);
  const login = popup.locator('button.demo-login');
  if (await login.isVisible()) await login.click();
  await expect(popup).toHaveURL(/\?session=/);
  await expect(popup.locator('input[name="session"]').first()).toHaveValue(/.+/);
  await expect(popup.locator('input[name="csrf"]').first()).toHaveValue(/.+/);
  await expect(popup.locator('input[name="code"]')).toHaveCount(0);
}

/**
 * Complete a Keycloak login on the four-party (federated) interaction popup.
 *
 * In federated mode the surfaced interaction URL is the Access Server's
 * login-start endpoint, which 302-redirects to the Keycloak OIDC login form.
 * The realm ships two demo users (samples/MockAccessServers/Federated/keycloak):
 *   demo / demo   → has the `wallet.payer` role (full access)
 *   guest / guest → no admin role (limited access)
 * After login Keycloak may render a consent/grant screen; approve it if shown.
 */
export async function keycloakLogin(
  popup: Page,
  username = 'demo',
  password = 'demo',
  approve = true,
): Promise<void> {
  for (let transition = 0; transition < 4; transition++) {
    let state = 'pending';
    await expect.poll(async () => {
      if (await popup.getByRole('heading', { name: 'Access granted', exact: true }).isVisible()) return state = 'granted';
      if (await popup.getByRole('heading', { name: 'Access denied', exact: true }).isVisible()) return state = 'denied';
      if (await popup.getByRole('heading', { name: 'Login error', exact: true }).isVisible()) return state = 'error';
      if (await popup.locator('#username').isVisible()) return state = 'login';
      if (await popup.locator('button[name="accept"], input[name="accept"]').isVisible()) return state = 'consent';
      return state = 'pending';
    }, { timeout: 30_000 }).not.toBe('pending');
    if (state === 'granted' || state === 'denied') {
      expect(state).toBe(approve ? 'granted' : 'denied');
      await expect(popup).toHaveURL(/^http:\/\/localhost:5500\/interaction\/callback\?/);
      await expect(popup.locator('.badge')).toContainText('Access Server');
      return;
    }
    if (state === 'error') throw new Error('The Keycloak policy callback failed.');
    if (state === 'login') {
      await popup.locator('#username').fill(username);
      await popup.locator('#password').fill(password);
      await popup.locator('#kc-login').click();
      await expect(popup.locator('#username')).toHaveCount(0);
    } else {
      const decision = approve ? 'accept' : 'cancel';
      await popup.locator(`button[name="${decision}"], input[name="${decision}"]`).click();
      await expect(popup.locator('button[name="accept"], input[name="accept"]')).toHaveCount(0);
    }
  }
  throw new Error('Keycloak did not complete its login/consent callback.');
}

export async function decideAccessConsent(popup: Page, approve = true): Promise<void> {
  if (process.env.KEYCLOAK_E2E === '1') {
    await keycloakLogin(popup, 'demo', 'demo', approve);
    return;
  }
  await authenticateConsent(popup);
  await expect(popup.locator('.badge')).toContainText('Access Server');
  if (approve) await approveInPopup(popup);
  else await denyInPopup(popup);
}
