import { BrowserContext, Page, expect } from '@playwright/test';
import { Urls } from './agents';

/**
 * PS consent dashboard helpers (samples/MockPersonServer/ConsentDashboard.cs).
 *
 * The dashboard lists every PS consent request for the signed-in demo person
 * and decides them out-of-band. The agent keeps polling; the decision reaches
 * it on its next poll, and the per-request link stops working.
 */

export interface DashboardMatch {
  agent?: string;
  /** Prefix match, so a trailing slash does not matter. */
  resource?: string;
  scope?: string;
  mission?: string;
}

const dashboards = new WeakMap<BrowserContext, Page>();

/**
 * The primary action of the shared agent-side prompt (samples/ConsentSupport):
 * the PS dashboard for PS-hosted consent, otherwise the Access Server or
 * resource page.
 */
export const CONSENT_ACTION = '[data-consent-prompt] :is(a.ps-dashboard, a.ps-external-link)';

/** The prompt's secondary per-request link (PS-hosted consent only). */
export const CONSENT_DIRECT_LINK = '[data-consent-prompt] a.ps-direct-link';

/** Whether a popup opened from a consent prompt is the PS dashboard. */
export async function isDashboard(popup: Page): Promise<boolean> {
  await popup.waitForLoadState('domcontentloaded');
  return new URL(popup.url()).pathname === '/dashboard';
}

/** Sign in to a dashboard tab if its sign-in form is showing. */
export async function signInToDashboard(page: Page): Promise<void> {
  const signIn = page.locator('button.demo-login');
  const heading = page.getByRole('heading', { name: 'Consent requests', exact: true });
  await expect(signIn.or(heading).first()).toBeVisible({ timeout: 30_000 });
  if (await signIn.isVisible()) await signIn.click();
  await expect(heading).toBeVisible();
}

/**
 * Decide the request a prompt deep-linked to (the `?code=` highlight) on a
 * dashboard popup, then close it so the next prompt opens a fresh tab. A link
 * with nothing to decide (a four-party request the Access Server is working
 * on) shows the settled note instead; that is returned as `false`.
 */
export async function decideHighlighted(popup: Page, action: 'approve' | 'deny'): Promise<boolean> {
  await signInToDashboard(popup);
  const card = popup.locator('#pending article.card.highlight');
  let state = 'wait';
  await expect.poll(async () => {
    if (await card.locator('button.' + action).isVisible()) return state = 'decide';
    if (await popup.locator('#settled').isVisible()) return state = 'settled';
    return state = 'wait';
  }, { timeout: 30_000 }).not.toBe('wait');
  if (state === 'settled') {
    await popup.close();
    return false;
  }
  const id = await card.getAttribute('data-id');
  await popup.locator(`#pending article.card[data-id=${JSON.stringify(id)}] button.${action}`).click();
  await expect(popup.locator(`#history article.card[data-id=${JSON.stringify(id)}]`)).toBeVisible();
  await popup.close();
  return true;
}

/** Open (or reuse) this context's dashboard tab, signing in once per context. */
export async function openDashboard(context: BrowserContext, code?: string): Promise<Page> {
  let page = dashboards.get(context);
  if (!page || page.isClosed()) {
    page = await context.newPage();
    dashboards.set(context, page);
  }
  const url = `${Urls.personServer}/dashboard${code ? '?code=' + encodeURIComponent(code) : ''}`;
  if (page.url() !== url) await page.goto(url);
  await signInToDashboard(page);
  return page;
}

function cardSelector(section: 'pending' | 'history', match: DashboardMatch): string {
  const quote = (value: string) => JSON.stringify(value);
  let selector = `#${section} article.card`;
  if (match.agent) selector += `[data-agent=${quote(match.agent)}]`;
  if (match.resource) selector += `[data-resource^=${quote(match.resource.replace(/\/$/, ''))}]`;
  if (match.scope) selector += `[data-scope=${quote(match.scope)}]`;
  if (match.mission) selector += `[data-mission=${quote(match.mission)}]`;
  return selector;
}

async function decideOnDashboard(
  context: BrowserContext,
  match: DashboardMatch,
  action: 'approve' | 'deny',
  timeout: number,
): Promise<Page> {
  const page = await openDashboard(context);
  const card = page.locator(cardSelector('pending', match)).first();
  await expect(card.locator('button.' + action)).toBeVisible({ timeout });
  const id = await card.getAttribute('data-id');
  await page.locator(`#pending article.card[data-id=${JSON.stringify(id)}] button.${action}`).click();
  await expect(page.locator(`#history article.card[data-id=${JSON.stringify(id)}]`)).toBeVisible();
  return page;
}

/** Approve the first pending request matching `match` on the PS dashboard. */
export function approveOnDashboard(context: BrowserContext, match: DashboardMatch = {}, timeout = 30_000): Promise<Page> {
  return decideOnDashboard(context, match, 'approve', timeout);
}

/** Deny the first pending request matching `match` on the PS dashboard. */
export function denyOnDashboard(context: BrowserContext, match: DashboardMatch = {}, timeout = 30_000): Promise<Page> {
  return decideOnDashboard(context, match, 'deny', timeout);
}
