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

/** Open (or reuse) this context's dashboard tab, signing in once per context. */
export async function openDashboard(context: BrowserContext, code?: string): Promise<Page> {
  let page = dashboards.get(context);
  if (!page || page.isClosed()) {
    page = await context.newPage();
    dashboards.set(context, page);
  }
  const url = `${Urls.personServer}/dashboard${code ? '?code=' + encodeURIComponent(code) : ''}`;
  if (page.url() !== url) await page.goto(url);
  const signIn = page.locator('button.demo-login');
  const heading = page.getByRole('heading', { name: 'Consent requests', exact: true });
  await expect(signIn.or(heading).first()).toBeVisible();
  if (await signIn.isVisible()) await signIn.click();
  await expect(heading).toBeVisible();
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
