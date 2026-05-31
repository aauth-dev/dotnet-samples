import { APIRequestContext, Page } from '@playwright/test';
import { Urls } from './agents';

/**
 * MockPersonServer consent control helpers.
 *
 * The PS exposes demo-only unauthenticated admin endpoints to flip consent
 * deterministically (see samples/MockPersonServer/Program.cs):
 *   POST /admin/consent  { agent, resource, scope? }  → grant standing consent
 *   POST /admin/revoke   { agent, resource, scope? }  → revoke (forces deferred)
 *
 * The user-facing consent page lives at GET /interaction?code={id} and renders
 * two forms with button.approve / button.deny.
 */

/** Grant standing consent for (agent, resource) so /token issues immediately. */
export async function grantConsent(
  request: APIRequestContext,
  agent: string,
  resource: string,
): Promise<void> {
  await request.post(`${Urls.personServer}/admin/consent`, {
    data: { agent, resource: resource.replace(/\/$/, '') },
  });
}

/** Revoke consent for (agent, resource) so /token returns 202 (deferred). */
export async function revokeConsent(
  request: APIRequestContext,
  agent: string,
  resource: string,
): Promise<void> {
  await request.post(`${Urls.personServer}/admin/revoke`, {
    data: { agent, resource: resource.replace(/\/$/, '') },
  });
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
