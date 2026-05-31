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

/** Grant standing consent for (agent, resource) so /token issues immediately. */
export async function grantConsent(
  request: APIRequestContext,
  agent: string,
  resource: string,
): Promise<void> {
  const res = await request.post(`${Urls.personServer}/admin/consent`, {
    data: { agent, resource: resource.replace(/\/$/, '') },
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
