import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';

/**
 * Resource-managed (two-party) — the Inbox manages authorization itself via its
 * own consent page (no Person Server). Click "Read my inbox" → 202 surfaces the
 * Inbox consent link → approve at the Inbox → the SDK captures the opaque
 * AAuth-Access token and replays it (bound to the signature) → 200 + messages.
 * Needs only the Inbox (:5004).
 */
test('inbox resource-managed flow: consent then replay returns messages', async ({ page, context }) => {
  test.setTimeout(60_000);

  await page.goto('/inbox');
  await expect(page.locator('h2')).toHaveText('Resource-Managed (Two-Party) Access');
  await waitForInteractive(page, 'button.btn-primary');

  await page.locator('button.btn-primary').click();

  // The Inbox needs approval — its own consent link appears while the SDK polls.
  const consentLink = page.locator('#consent-link');
  await expect(consentLink).toBeVisible({ timeout: 30_000 });
  const consentUrl = await consentLink.getAttribute('href');
  expect(consentUrl).toContain('/consent?code=');

  // Approve at the Inbox's OWN consent page (separate tab) — no PS involved.
  const consentPage = await context.newPage();
  await consentPage.goto(consentUrl!);
  await consentPage.locator('#approve').click();
  await expect(consentPage.locator('#done')).toBeVisible();
  await consentPage.close();

  // The poll loop resolves; the replayed signed request returns the inbox.
  await expectStatus(page, 200);
  const json = (await readResponseJson(page)) as Record<string, unknown>;
  expect(json.scope).toBe('inbox.read');
  expect(Array.isArray(json.messages)).toBe(true);
});
