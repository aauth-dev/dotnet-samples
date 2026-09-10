import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';
import { authenticateConsent } from '../../../tests/e2e/helpers/consent';

/**
 * Resource-managed (two-party) — the Inbox manages authorization itself via its
 * own consent page (no Person Server). Click "Read my inbox" → 202 surfaces the
 * Inbox consent link → approve at the Inbox → the SDK captures the opaque
 * AAuth-Access token and replays it (bound to the signature) → 200 + messages.
 * Setup uses the AP (:5301) for signed enrollment and refresh; authorization is
 * agent/Inbox only, with no PS/AS token exchange.
 */
test('inbox resource-managed flow: consent then replay returns messages', async ({ page, context }) => {
  test.setTimeout(60_000);

  await page.goto('/inbox');
  await expect(page.locator('h2')).toHaveText('Resource-Managed (Two-Party) Access');
  await expect(page.locator('body')).toContainText('signed refresh endpoint');
  await expect(page.locator('code.language-csharp').first()).toContainText('AAuthClientBuilder.Enrolled(Enrollment.Key)');
  await expect(page.locator('code.language-csharp').first()).toContainText('.WithKeyStore(Enrollment.KeyStore)');
  await waitForInteractive(page, 'button.btn-primary');

  await clickAndConfirm(page, 'button.btn-primary', async () =>
    await page.locator('button.btn-primary').isDisabled()
    || await page.locator('#consent-link').isVisible());

  // The Inbox needs approval — its own consent link appears while the SDK polls.
  const consentLink = page.locator('#consent-link');
  await expect(consentLink).toBeVisible({ timeout: 30_000 });
  const consentUrl = await consentLink.getAttribute('href');
  expect(consentUrl).toContain('/consent?code=');

  // Approve at the Inbox's OWN consent page (separate tab) — no PS involved.
  const consentPage = await context.newPage();
  await consentPage.goto(consentUrl!);
  await authenticateConsent(consentPage);
  await consentPage.locator('#approve').click();
  await expect(consentPage.locator('#done')).toBeVisible();
  await consentPage.close();

  // The poll loop resolves; the replayed signed request returns the inbox.
  await expectStatus(page, 200);
  const json = (await readResponseJson(page)) as Record<string, unknown>;
  expect(json.scope).toBe('inbox.read');
  expect(Array.isArray(json.messages)).toBe(true);
  await page.screenshot({ path: test.info().outputPath('inbox-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: test.info().outputPath('inbox-mobile.png'), fullPage: true });
});
