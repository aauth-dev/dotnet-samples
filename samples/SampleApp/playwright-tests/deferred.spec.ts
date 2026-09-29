import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus, expectError } from '../../../tests/e2e/helpers/json';
import { approveInPopup, denyInPopup, authenticateConsent } from '../../../tests/e2e/helpers/consent';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';
import { directedSubject } from '../../../tests/e2e/helpers/consent';
import { approveOnDashboard, denyOnDashboard } from '../../../tests/e2e/helpers/dashboard';

/**
 * Deferred — three-party user-consent flow. The page revokes consent first, so
 * POST /token returns 202 with an interaction URL. The user approves (or denies)
 * in a popup while the SDK polls. Extended timeout for the poll loop.
 */
test.describe('Deferred', () => {
  test.describe.configure({ timeout: 150_000 });

  test('approve path resolves to a three-party identity', async ({ page, context }) => {
    await page.goto('/calendar-deferred');
    await expect(page.locator('h2')).toContainText('Deferred');
    await waitForInteractive(page, 'button.btn-primary');

    // First clicking test on a cold circuit — confirm the click landed.
    const link = page.locator('a.btn[href*="/interaction"][target="_blank"]');
    await clickAndConfirm(page, 'button.btn-primary', () => link.isVisible());

    // Interaction URL + polling spinner appear. First /token round-trip on a
    // cold-started backend can exceed the default 5s assertion timeout.
    await expect(link).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('.spinner-border')).toBeVisible();

    // Open the PS consent page and approve.
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    const arrival = await link.getAttribute('href');
    const code = new URL(arrival!).searchParams.get('code')!;
    const codeOnly = await popup.request.post(`${Urls.personServer}/interaction/approve`, { form: { code } });
    expect(codeOnly.status()).toBe(401);
    await authenticateConsent(popup);
    const reuse = await popup.request.get(arrival!);
    expect(reuse.status()).toBe(400);
    expect((await reuse.json()).error).toBe('invalid_code');
    const session = await popup.locator('input[name="session"]').first().inputValue();
    const missingCsrf = await popup.request.post(`${Urls.personServer}/interaction/approve`, { form: { session } });
    expect(missingCsrf.status()).toBe(403);
    await expect(page.locator('[data-consent-stage="decision-pending"]')).toBeVisible();
    await approveInPopup(popup);

    await expectStatus(page, 200);
    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.accessMode).toBe('three-party');
    expect(json.scheme).toBe('jwt');
    // Consent was granted interactively, but the minted auth token carries the
    // same PS-asserted claims as the direct grant.
    expect(json.sub).toBe(directedSubject(Urls.calendar));
    expect(json.scope).toEqual(['calendar.read']);
    expect(json.iss).toBe(Urls.personServer);
    // Direct authorization (deferred consent) — no act chain.
    expect(json.act).toBeFalsy();
  });

  test('deny path surfaces an access-denied error', async ({ page, context }) => {
    await page.goto('/calendar-deferred');
    await waitForInteractive(page, 'button.btn-primary');

    const link = page.locator('a.btn[href*="/interaction"][target="_blank"]');
    await clickAndConfirm(page, 'button.btn-primary', () => link.isVisible());
    await expect(link).toBeVisible({ timeout: 30_000 });

    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await denyInPopup(popup);

    await expectError(page, 'denied');
  });

  test('dashboard approval resolves the poll and retires the link', async ({ page, context }) => {
    await page.goto('/calendar-deferred');
    await waitForInteractive(page, 'button.btn-primary');
    const link = page.locator('a.btn[href*="/interaction"][target="_blank"]');
    await clickAndConfirm(page, 'button.btn-primary', () => link.isVisible());
    await expect(link).toBeVisible({ timeout: 30_000 });
    const arrival = (await link.getAttribute('href'))!;

    const dashboard = await approveOnDashboard(context, { agent: Agents.sampleApp, resource: Urls.calendar });
    await expect(dashboard.locator('#history article.card').first()).toContainText('via dashboard');

    await expectStatus(page, 200);
    expect(((await readResponseJson(page)) as Record<string, unknown>).accessMode).toBe('three-party');
    const stale = await context.newPage();
    await stale.goto(arrival);
    const signIn = stale.locator('button.demo-login');
    if (await signIn.isVisible()) await signIn.click();
    await expect(stale.locator('body')).toContainText('invalid_code');
    await stale.close();
  });

  test('dashboard denial surfaces an access-denied error', async ({ page, context }) => {
    await page.goto('/calendar-deferred');
    await waitForInteractive(page, 'button.btn-primary');
    const link = page.locator('a.btn[href*="/interaction"][target="_blank"]');
    await clickAndConfirm(page, 'button.btn-primary', () => link.isVisible());
    await expect(link).toBeVisible({ timeout: 30_000 });

    await denyOnDashboard(context, { agent: Agents.sampleApp, resource: Urls.calendar });

    await expectError(page, 'denied');
  });
});
