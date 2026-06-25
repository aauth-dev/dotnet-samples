import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus, expectError } from '../../../tests/e2e/helpers/json';
import { approveInPopup, denyInPopup } from '../../../tests/e2e/helpers/consent';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

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
    const link = page.locator('a[target="_blank"]', { hasText: /interaction/ });
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
    await approveInPopup(popup);

    await expectStatus(page, 200);
    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.accessMode).toBe('three-party');
    expect(json.scheme).toBe('jwt');
    // Consent was granted interactively, but the minted auth token carries the
    // same PS-asserted claims as the direct grant.
    expect(json.sub).toBe('pairwise-sub');
    expect(json.scope).toEqual(['calendar.read']);
    expect(json.iss).toBe(Urls.personServer);
    // Direct authorization (deferred consent) — no act chain.
    expect(json.act).toBeFalsy();
  });

  test('deny path surfaces an access-denied error', async ({ page, context }) => {
    await page.goto('/calendar-deferred');
    await waitForInteractive(page, 'button.btn-primary');

    const link = page.locator('a[target="_blank"]', { hasText: /interaction/ });
    await clickAndConfirm(page, 'button.btn-primary', () => link.isVisible());
    await expect(link).toBeVisible({ timeout: 30_000 });

    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await denyInPopup(popup);

    await expectError(page, 'denied');
  });
});
