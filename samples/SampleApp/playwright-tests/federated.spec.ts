import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';
import { approveInPopup } from '../../../tests/e2e/helpers/consent';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Federated (four-party) — interactive consent path (stub Access Server).
 *
 * With a **stub** Access Server policy and `RequireConsent=true` the AS returns
 * `202 requirement=interaction`. The PS relays it, and the SampleApp surfaces
 * the AS interaction URL. The user opens the Access Server's own consent screen
 * (badged *Access Server*), clicks **Approve**, and the SDK poll resolves to a
 * 200 with an AS-minted `aa-auth+jwt`.
 *
 * From the agent's perspective this is identical to the Keycloak path (covered
 * by `federated-deferred.spec.ts`, gated on KEYCLOAK_E2E=1); only the
 * interaction URL's destination differs.
 */
test.describe('Federated (interactive consent)', () => {
  test.describe.configure({ timeout: 120_000 });

  test('approve at the AS consent screen resolves to a four-party identity', async ({ page, context }) => {
    await page.goto('/federated');
    await expect(page.locator('h2')).toContainText('Federated');
    await waitForInteractive(page, 'button.btn-primary');

    // Send the request; the AS returns 202 and the interaction URL is surfaced.
    const link = page.locator('a[target="_blank"]', { hasText: /interaction/ });
    await clickAndConfirm(page, 'button.btn-primary', () => link.isVisible());
    await expect(link).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('.spinner-border')).toBeVisible();

    // The interaction URL is the Access Server's own consent screen.
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await expect(popup.locator('.badge')).toContainText('Access Server');
    await approveInPopup(popup);

    await expectStatus(page, 200, 60_000);
    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.mode).toBe('four-party');
    expect(json.scheme).toBe('jwt');
    expect(json.scope).toEqual(['whoami']);
    // The auth token is minted by the Access Server, not the Person Server.
    expect(json.iss).toBe(Urls.accessServer);
    const act = json.act as Record<string, unknown>;
    expect(act.sub).toBe(Agents.sampleApp);
  });
});
