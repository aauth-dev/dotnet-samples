import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';
import { keycloakLogin } from '../../../tests/e2e/helpers/consent';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Federated (four-party) — interactive Keycloak path.
 *
 * With a **Keycloak** Access Server policy the AS returns
 * `202 requirement=interaction`. The Person Server relays it to the agent, and
 * the SampleApp surfaces the AS login-start URL on the same challenge callback
 * used by the three-party deferred page. The user logs in at Keycloak
 * (demo/demo), the AS mints the auth token, and the SDK poll resolves to 200.
 *
 * Requires the Keycloak-backed AS to be running (see
 * `make demo-federated-sample`). Skipped unless KEYCLOAK_E2E=1 so the default
 * (stub, no-Docker) CI run stays green.
 */
const keycloakEnabled = process.env.KEYCLOAK_E2E === '1';

test.describe('Federated (interactive Keycloak)', () => {
  test.describe.configure({ timeout: 180_000 });
  test.skip(!keycloakEnabled, 'Set KEYCLOAK_E2E=1 to run the Keycloak interactive path.');

  test('approve path (demo user) resolves to a four-party identity', async ({ page, context }) => {
    await page.goto('/federated');
    await expect(page.locator('h2')).toContainText('Federated');
    await waitForInteractive(page, 'button.btn-primary');

    const link = page.locator('a[target="_blank"]', { hasText: /interaction|realms|access/ });
    await clickAndConfirm(page, 'button.btn-primary', () => link.isVisible());
    await expect(link).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('.spinner-border')).toBeVisible();

    // The interaction URL is the AS login-start → Keycloak OIDC login.
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await keycloakLogin(popup, 'demo', 'demo');

    await expectStatus(page, 200, 60_000);
    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.mode).toBe('four-party');
    expect(json.scheme).toBe('jwt');
    expect(json.iss).toBe(Urls.accessServer);
    const act = json.act as Record<string, unknown>;
    expect(act.sub).toBe(Agents.sampleApp);
  });
});
