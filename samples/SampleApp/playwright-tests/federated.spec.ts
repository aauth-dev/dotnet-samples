import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';
import { Agents, Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Federated (four-party) — direct grant path.
 *
 * With a **stub** Access Server policy the AS auto-approves, so the
 * resource's /federated branch resolves to a direct 200 with an AS-minted
 * `aa-auth+jwt`. No interaction URL / consent popup appears. This is the path
 * exercised by `make demo-federated-sample-stub` (no Docker / Keycloak).
 */
test.describe('Federated (direct grant)', () => {
  test.describe.configure({ timeout: 90_000 });

  test('resolves to a four-party identity', async ({ page }) => {
    await page.goto('/federated');
    await expect(page.locator('h2')).toContainText('Federated');
    await waitForInteractive(page, 'button.btn-primary');

    // The first click on a cold Blazor circuit can be dropped; confirm it
    // landed by waiting for the button to enter its "Sending..." state or for
    // a result/error to render.
    const result = page.locator('div.alert.alert-success, div.alert.alert-warning, div.alert.alert-danger');
    await clickAndConfirm(
      page,
      'button.btn-primary',
      async () =>
        (await page.getByRole('button', { name: 'Sending...' }).isVisible()) ||
        (await result.first().isVisible()),
    );

    // Stub AS path: no interaction URL, direct 200.
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
