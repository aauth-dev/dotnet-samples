import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';
import { approveInPopup } from '../../../tests/e2e/helpers/consent';
import { Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Rich Resource Requests (R3) — four-party, Bookings resource.
 *
 * Bookings publishes a content-addressed R3 document (OpenAPI vocabulary,
 * `operationId`s). Its dedicated R3 Access Server (:5501) fetches + hash-verifies
 * the document, splits operations into `r3_granted` / `r3_conditional` by policy,
 * and mints the auth token. The agent code is the ordinary four-party self-issued
 * client — the R3 semantics ride the tokens.
 *
 * `searchAvailability` is granted outright (served immediately). `confirmReservation`
 * is conditional: the resource challenges with a per-call proposal carrying the
 * concrete parameters; the R3 Access Server then asks the user to approve that
 * specific reservation (r3 §Per-Call Proposals, Flow step 2). After approval the same
 * client resends the parameters and the resource verifies they match the approved
 * proposal's digest before serving.
 */
test.describe('Rich Resource Requests (R3)', () => {
  test.describe.configure({ timeout: 120_000 });

  test('search availability is served immediately (r3_granted)', async ({ page }) => {
    await page.goto('/bookings');
    await expect(page.locator('h2')).toContainText('Rich Resource Requests');
    await waitForInteractive(page, 'button.btn-primary');

    await clickAndConfirm(
      page,
      'button.btn-primary',
      async () => (await page.locator('pre code.language-json, div.alert-danger').count()) > 0,
    );

    await expectStatus(page, 200, 60_000);
    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.accessMode).toBe('four-party-r3');
    expect(json.operationId).toBe('searchAvailability');
    expect(json.source).toBe('r3_granted');
    // The auth token was minted by the dedicated R3 Access Server.
    expect(typeof json.r3_uri).toBe('string');
    expect(typeof json.r3_s256).toBe('string');
  });

  test('confirming a reservation requires per-call approval, then succeeds (r3_conditional)', async ({ page, context }) => {
    await page.goto('/bookings');
    await waitForInteractive(page, 'button.btn-primary');

    // confirmReservation is authorized only in principle (r3_conditional). The
    // resource challenges the concrete call with a per-call proposal carrying the
    // parameters (r3 §Per-Call Proposals); the R3 Access Server then asks the user to
    // approve that specific reservation. The SampleApp surfaces the R3 AS interaction URL.
    const link = page.locator('a[target="_blank"]', { hasText: /interaction/ });
    await clickAndConfirm(page, 'button.btn-outline-primary', () => link.isVisible());
    await expect(link).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('.spinner-border')).toBeVisible();

    // The interaction URL is the R3 Access Server's own per-call consent screen.
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await expect(popup.locator('.badge')).toContainText('R3 Access Server');
    await approveInPopup(popup);

    // On approval the AS mints the per-call token; the client resends the exact
    // parameters and the resource verifies them against the approved proposal digest.
    await expectStatus(page, 200, 60_000);
    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.accessMode).toBe('four-party-r3');
    expect(json.operationId).toBe('confirmReservation');
    expect(json.source).toBe('per-call-r3_granted');
    expect(json.status).toBe('confirmed');
    expect(typeof json.r3_uri).toBe('string');
    expect(typeof json.r3_s256).toBe('string');
  });
});
