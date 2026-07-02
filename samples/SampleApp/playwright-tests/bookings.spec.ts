import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';
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
 * concrete parameters; the same client resends them and the resource verifies they
 * match the approved proposal's digest before serving.
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

  test('confirming a reservation triggers a per-call proposal challenge (r3_conditional)', async ({ page }) => {
    await page.goto('/bookings');
    await waitForInteractive(page, 'button.btn-primary');

    // Second button = "Confirm a reservation (r3_conditional)".
    await clickAndConfirm(
      page,
      'button.btn-outline-primary',
      async () => (await page.locator('pre code.language-json, div.alert-danger').count()) > 0,
    );

    // confirmReservation is authorized only in principle (r3_conditional). The
    // resource challenges the concrete call with a per-call proposal carrying the
    // parameters (r3 §Per-Call Proposals) — surfaced here as r3_approval_required.
    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.error).toBe('r3_approval_required');
    expect(json.operationId).toBe('confirmReservation');
    expect(typeof json.r3_uri).toBe('string');
    expect(typeof json.r3_s256).toBe('string');
  });
});
