import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { readResponseJson, expectStatus } from '../../../tests/e2e/helpers/json';
import { approveInPopup, denyInPopup, authenticateConsent } from '../../../tests/e2e/helpers/consent';
import { Urls } from '../../../tests/e2e/helpers/agents';
import { approvePersonConsent } from '../../../tests/e2e/helpers/consent';
import { CONSENT_ACTION } from '../../../tests/e2e/helpers/dashboard';

/**
 * Rich Resource Requests (R3) — four-party, Bookings resource.
 *
 * Bookings publishes a content-addressed R3 document (OpenAPI vocabulary,
 * `operationId`s). Its dedicated R3 Access Server (:5501) fetches + hash-verifies
 * the document, splits operations into `r3_granted` / `r3_per_call` by policy,
 * and mints the auth token. The agent code is the ordinary four-party self-issued
 * client — the R3 semantics ride the tokens.
 *
 * `searchAvailability` is granted outright (served immediately). `confirmReservation`
 * is per-call: the resource challenges with a per-call proposal carrying the
 * concrete parameters; the R3 Access Server then asks the user to approve that
 * specific reservation (r3 §Per-Call Proposals, Flow step 2). After approval the same
 * client resends the parameters and the resource verifies they match the approved
 * proposal's digest before serving.
 */
test.describe('Rich Resource Requests (R3)', () => {
  test.describe.configure({ timeout: 120_000 });

  test('account switch rejects the previous grant and needs fresh consent', async ({ page, context }, testInfo) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/bookings');
    await waitForInteractive(page, 'button.btn-primary');
    await expect(async () => {
      await page.locator('#bookings-account').selectOption('personal');
      await expect(page.locator('#bookings-account')).toHaveAttribute('data-account', 'personal', { timeout: 2_000 });
    }).toPass({ timeout: 20_000 });
    await clickAndConfirm(page, 'button.btn-primary', async () =>
      (await page.locator(`${CONSENT_ACTION}, div.alert-danger`).count()) > 0);
    await approvePersonConsent(page, CONSENT_ACTION);
    await expectStatus(page, 200, 60_000);
    const personal = await readResponseJson(page) as Record<string, unknown>;
    expect(personal.account).toBe('personal');

    await page.locator('#bookings-account').selectOption('work');
    await page.getByRole('button', { name: 'Check previous account grant', exact: true }).click();
    await expectStatus(page, 401);
    await expect(page.locator('div.alert-danger')).toHaveCount(0);
    await page.getByRole('button', { name: 'Search availability (r3_granted)', exact: true }).click();
    const link = page.locator(CONSENT_ACTION);
    await expect(link).toBeVisible();
    const [denial] = await Promise.all([context.waitForEvent('page'), link.click()]);
    await authenticateConsent(denial);
    await expect(denial.locator('body')).toContainText('work');
    await denyInPopup(denial);
    await denial.close();
    await expect(page.locator('div.alert-danger')).toContainText(/denied/i);

    await page.getByRole('button', { name: 'Search availability (r3_granted)', exact: true }).click();
    await approvePersonConsent(page, CONSENT_ACTION);
    await expectStatus(page, 200, 60_000);
    const work = await readResponseJson(page) as Record<string, unknown>;
    expect(work.account).toBe('work');
    // Same person (ps, sub) behind both accounts; the grant names no agent.
    expect(work.subject).toBe(personal.subject);
    expect(work.ps).toBe(Urls.personServer);
    expect(work.ps).toBe(personal.ps);
    expect(work).not.toHaveProperty('agent');
    await page.locator('#bookings-account').scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath('accounts-mobile.png') });
  });

  test('search availability is served immediately (r3_granted)', async ({ page }) => {
    await page.goto('/bookings');
    await expect(page.locator('h2')).toContainText('Rich Resource Requests');
    await expect(page.locator('pre code.language-csharp').last()).toContainText('operation.Matches(Vocabulary.OpenApi');
    await expect(page.locator('pre code.language-csharp').last()).toContainText('new SqliteR3AuditSink(auditPath)');
    await waitForInteractive(page, 'button.btn-primary');

    await clickAndConfirm(
      page,
      'button.btn-primary',
      async () => (await page.locator(`${CONSENT_ACTION}, pre code.language-json, div.alert-danger`).count()) > 0,
    );
    await approvePersonConsent(page, CONSENT_ACTION);

    await expect(page.locator('div.alert-danger')).toHaveText([]);
    await expectStatus(page, 200, 60_000);
    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.accessMode).toBe('four-party-r3');
    expect(json.operationId).toBe('searchAvailability');
    expect(json.source).toBe('r3_granted');
    // The auth token was minted by the dedicated R3 Access Server.
    expect(typeof json.r3_uri).toBe('string');
    expect(typeof json.r3_s256).toBe('string');
  });

  test('confirming a reservation requires per-call approval, then succeeds (r3_per_call)', async ({ page, context }) => {
    await page.goto('/bookings');
    await waitForInteractive(page, 'button.btn-primary');
    await expect(async () => {
      await page.locator('#bookings-account').selectOption('personal');
      await expect(page.locator('#bookings-account')).toHaveAttribute('data-account', 'personal', { timeout: 2_000 });
    }).toPass({ timeout: 20_000 });

    // confirmReservation is authorized only in principle (r3_per_call). The
    // resource challenges the concrete call with a per-call proposal carrying the
    // parameters (r3 §Per-Call Proposals); the R3 Access Server then asks the user to
    // approve that specific reservation. The SampleApp surfaces the R3 AS interaction URL.
    const link = page.locator(CONSENT_ACTION);
    await clickAndConfirm(page, 'button.btn-outline-primary', async () =>
      await link.isVisible() || await page.locator('div.alert-danger').isVisible());
    await expect(page.locator('div.alert-danger')).toHaveText([]);
    await expect(link).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('.ps-spinner')).toBeVisible();
    await approvePersonConsent(page, CONSENT_ACTION);
    await expect(link).toHaveAttribute('href', /localhost:5501/);

    // The interaction URL is the R3 Access Server's own per-call consent screen.
    const [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await authenticateConsent(popup);
    await expect(popup.locator('.badge')).toContainText('R3 Access Server');
    await expect(popup.locator('body')).toContainText('Personal reservations');
    await approveInPopup(popup);

    // On approval the AS mints the per-call token; the client resends the exact
    // parameters and the resource verifies them against the approved proposal digest.
    await expectStatus(page, 200, 60_000);
    const json = (await readResponseJson(page)) as Record<string, unknown>;
    expect(json.accessMode).toBe('four-party-r3');
    expect(json.operationId).toBe('confirmReservation');
    expect(json.source).toBe('per-call-r3_granted');
    expect(json.status).toBe('confirmed');
    expect(json.account).toBe('personal');
    expect(typeof json.r3_uri).toBe('string');
    expect(typeof json.r3_s256).toBe('string');
  });
});
