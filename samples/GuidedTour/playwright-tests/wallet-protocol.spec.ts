import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import {
  openTour, selectFlow, driveTour, decideConsent, doneTitles, selectStepTitled,
  expectResponse, readResponseJson, TourMode,
} from '../../../tests/e2e/helpers/tour';
import { Urls } from '../../../tests/e2e/helpers/agents';

/**
 * Wallet Protocol (flow 13) in the standard tour. Each scenario runs real
 * requests; consent and clarification steps adapt to what the PS and Access
 * Server answer, and every scenario ends by proving a grant cannot be reused
 * beyond what was approved.
 */
test.describe('Wallet Protocol (Guided Tour)', () => {
  test.describe.configure({ timeout: 240_000 });

  async function selectScenario(page: import('@playwright/test').Page, scenario: string, lanes: string[]) {
    await openTour(page);
    await selectFlow(page, TourMode.WalletProtocol);
    const picker = page.locator('select#wallet-scenario-select');
    await expect(async () => {
      await picker.selectOption(scenario);
      await expect(page.locator('.lanes .lane')).toHaveText(lanes, { timeout: 2_000 });
    }).toPass({ timeout: 20_000 });
  }

  test('AS clarification is answered before the approved review', async ({ page }) => {
    await selectScenario(page, 'Clarification', ['Agent', 'Wallet', 'Person Server', 'Access Server']);
    await driveTour(page, (popup) => decideConsent(popup, true));
    await expect(page.locator('button.primary')).toHaveText('Done');
    const titles = await doneTitles(page);
    expect(titles.some((title) => title.startsWith('Answer the clarification'))).toBe(true);

    await selectStepTitled(page, /^Answer the clarification/);
    await expect(page.locator('section.payload article.inspector')).toContainText('clarification_response');

    await selectStepTitled(page, /GET \/wallet\/review with auth token → 200/);
    await expectResponse(page, 200, ['wallet.review']);
    await selectStepTitled(page, /GET \/wallet\/charge with the same grant → 401/);
    await expectResponse(page, 401);
  });

  test('the Concierge chains an AS-issued grant to the Wallet', async ({ page }) => {
    await selectScenario(page, 'AsGrantChaining', ['Agent', 'Concierge', 'Wallet', 'Person Server', 'Access Server']);
    await driveTour(page, (popup) => decideConsent(popup, true));
    await expect(page.locator('button.primary')).toHaveText('Done');

    await selectStepTitled(page, /chained Wallet result|GET Concierge \/wallet with upstream grant → 200/);
    const result = (await readResponseJson(page)) as {
      upstream: Record<string, unknown>; downstream: Record<string, unknown>;
    };
    expect(result.upstream.issuer).toBe(Urls.accessServer);
    expect(result.upstream.ps).toBe(Urls.personServer);
    expect(result.downstream.iss).toBe(Urls.accessServer);
    expect(result.downstream.ps).toBe(result.upstream.ps);
    expect(result.downstream.sub).not.toBe(result.upstream.sub);
    expect(result.downstream).not.toHaveProperty('agent');

    await selectStepTitled(page, /GET Wallet \/wallet with the upstream token → 401/);
    await expectResponse(page, 401);
    await selectStepTitled(page, /Repeat the delegated Concierge read → 200/);
    await expectResponse(page, 200);
  });

  test('federated revocation cascades and recovery needs a fresh grant', async ({ page }) => {
    await selectScenario(page, 'Revocation', ['Agent', 'Wallet', 'Person Server', 'Access Server']);
    await driveTour(page, (popup) => decideConsent(popup, true));
    await expect(page.locator('button.primary')).toHaveText('Done');

    await selectStepTitled(page, /Agent POSTs Wallet \/revoke → 403 unsupported_iss/);
    await expectResponse(page, 403, ['unsupported_iss']);
    await selectStepTitled(page, /PS revokes its person token at the Wallet and the AS → 200/);
    await expectResponse(page, 200, [Urls.accessServer, Urls.wallet]);
    await selectStepTitled(page, /GET \/wallet with revoked grant → 401/);
    await expectResponse(page, 401);
    await selectStepTitled(page, /GET \/wallet with fresh grant → 200 \(recovered\)/);
    await expectResponse(page, 200, ['four-party']);
  });
});
