import { Page } from '@playwright/test';
import { test, expect } from './fixtures';
import { clickAndConfirm, waitForInteractive } from './blazor';
import { approveInPopup, keycloakLogin } from './consent';
import { expectRequestResponseArrows } from './sequence';
import { expectReadableLinks, expectSyntaxHighlighted } from './visual-style';

async function finishExchange(page: Page, target: number, cancel = false) {
  const root = page.locator('.wallet-walkthrough');
  let previousConsent: string | null = null;
  for (let turn = 0; turn < 8; turn++) {
    let state = 'pending';
    await expect.poll(async () => {
      if (await page.getByRole('alert').count()) return state = 'error';
      if (await root.getAttribute('data-step') === String(target)) return state = 'done';
      if (await page.getByTestId('wallet-cancelled').count()) return state = 'cancelled';
      if (await page.locator('#wallet-answer').isVisible()) return state = 'question';
      const link = page.locator('.wallet-consent');
      if (await link.isVisible() && await link.getAttribute('href') !== previousConsent) return state = 'consent';
      return state = 'pending';
    }, { timeout: 60_000 }).not.toBe('pending');
    if (state === 'done' || state === 'cancelled') return;
    if (state === 'error') throw new Error(await page.getByRole('alert').innerText());
    if (state === 'question') {
      await expect(page.getByRole('heading', { name: 'Access Server clarification' })).toBeVisible();
      await page.getByRole('button', { name: cancel ? 'Cancel request' : 'Send answer', exact: true }).click();
      await expect(page.locator('#wallet-answer')).toHaveCount(0);
    } else {
      const link = page.locator('.wallet-consent');
      previousConsent = await link.getAttribute('href');
      const [popup] = await Promise.all([page.context().waitForEvent('page'), link.click()]);
      if (process.env.KEYCLOAK_E2E === '1' && previousConsent?.includes(':5500/')) {
        await keycloakLogin(popup);
      } else {
        await approveInPopup(popup);
      }
      await popup.close();
    }
  }
  throw new Error('Wallet exchange did not complete within eight user decisions.');
}

export function walletProtocolTests() {
  test.describe('Wallet protocol capabilities', () => {
    test.describe.configure({ timeout: 180_000 });
    for (const flow of ['Clarification', 'AsGrantChaining', 'Revocation']) {
      test(`${flow} executes real requests and rejects unauthorized reuse`, async ({ page }, testInfo) => {
        await page.goto('/');
        await page.locator('a[href="/wallet-protocol"], a[href="wallet-protocol"]').first().click();
        await waitForInteractive(page, '.wallet-next');
        await page.locator('#wallet-flow').selectOption(flow);
        const root = page.locator('.wallet-walkthrough');
        await expect(root.locator('.scenario-narrative')).toContainText('Aria');
        await expect(root.locator('.scenario-narrative')).toContainText('Wallet');
        await expect(root).toHaveAttribute('data-flow', flow);
        await expectSyntaxHighlighted(root.locator('.wallet-code code'));
        await expect(root.locator('.wallet-code code')).toContainText(
          flow === 'Clarification' ? 'ClarifyAsync' : flow === 'AsGrantChaining' ? 'ReadWalletAsync' : 'RevokeTokenAsync',
        );
        await expectReadableLinks(page);
        for (const step of [1, 2]) {
          await clickAndConfirm(page, '.wallet-next', async () => await root.getAttribute('data-step') === String(step));
          await expect(root).toHaveAttribute('data-step', String(step));
        }
        await page.locator('.wallet-next').click();
        await finishExchange(page, 3);
        const total = flow === 'Clarification' ? 5 : flow === 'AsGrantChaining' ? 6 : 8;
        for (let step = 4; step <= total; step++) {
          await page.locator('.wallet-next').click();
          // AsGrantChaining step 4: the Concierge chains the downstream PS consent back.
          if (step === 8 || (flow === 'AsGrantChaining' && step === 4)) await finishExchange(page, step);
          await expect.poll(async () => await page.getByRole('alert').count()
            ? await page.getByRole('alert').innerText() : await root.getAttribute('data-step'), { timeout: 45_000 }).toBe(String(step));
          await expect(page.getByRole('alert')).toHaveCount(0);
        }
        await expect(page.getByRole('list', { name: 'Protocol steps' }).locator('li')).toHaveCount(total);
        const diagram = page.getByRole('region', { name: 'Sequence diagram' });
        const expectedParticipants = flow === 'AsGrantChaining'
          ? ['Agent', 'Agent Provider', 'Concierge', 'Wallet', 'Person Server', 'Access Server', 'User / Browser']
          : ['Agent', 'Agent Provider', 'Wallet', 'Person Server', 'Access Server', 'User / Browser'];
        await expect(diagram.locator('.sequence-participant')).toHaveText(expectedParticipants);
        for (let step = 1; step <= total; step++)
          expect(await diagram.locator(`[data-sequence-step="${step}"]`).count()).toBeGreaterThan(0);
        await expectRequestResponseArrows(diagram);
        await expect(page.locator('.wallet-code')).toHaveAttribute('data-flow', flow);
        await expect(page.locator('.wallet-next')).toBeDisabled();
        if (flow === 'Clarification') {
          await expect(root).toContainText('clarification_response');
          await expect(root).toContainText('wallet.review');
          await expect(page.locator('.wallet-exchange[data-status="401"]').filter({ hasText: '/wallet/charge' })).toHaveCount(1);
        } else if (flow === 'AsGrantChaining') {
          const result = JSON.parse(await page.getByTestId('wallet-result').innerText());
          expect(result.upstream.issuer).toBe('http://localhost:5500');
          expect(result.upstream.ps).toBe('http://localhost:5100');
          expect(result.upstream.mission_s256).toBeNull();
          // The chained Wallet grant is AS-issued for the same person's PS, with a
          // sub directed at the Wallet rather than copied from the upstream token.
          expect(result.downstream.iss).toBe('http://localhost:5500');
          expect(result.downstream.ps).toBe(result.upstream.ps);
          expect(typeof result.downstream.sub).toBe('string');
          expect(result.downstream.sub).not.toBe(result.upstream.sub);
          expect(result.downstream).not.toHaveProperty('agent');
          expect(result.downstream).not.toHaveProperty('act');
          // The repeated read reuses the Concierge's cached Wallet grant for this upstream
          // token: one signed request, no new challenge.
          expect(result.exchanges.map((entry: { status: number }) => entry.status)).toEqual([200]);
          await expect(root).toContainText('HTTP 401');
        } else {
          // draft-11: an agent is not a server revoker; the PS revokes its person
          // token at the Wallet and at the AS, which cascades to the Wallet and reports it.
          await expect(root).toContainText('unsupported_iss');
          await expect(root).toContainText('HTTP 401');
          await expect(root).toContainText('http://localhost:5500');
          const revocations = page.locator('.wallet-exchange').filter({ hasText: 'POST http://localhost:5100/local/wallet/revoke' });
          await expect(revocations).toHaveCount(2);
          await expect(revocations.first()).toHaveAttribute('data-status', '200');
          await expect(revocations.last()).toHaveAttribute('data-status', '200');
          await expect(revocations.last()).toContainText('http://localhost:5003');
          await expect(revocations.last()).not.toContainText('revocation_unavailable');
        }
        for (const width of [1280, 390]) {
          await page.setViewportSize({ width, height: 844 });
          await root.scrollIntoViewIfNeeded();
          expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
          const images = root.locator('img');
          for (let index = 0; index < await images.count(); index++)
            expect(await images.nth(index).evaluate(image => (image as HTMLImageElement).naturalWidth)).toBeGreaterThan(0);
          await page.screenshot({ path: testInfo.outputPath(`wallet-${flow}-${width}.png`) });
        }
        await page.getByRole('button', { name: 'Reset wallet flow' }).click();
        await expect(root).toHaveAttribute('data-step', '0');
        await expect(page.locator('.wallet-exchange')).toHaveCount(0);
        await page.locator('.wallet-next').click();
        await expect(root).toHaveAttribute('data-step', '1');
      });
    }

    test('AS clarification cancellation withdraws the pending exchange and can restart', async ({ page }) => {
      await page.goto('/wallet-protocol');
      await waitForInteractive(page, '.wallet-next');
      const root = page.locator('.wallet-walkthrough');
      for (const step of [1, 2]) {
        await page.locator('.wallet-next').click();
        await expect(root).toHaveAttribute('data-step', String(step));
      }
      await page.locator('.wallet-next').click();
      await finishExchange(page, 3, true);
      await expect(page.getByTestId('wallet-cancelled')).toBeVisible();
      await expect(root).toContainText('DELETE');
      await expect(page.locator('.wallet-next')).toBeDisabled();
      await page.getByRole('button', { name: 'Reset wallet flow' }).click();
      await expect(root).toHaveAttribute('data-step', '0');
      await expect(page.locator('.wallet-next')).toBeEnabled();
    });
  });
}