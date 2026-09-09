import { test, expect } from './fixtures';
import { clickAndConfirm, waitForInteractive } from './blazor';
import { approveInPopup } from './consent';

export function documentTests() {
  test.describe.configure({ timeout: 120_000 });
  for (const approve of [true, false]) {
    test(`document resource ${approve ? 'approval precedes PS consent' : 'denial aborts authorization'}`, async ({ page }, testInfo) => {
      test.setTimeout(180_000);
      await page.goto('/');
      await page.locator('a[href="/documents"], a[href="documents"]').first().click();
      await waitForInteractive(page, '.document-next');
      const root = page.locator('.document-view');
      await expect(root.locator('[data-protocol-step]')).toHaveCount(4);
      const methods = ['EnrollDocumentAgentAsync', 'VerifyResourceTokenAsync', 'TokenExchangeClient', 'DownloadDocumentAsync'];
      for (const step of [1, 2, 3, 4]) {
        expect(await root.locator(`[data-sequence-step="${step}"]`).count()).toBeGreaterThan(0);
        await expect(root.locator(`[data-code-step="${step}"] summary`)).toContainText(`${step}.`);
        await expect(root.locator(`[data-code-step="${step}"] code`)).toContainText(methods[step - 1]);
      }
      await expect(root.locator('tr[data-kind="setup"]')).toContainText('AP');
      await expect(root.locator('tr[data-kind="local"] img')).toHaveCount(0);
      await expect(root.getByRole('table', { name: 'Sequence diagram' })).toContainText('Signed GET pending Location');
      for (const cycle of [0, 1]) {
      for (const step of [1, 2]) {
        await expect(root.locator(`[data-protocol-step="${step}"]`)).toHaveAttribute('aria-current', 'step');
        await clickAndConfirm(page, '.document-next', async () => await root.getAttribute('data-step') === String(step));
        await expect(root).toHaveAttribute('data-step', String(step), { timeout: 30_000 });
      }
      const resourceToken = JSON.parse(await page.getByTestId('document-result').innerText());
      expect(resourceToken.interaction.url).toBe('http://localhost:5007/permission');
      expect(resourceToken.account).toBe('work');
      await page.locator('.document-next').click();
      const link = page.locator('.document-consent');
      await expect(link).toHaveAttribute('href', /:5100\/interaction\/resource\?code=/, { timeout: 30_000 });
      const [popup] = await Promise.all([page.context().waitForEvent('page'), link.click()]);
      await popup.locator('button.demo-login, button').filter({ hasText: /Sign in|Continue to resource/ }).first().waitFor();
      if (await popup.locator('button.demo-login').isVisible()) await popup.locator('button.demo-login').click();
      await expect(popup.getByRole('heading', { name: 'Resource permissions', exact: true })).toBeVisible();
      await expect(popup.locator('button.approve')).toHaveCount(0);
      const prematureConsent = new URL(popup.url());
      prematureConsent.pathname = '/interaction';
      const blockedConsent = await popup.request.get(prematureConsent.toString());
      expect(blockedConsent.status()).toBe(400);
      expect((await blockedConsent.json()).error).toBe('invalid_code');
      const [permissionRequest] = await Promise.all([
        popup.waitForRequest(request => request.isNavigationRequest() && /:5007\/permission\?code=.+&callback=/.test(request.url())),
        popup.getByRole('button', { name: 'Continue to resource' }).click(),
      ]);
      await expect(popup).toHaveURL(/:5007\/permission\?(code|session)=/);
      const callback = new URL(permissionRequest.url()).searchParams.get('callback')!;
      expect(callback).toMatch(/^http:\/\/localhost:5100\/interaction\/resource\/callback\/.+\?state=.+/);
      await popup.locator('button.demo-login, button').filter({ hasText: /Sign in|Release document/ }).first().waitFor();
      if (await popup.locator('button.demo-login').isVisible()) await popup.locator('button.demo-login').click();
      await expect(popup.getByRole('heading', { name: 'Release travel document', exact: true })).toBeVisible();
      await popup.getByRole('button', { name: approve ? 'Release document' : 'Decline release', exact: true }).click();
      if (approve) {
        await expect(popup).toHaveURL(/:5100\/interaction\?session=/);
        await approveInPopup(popup);
        await expect(root).toHaveAttribute('data-step', '3', { timeout: 30_000 });
        const auth = JSON.parse(await page.getByTestId('document-result').innerText());
        expect(auth.agent).toBe(resourceToken.agent);
        expect(auth.account).toBe(resourceToken.account);
        expect(auth.scope).toBe(resourceToken.scope);
        await page.locator('.document-next').click();
        await expect(root).toHaveAttribute('data-step', '4');
        expect(JSON.parse(await page.getByTestId('document-result').innerText()).released).toBe(true);
        await expect(page.locator('.document-exchange[data-status="200"]').filter({ hasText: 'GET http://localhost:5007/document' })).toHaveCount(1);
      } else {
        await expect(popup.getByRole('heading', { name: 'Authorization stopped', exact: true })).toBeVisible();
        await expect(page.getByTestId('document-denied')).toBeVisible({ timeout: 30_000 });
        await expect(page.locator('.document-next')).toBeDisabled();
        await expect(page.locator('.document-exchange[data-status="200"]').filter({ hasText: 'GET http://localhost:5007/document' })).toHaveCount(0);
      }
      await popup.close();
      await expect(page.getByRole('alert')).toHaveCount(0);
      for (const width of [1280, 390]) {
        await page.setViewportSize({ width, height: 844 });
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
        await page.screenshot({ path: testInfo.outputPath(`documents-${approve}-${cycle}-${width}.png`) });
        await root.getByRole('table', { name: 'Sequence diagram' }).screenshot({ path: testInfo.outputPath(`documents-diagram-${cycle}-${width}.png`) });
        const code = root.locator('[data-code-step="3"]');
        if (!await code.evaluate(element => (element as HTMLDetailsElement).open)) await code.locator('summary').click();
        await code.screenshot({ path: testInfo.outputPath(`documents-code-${cycle}-${width}.png`) });
      }
      await page.getByRole('button', { name: 'Reset document flow' }).click();
      await expect(root).toHaveAttribute('data-step', '0');
      await expect(root.locator('.document-exchange')).toHaveCount(0);
      await expect(page.getByTestId('document-result')).toHaveCount(0);
      await expect(page.getByTestId('document-denied')).toHaveCount(0);
      await expect(root.locator('.document-consent')).toHaveCount(0);
      }
    });
  }
}