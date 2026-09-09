import { test, expect } from './fixtures';
import { clickAndConfirm, waitForInteractive } from './blazor';
import { approveInPopup } from './consent';

export function documentTests() {
  test.describe.configure({ timeout: 120_000 });
  for (const approve of [true, false]) {
    test(`document resource ${approve ? 'approval precedes PS consent' : 'denial aborts authorization'}`, async ({ page }, testInfo) => {
      test.setTimeout(120_000);
      await page.goto('/');
      await page.locator('a[href="/documents"], a[href="documents"]').first().click();
      await waitForInteractive(page, '.document-next');
      const root = page.locator('.document-view');
      for (const step of [1, 2]) {
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
      await popup.locator('button.demo-login').click();
      await expect(popup.getByRole('heading', { name: 'Resource permissions', exact: true })).toBeVisible();
      await expect(popup.locator('button.approve')).toHaveCount(0);
      const prematureConsent = new URL(popup.url());
      prematureConsent.pathname = '/interaction';
      const blockedConsent = await popup.request.get(prematureConsent.toString());
      expect(blockedConsent.status()).toBe(400);
      expect((await blockedConsent.json()).error).toBe('invalid_code');
      await popup.getByRole('button', { name: 'Continue to resource' }).click();
      await expect(popup).toHaveURL(/:5007\/permission\?code=.+&callback=/);
      const callback = new URL(popup.url()).searchParams.get('callback')!;
      expect(callback).toMatch(/^http:\/\/localhost:5100\/interaction\/resource\/callback\/.+\?state=.+/);
      await popup.locator('button.demo-login').click();
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
        await page.screenshot({ path: testInfo.outputPath(`documents-${approve}-${width}.png`) });
      }
      await page.getByRole('button', { name: 'Reset document flow' }).click();
      await expect(root).toHaveAttribute('data-step', '0');
    });
  }
}