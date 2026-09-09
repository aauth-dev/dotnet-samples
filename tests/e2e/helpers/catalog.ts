import { test, expect } from './fixtures';
import { waitForInteractive } from './blazor';
import { approveInPopup } from './consent';

export function catalogTests() {
  test.describe('Service-qualified catalog gateway', () => {
    test.describe.configure({ timeout: 120_000 });
    for (const service of ['destinations', 'experiences']) {
      test(`${service} grant cannot read the sibling catalog and recovers with consent`, async ({ page }, testInfo) => {
        await page.goto('/');
        await page.locator('a[href="/catalog-gateway"], a[href="catalog-gateway"]').first().click();
        await waitForInteractive(page, '.catalog-next');
        await page.locator('#catalog-service').selectOption(service);
        const root = page.locator('.catalog-view');
        for (let step = 1; step <= 5; step++) {
          await page.locator('.catalog-next').click();
          if (step === 2 || step === 5) {
            let previous: string | null = null;
            for (let turn = 0; turn < 3; turn++) {
              let state = 'pending';
              await expect.poll(async () => {
                if (await page.getByRole('alert').count()) return state = 'error';
                if (await root.getAttribute('data-step') === String(step)) return state = 'done';
                const link = page.locator('.catalog-consent');
                if (await link.isVisible() && await link.getAttribute('href') !== previous) return state = 'consent';
                return state = 'pending';
              }, { timeout: 40_000 }).not.toBe('pending');
              if (state === 'error') throw new Error(await page.getByRole('alert').innerText());
              if (state === 'done') break;
              const link = page.locator('.catalog-consent');
              previous = await link.getAttribute('href');
              const [popup] = await Promise.all([page.context().waitForEvent('page'), link.click()]);
              await approveInPopup(popup);
              await popup.close();
            }
          }
          await expect.poll(async () => await page.getByRole('alert').count()
            ? await page.getByRole('alert').innerText() : await root.getAttribute('data-step'), { timeout: 30_000 }).toBe(String(step));
          if (step === 1) {
            await expect(page.getByTestId('catalog-result')).toContainText('openapi-gateway');
            await expect(page.getByTestId('catalog-result')).toContainText('destinations');
            await expect(page.getByTestId('catalog-result')).toContainText('experiences');
          }
          if (step === 3) expect(JSON.parse(await page.getByTestId('catalog-result').innerText()).service).toBe(service);
          if (step === 4) await expect(page.getByTestId('catalog-result')).toContainText('operation_not_granted');
        }
        const result = JSON.parse(await page.getByTestId('catalog-result').innerText());
        expect(result.service).toBe(service === 'destinations' ? 'experiences' : 'destinations');
        expect(result.grant.vocabulary).toBe('urn:aauth:vocabulary:openapi-gateway');
        expect(result.grant.operations).toEqual([{ service: result.service, operationId: 'list' }]);
        await expect(root.locator('.catalog-exchange[data-status="403"]')).toHaveCount(1);
        await expect(root.getByRole('list', { name: 'Protocol steps' }).locator('li')).toHaveCount(5);
        await expect(root.getByRole('table', { name: 'Sequence diagram' }).locator('tbody tr')).toHaveCount(5);
        await expect(root.locator('.catalog-code')).toContainText('R3Operation.OpenApiGateway(service, "list")');
        for (const width of [1280, 390]) {
          await page.setViewportSize({ width, height: 844 });
          await root.scrollIntoViewIfNeeded();
          expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
          await page.screenshot({ path: testInfo.outputPath(`catalog-${service}-${width}.png`) });
        }
        await page.getByRole('button', { name: 'Reset catalog flow' }).click();
        await expect(root).toHaveAttribute('data-step', '0');
        await expect(root.locator('.catalog-exchange')).toHaveCount(0);
        await page.locator('.catalog-next').click();
        await expect(root).toHaveAttribute('data-step', '1');
      });
    }
  });
}