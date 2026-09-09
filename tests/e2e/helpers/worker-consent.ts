import { Page, expect } from '@playwright/test';
import { approveInPopup, decideAccessConsent } from './consent';

export async function completeWorkerConsent(page: Page, selector: string, completed: () => Promise<boolean>): Promise<void> {
  const visited = new Set<string>();
  await expect(async () => {
    if (await completed()) return;
    const link = page.locator(selector);
    const url = await link.first().getAttribute('href', { timeout: 1_000 }).catch(() => null);
    if (url && !visited.has(url)) {
      visited.add(url);
      const popup = await page.context().newPage();
      await popup.goto(url);
      if (new URL(url).origin === 'http://localhost:5500') await decideAccessConsent(popup);
      else await approveInPopup(popup);
      await popup.close();
    }
    expect(await completed()).toBe(true);
  }).toPass({ timeout: 90_000, intervals: [250, 500, 1_000] });
  expect(visited.size).toBeGreaterThanOrEqual(2);
}