import { Page, expect } from '@playwright/test';
import { approveInPopup, decideAccessConsent } from './consent';

export async function completeWorkerConsent(
  page: Page,
  selector: string,
  completed: () => Promise<boolean>,
  onVisit?: (url: string, round: number) => Promise<void>,
): Promise<void> {
  const visited = new Set<string>();
  await expect(async () => {
    if (await completed()) return;
    const link = page.locator(selector);
    const url = await link.first().getAttribute('href', { timeout: 1_000 }).catch(() => null);
    if (url && !visited.has(url)) {
      visited.add(url);
      await onVisit?.(url, visited.size);
      const [popup] = await Promise.all([page.context().waitForEvent('page'), link.first().click()]);
      await popup.waitForLoadState('domcontentloaded');
      if (new URL(url).origin === 'http://localhost:5500') await decideAccessConsent(popup);
      else await approveInPopup(popup);
      await popup.close();
    }
    expect(await completed()).toBe(true);
  }).toPass({ timeout: 90_000, intervals: [250, 500, 1_000] });
  expect(visited.size).toBe(3);
}