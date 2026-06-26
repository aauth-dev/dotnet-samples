import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive, clickAndConfirm } from '../../../tests/e2e/helpers/blazor';
import { approveInPopup } from '../../../tests/e2e/helpers/consent';

test.describe('Rich Requests (R3)', () => {
  test.describe.configure({ timeout: 180_000 });

  test('approves initial consent and per-call proposal, then books the trip', async ({ page, context }) => {
    await page.goto('/rich-request');
    await expect(page.locator('h2')).toContainText('Rich Requests');
    await expect(page.locator('.alert-warning')).toContainText('Experimental');
    await waitForInteractive(page, 'button.btn-primary');

    let link = page.locator('a[target="_blank"]', { hasText: /interaction/ });
    await clickAndConfirm(page, 'button.btn-primary', () => link.isVisible());
    await expect(link).toBeVisible({ timeout: 45_000 });

    let [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await expect(popup.locator('body')).toContainText(/search|hold|book|R3/i);
    await approveInPopup(popup);

    await expect(page.locator('details', { hasText: 'book_trip → per-call proposal' })).toBeVisible({ timeout: 90_000 });
    await expect(page.locator('body')).toContainText('proposal');
    await expect(page.locator('body')).toContainText('r3_s256');

    link = page.locator('a[target="_blank"]', { hasText: /interaction/ });
    await expect(link).toBeVisible({ timeout: 45_000 });
    [popup] = await Promise.all([
      context.waitForEvent('page'),
      link.click(),
    ]);
    await expect(popup.locator('body')).toContainText(/Seattle|842|itinerary|book/i);
    await approveInPopup(popup);

    await expect(page.locator('div.alert.alert-success strong').filter({ hasText: /\b200\b/ })).toBeVisible({ timeout: 90_000 });
    await expect(page.locator('body')).toContainText('r3_uri');
    await expect(page.locator('body')).toContainText('r3_granted');
    await expect(page.locator('body')).toContainText('r3_conditional');
    await expect(page.locator('body')).toContainText('approved_proposal_s256');

    const finalText = await page.locator('pre code.language-json').last().innerText();
    expect(finalText).toContain('SEA-2026-09-18-A');
    expect(finalText).toContain('approved_proposal_s256');
  });
});
