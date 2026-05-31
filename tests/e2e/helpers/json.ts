import { Locator, Page, expect } from '@playwright/test';

/**
 * Output-assertion helpers shared across SampleApp specs.
 *
 * Each demo page renders the result in a Bootstrap alert plus a JSON code
 * block:
 *   <div class="alert alert-success|alert-warning"><strong>{status}</strong></div>
 *   <pre><code class="language-json">{pretty JSON}</code></pre>
 * Errors render as <div class="alert alert-danger">{message}</div>.
 */

/** Read and JSON-parse the rendered `pre > code.language-json` block. */
export async function readResponseJson(page: Page): Promise<unknown> {
  const code = page.locator('pre code.language-json').first();
  await expect(code).toBeVisible();
  const text = await code.innerText();
  return JSON.parse(text);
}

/** Assert the status alert contains the given HTTP status code (e.g. 200). */
export async function expectStatus(
  page: Page,
  code: number,
  timeout = 15_000,
): Promise<void> {
  const alert = page.locator('div.alert', { hasText: String(code) }).first();
  await expect(alert).toBeVisible({ timeout });
}

/** Assert a success (2xx) result alert is shown. */
export function successAlert(page: Page): Locator {
  return page.locator('div.alert.alert-success');
}

/** Assert an error (alert-danger) is shown with optional substring. */
export async function expectError(page: Page, contains?: string): Promise<void> {
  const danger = page.locator('div.alert.alert-danger').first();
  await expect(danger).toBeVisible();
  if (contains) {
    await expect(danger).toContainText(contains);
  }
}
