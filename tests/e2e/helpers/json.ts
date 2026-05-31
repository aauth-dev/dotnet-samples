import { Page, expect } from '@playwright/test';

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
  // The result alert renders the status in a <strong> ("200 OK"). Scope to that
  // element with a word-boundary match so a bare "200" elsewhere on the page
  // can't satisfy the assertion.
  const status = page
    .locator('div.alert.alert-success strong, div.alert.alert-warning strong')
    .filter({ hasText: new RegExp(`\\b${code}\\b`) })
    .first();
  await expect(status).toBeVisible({ timeout });
}

/** Assert an error (alert-danger) is shown with optional substring. */
export async function expectError(page: Page, contains?: string): Promise<void> {
  const danger = page.locator('div.alert.alert-danger').first();
  await expect(danger).toBeVisible();
  if (contains) {
    await expect(danger).toContainText(contains);
  }
}
