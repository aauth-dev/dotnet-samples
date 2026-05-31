import { Page, expect } from '@playwright/test';

/**
 * Blazor Server (InteractiveServer) readiness helpers.
 *
 * With `@rendermode InteractiveServer`, a page first ships static prerendered
 * HTML; event handlers only work once the SignalR circuit connects and the
 * component re-renders interactively. Interacting before that silently no-ops.
 *
 * The canonical "interactive" signal we use is: the primary action control is
 * present AND enabled. Each page exposes at least one enabled button once its
 * circuit is live, so we wait on that rather than a fixed delay.
 */

/**
 * Wait until the given locator (default: the first enabled primary button) is
 * attached and enabled, signalling the Blazor circuit is interactive.
 */
export async function waitForInteractive(
  page: Page,
  selector = 'button:not([disabled])',
): Promise<void> {
  await expect(page.locator(selector).first()).toBeEnabled({ timeout: 30_000 });
}

/** Navigate to `path` and wait for the circuit to become interactive. */
export async function gotoInteractive(
  page: Page,
  path: string,
  selector = 'button:not([disabled])',
): Promise<void> {
  await page.goto(path);
  await waitForInteractive(page, selector);
}

/**
 * Click a button and confirm the Blazor circuit actually processed the event.
 *
 * Even after `waitForInteractive` reports the button enabled, the very FIRST
 * interactive event on a freshly-connected circuit can be silently dropped
 * (the SignalR circuit accepts input slightly before it dispatches it). This
 * bites the first clicking test in a suite. We click, then wait for a
 * caller-supplied "the click landed" signal; if it never appears we re-click
 * once before giving up.
 */
export async function clickAndConfirm(
  page: Page,
  buttonSelector: string,
  landed: () => Promise<boolean>,
  attempts = 3,
): Promise<void> {
  const button = page.locator(buttonSelector).first();
  for (let i = 0; i < attempts; i++) {
    await button.click();
    try {
      await expect.poll(landed, { timeout: 4_000, intervals: [250, 500, 1000] }).toBe(true);
      return;
    } catch {
      // Click was dropped (cold circuit) — loop and retry.
    }
  }
  // Final attempt: click once more and let the caller's own assertion surface
  // any genuine failure with its full timeout.
  await button.click();
}
