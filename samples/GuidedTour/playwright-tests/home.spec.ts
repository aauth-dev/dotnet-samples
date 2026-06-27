import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive } from '../../../tests/e2e/helpers/blazor';

/**
 * Overview (home) page specs.
 *
 * The GuidedTour root `/` is a static landing page that introduces Aria and the
 * overall narrative, then indexes every flow as a card linking into the live
 * walkthrough at `/tour?flow=<Mode>`. These specs assert the index is complete
 * and that a card deep-links into the matching flow.
 */

const FLOWS = [
  'Bootstrap',
  'Identity',
  'ResourceManaged',
  'Autonomous',
  'Deferred',
  'CallChain',
  'Federated',
  'Mission',
  'MissionCallChain',
  'SubAgent',
] as const;

test('overview introduces Aria and indexes every flow', async ({ page }) => {
  await page.goto('/');

  // Intro: Aria narrative + the role of the guided tour.
  await expect(page.locator('header.topbar h1')).toHaveText('AAuth Guided Tour');
  await expect(page.locator('.intro h2')).toContainText('Meet Aria');
  await expect(page.locator('.intro')).toContainText('AI travel assistant');
  await expect(page.locator('.intro')).toContainText('for real');

  // The five Aria servers are introduced.
  const servers = page.locator('.intro__servers .srv');
  await expect(servers).toHaveText(['Profile', 'Inbox', 'Calendar', 'Trips', 'Wallet']);

  // One card per flow, each deep-linking into the tour.
  const cards = page.locator('.flow-card');
  await expect(cards).toHaveCount(FLOWS.length);

  for (let i = 0; i < FLOWS.length; i++) {
    const card = cards.nth(i);
    await expect(card).toHaveAttribute('href', `tour?flow=${FLOWS[i]}`);
    await expect(card.locator('.flow-card__num')).toHaveText(String(i + 1));
    await expect(card.locator('.flow-card__title')).not.toBeEmpty();
    await expect(card.locator('.flow-card__what')).not.toBeEmpty();
  }
});

test('a flow card deep-links into that flow in the tour', async ({ page }) => {
  await page.goto('/');

  // Open the Mission card.
  await page.locator('.flow-card', { hasText: 'Mission — PS-Governed' }).click();

  await expect(page).toHaveURL(/\/tour\?flow=Mission$/);
  await expect(page.locator('header.topbar h1')).toHaveText('AAuth Guided Tour');

  // The tour preselects the linked flow once the circuit is interactive.
  await waitForInteractive(page, 'button.primary');
  await expect(page.locator('select#flow-select')).toHaveValue('Mission');

  // The Overview link returns to the landing page.
  await page.locator('.topbar__back').click();
  await expect(page.locator('.intro h2')).toContainText('Meet Aria');
});
