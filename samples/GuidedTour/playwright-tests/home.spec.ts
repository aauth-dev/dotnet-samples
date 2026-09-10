import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { waitForInteractive } from '../../../tests/e2e/helpers/blazor';
import { openTour, selectFlow, TourMode } from '../../../tests/e2e/helpers/tour';
import { expectReadableLinks } from '../../../tests/e2e/helpers/visual-style';

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
  'RichRequests',
  'Mission',
  'MissionCallChain',
  'SubAgent',
] as const;

const CAPABILITIES: Array<[string, string]> = [
  ['Bookings Events', '/events'],
  ['Wallet Protocol', '/wallet-protocol'],
  ['Document Release', '/documents'],
  ['Travel Catalog', '/catalog-gateway'],
];

const TOUR_MODES = Object.values(TourMode);

test('overview introduces Aria and indexes every flow', async ({ page }) => {
  await page.goto('/');

  // Intro: Aria narrative + the role of the guided tour.
  await expect(page.locator('header.topbar h1')).toHaveText('AAuth Guided Tour');
  await expect(page.locator('.intro h2')).toContainText('Meet Aria');
  await expect(page.locator('.intro')).toContainText('AI travel assistant');
  await expect(page.locator('.intro')).toContainText('for real');
  await expectReadableLinks(page);

  // Every focused Aria resource is introduced.
  const servers = page.locator('.intro__servers .srv');
  await expect(servers).toHaveText([
    'Profile', 'Inbox', 'Calendar', 'Trips', 'Wallet', 'Bookings', 'Catalog', 'Documents',
    'Concierge', 'Agent Provider', 'Person Server', 'Federated Access Server', 'R3 Access Server',
    'User / Browser', 'Original / Parent / Worker',
  ]);

  // The original flows and new capability walkthroughs share one card index.
  const cards = page.locator('.flow-card');
  await expect(cards).toHaveCount(FLOWS.length + CAPABILITIES.length);

  for (let i = 0; i < FLOWS.length; i++) {
    const card = cards.nth(i);
    await expect(card).toHaveAttribute('href', `tour?flow=${FLOWS[i]}`);
    await expect(card.locator('.flow-card__num')).toHaveText(String(i + 1));
    await expect(card.locator('.flow-card__title')).not.toBeEmpty();
    await expect(card.locator('.flow-card__what')).not.toBeEmpty();
  }

  for (let i = 0; i < CAPABILITIES.length; i++) {
    const [title, href] = CAPABILITIES[i];
    const card = cards.nth(FLOWS.length + i);
    await expect(card).toContainText(title);
    await expect(card).toHaveAttribute('href', href);
    await expect(card.locator('.flow-card__num')).toHaveText(String(FLOWS.length + i + 1));
    await expect(card.locator('.flow-card__what')).toContainText('Aria');
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

test('every tour flow aligns a full-height tramline under each participant', async ({ page }, testInfo) => {
  await openTour(page);
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 844 });
    for (const mode of TOUR_MODES) {
      await selectFlow(page, mode);
      const lanes = page.locator('.lanes .lane');
      const tramlines = page.locator('.messages > .tramline');
      await expect(tramlines).toHaveCount(await lanes.count());
      const alignment = await page.locator('.seq').evaluate(sequence => {
        const laneNodes = Array.from(sequence.querySelectorAll<HTMLElement>('.lanes .lane'));
        const lineNodes = Array.from(sequence.querySelectorAll<HTMLElement>('.messages > .tramline'));
        return laneNodes.map((lane, index) => {
          const laneRect = lane.getBoundingClientRect();
          const lineRect = lineNodes[index].getBoundingClientRect();
          return {
            offset: Math.abs(laneRect.x + laneRect.width / 2 - (lineRect.x + lineRect.width / 2)),
            height: lineRect.height,
            visible: getComputedStyle(lineNodes[index]).backgroundColor !== 'rgba(0, 0, 0, 0)',
          };
        });
      });
      for (const line of alignment) {
        expect(line.offset).toBeLessThanOrEqual(1);
        expect(line.height).toBeGreaterThanOrEqual(190);
        expect(line.visible).toBe(true);
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
      await page.locator('.seq').screenshot({ path: testInfo.outputPath(`tramlines-${mode}-${width}.png`) });
    }
  }
});
