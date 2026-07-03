import { test, expect } from '../../../tests/e2e/helpers/fixtures';
import { openTour, selectFlow, TourMode } from '../../../tests/e2e/helpers/tour';

// Actor-bar visual verification: for each flow, confirm the top actor bar shows
// the CORRECT Aria resource server name + URL, then screenshot the bar +
// swimlanes. Capture-and-assert (not part of the product spec suite).

const cases: Array<{ mode: TourMode; server: string; url: string }> = [
  { mode: TourMode.Identity, server: 'Profile', url: 'http://localhost:5000' },
  { mode: TourMode.ResourceManaged, server: 'Inbox', url: 'http://localhost:5004' },
  { mode: TourMode.Autonomous, server: 'Calendar', url: 'http://localhost:5001' },
  { mode: TourMode.Mission, server: 'Trips', url: 'http://localhost:5002' },
  { mode: TourMode.Federated, server: 'Wallet', url: 'http://localhost:5003' },
  { mode: TourMode.RichRequests, server: 'Bookings', url: 'http://localhost:5005' },
];

for (const { mode, server, url } of cases) {
  test(`actor bar shows ${server} for the ${mode} flow`, async ({ page }) => {
    await openTour(page);
    await selectFlow(page, mode);

    // The resource entry in the top config bar must name the flow's server + URL.
    const resourceEntry = page.locator('header .config span.hl-resource').first();
    await expect(resourceEntry).toContainText(server);
    await expect(resourceEntry).toContainText(url);

    await page.locator('header.topbar').screenshot({ path: `/tmp/actor-bar-${server}.png` });
    await page.screenshot({ path: `/tmp/actor-bar-full-${server}.png`, fullPage: true });
  });
}
