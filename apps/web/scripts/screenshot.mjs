/**
 * Regenerates docs/screenshot.png (the README hero): Explore view with the
 * demo cascade loaded and a package selected, light theme, 1360×850 @2x.
 * Uses the locally installed Chrome via playwright-core (no browser
 * download). A dev server must be running:
 *
 *   npm run dev            # in another terminal
 *   npm run screenshot -w @sbomlens/web
 */
import { chromium } from 'playwright-core';

const url = process.env.SCREENSHOT_URL ?? 'http://localhost:5173';
const target = new URL('../../../docs/screenshot.png', import.meta.url);

const browser = await chromium.launch({ channel: 'chrome' });
try {
  const page = await browser.newPage({
    viewport: { width: 1360, height: 850 },
    deviceScaleFactor: 2,
    colorScheme: 'light',
  });
  await page.goto(url);
  await page.getByRole('button', { name: 'Load example' }).click();
  await page.waitForSelector('[role="treeitem"]');

  // Expand the platform package and select webstack — shows the cascade,
  // a cross-document badge, and a filled detail pane.
  await page.getByText('ACME Platform', { exact: false }).first().click();
  await page.keyboard.press('ArrowRight');
  const webstack = page.getByRole('treeitem').filter({ hasText: 'webstack' }).first();
  await webstack.click();
  // Dismiss any toasts (resolution notices) so the shot is clean.
  await page.waitForTimeout(400);
  for (const dismiss of await page.locator('.fixed.bottom-10 button').all()) {
    await dismiss.click().catch(() => {});
  }
  await page.waitForTimeout(250);

  await page.screenshot({ path: target.pathname });
  console.log(`wrote ${target.pathname}`);
} finally {
  await browser.close();
}
