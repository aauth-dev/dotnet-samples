import { expect, Locator, Page } from '@playwright/test';

export async function expectSyntaxHighlighted(code: Locator): Promise<void> {
  await expect(code).toHaveClass(/\bhljs\b/, { timeout: 15_000 });
  expect(await code.locator('span[class^="hljs-"]').count()).toBeGreaterThan(0);
}

export async function expectReadableLinks(page: Page): Promise<void> {
  const failures = await page.locator('a:visible').evaluateAll(links => {
    const rgba = (value: string): number[] | null => {
      const match = value.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?/);
      return match ? [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4] ?? 1)] : null;
    };
    const luminance = (color: number[]) => {
      const channels = color.map(value => {
        const normalized = value / 255;
        return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
    };
    const contrast = (foreground: number[], background: number[]) => {
      const lighter = Math.max(luminance(foreground), luminance(background));
      const darker = Math.min(luminance(foreground), luminance(background));
      return (lighter + 0.05) / (darker + 0.05);
    };

    return links.flatMap(link => {
      const foreground = rgba(getComputedStyle(link).color);
      let ancestor: Element | null = link;
      const layers: number[][] = [];
      let gradient = false;
      while (ancestor) {
        const style = getComputedStyle(ancestor);
        if (style.backgroundImage !== 'none') gradient = true;
        const layer = rgba(style.backgroundColor);
        if (layer && layer[3] > 0) layers.push(layer);
        if (layer?.[3] === 1) break;
        ancestor = ancestor.parentElement;
      }
      if (!foreground || gradient) return [];
      const background = layers.reverse().reduce(
        (base, layer) => layer.slice(0, 3).map((channel, index) => channel * layer[3] + base[index] * (1 - layer[3])),
        [255, 255, 255],
      );
      const ratio = contrast(foreground, background);
      return ratio < 4.5 ? [{ text: link.textContent?.trim().slice(0, 60), ratio }] : [];
    });
  });
  expect(failures).toEqual([]);
}
