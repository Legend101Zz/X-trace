import { afterEach, expect, it } from 'vitest';
import { clampPanel, DEFAULT_LAYOUT, DEFAULT_PANELS, PANEL_LAYOUT_KEY, readPanelLayout, savePanelLayout } from './panel-layout';

afterEach(() => localStorage.removeItem(PANEL_LAYOUT_KEY));

it('clamps saved panel sizes and restores an intentional collapse', () => {
  localStorage.setItem(PANEL_LAYOUT_KEY, '{"requests":0,"code":200,"inspector":"out-of-range","lastOpen":{"requests":28},"injected":92}');
  expect(readPanelLayout()).toEqual({
    sizes: { requests: 0, code: 72, inspector: DEFAULT_PANELS.inspector },
    lastOpen: { requests: 28, code: 72, inspector: DEFAULT_PANELS.inspector },
  });
});

it('persists a valid layout and falls back for corrupt storage', () => {
  const size = { ...DEFAULT_PANELS, requests: clampPanel('requests', -5) };
  const layout = { sizes: size, lastOpen: size };
  savePanelLayout(layout);
  expect(readPanelLayout()).toEqual(layout);
  localStorage.setItem(PANEL_LAYOUT_KEY, 'broken');
  expect(readPanelLayout()).toEqual(DEFAULT_LAYOUT);
});
