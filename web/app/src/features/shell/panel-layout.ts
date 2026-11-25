export const PANEL_LAYOUT_KEY = 'xtrace.viewer.panels';
export const DEFAULT_PANELS = { requests: 22, code: 50, inspector: 26 };
export const PANEL_LIMITS = { requests: [16, 32], code: [28, 72], inspector: [18, 40] } as const;
export type Panel = keyof typeof DEFAULT_PANELS;
export type PanelSizes = typeof DEFAULT_PANELS;
export interface PanelLayout {
  sizes: PanelSizes;
  lastOpen: PanelSizes;
}

export const DEFAULT_LAYOUT: PanelLayout = { sizes: DEFAULT_PANELS, lastOpen: DEFAULT_PANELS };

export function clampPanel(panel: Panel, value: number): number {
  const [min, max] = PANEL_LIMITS[panel];
  return Math.max(min, Math.min(max, Math.round(value)));
}

function readSize(input: unknown, panel: Panel, canCollapse: boolean): number {
  const value: unknown = input && typeof input === 'object' ? Reflect.get(input, panel) : undefined;
  if (typeof value !== 'number' || !Number.isFinite(value)) return DEFAULT_PANELS[panel];
  return canCollapse && value === 0 ? 0 : clampPanel(panel, value);
}

export function readPanelLayout(): PanelLayout {
  try {
    const saved: unknown = JSON.parse(window.localStorage.getItem(PANEL_LAYOUT_KEY) ?? 'null');
    if (!saved || typeof saved !== 'object') return DEFAULT_LAYOUT;
    const sizes = { ...DEFAULT_PANELS };
    const lastOpen = { ...DEFAULT_PANELS };
    const restoration: unknown = Reflect.get(saved, 'lastOpen');
    for (const panel of Object.keys(sizes) as Panel[]) {
      sizes[panel] = readSize(saved, panel, true);
      lastOpen[panel] = sizes[panel] || readSize(restoration, panel, false);
    }
    return { sizes, lastOpen };
  } catch {
    return DEFAULT_LAYOUT;
  }
}

export function savePanelLayout(layout: PanelLayout): void {
  try {
    window.localStorage.setItem(PANEL_LAYOUT_KEY, JSON.stringify({ ...layout.sizes, lastOpen: layout.lastOpen }));
  } catch {
    // Resizing remains available in this session.
  }
}
