import { readFileSync } from 'node:fs';

const stylesheet = readFileSync(new URL('../src/style.css', import.meta.url), 'utf8');
const luminance = (hex) => {
  const [red, green, blue] = hex.slice(1).match(/.{2}/g).map((part) => parseInt(part, 16) / 255);
  const linear = (channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  return 0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue);
};

const quietStatus = stylesheet.match(/\.recording-status\s*\{([^}]*)\}/s)?.[1] ?? '';
if (!/font:\s*9px/.test(quietStatus) || !/color:\s*var\(--quiet\)/.test(quietStatus)) {
  throw new Error('The nine-pixel recording status must use the audited quiet text token');
}

const ratioOf = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};
// Quiet labels are text at small sizes, and every meaningful edge or mark
// must still be legible along the boundary of each viewer surface.
const surfaces = ['--bg', '--chrome', '--panel', '--panel-raised', '--surface', '--hover', '--select'];
const textTokens = ['--text', '--muted', '--quiet', '--amber', '--danger', '--good'];
const markTokens = ['--line-strong', '--quiet', '--amber', '--danger', '--good', '--muted'];
const lines = [];
for (const [theme, textMinimum] of [['dark', 4.5], ['light', 4.5], ['hc', 7]]) {
  const declaration = stylesheet.match(new RegExp(`:root\\[data-theme="${theme}"\\]\\s*\\{([^}]*)\\}`))?.[1];
  if (!declaration) throw new Error(`Missing ${theme} palette in viewer stylesheet`);
  const palette = new Map(
    Array.from(declaration.matchAll(/^\s*(--[a-z-]+):\s*(#[0-9a-fA-F]{6});/gm), ([, name, value]) => [name, value]),
  );
  const check = (foreground, surface, minimum, description) => {
    const a = palette.get(foreground);
    const b = palette.get(surface);
    if (!a || !b) throw new Error(`Missing color in ${theme}: ${foreground} on ${surface}`);
    const ratio = ratioOf(a, b);
    const label = `${theme} ${foreground} on ${surface} (${description})`;
    if (ratio < minimum) throw new Error(`${label} is ${ratio.toFixed(2)}:1; requires ${minimum}:1`);
    lines.push(`${label}: ${ratio.toFixed(2)}:1`);
  };
  for (const surface of surfaces) {
    for (const token of textTokens) check(token, surface, textMinimum, 'text');
    for (const token of markTokens) check(token, surface, 3, 'non-text');
  }
  check('--on-accent', '--amber', textMinimum, 'text on accent');
}
process.stdout.write(`contrast (WCAG AA, high contrast text ≥ 7:1): ${lines.length} token pairs pass\n${lines.join('\n')}\n`);
