import { readFileSync } from 'node:fs';

const stylesheet = readFileSync(new URL('../src/style.css', import.meta.url), 'utf8');
const color = (name) => {
  const value = stylesheet.match(new RegExp(`${name}:\\s*(#[0-9a-fA-F]{6})`))?.[1];
  if (!value) throw new Error(`Missing ${name} color token in viewer stylesheet`);
  return value;
};
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
// Every text token against every surface it is drawn on (WCAG AA 1.4.3, 4.5:1), and the
// non-text marks (edges, borders that carry meaning) against the drawing surface (1.4.11, 3:1).
const surfaces = ['--bg', '--panel', '--panel-raised'];
const textTokens = ['--text', '--muted', '--quiet', '--amber', '--danger', '--good'];
const lines = [];
for (const token of textTokens) {
  for (const surface of surfaces) {
    const ratio = ratioOf(color(token), color(surface));
    if (ratio < 4.5) throw new Error(`${token} on ${surface} is ${ratio.toFixed(2)}:1; WCAG AA requires 4.5:1`);
    lines.push(`${token} on ${surface}: ${ratio.toFixed(2)}:1`);
  }
}
for (const token of ['--quiet', '--amber']) {
  const ratio = ratioOf(color(token), color('--panel'));
  if (ratio < 3) throw new Error(`${token} mark on --panel is ${ratio.toFixed(2)}:1; WCAG 1.4.11 requires 3:1`);
  lines.push(`${token} mark on --panel: ${ratio.toFixed(2)}:1 (non-text)`);
}
process.stdout.write(`contrast (WCAG AA): ${lines.length} token pairs pass\n${lines.join('\n')}\n`);
