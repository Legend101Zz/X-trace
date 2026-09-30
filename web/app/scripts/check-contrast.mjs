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

const foreground = luminance(color('--quiet'));
const background = luminance(color('--bg'));
const ratio = (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05);
if (ratio < 4.5) {
  throw new Error(`Quiet metadata contrast is ${ratio.toFixed(2)}:1; WCAG AA requires 4.5:1`);
}
process.stdout.write(`quiet metadata contrast: ${ratio.toFixed(2)}:1 (WCAG AA)\n`);
