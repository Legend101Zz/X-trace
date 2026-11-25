import type { ReplayEvent } from '../../types';
import type { Binding } from '../../replay/value-evidence';
import { recordedLine } from '../../replay/source-rows';

const identifier = /[\p{L}\p{Nl}\p{Sc}\p{Pc}][\p{L}\p{Nl}\p{Sc}\p{Pc}\p{Mn}\p{Mc}\p{Nd}\p{Cf}]*/uy;
const redactionMarker = '[redacted by x-trace]';

interface NameMatch {
  from: number;
  to: number;
  binding: Binding;
}

/** Return exact displayed Java identifier spans. An unknown lexical prefix cannot certify code. */
export function javaNameMatches(event: ReplayEvent): NameMatch[] {
  const source = event.source;
  const line = recordedLine(event);
  if (source?.status !== 'matched' || source.truncated || !source.path.endsWith('.java')
      || source.startLine !== 1 || line === null || typeof source.excerpt !== 'string') return [];
  const excerpt = source.excerpt;
  // Java translates Unicode escapes before tokenization, including inside comments. A
  // redacted prefix can also conceal a delimiter, so decline either ambiguous projection.
  if (excerpt.includes(redactionMarker) || /\\u|[\x00-\x08\x0E-\x1B\x7F-\x9F]/.test(excerpt)) return [];

  let lineStart = 0;
  for (let number = 1; number < line; number += 1) {
    const newline = excerpt.indexOf('\n', lineStart);
    if (newline < 0) return [];
    lineStart = newline + 1;
  }
  const newline = excerpt.indexOf('\n', lineStart);
  const lineEnd = newline < 0 ? excerpt.length : newline;
  const names = new Map<string, Binding | null>();
  for (const binding of event.bindings ?? []) {
    // Duplicate names are ambiguous even if only one observation has role local.
    names.set(binding.name, names.has(binding.name) ? null : binding);
  }

  const matches: NameMatch[] = [];
  const matchIdentifier = new RegExp(identifier.source, identifier.flags);
  for (let index = 0; index < lineEnd;) {
    const character = excerpt[index];
    if (excerpt.startsWith('//', index)) {
      const end = excerpt.indexOf('\n', index + 2);
      if (end < 0) break;
      index = end + 1;
    } else if (excerpt.startsWith('/*', index)) {
      const end = excerpt.indexOf('*/', index + 2);
      if (end < 0) break;
      index = end + 2;
    } else if (character === '"' || character === "'") {
      const delimiter = excerpt.startsWith('"""', index) ? '"""' : character;
      index += delimiter.length;
      while (index < lineEnd && !excerpt.startsWith(delimiter, index)) {
        if (delimiter.length === 1 && excerpt[index] === '\n') return [];
        index += excerpt[index] === '\\' ? 2 : 1;
      }
      index += delimiter.length;
    } else if (/[0-9]/.test(character)) {
      // Suffixes and hexadecimal digits are part of a literal, never name matches.
      index += 1;
      while (index < lineEnd && /[A-Za-z0-9_.]/.test(excerpt[index])) index += 1;
    } else {
      matchIdentifier.lastIndex = index;
      const token = matchIdentifier.exec(excerpt)?.[0];
      if (!token) {
        index += (excerpt.codePointAt(index) ?? 0) > 0xffff ? 2 : 1;
        continue;
      }
      const binding = names.get(token);
      if (index >= lineStart && binding?.role === 'local' && binding.nameOrigin === 'declared') {
        matches.push({ from: index - lineStart, to: index + token.length - lineStart, binding });
      }
      index += token.length;
    }
  }
  return matches;
}
