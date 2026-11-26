import honesty from '../../../../schema/fixtures/replay/honesty-strings.json';
import type { ReplayEvent } from '../types';

export type Binding = ReplayEvent['bindings'][number];

function explanation(dictionary: Readonly<Record<string, string>>, key: string): string | null {
  return Object.hasOwn(dictionary, key) ? dictionary[key] : null;
}

/** State labels are provisional; explanations are the exact shared copy. */
export function valueEvidence(binding: Binding) {
  const value = binding.value;
  switch (value?.state) {
    case 'captured':
      return { state: value.state, label: 'Captured', preview: value.preview, wording: null, reason: null };
    case 'truncated':
      return { state: value.state, label: 'Cut short', preview: value.preview, wording: honesty.markers.truncated, reason: null };
    case 'redacted':
      return { state: value.state, label: 'Hidden', preview: null, wording: honesty.markers.redacted, reason: null };
    case 'dropped':
      return { state: value.state, label: 'Dropped', preview: null, wording: honesty.markers.dropped,
        reason: explanation(honesty.dropReasons, value.reason) ?? 'Reason unavailable' };
    case 'unavailable':
      return { state: value.state, label: 'Not captured', preview: null, wording: honesty.markers.unavailable,
        reason: explanation(honesty.unavailableReasons, value.reason) ?? 'Reason unavailable' };
    default:
      return { state: 'unavailable', label: 'Not captured', preview: null, wording: honesty.markers.unavailable, reason: 'Reason unavailable' };
  }
}
