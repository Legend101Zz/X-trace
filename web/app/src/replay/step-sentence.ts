import honesty from '../../../../schema/fixtures/replay/honesty-strings.json';
import { displaySymbol } from './display-symbol';
import type { ReplayEvent } from '../types';

type StepEvidence = Pick<ReplayEvent, 'kind' | 'symbol' | 'line' | 'depth' | 'interaction' | 'gap' | 'exception'>;

export interface StepSentence {
  text: string;
  depth: number | null;
  gap: { wording: string; reason: string | null } | null;
}

function observedGap(gap: StepEvidence['gap']): StepSentence['gap'] {
  const reason = gap?.reason;
  return {
    wording: honesty.markers.gap,
    reason: reason && Object.hasOwn(honesty.gapReasons, reason)
      ? honesty.gapReasons[reason as keyof typeof honesty.gapReasons]
      : null,
  };
}

/** Provisional short labels until the owner approves the copy table. Why text comes from the shared fixture. */
export function stepSentence(event: StepEvidence): StepSentence {
  const kind = event.kind.startsWith('recording_event_kind:') ? event.kind.slice('recording_event_kind:'.length) : event.kind;
  const depth = typeof event.depth === 'number' && Number.isInteger(event.depth) && event.depth >= 0 ? event.depth : null;
  const result = (text: string, gap: StepSentence['gap'] = null): StepSentence => ({ text, depth, gap });
  const interaction = event.interaction;
  const symbol = event.symbol ? displaySymbol(event.symbol) : null;

  switch (kind) {
    case 'request_update': return result('Request updated');
    case 'frame_enter': return result(symbol ? `Called ${symbol}` : 'Call recorded');
    case 'frame_exit': return result(symbol ? `Returned from ${symbol}` : 'Return recorded');
    case 'frame_throw':
    case 'exception': {
      const type = event.exception?.exceptionType;
      return result(type ? `Threw ${type}` : 'Exception recorded');
    }
    case 'line_cursor':
      return result(typeof event.line === 'number' && Number.isInteger(event.line) && event.line > 0 ? `Ran line ${event.line}` : 'Line number unavailable');
    case 'value_snapshot': return result('Value snapshot recorded');
    case 'database_start':
    case 'database_end': {
      const location = interaction?.table ? [interaction.schema, interaction.table].filter(Boolean).join('.') : interaction?.schema;
      const phase = kind === 'database_start' ? 'Database call started' : 'Database call ended';
      return result(location ? `${phase} · ${location}` : phase);
    }
    case 'outbound_http_start':
    case 'outbound_http_end': {
      const target = [interaction?.method, interaction?.host].filter(Boolean).join(' ');
      const phase = kind === 'outbound_http_start' ? 'HTTP call started' : 'HTTP call ended';
      return result(target ? `${phase} · ${target}` : phase);
    }
    case 'async_link': return result('Async link recorded');
    case 'response': return result('Response event recorded');
    case 'gap': {
      const count = event.gap?.count;
      const wording = observedGap(event.gap);
      return result(count && /^(0|[1-9]\d*)$/.test(count)
        ? `${count} ${count === '1' ? 'event was' : 'events were'} not recorded here`
        : 'Events were not recorded here', wording);
    }
    case 'unspecified': return result('Event kind unavailable');
    default: return result(event.kind ? 'Event recorded' : 'Event kind unavailable');
  }
}
