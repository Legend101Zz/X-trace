/** Replay-core reducer (selection, filter, playback). Tested in isolation; the App currently dispatches only `set-mode`, selection is still the App's `selectedEvent` index, and filter/playback actions are not wired into production yet. */

export type ReplayMode = 'linear' | 'canvas';
export type PlaybackSpeed = 0.5 | 1 | 2 | 4;

export interface ReplayFilter {
  /** Event kinds to show; empty means no filter (everything). */
  kinds: readonly string[];
}

export interface Playback {
  status: 'paused' | 'playing';
  speed: PlaybackSpeed;
  /** Plain-language reason playback last stopped on its own; null when the person paused or never played. */
  stopReason: string | null;
}

export interface ReplayState {
  operationId: string;
  recordingId: string;
  /** Selected frame; null when no frame is selected. Both views key off this one value. */
  frameId: string | null;
  /** Event sequence of the selected frame (decimal string, as on the wire). */
  sequence: string | null;
  mode: ReplayMode;
  filter: ReplayFilter;
  playback: Playback;
}

export type ReplayAction =
  | { type: 'select-operation'; operationId: string }
  | { type: 'select-recording'; recordingId: string }
  | { type: 'select-frame'; frameId: string | null; sequence: string | null }
  | { type: 'set-mode'; mode: ReplayMode }
  | { type: 'set-filter'; kinds: readonly string[] }
  | { type: 'play' }
  | { type: 'pause' }
  | { type: 'set-speed'; speed: PlaybackSpeed }
  | { type: 'playback-stopped'; reason: string }
  | { type: 'reset' };

const PAUSED: Playback = { status: 'paused', speed: 1, stopReason: null };

export const initialReplayState: ReplayState = {
  operationId: '',
  recordingId: '',
  frameId: null,
  sequence: null,
  mode: 'linear',
  filter: { kinds: [] },
  playback: PAUSED,
};

function clearSelection(state: ReplayState): ReplayState {
  return { ...state, frameId: null, sequence: null, playback: { ...state.playback, status: 'paused', stopReason: null } };
}

export function replayReducer(state: ReplayState, action: ReplayAction): ReplayState {
  switch (action.type) {
    case 'select-operation':
      if (action.operationId === state.operationId) return state;
      return { ...clearSelection(state), operationId: action.operationId, recordingId: '' };
    case 'select-recording':
      if (action.recordingId === state.recordingId) return state;
      return { ...clearSelection(state), recordingId: action.recordingId };
    case 'select-frame':
      // A manual selection ends playback: the person took the wheel.
      return { ...state, frameId: action.frameId, sequence: action.sequence, playback: { ...state.playback, status: 'paused', stopReason: null } };
    case 'set-mode':
      // Mode is a view; it never moves the selection.
      return action.mode === state.mode ? state : { ...state, mode: action.mode };
    case 'set-filter': {
      const kinds = [...new Set(action.kinds)].sort();
      const same = kinds.length === state.filter.kinds.length && kinds.every((kind, index) => kind === state.filter.kinds[index]);
      return same ? state : { ...state, filter: { kinds } };
    }
    case 'play':
      // Nothing to play without a recording and a selected frame.
      if (!state.recordingId || state.frameId === null) return state;
      return { ...state, playback: { ...state.playback, status: 'playing', stopReason: null } };
    case 'pause':
      return state.playback.status === 'paused' ? state : { ...state, playback: { ...state.playback, status: 'paused', stopReason: null } };
    case 'set-speed':
      return { ...state, playback: { ...state.playback, speed: action.speed } };
    case 'playback-stopped':
      return { ...state, playback: { ...state.playback, status: 'paused', stopReason: action.reason } };
    case 'reset':
      return initialReplayState;
  }
}

/** True when a kind passes the filter. An empty filter admits everything. */
export function passesFilter(filter: ReplayFilter, kind: string): boolean {
  return filter.kinds.length === 0 || filter.kinds.includes(kind);
}
