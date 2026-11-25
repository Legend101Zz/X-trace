/** Replay-core reducer for exact event selection, view mode and loaded-step filtering. */

export type ReplayMode = 'linear' | 'canvas';
export type PlaybackSpeed = 0.5 | 1 | 2 | 4;
export const PLAYBACK_SPEEDS: readonly PlaybackSpeed[] = [0.5, 1, 2, 4];

export interface ReplayFilter {
  /** Event kinds to show; empty means no filter (everything). */
  kinds: readonly string[];
}

export interface Playback {
  status: 'paused' | 'playing';
  speed: PlaybackSpeed;
  /** Plain-language reason playback last stopped on its own; null when the person paused or never played. */
  stopReason: string | null;
  /** Invalidates scheduled work even when a manual action selects the same event again. */
  epoch: number;
  /** Identity of the last accepted scheduled advance, used to confirm its side effects. */
  acceptedAdvance?: object;
  /** Identity of the last accepted automatic stop. */
  acceptedStop?: object;
}

export interface ReplayState {
  operationId: string;
  recordingId: string;
  /** Frame containing the selected event, if the event has a frame. */
  frameId: string | null;
  /** Selected event sequence within the recording. Null before an event is selected. */
  sequence: string | null;
  mode: ReplayMode;
  filter: ReplayFilter;
  playback: Playback;
}

export type ReplayAction =
  | { type: 'select-operation'; operationId: string }
  | { type: 'select-recording'; recordingId: string; restore?: Pick<ReplayState, 'frameId' | 'sequence'> }
  | { type: 'initialize-selection'; recordingId: string; frameId: string | null; sequence: string }
  | { type: 'select-frame'; frameId: string | null; sequence: string | null }
  | { type: 'playback-advance'; recordingId: string; fromFrameId: string | null; fromSequence: string; epoch: number; frameId: string | null; sequence: string; advanceId?: object }
  | { type: 'set-mode'; mode: ReplayMode }
  | { type: 'set-filter'; kinds: readonly string[] }
  | { type: 'play' }
  | { type: 'pause' }
  | { type: 'set-speed'; speed: PlaybackSpeed }
  | { type: 'playback-stopped'; reason: string; epoch?: number; stopId?: object }
  | { type: 'reset' };

const PAUSED: Playback = { status: 'paused', speed: 1, stopReason: null, epoch: 0 };

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
  return { ...state, frameId: null, sequence: null, playback: pause(state.playback) };
}

function pause(playback: Playback): Playback {
  return { ...playback, status: 'paused', stopReason: null, epoch: playback.epoch + 1 };
}

export function replayReducer(state: ReplayState, action: ReplayAction): ReplayState {
  switch (action.type) {
    case 'select-operation':
      if (action.operationId === state.operationId) return state;
      return { ...clearSelection(state), operationId: action.operationId, recordingId: '' };
    case 'select-recording':
      if (action.recordingId === state.recordingId) return state;
      return { ...clearSelection(state), recordingId: action.recordingId, ...action.restore };
    case 'initialize-selection':
      if (state.recordingId !== action.recordingId || state.sequence !== null) return state;
      return { ...state, frameId: action.frameId, sequence: action.sequence };
    case 'select-frame':
      // A manual selection ends playback: the person took the wheel.
      return { ...state, frameId: action.frameId, sequence: action.sequence,
        playback: { ...pause(state.playback), acceptedAdvance: undefined } };
    case 'playback-advance':
      if (state.playback.status !== 'playing' || state.playback.epoch !== action.epoch || state.recordingId !== action.recordingId
        || state.sequence !== action.fromSequence || state.frameId !== action.fromFrameId) return state;
      return { ...state, frameId: action.frameId, sequence: action.sequence, playback: { ...state.playback, epoch: state.playback.epoch + 1,
        ...(action.advanceId ? { acceptedAdvance: action.advanceId } : {}) } };
    case 'set-mode':
      // Reproject the same playback state, but retire work scheduled for the old view.
      return action.mode === state.mode ? state
        : { ...state, mode: action.mode, playback: { ...state.playback, epoch: state.playback.epoch + 1 } };
    case 'set-filter': {
      const kinds = [...new Set(action.kinds)].sort();
      const same = kinds.length === state.filter.kinds.length && kinds.every((kind, index) => kind === state.filter.kinds[index]);
      return same ? state : { ...state, filter: { kinds }, playback: pause(state.playback) };
    }
    case 'play':
      // A recorded event can be frame-less; sequence, not a fabricated frame, is its identity.
      if (!state.recordingId || state.sequence === null) return state;
      return { ...state, playback: { ...state.playback, status: 'playing', stopReason: null, epoch: state.playback.epoch + 1 } };
    case 'pause':
      return { ...state, playback: pause(state.playback) };
    case 'set-speed':
      return !PLAYBACK_SPEEDS.includes(action.speed) || action.speed === state.playback.speed ? state
        : { ...state, playback: { ...state.playback, speed: action.speed, epoch: state.playback.epoch + 1 } };
    case 'playback-stopped':
      if (action.epoch !== undefined && action.epoch !== state.playback.epoch) return state;
      return { ...state, playback: { ...pause(state.playback), stopReason: action.reason,
        ...(action.stopId ? { acceptedStop: action.stopId } : {}) } };
    case 'reset':
      return initialReplayState;
  }
}

/** True when a kind passes the filter. An empty filter admits everything. */
export function passesFilter(filter: ReplayFilter, kind: string): boolean {
  return filter.kinds.length === 0 || filter.kinds.includes(kind);
}
