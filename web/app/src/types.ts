import type { components } from './api.generated';

export type Recording = components['schemas']['ObservedRecording'];
export type Endpoint = components['schemas']['ObservedEndpoint'];
export type Detail = components['schemas']['RecordingDetail'];
export type ReplayEvent = Detail['events'][number];
export type Pane = 'recordings' | 'events' | 'evidence';
export type CatalogMode = 'endpoints' | 'linked' | 'unmatched';
export type AuthState = 'checking' | 'ready' | 'expired' | 'error';

export const MAX_RETAINED_ROWS = 500;
export const MAX_RETAINED_EVENTS = 2_000;
