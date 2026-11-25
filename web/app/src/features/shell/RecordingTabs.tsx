import type { KeyboardEvent } from 'react';
import type { Endpoint } from '../../types';

export interface OpenRecording {
  id: string;
  endpoint: Endpoint | null;
}

export function RecordingTabs({ recordings, selected, onSelect, onClose }: {
  recordings: readonly OpenRecording[];
  selected: string;
  onSelect: (id: string) => void;
  onClose: (id: string) => void;
}) {
  function handleKey(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const { key } = event;
    if (key === 'Delete') {
      event.preventDefault();
      onClose(recordings[index].id);
      return;
    }
    const next = key === 'Home' ? 0 : key === 'End' ? recordings.length - 1
      : key === 'ArrowRight' ? (index + 1) % recordings.length
        : key === 'ArrowLeft' ? (index + recordings.length - 1) % recordings.length : null;
    if (next === null) return;
    event.preventDefault();
    const id = recordings[next].id;
    onSelect(id);
    document.getElementById(`open-recording-${id}`)?.focus();
  }

  if (recordings.length === 0) return null;
  return <div className="recording-tabs">
    <div className="recording-tabs-list" role="tablist" aria-label="Open recordings">
      {recordings.map(({ id, endpoint }, index) => <button key={id} type="button" role="tab"
        id={`open-recording-${id}`} tabIndex={id === selected ? 0 : -1} aria-selected={id === selected}
        aria-controls="events-panel" className="open-recording" onClick={() => onSelect(id)}
        onKeyDown={(event) => handleKey(event, index)}>
        {endpoint ? `${endpoint.method} ${endpoint.routeTemplate} · ` : ''}{id}
      </button>)}
    </div>
    {selected ? <button type="button" className="button" onClick={() => onClose(selected)}>Close recording</button> : null}
  </div>;
}
