import type { Recording } from '../../types';

export function RecordingRows({ items, selected, onSelect }: { items: Recording[]; selected: string; onSelect: (id: string) => void }) {
  return <div className="recording-list">{items.map((recording) => <button className="recording" key={recording.recordingId} aria-current={selected === recording.recordingId} onClick={() => onSelect(recording.recordingId)}>
    <span className={`status-mark status-mark--${recording.status}`} aria-hidden="true" />
    <span><span className="recording-title">{recording.recordingId}</span><span className="recording-sub">{recording.eventCount} persisted events · {recording.openedAt}</span><span className="recording-status">{recording.status}</span>{recording.unmatchedReason ? <span className="recording-reason">{recording.unmatchedReason}</span> : recording.operationId === null ? <span className="recording-reason">No historical reason recorded</span> : null}</span>
  </button>)}</div>;
}
