//! Private, bounded append journal for the one unfinished segment of a recording.
//!
//! XTF objects remain immutable. Only the current tail is appendable: each
//! envelope has a length and digest, and an incomplete final append is ignored
//! on recovery. Acknowledgement follows file sync, never merely a write.

use std::io::{Seek as _, SeekFrom};

use prost::Message as _;
use xtrace_application::recording::{
    DEFAULT_SEGMENT_EVENT_BYTES, DEFAULT_SEGMENT_EVENTS, PersistRecordingSegment,
};
use xtrace_protocol::xtf::XtfEventEnvelope;

use super::*;

const MAGIC: &[u8; 8] = b"XTRTAIL1";
const HEADER_BYTES: usize = 44;
const MAX_JOURNAL_BYTES: usize =
    HEADER_BYTES + DEFAULT_SEGMENT_EVENT_BYTES + DEFAULT_SEGMENT_EVENTS * 32;

#[cfg(test)]
thread_local! {
    static JOURNAL_SYNCS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn take_sync_count() -> usize {
    JOURNAL_SYNCS.with(|count| count.replace(0))
}

/// A checkpoint is installed only after file and creation-directory sync.
/// Digests prevent an ambiguous retry from changing an already written prefix.
#[derive(Debug)]
pub(crate) struct Checkpoint {
    ordinal: u32,
    length: u64,
    digests: Vec<[u8; 32]>,
    first_sequence: u64,
    identities: HashSet<String>,
}

struct Tail {
    project_id: ProjectId,
    ordinal: u32,
    events: Vec<XtfEventEnvelope>,
    length: u64,
}

fn directory(
    binding: &ProjectRootBinding,
    create: bool,
    id: CorrelationId,
) -> Result<Option<AdmittedPrivateRoot>, RecordingStoreError> {
    binding.revalidate(id)?;
    let root = AdmittedPrivateRoot::open(&binding.root).map_err(|_| object_io_error(id))?;
    if create {
        if std::fs::symlink_metadata(binding.root.join("journals")).is_ok() {
            return root.open_private_child("journals").map(Some).map_err(|_| object_io_error(id));
        }
        let child =
            root.open_or_create_private_child("journals").map_err(|_| object_io_error(id))?;
        root.sync().map_err(|_| object_io_error(id))?;
        Ok(Some(child))
    } else {
        match std::fs::symlink_metadata(binding.root.join("journals")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(object_io_error(id)),
            Ok(_) => root.open_private_child("journals").map(Some).map_err(|_| object_io_error(id)),
        }
    }
}

fn name(recording_id: RecordingId) -> String {
    format!("{}.tail", recording_id.as_uuid())
}

fn load(
    binding: &ProjectRootBinding,
    recording_id: RecordingId,
    id: CorrelationId,
) -> Result<Option<Tail>, RecordingStoreError> {
    let Some(root) = directory(binding, false, id)? else { return Ok(None) };
    let name = name(recording_id);
    match std::fs::symlink_metadata(root.path().join(&name)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(object_io_error(id)),
        Ok(_) => {}
    }
    let bytes =
        root.read_bounded_file(&name, MAX_JOURNAL_BYTES).map_err(|_| object_io_error(id))?;
    // A crash during initial header creation cannot have acknowledged events.
    if bytes.len() < HEADER_BYTES {
        return Ok(None);
    }
    if &bytes[..8] != MAGIC || &bytes[24..40] != recording_id.as_uuid().as_bytes() {
        return Err(object_corrupt_error(id));
    }
    let project_id = project_id_from_bytes(&bytes[8..24], id)?;
    let ordinal =
        u32::from_be_bytes(bytes[40..44].try_into().map_err(|_| object_corrupt_error(id))?);
    if u64::from(ordinal) >= MAX_RECORDING_QUERY_SEGMENTS {
        return Err(object_corrupt_error(id));
    }
    let mut events = Vec::new();
    let mut offset = HEADER_BYTES;
    while bytes.len().saturating_sub(offset) >= 4 {
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4].try_into().map_err(|_| object_corrupt_error(id))?,
        ) as usize;
        let end = offset
            .checked_add(4)
            .and_then(|value| value.checked_add(length))
            .ok_or_else(|| object_corrupt_error(id))?;
        let Some(digest_end) = end.checked_add(32) else { return Err(object_corrupt_error(id)) };
        if digest_end > bytes.len() {
            break;
        }
        let payload = &bytes[offset + 4..end];
        if blake3::hash(payload).as_bytes() != &bytes[end..digest_end] {
            return Err(object_corrupt_error(id));
        }
        let envelope = XtfEventEnvelope::decode(payload).map_err(|_| object_corrupt_error(id))?;
        if envelope.encode_to_vec() != payload
            || envelope
                .event
                .as_ref()
                .is_none_or(|event| event.recording_seq != envelope.recording_seq)
        {
            return Err(object_corrupt_error(id));
        }
        if let Some(previous) =
            events.last().and_then(|envelope: &XtfEventEnvelope| envelope.event.as_ref())
        {
            if previous.recording_seq.checked_add(1)
                != envelope.event.as_ref().map(|event| event.recording_seq)
            {
                return Err(object_corrupt_error(id));
            }
        }
        events.push(envelope);
        if events.len() > DEFAULT_SEGMENT_EVENTS {
            return Err(object_corrupt_error(id));
        }
        offset = digest_end;
    }
    Ok(Some(Tail { project_id, ordinal, events, length: offset as u64 }))
}

impl SqliteRecordingStore<'_> {
    pub(crate) fn persist_capture_cap(
        &self,
        recording_id: RecordingId,
        cap: usize,
    ) -> Result<(), RecordingStoreError> {
        let id = CorrelationId::new();
        if !event_cap_in_bounds(cap as u64) {
            return Err(terminal_validation_error(id));
        }
        let _writer =
            self.store.lock_recording_writer(id).map_err(|error| map_store_error(error, id))?;
        {
            let connection = self.store.lock().map_err(|error| map_store_error(error, id))?;
            let status: Option<String> = connection
                .query_row(
                    "SELECT status FROM recordings WHERE recording_id = ?1",
                    rusqlite::params![recording_id.as_uuid().as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| map_store_error(StoreError::from_rusqlite(error, id), id))?;
            match status.as_deref() {
                Some("recording") => {}
                Some(_) => return Ok(()), // Never retrofit policy onto terminal legacy evidence.
                None => return Err(read_not_found_error(id)),
            }
        }
        let root = directory(&self.binding, true, id)?.ok_or_else(|| object_io_error(id))?;
        let name = format!("{}.cap", recording_id.as_uuid());
        let expected = (cap as u64).to_be_bytes();
        let mut file = root.open_or_create_private_file(&name).map_err(|_| object_io_error(id))?;
        let stored = root.read_bounded_file(&name, 8).map_err(|_| object_io_error(id))?;
        if !expected.starts_with(&stored) {
            return Err(segment_conflict_error(id));
        }
        if stored.len() < expected.len() {
            file.write_all(&expected).map_err(|_| object_io_error(id))?;
        }
        // Also sync an exact retry: a previous sync may have failed ambiguously.
        file.sync_all().map_err(|_| object_io_error(id))?;
        root.validate_file_binding(&name, &file, true).map_err(|_| object_io_error(id))?;
        root.sync().map_err(|_| object_io_error(id))?;
        AdmittedPrivateRoot::open(&self.binding.root)
            .and_then(|parent| parent.sync())
            .map_err(|_| object_io_error(id))
    }

    pub(crate) fn capture_cap(
        &self,
        recording_id: RecordingId,
    ) -> Result<Option<u64>, RecordingStoreError> {
        let id = CorrelationId::new();
        let Some(root) = directory(&self.binding, false, id)? else { return Ok(None) };
        let name = format!("{}.cap", recording_id.as_uuid());
        match std::fs::symlink_metadata(root.path().join(&name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(object_io_error(id)),
            Ok(_) => {}
        }
        let stored = root.read_bounded_file(&name, 8).map_err(|_| object_io_error(id))?;
        // An interrupted Begin with no policy acknowledgement has no admitted events.
        if stored.len() < 8 {
            return Ok(None);
        }
        let cap = u64::from_be_bytes(stored.try_into().map_err(|_| object_corrupt_error(id))?);
        if !event_cap_in_bounds(cap) {
            return Err(object_corrupt_error(id));
        }
        Ok(Some(cap))
    }

    pub(crate) fn journal_tail(
        &self,
        request: &PersistRecordingSegment<XtfEventEnvelope>,
        prefix_events: usize,
        checkpoint: &mut Option<Checkpoint>,
    ) -> Result<(), RecordingStoreError> {
        let id = CorrelationId::new();
        let _writer =
            self.store.lock_recording_writer(id).map_err(|error| map_store_error(error, id))?;
        if u64::from(request.segment_ordinal) >= MAX_RECORDING_QUERY_SEGMENTS {
            return Err(recording_query_resource_error(id));
        }
        let commit = SegmentCommitRequest {
            project_id: request.project_id,
            recording_id: request.recording_id,
            segment_ordinal: request.segment_ordinal,
            events: request.events.iter().map(|event| event.payload.clone()).collect(),
        };
        let logical = encode_logical_segment(&XtfSegmentInput {
            project_id: commit.project_id,
            recording_id: commit.recording_id,
            segment_ordinal: commit.segment_ordinal,
            events: commit.events.clone(),
        })
        .map_err(|error| map_xtf_error(error, id))?;
        let root = directory(&self.binding, true, id)?.ok_or_else(|| object_io_error(id))?;
        let name = name(request.recording_id);
        let mut file = root.open_or_create_private_file(&name).map_err(|_| object_io_error(id))?;
        let length = file.metadata().map_err(|_| object_io_error(id))?.len();
        let mut known = checkpoint
            .take()
            .filter(|known| known.ordinal == request.segment_ordinal && known.length == length);
        let cached = known.is_some();
        if known.is_none() {
            let tail = load(&self.binding, request.recording_id, id)?;
            if tail.as_ref().is_some_and(|tail| tail.project_id != request.project_id) {
                return Err(segment_conflict_error(id));
            }
            known = tail.map(|tail| Checkpoint {
                ordinal: tail.ordinal,
                length: tail.length,
                first_sequence: tail.events.first().map_or(0, |event| event.recording_seq),
                digests: tail
                    .events
                    .iter()
                    .map(|event| *blake3::hash(&event.encode_to_vec()).as_bytes())
                    .collect(),
                identities: tail
                    .events
                    .iter()
                    .filter_map(|event| event.event.as_ref())
                    .map(|event| event.event_id.clone())
                    .collect(),
            });
        }
        let mut known = known.unwrap_or(Checkpoint {
            ordinal: request.segment_ordinal,
            length: 0,
            digests: Vec::new(),
            first_sequence: request.events.first().map_or(0, |event| event.recording_seq),
            identities: HashSet::new(),
        });
        if known.digests.is_empty() {
            known.first_sequence = request.events.first().map_or(0, |event| event.recording_seq);
        }
        let digests: Vec<_> = request
            .events
            .iter()
            .map(|event| *blake3::hash(&event.canonical_bytes).as_bytes())
            .collect();
        if known.ordinal != request.segment_ordinal
            || prefix_events > known.digests.len()
            || !digests.starts_with(&known.digests[prefix_events..])
            || known.first_sequence.checked_add(prefix_events as u64)
                != request.events.first().map(|event| event.recording_seq)
        {
            return Err(segment_conflict_error(id));
        }
        let overlap = known.digests.len() - prefix_events;
        let suffix = &request.events[overlap..];
        let new_count = known
            .digests
            .len()
            .checked_add(suffix.len())
            .ok_or_else(|| segment_validation_error(id))?;
        let new_bytes = suffix
            .iter()
            .try_fold(0_usize, |total, event| {
                total.checked_add(4 + event.canonical_bytes.len() + 32)
            })
            .ok_or_else(|| segment_validation_error(id))?;
        let base_length = known.length.max(HEADER_BYTES as u64);
        let final_length = base_length
            .checked_add(new_bytes as u64)
            .ok_or_else(|| segment_validation_error(id))?;
        // XTF's event budget excludes the per-envelope journal digests.
        if new_count > DEFAULT_SEGMENT_EVENTS
            || final_length > MAX_JOURNAL_BYTES as u64
            || final_length - HEADER_BYTES as u64 - new_count as u64 * 32
                > DEFAULT_SEGMENT_EVENT_BYTES as u64
        {
            return Err(segment_validation_error(id));
        }
        let mut candidate = SegmentMetadata::from_logical(&logical, &commit, id)?;
        candidate.first_recording_seq = known.first_sequence;
        {
            let connection = self.store.lock().map_err(|error| map_store_error(error, id))?;
            validate_recording_anchor(&connection, &commit, id)?;
            validate_new_continuity(&connection, &commit, &candidate, id)?;
            validate_frame_identities(
                &connection,
                &SegmentCommitRequest {
                    events: suffix.iter().map(|event| event.payload.clone()).collect(),
                    ..commit
                },
                id,
            )?;
        }
        for envelope in suffix {
            let event =
                envelope.payload.event.as_ref().ok_or_else(|| segment_validation_error(id))?;
            if !known.identities.insert(event.event_id.clone()) {
                return Err(frame_identity_error(id));
            }
        }
        if cached && suffix.is_empty() {
            *checkpoint = Some(known);
            return Ok(());
        }
        // Remove only an incomplete, unacknowledged suffix before an exact retry.
        if length != known.length {
            file.set_len(known.length).map_err(|_| object_io_error(id))?;
        }
        file.seek(SeekFrom::Start(known.length)).map_err(|_| object_io_error(id))?;
        if known.length == 0 {
            file.write_all(MAGIC)
                .and_then(|()| file.write_all(request.project_id.as_uuid().as_bytes()))
                .and_then(|()| file.write_all(request.recording_id.as_uuid().as_bytes()))
                .and_then(|()| file.write_all(&request.segment_ordinal.to_be_bytes()))
                .map_err(|_| object_io_error(id))?;
        }
        for event in suffix {
            let bytes = &event.canonical_bytes;
            let length = u32::try_from(bytes.len()).map_err(|_| segment_validation_error(id))?;
            file.write_all(&length.to_be_bytes())
                .and_then(|()| file.write_all(bytes))
                .and_then(|()| file.write_all(blake3::hash(bytes).as_bytes()))
                .map_err(|_| object_io_error(id))?;
        }
        commit_failpoint("journal-before-sync", id, false)?;
        file.sync_all().map_err(|_| object_io_error(id))?;
        root.validate_file_binding(&name, &file, true).map_err(|_| object_io_error(id))?;
        #[cfg(test)]
        JOURNAL_SYNCS.with(|count| count.set(count.get() + 1));
        if !cached {
            root.sync().map_err(|_| object_io_error(id))?;
            AdmittedPrivateRoot::open(&self.binding.root)
                .and_then(|parent| parent.sync())
                .map_err(|_| object_io_error(id))?;
        }
        commit_failpoint("journal-after-sync", id, false)?;
        known.length = final_length;
        known.digests.extend_from_slice(&digests[overlap..]);
        *checkpoint = Some(known);
        Ok(())
    }

    pub(crate) fn clear_journal(
        &self,
        recording_id: RecordingId,
    ) -> Result<(), RecordingStoreError> {
        let id = CorrelationId::new();
        if let Some(root) = directory(&self.binding, false, id)? {
            let name = name(recording_id);
            match std::fs::symlink_metadata(root.path().join(&name)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(_) => return Err(object_io_error(id)),
                Ok(_) => {}
            }
            root.remove_private_file(&name).map_err(|_| object_io_error(id))?;
            root.sync().map_err(|_| object_io_error(id))?;
        }
        Ok(())
    }

    pub(crate) fn clear_segment_journal(
        &self,
        recording_id: RecordingId,
        ordinal: u32,
    ) -> Result<bool, RecordingStoreError> {
        let id = CorrelationId::new();
        if load(&self.binding, recording_id, id)?.is_some_and(|tail| tail.ordinal == ordinal) {
            self.clear_journal(recording_id)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// A normal XTF publication may extend an acknowledged journal prefix,
    /// but must never replace or shorten it, including through a fresh port.
    pub(super) fn validate_journal_segment(
        &self,
        request: &SegmentCommitRequest,
    ) -> Result<(), RecordingStoreError> {
        let id = CorrelationId::new();
        if let Some(tail) = load(&self.binding, request.recording_id, id)? {
            if tail.ordinal == request.segment_ordinal
                && (tail.project_id != request.project_id
                    || !request.events.starts_with(&tail.events))
            {
                return Err(segment_conflict_error(id));
            }
        }
        Ok(())
    }

    /// Publish the tail before terminal verification. A crash after publication
    /// leaves a stale journal; verify its prefix against the immutable object.
    /// The caller holds the store writer through publication, cleanup and Finish.
    pub(super) fn recover_journal_under_writer(
        &self,
        recording_id: RecordingId,
    ) -> Result<(), RecordingStoreError> {
        let id = CorrelationId::new();
        let Some(tail) = load(&self.binding, recording_id, id)? else { return Ok(()) };
        if tail.events.is_empty() {
            return self.clear_journal(recording_id);
        }
        let existing = {
            let connection = self.store.lock().map_err(|error| map_store_error(error, id))?;
            load_segment_row(&connection, recording_id, tail.ordinal, id)?
        };
        if let Some(existing) = existing {
            let path = object_path_from_row(&self.binding.root, &existing.object_hash, id)?;
            let bytes = read_bounded_regular_file(&path, id, false)?;
            let hash = content_hash_from_bytes(&existing.object_hash, id)?;
            let decoded = crate::xtf::decode_compressed_segment(&bytes, hash)
                .map_err(|_| object_corrupt_error(id))?;
            if decoded.verified().project_id() != tail.project_id
                || decoded.verified().recording_id() != recording_id
                || decoded.verified().segment_ordinal() != tail.ordinal
                || !decoded.events().starts_with(&tail.events)
            {
                return Err(object_corrupt_error(id));
            }
        } else {
            self.commit_segment_under_writer(&SegmentCommitRequest {
                project_id: tail.project_id,
                recording_id,
                segment_ordinal: tail.ordinal,
                events: tail.events,
            })?;
        }
        self.clear_journal(recording_id)
    }

    /// Journal events beyond the sealed prefix, for truthful lifecycle metadata.
    pub(crate) fn journal_summary(
        &self,
        recording_id: RecordingId,
        sealed_last: u64,
    ) -> Result<Option<(u64, u64, u64)>, RecordingStoreError> {
        let id = CorrelationId::new();
        let Some(tail) = load(&self.binding, recording_id, id)? else { return Ok(None) };
        let mut sequences = tail
            .events
            .iter()
            .filter_map(|envelope| envelope.event.as_ref())
            .map(|event| event.recording_seq)
            .filter(|sequence| *sequence > sealed_last);
        let Some(first) = sequences.next() else { return Ok(None) };
        let mut last = first;
        let mut count = 1;
        for sequence in sequences {
            last = sequence;
            count += 1;
        }
        if sealed_last.checked_add(1) != Some(first) {
            return Err(object_corrupt_error(id));
        }
        Ok(Some((first, last, count)))
    }
}
