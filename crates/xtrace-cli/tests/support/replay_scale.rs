//! Synthetic scale data for a new private project; never included in the product binary.

use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use prost::Message as _;
use serde_json::Value;
use tempfile::TempDir;
use xtrace_application::recording::{
    AcceptedRecordingEvent, BeginRecording, FinishRecording, PersistRecordingSegment,
    RecordingCompletion, RecordingPersistencePort as _, STANDARD_EVENT_CAP,
};
use xtrace_domain::{ProjectId, RecordingId, RuntimeSessionId, WallTime};
use xtrace_protocol::generated::agent::{RecordingEvent, RecordingEventKind};
use xtrace_protocol::xtf::XtfEventEnvelope;
use xtrace_store::{OpenOptions, SqliteRecordingPersistence, SqliteStore};

pub const FRAME_COUNT: u32 = 10_000;
const SEGMENT_FRAMES: u32 = 500;

// Balanced synthetic calls, including explicit closing events parented to their observed entry.
// Distinct sibling symbols and non-leaf roots survive Map's adjacent-leaf coalescing.
pub const CALL_SHAPE: [(&str, RecordingEventKind, Option<usize>, u32); 20] = {
    use RecordingEventKind::{FrameEnter as Enter, FrameExit as Exit};
    [
        ("SyntheticReplayScale.request", Enter, None, 0),
        ("SyntheticReplayScale.validate", Enter, Some(0), 1),
        ("SyntheticReplayScale.normalize", Enter, Some(1), 2),
        ("SyntheticReplayScale.normalize", Exit, Some(2), 3),
        ("SyntheticReplayScale.authorize", Enter, Some(1), 2),
        ("SyntheticReplayScale.authorize", Exit, Some(4), 3),
        ("SyntheticReplayScale.validate", Exit, Some(1), 2),
        ("SyntheticReplayScale.repository", Enter, Some(0), 1),
        ("SyntheticReplayScale.lookup", Enter, Some(7), 2),
        ("SyntheticReplayScale.lookup", Exit, Some(8), 3),
        ("SyntheticReplayScale.save", Enter, Some(7), 2),
        ("SyntheticReplayScale.save", Exit, Some(10), 3),
        ("SyntheticReplayScale.repository", Exit, Some(7), 2),
        ("SyntheticReplayScale.render", Enter, Some(0), 1),
        ("SyntheticReplayScale.encode", Enter, Some(13), 2),
        ("SyntheticReplayScale.encode", Exit, Some(14), 3),
        ("SyntheticReplayScale.decorate", Enter, Some(13), 2),
        ("SyntheticReplayScale.decorate", Exit, Some(16), 3),
        ("SyntheticReplayScale.render", Exit, Some(13), 2),
        ("SyntheticReplayScale.request", Exit, Some(0), 1),
    ]
};

pub struct SyntheticScaleProject {
    root: TempDir,
    cli: PathBuf,
    pub repo: PathBuf,
    pub data_home: PathBuf,
    pub project_id: ProjectId,
    pub recording_id: RecordingId,
}

impl SyntheticScaleProject {
    pub fn seed() -> Self {
        let scratch = private_scratch();
        let root = tempfile::Builder::new()
            .prefix("xt-scale-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(scratch)
            .expect("create a new private scale fixture");
        let repo = root.path().join("repo");
        let data_home = root.path().join("data");
        std::fs::create_dir(&repo).expect("new fixture repository");
        let cli = std::env::var_os("XTRACE_SCALE_XTRACE")
            .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_xtrace")), PathBuf::from);
        let init = Command::new(&cli)
            .args(["init", "--project-dir"])
            .arg(&repo)
            .env("XTRACE_DATA_HOME", &data_home)
            .stdin(Stdio::null())
            .output()
            .expect("invoke actual CLI init");
        assert!(init.status.success(), "synthetic project CLI init failed");
        let init: Value = serde_json::from_slice(&init.stdout).expect("CLI init JSON");
        let project_id = init["project_id"].as_str().expect("project identity").parse().unwrap();
        let fixture =
            Self { root, cli, repo, data_home, project_id, recording_id: RecordingId::new() };
        fixture.persist();
        fixture
    }

    pub fn project_root(&self) -> PathBuf {
        self.data_home.join("projects").join(self.project_id.to_string())
    }

    pub fn show(&self, cursor: Option<&str>, limit: u32) -> xtrace_application::RecordingDetail {
        let mut command = Command::new(&self.cli);
        command
            .args(["recording", "show"])
            .arg(self.recording_id.to_string())
            .args(["--limit", &limit.to_string(), "--project-dir"])
            .arg(&self.repo)
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdin(Stdio::null());
        if let Some(cursor) = cursor {
            command.args(["--cursor", cursor]);
        }
        let output = command.output().expect("invoke actual CLI recording show");
        assert!(output.status.success(), "synthetic fixture CLI page failed");
        // The CLI writes RecordingDetail directly (snake_case outer/event fields), while
        // nested capacity and navigation DTOs retain their own camelCase serde contracts.
        let wire: Value = serde_json::from_slice(&output.stdout).expect("CLI recording JSON");
        assert!(wire.get("recording_id").is_some());
        assert!(wire["events"][0].get("frame_id").is_some());
        assert!(wire["capacity"].get("eventCount").is_some());
        serde_json::from_value(wire).expect("typed CLI recording detail with actual serde casing")
    }

    fn persist(&self) {
        let store = SqliteStore::open(
            &self.project_root().join("metadata.sqlite3"),
            OpenOptions::default().with_must_exist(true),
        )
        .expect("open CLI-created store");
        let persistence = SqliteRecordingPersistence::new(store, self.project_root());
        persistence
            .begin_recording(&BeginRecording {
                project_id: self.project_id,
                recording_id: self.recording_id,
                runtime_session_id: RuntimeSessionId::new(),
                opened_at: WallTime::now(),
                endpoint_observation: Default::default(),
                limitations: Vec::new(),
            })
            .expect("begin synthetic scale recording");
        let mut digest = blake3::Hasher::new();
        for segment in 0..FRAME_COUNT / SEGMENT_FRAMES {
            let events = (0..SEGMENT_FRAMES)
                .map(|offset| {
                    let sequence = u64::from(segment * SEGMENT_FRAMES + offset) + 2;
                    let index = usize::try_from(sequence - 2).unwrap();
                    let shape_index = index % CALL_SHAPE.len();
                    let (symbol, kind, parent_offset, _) = CALL_SHAPE[shape_index];
                    let parent_event_id = parent_offset.map_or_else(String::new, |parent| {
                        format!("synthetic-scale-{:05}", index - shape_index + parent + 2)
                    });
                    let event_id = format!("synthetic-scale-{sequence:05}");
                    digest.update(event_id.as_bytes());
                    let payload = XtfEventEnvelope {
                        recording_seq: sequence,
                        event: Some(RecordingEvent {
                            event_id,
                            parent_event_id,
                            recording_seq: sequence,
                            // Synthetic ordering data, not measured application timing.
                            monotonic_ns: sequence,
                            kind: kind as i32,
                            symbol: symbol.to_owned(),
                            ..RecordingEvent::default()
                        }),
                    };
                    AcceptedRecordingEvent {
                        recording_seq: sequence,
                        monotonic_ns: sequence,
                        priority: 0,
                        canonical_bytes: payload.encode_to_vec(),
                        payload,
                    }
                })
                .collect();
            persistence
                .persist_segment(&PersistRecordingSegment {
                    project_id: self.project_id,
                    recording_id: self.recording_id,
                    segment_ordinal: segment,
                    events,
                })
                .expect("persist synthetic segment through application port");
        }
        let mut finish =
            FinishRecording::without_digest(self.recording_id, u64::from(FRAME_COUNT) + 1);
        finish.event_cap = STANDARD_EVENT_CAP as u64;
        finish.event_digest = digest.finalize().as_bytes().to_vec();
        assert_eq!(
            persistence.finish_recording(&finish).expect("verify synthetic count and digest"),
            RecordingCompletion::Complete
        );
    }

    /// Keep only this newly generated project, on explicit request, for later viewer measurement.
    /// The private manifest is created without replacement; it is never printed or uploaded.
    pub fn retain_if_requested(self) {
        let Some(manifest) = std::env::var_os("XTRACE_SCALE_FIXTURE_MANIFEST") else {
            return;
        };
        let manifest = PathBuf::from(manifest);
        assert_eq!(
            manifest.parent().and_then(|parent| parent.canonicalize().ok()),
            Some(private_scratch()),
            "manifest must be a new direct child of private test scratch"
        );
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&manifest)
            .expect("create new private fixture manifest without replacement");
        let document = serde_json::json!({
            "schema_version": 1,
            "synthetic": true,
            "purpose": "replay-scale-correctness; no application or performance claim",
            "fixture_root": self.root.path(),
            "project_dir": self.repo,
            "data_home": self.data_home,
            "project_id": self.project_id,
            "recording_id": self.recording_id,
            "verified_frame_count": FRAME_COUNT,
        });
        serde_json::to_writer(&mut file, &document).expect("write private fixture manifest");
        file.sync_all().expect("sync private fixture manifest");
        let _retained = self.root.keep();
    }
}

fn private_scratch() -> PathBuf {
    let scratch = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
        .expect("source tools/dev/env.sh before running the scale fixture");
    let scratch = Path::new(&scratch).canonicalize().expect("canonical private test scratch");
    let metadata = std::fs::metadata(&scratch).expect("private test scratch metadata");
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o077, 0, "scratch must be owner-only");
    scratch
}
