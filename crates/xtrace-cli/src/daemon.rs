//! Foreground CLI composition for a project-scoped recording daemon.

#[cfg(unix)]
use std::num::NonZeroUsize;
#[cfg(any(unix, test))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use serde::Serialize;
#[cfg(unix)]
use xtrace_application::recording::{RecordingCapture, RecordingCaptureService, SegmentPolicy};
#[cfg(any(unix, test))]
use xtrace_application::{Application, GetProject, Query, QueryResult, RequestContext};
#[cfg(unix)]
use xtrace_daemon::{BoundDaemon, DaemonBuilder, DaemonConfig, DaemonError};
#[cfg(unix)]
use xtrace_domain::RuntimeSessionId;
#[cfg(any(unix, test))]
use xtrace_domain::{ProjectId, WallTime};
use xtrace_private_storage::AdmittedPrivateRoot;
#[cfg(unix)]
use xtrace_protocol::xtf::XtfEventEnvelope;
#[cfg(unix)]
use xtrace_store::SqliteRecordingPersistence;
#[cfg(any(unix, test))]
use xtrace_store::{
    CURRENT_SCHEMA_VERSION, OpenOptions, SqliteIdempotencyStore, SqliteProjectRepository,
    SqliteStore,
};

#[cfg(any(unix, test))]
use crate::commands::{map_store_error, resolve_data_home, resolve_repo};
#[cfg(unix)]
use crate::daemon_lock::{RuntimeDirectory, acquire_project_lock};
use crate::error::CliError;
#[cfg(unix)]
use crate::output::write_success_line;
#[cfg(any(unix, test))]
use crate::paths::{RepositoryPointer, UserDataPaths};

#[cfg(unix)]
const RETAINED_RECORDING_LIMIT: usize = 1_024;

/// Runs a foreground daemon for one already-initialized repository.
pub(crate) async fn run(project_dir: PathBuf) -> Result<(), CliError> {
    #[cfg(not(unix))]
    {
        let _ = project_dir;
        return Err(CliError::DaemonUnsupportedPlatform);
    }
    #[cfg(unix)]
    {
        run_with_env(project_dir, &crate::paths::read_env_path).await
    }
}

#[cfg(unix)]
async fn run_with_env<F>(project_dir: PathBuf, env_reader: &F) -> Result<(), CliError>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let prepared = prepare(project_dir, env_reader).await?;
    let PreparedDaemon { bound, bootstrap_path, mut runtime_dir, lock } = prepared;
    let signals = ShutdownSignals::install()?;

    let document = DaemonBoundDocument {
        kind: "daemon_bound",
        project_id: bound.project_id().to_string(),
        runtime_session_id: bound.runtime_session_id().to_string(),
        host: bound.local_addr().ip().to_string(),
        port: bound.local_addr().port(),
        certificate_sha256_pin: bound.certificate_pin().to_string(),
        bootstrap_path: bootstrap_path.display().to_string(),
        recording_ingress: "durable_segments",
        ack_durability: "staged",
        capture_supported: false,
        replay_supported: false,
    };
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write_success_line(&mut handle, &document)?;
    drop(handle);

    let serve_result = bound.serve(signals.wait()).await.map_err(map_daemon_error);
    let cleanup_result = runtime_dir.cleanup();
    drop(lock);
    combine_serve_cleanup(serve_result, cleanup_result)
}

/// Owns all project resources needed to run one already-bound daemon.
#[cfg(unix)]
pub(crate) struct PreparedDaemon {
    pub(crate) bound: BoundDaemon,
    pub(crate) bootstrap_path: PathBuf,
    pub(crate) runtime_dir: RuntimeDirectory,
    pub(crate) lock: crate::daemon_lock::ProjectDaemonLock,
}

/// Validates and opens an existing project, then binds its private daemon.
///
/// The project lock is acquired before SQLite is opened, and the bootstrap
/// path remains within the owned runtime directory for the bound daemon's life.
#[cfg(unix)]
pub(crate) async fn prepare<F>(
    project_dir: PathBuf,
    env_reader: &F,
) -> Result<PreparedDaemon, CliError>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    prepare_with_observation(
        project_dir,
        env_reader,
        xtrace_application::recording::EndpointObservationInput::default(),
    )
    .await
}

/// Prepares capture with invocation-scoped endpoint observation context.
#[cfg(unix)]
pub(crate) async fn prepare_with_observation<F>(
    project_dir: PathBuf,
    env_reader: &F,
    run_observation: xtrace_application::recording::EndpointObservationInput,
) -> Result<PreparedDaemon, CliError>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let preflight = preflight_project(&project_dir, env_reader)?;
    let lock = acquire_project_lock(&preflight.private_root)?;
    let selected = open_validated_project(preflight)?;
    let runtime_session_id = RuntimeSessionId::new();
    let runtime_dir = RuntimeDirectory::create(&selected.private_root, runtime_session_id)?;
    let bootstrap_path = runtime_dir.path().join("bootstrap.json");
    let capture = compose_capture(&selected)?;
    let bound = DaemonBuilder::new(DaemonConfig::default())
        .with_project_id(selected.project_id)
        .with_runtime_session_id(runtime_session_id)
        .with_expected_repository_fingerprint(selected.repository_fingerprint)
        .with_bootstrap_artifact(bootstrap_path.clone())
        .with_recording_capture(capture)
        .with_endpoint_observation_context(run_observation)
        .bind()
        .await
        .map_err(map_daemon_error)?;
    Ok(PreparedDaemon { bound, bootstrap_path, runtime_dir, lock })
}

#[cfg(any(unix, test))]
fn combine_serve_cleanup(
    serve_result: Result<(), CliError>,
    cleanup_result: Result<(), CliError>,
) -> Result<(), CliError> {
    match (serve_result, cleanup_result) {
        (Err(primary), _) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(any(unix, test))]
struct ValidatedProject {
    store: SqliteStore,
    project_id: ProjectId,
    repository_fingerprint: xtrace_domain::RepositoryFingerprint,
    project_data_root: PathBuf,
    private_root: AdmittedPrivateRoot,
}

#[cfg(any(unix, test))]
struct ProjectPreflight {
    canonical_repo_path: String,
    expected_repository_fingerprint: xtrace_domain::RepositoryFingerprint,
    project_id: ProjectId,
    project_data_root: PathBuf,
    database_path: PathBuf,
    private_root: AdmittedPrivateRoot,
}

#[cfg(any(unix, test))]
fn preflight_project<F>(project_dir: &Path, env_reader: &F) -> Result<ProjectPreflight, CliError>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let repo = resolve_repo(project_dir)?;
    let canonical_repo_path = repo.to_str().ok_or_else(|| {
        CliError::InvalidArgument("repository path must be valid UTF-8".to_string())
    })?;
    let expected_repository_fingerprint =
        xtrace_domain::RepositoryFingerprint::from_canonical_path(canonical_repo_path);
    let pointer = RepositoryPointer::read(&repo)?;
    let data_home = resolve_data_home(Some(&pointer), env_reader)?;
    let unresolved_root = UserDataPaths::project_dir_with_home(&data_home, pointer.project_id)?;
    let private_root = AdmittedPrivateRoot::open(&unresolved_root)
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    let project_data_root = private_root.path().to_path_buf();
    let database_path = project_data_root.join("metadata.sqlite3");
    private_root
        .validate_regular_file("metadata.sqlite3")
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    Ok(ProjectPreflight {
        canonical_repo_path: canonical_repo_path.to_string(),
        expected_repository_fingerprint,
        project_id: pointer.project_id,
        project_data_root,
        database_path,
        private_root,
    })
}

#[cfg(any(unix, test))]
fn open_validated_project(preflight: ProjectPreflight) -> Result<ValidatedProject, CliError> {
    let ProjectPreflight {
        canonical_repo_path,
        expected_repository_fingerprint,
        project_id,
        project_data_root,
        database_path,
        private_root,
    } = preflight;
    private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    private_root
        .validate_regular_file("metadata.sqlite3")
        .map_err(|_| CliError::PrivateStorageUnavailable)?;

    let requested_at = WallTime::now();
    let context = RequestContext::new("xtrace-cli".to_string(), requested_at);
    let store = SqliteStore::open(
        &database_path,
        OpenOptions::default().with_must_exist(true).with_correlation_id(context.correlation_id),
    )
    .map_err(map_store_error)?;
    private_root
        .validate_regular_file("metadata.sqlite3")
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    let app = Application::new(
        SqliteProjectRepository::new(&store),
        SqliteIdempotencyStore::new(&store),
        CURRENT_SCHEMA_VERSION,
        1,
        0,
    );
    let query = app.query(
        Query::GetProject(GetProject { canonical_repo_path: canonical_repo_path.to_string() }),
        &context,
    )?;
    let project = match query {
        QueryResult::Project(snapshot) => snapshot.project,
        QueryResult::StoreStatus(_) => {
            return Err(CliError::StoreUnavailable(
                "project validation returned an unexpected result".to_string(),
            ));
        }
    };
    if project.id != project_id {
        return Err(CliError::StoreCorrupted(
            "repository pointer and project database identities disagree".to_string(),
        ));
    }
    if project.canonical_repo_hash != expected_repository_fingerprint {
        return Err(CliError::StoreCorrupted(
            "project repository fingerprint does not match its canonical path".to_string(),
        ));
    }
    Ok(ValidatedProject {
        store,
        project_id: project.id,
        repository_fingerprint: project.canonical_repo_hash,
        project_data_root,
        private_root,
    })
}

#[cfg(unix)]
fn map_daemon_error(error: DaemonError) -> CliError {
    CliError::DaemonFailure(error.code())
}

#[cfg(unix)]
fn compose_capture(
    selected: &ValidatedProject,
) -> Result<Arc<dyn RecordingCapture<Event = XtfEventEnvelope>>, CliError> {
    let persistence = Arc::new(SqliteRecordingPersistence::new(
        selected.store.clone(),
        selected.project_data_root.clone(),
    ));
    let retained_limit = NonZeroUsize::new(RETAINED_RECORDING_LIMIT).ok_or_else(|| {
        CliError::StoreUnavailable("invalid daemon recording retention budget".to_string())
    })?;
    Ok(Arc::new(RecordingCaptureService::new(
        persistence,
        SegmentPolicy::default(),
        retained_limit,
    )))
}

#[cfg(unix)]
#[derive(Debug, Serialize)]
struct DaemonBoundDocument {
    kind: &'static str,
    project_id: String,
    runtime_session_id: String,
    host: String,
    port: u16,
    certificate_sha256_pin: String,
    bootstrap_path: String,
    recording_ingress: &'static str,
    ack_durability: &'static str,
    capture_supported: bool,
    replay_supported: bool,
}

#[cfg(unix)]
enum ShutdownSignals {
    Unix { interrupt: tokio::signal::unix::Signal, terminate: tokio::signal::unix::Signal },
}

#[cfg(unix)]
impl ShutdownSignals {
    fn install() -> Result<Self, CliError> {
        use tokio::signal::unix::{SignalKind, signal};
        let interrupt = signal(SignalKind::interrupt()).map_err(|_| {
            CliError::StoreUnavailable("register interrupt handler failed".to_string())
        })?;
        let terminate = signal(SignalKind::terminate()).map_err(|_| {
            CliError::StoreUnavailable("register terminate handler failed".to_string())
        })?;
        Ok(Self::Unix { interrupt, terminate })
    }

    async fn wait(self) {
        match self {
            Self::Unix { mut interrupt, mut terminate } => {
                tokio::select! {
                    _ = interrupt.recv() => {},
                    _ = terminate.recv() => {},
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "project fixtures are deliberately constructed with checked assertions"
)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use xtrace_application::ProjectRepository;
    use xtrace_domain::{Project, RepositoryFingerprint};
    #[cfg(unix)]
    use xtrace_domain::{RecordingId, RuntimeSessionId};
    use xtrace_store::{OpenOptions, SqliteProjectRepository};

    #[cfg(unix)]
    use prost::Message as _;
    #[cfg(unix)]
    use xtrace_application::recording::{
        AcceptedRecordingEvent, BeginRecording, FinishRecording, PersistRecordingSegment,
        RecordEvents, RecordingPersistencePort,
    };
    #[cfg(unix)]
    use xtrace_protocol::generated::agent::RecordingEvent;
    #[cfg(unix)]
    use xtrace_protocol::xtf::XtfEventEnvelope;
    #[cfg(unix)]
    use xtrace_store::SqliteRecordingPersistence;

    fn temp_root(label: &str) -> tempfile::TempDir {
        let scratch = PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required"),
        );
        AdmittedPrivateRoot::open(&scratch).expect("admitted private test scratch");
        tempfile::Builder::new()
            .prefix(label)
            .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .tempdir_in(scratch)
            .expect("temp root")
    }

    /// Creates `path` and any missing parents as 0700 whatever the process umask is: the product
    /// admits project storage as private, and a umask 022 runner would make `create_dir_all` 0755.
    fn private_dir_all(path: &Path) {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .expect("private directory");
    }

    /// Creates an empty 0600 file whatever the process umask is.
    fn private_empty_file(path: &Path) {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("private file");
    }

    fn initialized_project(repo: &Path, data_home: &Path) -> ProjectId {
        std::fs::create_dir_all(repo).expect("repo directory");
        let canonical_repo = repo.canonicalize().expect("canonical repo");
        let project_id = ProjectId::new();
        let project_data_root =
            UserDataPaths::project_dir_with_home(data_home, project_id).expect("project root");
        private_dir_all(&project_data_root);
        let database_path = project_data_root.join("metadata.sqlite3");
        let store = SqliteStore::open(&database_path, OpenOptions::default()).expect("store");
        let project = Project {
            id: project_id,
            canonical_repo_hash: RepositoryFingerprint::from_canonical_path(
                canonical_repo.to_str().expect("repo utf-8"),
            ),
            display_name: "test project".to_string(),
            created_at: WallTime::now(),
            last_opened_at: WallTime::now(),
            config_schema_version: 1,
            effective_config_hash: "test".to_string(),
            active_capture_policy_id: None,
            active_redaction_policy_id: None,
        };
        SqliteProjectRepository::new(&store).insert_project(&project).expect("insert project");
        RepositoryPointer { schema_version: 1, project_id, data_home: data_home.to_path_buf() }
            .write(&canonical_repo)
            .expect("write pointer");
        project_id
    }

    fn env(values: HashMap<&'static str, PathBuf>) -> impl Fn(&str) -> Option<PathBuf> {
        move |name| values.get(name).cloned()
    }

    #[test]
    fn validates_project_paths_with_spaces_and_honors_data_home_override() {
        let root = temp_root("xtrace-cli-daemon-project-");
        let repo = root.path().join("repository with spaces");
        let pointer_home = root.path().join("pointer home");
        let override_home = root.path().join("override home");
        let project_id = initialized_project(&repo, &override_home);
        let override_root = UserDataPaths::project_dir_with_home(&override_home, project_id)
            .expect("override project root");
        let resolved = open_validated_project(
            preflight_project(&repo, &env(HashMap::from([("XTRACE_DATA_HOME", override_home)])))
                .expect("project preflight"),
        )
        .expect("project validates");
        assert_eq!(resolved.project_id, project_id);
        assert_eq!(resolved.project_data_root, override_root.canonicalize().expect("canonical"));
        assert!(!pointer_home.exists());
    }

    #[test]
    fn missing_database_is_rejected_without_creation() {
        let root = temp_root("xtrace-cli-daemon-missing-");
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repo");
        let home = root.path().join("home");
        let id = ProjectId::new();
        let project_root = UserDataPaths::project_dir_with_home(&home, id).expect("project root");
        private_dir_all(&project_root);
        RepositoryPointer { schema_version: 1, project_id: id, data_home: home }
            .write(&repo)
            .expect("pointer");
        assert!(preflight_project(&repo, &|_| None).is_err());
        assert!(!project_root.join("metadata.sqlite3").exists());
    }

    #[test]
    fn pointer_database_identity_mismatch_is_rejected() {
        let root = temp_root("xtrace-cli-daemon-mismatch-");
        let repo = root.path().join("repo");
        let home = root.path().join("home");
        let actual_id = initialized_project(&repo, &home);
        let canonical_repo = repo.canonicalize().expect("canonical repo");
        let mismatched_id = ProjectId::new();
        let actual_root =
            UserDataPaths::project_dir_with_home(&home, actual_id).expect("actual root");
        let mismatched_root =
            UserDataPaths::project_dir_with_home(&home, mismatched_id).expect("mismatched root");
        std::fs::rename(&actual_root, &mismatched_root).expect("move project data root");
        // Pointer writes never replace an existing pointer, so remove the original first
        // to build the mismatched-identity fixture.
        std::fs::remove_file(canonical_repo.join(".xtrace").join("config.toml"))
            .expect("remove original pointer");
        RepositoryPointer { schema_version: 1, project_id: mismatched_id, data_home: home }
            .write(&canonical_repo)
            .expect("write mismatched pointer");
        assert!(matches!(
            open_validated_project(preflight_project(&repo, &|_| None).expect("preflight")),
            Err(CliError::StoreCorrupted(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn database_symlink_is_rejected_before_any_database_open_or_repair() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = temp_root("xtrace-cli-daemon-db-symlink-");
        let repo = root.path().join("repo");
        let home = root.path().join("home");
        let project_id = initialized_project(&repo, &home);
        let project_root =
            UserDataPaths::project_dir_with_home(&home, project_id).expect("project root");
        let database = project_root.join("metadata.sqlite3");
        let target = root.path().join("database-target.sqlite3");
        std::fs::rename(&database, &target).expect("move SQLite database target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
            .expect("set target mode");
        symlink(&target, &database).expect("link database to target");
        std::fs::set_permissions(&project_root, std::fs::Permissions::from_mode(0o755))
            .expect("set project root mode");
        let original_bytes = std::fs::read(&target).expect("read target bytes");

        assert!(matches!(
            preflight_project(&repo, &|_| None),
            Err(CliError::PrivateStorageUnavailable)
        ));
        assert_eq!(std::fs::read(&target).expect("target bytes unchanged"), original_bytes);
        assert_eq!(
            std::fs::metadata(&target).expect("target metadata").permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            std::fs::metadata(&project_root).expect("root metadata").permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn database_hardlink_is_rejected_before_any_database_open_or_repair() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = temp_root("xtrace-cli-daemon-db-hardlink-");
        let repo = root.path().join("repo");
        let home = root.path().join("home");
        let project_id = initialized_project(&repo, &home);
        let project_root =
            UserDataPaths::project_dir_with_home(&home, project_id).expect("project root");
        let database = project_root.join("metadata.sqlite3");
        let external_link = root.path().join("external-database.sqlite3");
        std::fs::hard_link(&database, &external_link).expect("create external hardlink");
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644))
            .expect("set database mode");
        std::fs::set_permissions(&project_root, std::fs::Permissions::from_mode(0o755))
            .expect("set project root mode");
        let original_bytes = std::fs::read(&external_link).expect("read linked bytes");

        assert!(matches!(
            preflight_project(&repo, &|_| None),
            Err(CliError::PrivateStorageUnavailable)
        ));
        assert_eq!(std::fs::read(&external_link).expect("external bytes"), original_bytes);
        assert_eq!(
            std::fs::metadata(&external_link).expect("external metadata").permissions().mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            std::fs::metadata(&project_root).expect("root metadata").permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(std::fs::symlink_metadata(&database).expect("database metadata").nlink(), 2);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lock_contention_precedes_sqlite_open_or_migration() {
        let root = temp_root("xtrace-cli-daemon-lock-before-store-");
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repo");
        let home = root.path().join("home");
        let project_id = ProjectId::new();
        let project_root =
            UserDataPaths::project_dir_with_home(&home, project_id).expect("project data root");
        private_dir_all(&project_root);
        RepositoryPointer { schema_version: 1, project_id, data_home: home.clone() }
            .write(&repo)
            .expect("pointer");
        let database = project_root.join("metadata.sqlite3");
        private_empty_file(&database);
        let admitted = AdmittedPrivateRoot::open(&project_root).expect("admitted project root");
        let _lock = acquire_project_lock(&admitted).expect("hold project lock");

        let env_reader = env(HashMap::from([("XTRACE_DATA_HOME", home)]));
        assert!(matches!(
            run_with_env(repo, &env_reader).await,
            Err(CliError::DaemonAlreadyRunning)
        ));
        assert!(std::fs::read(&database).expect("database bytes remain untouched").is_empty());
    }

    #[test]
    fn serve_error_remains_primary_when_runtime_cleanup_also_fails() {
        let result = combine_serve_cleanup(
            Err(CliError::DaemonFailure(xtrace_daemon::ProtocolErrorCode::Transport)),
            Err(CliError::StoreUnavailable("cleanup failed".to_string())),
        );
        assert!(
            matches!(result, Err(CliError::DaemonFailure(code)) if code == xtrace_daemon::ProtocolErrorCode::Transport)
        );
    }

    #[cfg(unix)]
    #[test]
    fn cli_capture_composition_persists_against_the_selected_project_root() {
        use xtrace_application::recording::PersistSegmentDisposition;

        let root = temp_root("xtrace-cli-daemon-compose-");
        let repo = root.path().join("repo");
        let home = root.path().join("home");
        let project_id = initialized_project(&repo, &home);
        let selected =
            open_validated_project(preflight_project(&repo, &|_| None).expect("project preflight"))
                .expect("validated project");
        let capture = compose_capture(&selected).expect("capture service");
        let recording_id = RecordingId::new();
        let runtime_session_id = RuntimeSessionId::new();
        let opened_at = WallTime::now();
        capture
            .begin_recording(BeginRecording {
                project_id,
                recording_id,
                runtime_session_id,
                opened_at,
                endpoint_observation:
                    xtrace_application::recording::EndpointObservationInput::default(),
            })
            .expect("begin anchor");

        let payload = XtfEventEnvelope {
            recording_seq: 2,
            event: Some(RecordingEvent {
                event_id: "cli-composition-event".to_string(),
                recording_seq: 2,
                monotonic_ns: 17,
                ..RecordingEvent::default()
            }),
        };
        let accepted = AcceptedRecordingEvent {
            recording_seq: 2,
            monotonic_ns: 17,
            canonical_bytes: payload.encode_to_vec(),
            payload,
        };
        capture
            .record_events(RecordEvents { recording_id, events: vec![accepted.clone()] })
            .expect("stage event");
        capture
            .finish_recording(FinishRecording::without_digest(recording_id, 2))
            .expect("finish and persist segment");

        let verifier = SqliteRecordingPersistence::new(
            selected.store.clone(),
            selected.project_data_root.clone(),
        );
        let replay = verifier
            .persist_segment(&PersistRecordingSegment {
                project_id,
                recording_id,
                segment_ordinal: 0,
                events: vec![accepted],
            })
            .expect("selected-root segment exact replay verifies durable object");
        assert_eq!(replay.disposition, PersistSegmentDisposition::ExactReplay);
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn unsupported_platform_fails_before_project_access_or_binding() {
        let result = run(PathBuf::from("path-does-not-exist")).await;
        assert!(matches!(result, Err(CliError::DaemonUnsupportedPlatform)));
    }
}
