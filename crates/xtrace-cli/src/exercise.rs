//! `xtrace exercise`: private plan, review and approval. No request sender.

use std::path::PathBuf;

use clap::Subcommand;
use xtrace_application::exercise::{
    CreateExercisePlan, ExerciseError, ExercisePlanService, MAX_PLAN_DOCUMENT_BYTES,
    review_document,
};

use crate::error::CliError;

/// Shared arguments for `xtrace exercise` subcommands.
#[derive(Clone, Debug, clap::Args)]
pub struct ExerciseArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON (private review output).
    #[arg(long)]
    pub json: bool,
}

/// Arguments for `xtrace exercise plan`.
#[derive(Clone, Debug, clap::Args)]
pub struct PlanArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: ExerciseArgs,
    /// Owner-private JSON input. Its parent and file must pass private admission.
    #[arg(long, value_name = "FILE")]
    pub input: PathBuf,
}

/// Arguments for an explicit edit, revoking the exact original and creating a new draft.
#[derive(Clone, Debug, clap::Args)]
pub struct EditArgs {
    /// Input for the new draft.
    #[command(flatten)]
    pub plan: PlanArgs,
    /// Exact immutable hash whose consent this edit revokes.
    #[arg(long = "plan-hash", value_name = "HASH")]
    pub plan_hash: String,
}

/// Arguments for `xtrace exercise review`.
#[derive(Clone, Debug, clap::Args)]
pub struct ReviewArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: ExerciseArgs,
    /// Exact immutable plan hash.
    #[arg(long = "plan-hash", value_name = "HASH")]
    pub plan_hash: String,
}

/// Arguments for `xtrace exercise approve`.
#[derive(Clone, Debug, clap::Args)]
pub struct ApproveArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: ExerciseArgs,
    /// Hash of the reviewed plan being approved.
    #[arg(long = "plan-hash", value_name = "HASH")]
    pub plan_hash: String,
    /// Identity from the exact reviewed plan. Without a selected plan the legacy fallback remains.
    #[arg(long = "plan-id", value_name = "ID")]
    pub plan_id: Option<String>,
    /// Explicit consent to each reviewed item (including mutations and unknown effects).
    #[arg(long = "item", value_name = "ITEM_ID")]
    pub items: Vec<String>,
    /// Confirm this exact target is your ordinary local development application.
    #[arg(long)]
    pub confirm_owned_development_target: bool,
}

/// Arguments for `xtrace exercise show`.
#[derive(Clone, Debug, clap::Args)]
pub struct ShowArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: ExerciseArgs,
    /// Exact immutable plan hash; no selection retains the legacy fallback.
    #[arg(long = "plan-hash", value_name = "HASH")]
    pub plan_hash: Option<String>,
}

/// `xtrace exercise` subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum ExerciseCommand {
    /// Build a private immutable plan from an actually observed operation.
    Plan(PlanArgs),
    /// Replace an exact active plan with a new unapproved draft; sends nothing.
    Edit(EditArgs),
    /// Explicitly review an exact plan; sends nothing.
    Review(ReviewArgs),
    /// Approve an exact reviewed plan; sends nothing.
    Approve(ApproveArgs),
    /// Run an approved plan (executor unavailable in this build).
    Run(ExerciseArgs),
    /// Inspect a private plan without changing approval.
    Show(ShowArgs),
}

fn map_error(error: ExerciseError) -> CliError {
    use xtrace_domain::{AppError, CorrelationId, ErrorCategory, ErrorCode, RetryAdvice};
    let (code, category) = match error {
        ExerciseError::InvalidInput => ("XTR-EXERCISE-INPUT", ErrorCategory::Validation),
        ExerciseError::BindingUnavailable => ("XTR-EXERCISE-BINDING", ErrorCategory::NotFound),
        ExerciseError::NotFound => ("XTR-EXERCISE-NOT-FOUND", ErrorCategory::NotFound),
        ExerciseError::StorageUnavailable => ("XTR-EXERCISE-STORAGE", ErrorCategory::Resource),
        ExerciseError::StagingOccupied => ("XTR-EXERCISE-STAGING", ErrorCategory::Resource),
        ExerciseError::Conflict => ("XTR-EXERCISE-CONFLICT", ErrorCategory::Conflict),
        ExerciseError::HashMismatch => ("XTR-EXERCISE-HASH", ErrorCategory::Conflict),
        ExerciseError::Expired => ("XTR-EXERCISE-EXPIRED", ErrorCategory::Policy),
        ExerciseError::UnresolvedInput => ("XTR-EXERCISE-UNRESOLVED", ErrorCategory::Policy),
        ExerciseError::ApprovalRequired => ("XTR-EXERCISE-APPROVAL", ErrorCategory::Policy),
        ExerciseError::CredentialValue => ("XTR-EXERCISE-CREDENTIAL", ErrorCategory::Policy),
        ExerciseError::Superseded => ("XTR-EXERCISE-SUPERSEDED", ErrorCategory::Conflict),
        ExerciseError::AlreadyConsumed => ("XTR-EXERCISE-CONSUMED", ErrorCategory::Conflict),
    };
    CliError::App(AppError::new(
        ErrorCode::new(code),
        category,
        error.to_string(),
        RetryAdvice::None,
        CorrelationId::new(),
    ))
}

#[cfg(unix)]
fn open(
    common: &ExerciseArgs,
) -> Result<
    (ExercisePlanService<crate::exercise_store::PrivateExerciseStore>, xtrace_domain::ProjectId),
    CliError,
> {
    let preflight =
        crate::daemon::preflight_project(&common.project_dir, &crate::paths::read_env_path)?;
    let project = crate::daemon::open_validated_project(preflight)?;
    let plans = project
        .private_root
        .open_or_create_private_child("exercise-plans")
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    Ok((
        ExercisePlanService::new(crate::exercise_store::PrivateExerciseStore {
            project: project.project_id,
            plans,
            catalog: project.store,
            project_data_root: project.project_data_root,
        }),
        project.project_id,
    ))
}

#[cfg(unix)]
fn input(path: &std::path::Path) -> Result<CreateExercisePlan, CliError> {
    let absolute = std::path::absolute(path).map_err(|_| map_error(ExerciseError::InvalidInput))?;
    let parent = absolute.parent().ok_or_else(|| map_error(ExerciseError::InvalidInput))?;
    let name = absolute
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| map_error(ExerciseError::InvalidInput))?;
    let root = xtrace_private_storage::AdmittedPrivateRoot::open(parent)
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    let bytes = root
        .read_bounded_file(name, MAX_PLAN_DOCUMENT_BYTES)
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    // Parse diagnostics can quote values or keys: only the fixed typed error escapes.
    serde_json::from_slice(&bytes).map_err(|_| map_error(ExerciseError::InvalidInput))
}

#[cfg(unix)]
pub(crate) fn trusted_now() -> Result<u64, ExerciseError> {
    u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| ExerciseError::Expired)
}

/// Runs `xtrace exercise <command>`. Every implemented branch sends zero requests.
pub async fn run(command: ExerciseCommand) -> Result<i32, CliError> {
    // Preserve existing explicitly tested no-plan fallbacks without weakening
    // assertions; selected plans take the real project-scoped path below.
    match &command {
        ExerciseCommand::Run(_) => {
            return Err(CliError::NotImplemented { command: "exercise run" });
        }
        ExerciseCommand::Approve(args) if args.plan_id.is_none() => {
            return Err(CliError::NotImplemented { command: "exercise approve" });
        }
        ExerciseCommand::Show(args) if args.plan_hash.is_none() => {
            return Err(CliError::NotImplemented { command: "exercise show" });
        }
        _ => {}
    }
    #[cfg(unix)]
    {
        let now = || trusted_now().map_err(map_error);
        let (plan, json) = match command {
            ExerciseCommand::Plan(args) => {
                let request = input(&args.input)?;
                let (service, project) = open(&args.common)?;
                (service.create(project, request, now()?).map_err(map_error)?, args.common.json)
            }
            ExerciseCommand::Edit(args) => {
                let request = input(&args.plan.input)?;
                let (service, project) = open(&args.plan.common)?;
                (
                    service.edit(project, &args.plan_hash, request, now()?).map_err(map_error)?,
                    args.plan.common.json,
                )
            }
            ExerciseCommand::Review(args) => {
                let (service, project) = open(&args.common)?;
                (
                    service.review(project, &args.plan_hash, now()?).map_err(map_error)?,
                    args.common.json,
                )
            }
            ExerciseCommand::Approve(args) => {
                let (service, project) = open(&args.common)?;
                let current = service.show(project, &args.plan_hash).map_err(map_error)?;
                if args.plan_id.as_deref() != Some(current.content.plan_id.as_str()) {
                    return Err(map_error(ExerciseError::HashMismatch));
                }
                (
                    service
                        .approve(
                            project,
                            &args.plan_hash,
                            &args.items,
                            args.confirm_owned_development_target,
                            now()?,
                        )
                        .map_err(map_error)?,
                    args.common.json,
                )
            }
            ExerciseCommand::Show(args) => {
                let hash = args.plan_hash.ok_or_else(|| map_error(ExerciseError::InvalidInput))?;
                let (service, project) = open(&args.common)?;
                (service.show(project, &hash).map_err(map_error)?, args.common.json)
            }
            ExerciseCommand::Run(_) => {
                return Err(CliError::NotImplemented { command: "exercise run" });
            }
        };
        let document = review_document(&plan, now()?).map_err(map_error)?;
        let mut out = std::io::stdout().lock();
        if json {
            crate::output::write_success(&mut out, &document)
        } else {
            use std::io::Write as _;
            writeln!(
                out,
                "{}",
                serde_json::to_string_pretty(&document)
                    .map_err(|_| map_error(ExerciseError::InvalidInput))?
            )
        }
        .map_err(|_| {
            CliError::StoreUnavailable("could not write private exercise review".into())
        })?;
        Ok(0)
    }
    #[cfg(not(unix))]
    Err(CliError::StoreUnavailable("exercise plans require owner-enforced private storage".into()))
}
