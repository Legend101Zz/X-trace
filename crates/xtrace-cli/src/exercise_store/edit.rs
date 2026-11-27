//! Crash-consistent edits. Every entry point holds the same project lifecycle lock.
//! Moving the exact original to its archive is the commit point. Before the move,
//! recovery abandons the preparation. After it, recovery only rolls forward.

use std::io::Write as _;

use serde::{Deserialize, Serialize};
use xtrace_application::exercise::{
    ExerciseError, ExercisePhase, MAX_PLAN_DOCUMENT_BYTES, StoredExercisePlan,
};

use super::{PrivateExerciseStore, STAGING, filename};

// Only SCRATCH may contain a torn write. It is never a source of consent or recovery data.
const SCRATCH: &str = "edit-scratch-v1.tmp";
const INTENT: &str = "edit-intent-v1.json";
const ACTIVE: &str = "edit-active-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Revocation {
    replacement_hash: String,
    replacement_created_at: u64,
}

fn archive_name(hash: &str) -> Result<String, ExerciseError> {
    filename(hash)?;
    Ok(format!("{hash}.predecessor"))
}

impl PrivateExerciseStore {
    fn edit_exists(&self, name: &str) -> Result<bool, ExerciseError> {
        self.plans
            .validate_optional_private_file(name)
            .map_err(|_| ExerciseError::StorageUnavailable)
    }

    fn edit_bytes(&self, name: &str, maximum: usize) -> Result<Vec<u8>, ExerciseError> {
        self.plans.read_bounded_file(name, maximum).map_err(|_| ExerciseError::StorageUnavailable)
    }

    fn write_edit_file(&self, name: &str, bytes: &[u8]) -> Result<(), ExerciseError> {
        let mut scratch = self
            .plans
            .create_private_file(SCRATCH)
            .map_err(|_| ExerciseError::StorageUnavailable)?;
        scratch
            .write_all(bytes)
            .and_then(|()| scratch.sync_all())
            .map_err(|_| ExerciseError::StorageUnavailable)?;
        self.plans
            .validate_file_binding(SCRATCH, &scratch, true)
            .map_err(|_| ExerciseError::StorageUnavailable)?;
        self.plans.rename_replace(SCRATCH, name).map_err(|_| ExerciseError::StorageUnavailable)
    }

    fn install_edit_file(&self, name: &str, bytes: &[u8]) -> Result<(), ExerciseError> {
        if self.edit_exists(name)? {
            if self.edit_bytes(name, MAX_PLAN_DOCUMENT_BYTES)? != bytes {
                return Err(ExerciseError::Conflict);
            }
            return Ok(());
        }
        self.write_edit_file(name, bytes)
    }

    pub(super) fn read_revocation(
        &self,
        bytes: &[u8],
    ) -> Result<StoredExercisePlan, ExerciseError> {
        let receipt: Revocation =
            serde_json::from_slice(bytes).map_err(|_| ExerciseError::StorageUnavailable)?;
        let previous = self.archived_predecessor(&receipt.replacement_hash)?;
        // A later edit may already have revoked this successor. Its own immutable
        // material is then in the next archive; no traversal of the edit chain is needed.
        let next_bytes =
            self.edit_bytes(&filename(&receipt.replacement_hash)?, MAX_PLAN_DOCUMENT_BYTES)?;
        let mut next = match serde_json::from_slice::<StoredExercisePlan>(&next_bytes) {
            Ok(active) => active,
            Err(_) => {
                let later: Revocation = serde_json::from_slice(&next_bytes)
                    .map_err(|_| ExerciseError::StorageUnavailable)?;
                self.archived_predecessor(&later.replacement_hash)?
            }
        };
        if next.plan_hash != receipt.replacement_hash
            || next.content.created_at != receipt.replacement_created_at
        {
            return Err(ExerciseError::HashMismatch);
        }
        next.phase = ExercisePhase::Draft {};
        next.revision = 0;
        previous.revoked_by(&next)
    }

    pub(super) fn check_incoming_edit(
        &self,
        plan: &StoredExercisePlan,
    ) -> Result<(), ExerciseError> {
        let Some(parent) = &plan.content.supersedes else { return Ok(()) };
        let original = self.archived_predecessor(&plan.plan_hash)?;
        let bytes = self.edit_bytes(&filename(&parent.plan_hash)?, MAX_PLAN_DOCUMENT_BYTES)?;
        let receipt: Revocation =
            serde_json::from_slice(&bytes).map_err(|_| ExerciseError::StorageUnavailable)?;
        if receipt.replacement_hash != plan.plan_hash
            || receipt.replacement_created_at != plan.content.created_at
        {
            return Err(ExerciseError::HashMismatch);
        }
        let mut draft = plan.clone();
        draft.phase = ExercisePhase::Draft {};
        draft.revision = 0;
        original.revoked_by(&draft)?;
        Ok(())
    }

    fn archived_predecessor(
        &self,
        replacement_hash: &str,
    ) -> Result<StoredExercisePlan, ExerciseError> {
        let bytes = self.edit_bytes(&archive_name(replacement_hash)?, MAX_PLAN_DOCUMENT_BYTES)?;
        serde_json::from_slice(&bytes).map_err(|_| ExerciseError::StorageUnavailable)
    }

    pub(super) fn commit_edit(
        &self,
        previous: &StoredExercisePlan,
        replacement: &StoredExercisePlan,
        clock: impl Fn() -> Result<u64, ExerciseError>,
    ) -> Result<(), ExerciseError> {
        self.check_project(previous.content.binding.project_id)?;
        previous.revoked_by(replacement)?;
        let original_name = filename(&previous.plan_hash)?;
        let next_name = filename(&replacement.plan_hash)?;
        let archive = archive_name(&replacement.plan_hash)?;
        if self.edit_exists(STAGING)? {
            return Err(ExerciseError::StagingOccupied);
        }
        let original = self.edit_bytes(&original_name, MAX_PLAN_DOCUMENT_BYTES)?;
        if serde_json::from_slice::<StoredExercisePlan>(&original).ok().as_ref() != Some(previous)
            || self.edit_exists(&next_name)?
            || self.edit_exists(&archive)?
            || self.edit_exists(INTENT)?
        {
            return Err(ExerciseError::Conflict);
        }
        let bytes = serde_json::to_vec(replacement).map_err(|_| ExerciseError::InvalidInput)?;
        if bytes.len() > MAX_PLAN_DOCUMENT_BYTES {
            return Err(ExerciseError::InvalidInput);
        }
        // Claim vacant reserved names first. Recovery may discard a torn scratch
        // only within this durable reservation. Occupants outside it are preserved.
        if self.edit_exists(SCRATCH)? || self.edit_exists(ACTIVE)? {
            return Err(ExerciseError::StagingOccupied);
        }
        let active = self
            .plans
            .create_private_file(ACTIVE)
            .map_err(|_| ExerciseError::StorageUnavailable)?;
        active.sync_all().map_err(|_| ExerciseError::StorageUnavailable)?;
        self.plans.sync().map_err(|_| ExerciseError::StorageUnavailable)?;
        self.write_edit_file(INTENT, &bytes)?;
        let before = clock()?;
        previous.ensure_editable_at(before)?;
        replacement.ensure_active_at(before)?;
        self.plans
            .rename_replace(&original_name, &archive)
            .map_err(|_| ExerciseError::StorageUnavailable)?;
        self.recover_edit()?;
        let after = clock()?;
        if after < before {
            return Err(ExerciseError::Expired);
        }
        previous.ensure_active_at(after)?;
        replacement.ensure_active_at(after)
    }

    pub(super) fn recover_edit(&self) -> Result<(), ExerciseError> {
        if !self.edit_exists(ACTIVE)? {
            return Ok(());
        }
        let active =
            self.plans.open_regular_file(ACTIVE).map_err(|_| ExerciseError::StorageUnavailable)?;
        if active.metadata().map_err(|_| ExerciseError::StorageUnavailable)?.len() != 0 {
            return Err(ExerciseError::StorageUnavailable);
        }
        if self.edit_exists(SCRATCH)? {
            let scratch = self
                .plans
                .open_regular_file(SCRATCH)
                .map_err(|_| ExerciseError::StorageUnavailable)?;
            self.plans
                .remove_private_file_if_matches(SCRATCH, &scratch)
                .and_then(|()| self.plans.sync())
                .map_err(|_| ExerciseError::StorageUnavailable)?;
        }
        if self.edit_exists(INTENT)? {
            self.finish_preparation()?;
        }
        self.plans
            .remove_private_file_if_matches(ACTIVE, &active)
            .and_then(|()| self.plans.sync())
            .map_err(|_| ExerciseError::StorageUnavailable)
    }

    fn finish_preparation(&self) -> Result<(), ExerciseError> {
        let handle =
            self.plans.open_regular_file(INTENT).map_err(|_| ExerciseError::StorageUnavailable)?;
        let bytes = self.edit_bytes(INTENT, MAX_PLAN_DOCUMENT_BYTES)?;
        let next: StoredExercisePlan =
            serde_json::from_slice(&bytes).map_err(|_| ExerciseError::StorageUnavailable)?;
        self.check_project(next.content.binding.project_id)?;
        let parent = next.content.supersedes.as_ref().ok_or(ExerciseError::HashMismatch)?;
        let old_hash = &parent.plan_hash;
        let original_name = filename(old_hash)?;
        let next_name = filename(&next.plan_hash)?;
        let archive_name = archive_name(&next.plan_hash)?;
        if self.edit_exists(&archive_name)? {
            let archived = self.edit_bytes(&archive_name, MAX_PLAN_DOCUMENT_BYTES)?;
            let previous: StoredExercisePlan =
                serde_json::from_slice(&archived).map_err(|_| ExerciseError::StorageUnavailable)?;
            previous.revoked_by(&next)?;
            let receipt = Revocation {
                replacement_created_at: next.content.created_at,
                replacement_hash: next.plan_hash.clone(),
            };
            let revoked = serde_json::to_vec(&receipt).map_err(|_| ExerciseError::InvalidInput)?;

            if self.edit_exists(&next_name)? {
                return Err(ExerciseError::Conflict);
            }
            self.install_edit_file(&original_name, &revoked)?;
            self.plans
                .validate_file_binding(INTENT, &handle, true)
                .map_err(|_| ExerciseError::StorageUnavailable)?;
            // The verified intent already is the exact replacement draft. Publishing
            // that inode avoids a second full private payload or a torn destination.
            return self
                .plans
                .rename_replace(INTENT, &next_name)
                .map_err(|_| ExerciseError::StorageUnavailable);
        }
        if self.edit_exists(&next_name)?
            || matches!(self.read(self.project, old_hash)?.phase, ExercisePhase::Superseded { .. })
        {
            return Err(ExerciseError::Conflict);
        }
        // The active original still owns its name. Discard only this uncommitted intent.
        self.plans
            .remove_private_file_if_matches(INTENT, &handle)
            .and_then(|()| self.plans.sync())
            .map_err(|_| ExerciseError::StorageUnavailable)
    }
}
