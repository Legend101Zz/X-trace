//! Pure lifecycle orchestration. Storage is behind an atomic port; no networking.

use std::collections::BTreeSet;

use serde_json::{Value, json};
use xtrace_domain::ProjectId;
use xtrace_exercise::{CandidateOp, CandidateParam, ChangeKind, Plan, PlanInput};

use super::model::*;

/// Shared exercise lifecycle use case. The caller supplies authenticated project
/// context and trusted wall time, never a client-selected timestamp.
pub struct ExercisePlanService<P> {
    port: P,
}

impl<P: ExercisePlanPort> ExercisePlanService<P> {
    /// Bind the service to an evidence/storage adapter.
    pub const fn new(port: P) -> Self {
        Self { port }
    }

    /// Create a new immutable draft. No review, approval or request is implied.
    pub fn create(
        &self,
        project: ProjectId,
        request: CreateExercisePlan,
        now: u64,
    ) -> Result<StoredExercisePlan, ExerciseError> {
        let plan = self.draft(project, request, None, now)?;
        self.port.insert(&plan)?;
        Ok(plan)
    }

    /// Replace an exact active plan with a separately identified draft. The old consent is terminal.
    pub fn edit(
        &self,
        project: ProjectId,
        hash: &str,
        request: CreateExercisePlan,
        now: u64,
    ) -> Result<StoredExercisePlan, ExerciseError> {
        let original = self.show(project, hash)?;
        original.ensure_editable_at(now)?;
        let replacement = self.draft(project, request, Some(original.edit_predecessor()?), now)?;
        self.port.supersede(&original, &replacement)?;
        Ok(replacement)
    }

    fn draft(
        &self,
        project: ProjectId,
        request: CreateExercisePlan,
        supersedes: Option<EditPredecessor>,
        now: u64,
    ) -> Result<StoredExercisePlan, ExerciseError> {
        let binding = self.port.observed_binding(project, &request)?;
        if binding.project_id != project
            || binding.selected_catalog.revision_id != request.revision_id
            || binding.selected_catalog.operation_version_id
                != request.selected_operation_version_id
            || binding.operation_id != request.operation_id
            || binding.recording_id != request.recording_id
        {
            return Err(ExerciseError::BindingUnavailable);
        }
        let content = ExercisePlanContent {
            schema_version: 1,
            supersedes,
            plan_id: uuid::Uuid::now_v7().to_string(),
            expires_at: now
                .checked_add(request.lifetime_seconds)
                .ok_or(ExerciseError::InvalidInput)?,
            binding,
            request,
            created_at: now,
            bounds: ExecutionBounds::default(),
        };
        let plan_hash = checked_hash(&content)?;
        let plan =
            StoredExercisePlan { content, plan_hash, revision: 0, phase: ExercisePhase::Draft {} };
        ensure_envelope_capacity(&plan)?;
        Ok(plan)
    }

    /// Read/preview without changing lifecycle. An expired plan may still be
    /// inspected, but can never be approved or consumed.
    pub fn show(
        &self,
        project: ProjectId,
        hash: &str,
    ) -> Result<StoredExercisePlan, ExerciseError> {
        check_hash_syntax(hash)?;
        let plan = self.port.load(project, hash)?;
        verify_identity(&plan, project, hash)?;
        Ok(plan)
    }

    /// Mark an explicit review of this exact hash. Missing inputs are shown in
    /// the review and may remain unresolved until a newly created plan fixes them.
    pub fn review(
        &self,
        project: ProjectId,
        hash: &str,
        now: u64,
    ) -> Result<StoredExercisePlan, ExerciseError> {
        let mut plan = self.show(project, hash)?;
        plan.ensure_active_at(now)?;
        match plan.phase {
            ExercisePhase::Draft {} => {
                let revision = plan.revision;
                plan.phase = ExercisePhase::Reviewed { reviewed_at: now };
                self.save(project, hash, revision, &mut plan)?;
            }
            ExercisePhase::Consumed { .. } => return Err(ExerciseError::AlreadyConsumed),
            ExercisePhase::Superseded { .. } => return Err(ExerciseError::Superseded),
            // A repeated review neither renews expiry nor restores/changes consent.
            ExercisePhase::Reviewed { .. } | ExercisePhase::Approved { .. } => {}
        }
        Ok(plan)
    }

    /// Approve the exact reviewed plan with explicit consent to the local
    /// development target and item IDs. No credential is resolved and nothing sends.
    pub fn approve(
        &self,
        project: ProjectId,
        hash: &str,
        item_ids: &[String],
        confirm_owned_development_target: bool,
        now: u64,
    ) -> Result<StoredExercisePlan, ExerciseError> {
        let mut plan = self.show(project, hash)?;
        plan.ensure_active_at(now)?;
        let reviewed_at = match plan.phase {
            ExercisePhase::Reviewed { reviewed_at } => reviewed_at,
            ExercisePhase::Consumed { .. } => return Err(ExerciseError::AlreadyConsumed),
            ExercisePhase::Superseded { .. } => return Err(ExerciseError::Superseded),
            _ => return Err(ExerciseError::ApprovalRequired),
        };
        if !confirm_owned_development_target {
            return Err(ExerciseError::ApprovalRequired);
        }
        let synthesized = synthesize(&plan.content)?;
        check_ready(&plan.content, &synthesized)?;
        let selected: BTreeSet<String> = synthesized
            .items
            .iter()
            .filter(|i| i.selected)
            .map(|i| xtrace_exercise::canonical::item_uuid(hash, &i.operation_id))
            .collect();
        let approved: BTreeSet<String> = item_ids.iter().cloned().collect();
        // Explicit approval is required even for a read-only candidate. In
        // particular, no global boolean silently approves mutations or unknowns.
        if selected.is_empty() || approved != selected || approved.len() != item_ids.len() {
            return Err(ExerciseError::ApprovalRequired);
        }
        let revision = plan.revision;
        plan.phase = ExercisePhase::Approved {
            reviewed_at,
            approved_at: now,
            item_ids: approved.into_iter().collect(),
        };
        self.save(project, hash, revision, &mut plan)?;
        Ok(plan)
    }

    /// Reserve approval exactly once, durably, BEFORE any future executor could
    /// resolve credentials or send. This method does not send. Lost responses or
    /// crashes after reservation remain consumed/unknown and must never be retried.
    /// A later executor must enforce all pinned bounds and connect-time guards.
    pub fn consume_once(
        &self,
        project: ProjectId,
        hash: &str,
        now: u64,
    ) -> Result<StoredExercisePlan, ExerciseError> {
        let mut plan = self.show(project, hash)?;
        plan.ensure_active_at(now)?;
        match plan.phase {
            ExercisePhase::Approved { .. } => {}
            ExercisePhase::Consumed { .. } => return Err(ExerciseError::AlreadyConsumed),
            ExercisePhase::Superseded { .. } => return Err(ExerciseError::Superseded),
            _ => return Err(ExerciseError::ApprovalRequired),
        }
        check_ready(&plan.content, &synthesize(&plan.content)?)?;
        let revision = plan.revision;
        plan.phase = ExercisePhase::Consumed { consumed_at: now };
        self.save(project, hash, revision, &mut plan)?;
        Ok(plan)
    }

    fn save(
        &self,
        project: ProjectId,
        hash: &str,
        revision: u64,
        plan: &mut StoredExercisePlan,
    ) -> Result<(), ExerciseError> {
        plan.revision = revision.checked_add(1).ok_or(ExerciseError::Conflict)?;
        self.port.replace(project, hash, revision, plan)
    }
}

/// Operator review includes private inputs by explicit request. Do not log or
/// publish this document. Credentials remain references, and body absence stays
/// visibly `not_recorded` until the operator makes an explicit decision.
pub fn review_document(plan: &StoredExercisePlan, now: u64) -> Result<Value, ExerciseError> {
    verify_identity(plan, plan.content.binding.project_id, &plan.plan_hash)?;
    let synthesized = synthesize(&plan.content)?;
    let ready = check_ready(&plan.content, &synthesized).is_ok();
    let mut preview = xtrace_exercise::preview(&synthesized);
    preview["synthesis_plan_hash"] = Value::String(synthesized.plan_hash.clone());
    preview["plan_hash"] = Value::String(plan.plan_hash.clone());
    // The lifecycle requires exact item consent for every selected operation.
    preview["items_needing_approval"] = preview["selected_items"].clone();
    if let Some(items) = preview.get_mut("items").and_then(Value::as_array_mut) {
        for item in items {
            item["needs_approval"] = item["selected"].clone();
            item["ready"] = Value::Bool(ready);
            item["synthesis_item_id"] = item["item_id"].clone();
            let operation = item["operation_id"].as_str().ok_or(ExerciseError::InvalidInput)?;
            item["item_id"] =
                Value::String(xtrace_exercise::canonical::item_uuid(&plan.plan_hash, operation));
        }
    }
    let mut document = json!({
        "kind": "exercise_plan_review",
        "plan_hash": plan.plan_hash,
        "plan_id": plan.content.plan_id,
        "project_id": plan.content.binding.project_id,
        "observed_recording": {
            "recording_id": plan.content.binding.recording_id,
            "operation_id": plan.content.binding.operation_id,
            "catalog_revision_id": null,
            "operation_version_id": null,
            "version_evidence": "not_observed"
        },
        "selected_catalog_operation": {
            "operation_id": plan.content.binding.operation_id,
            "selection_basis": "operator_selected_catalog_version",
            "catalog": plan.content.binding.selected_catalog
        },
        "target": plan.content.request.target,
        "inputs": plan.content.request.inputs,
        "body": plan.content.request.body,
        "created_at": plan.content.created_at,
        "expires_at": plan.content.expires_at,
        "expired": plan.ensure_active_at(now).is_err(),
        "bounds": plan.content.bounds,
        "phase": plan.phase,
        "preview": preview,
        "ready_for_approval": ready && plan.ensure_active_at(now).is_ok()
            && matches!(plan.phase, ExercisePhase::Reviewed { .. }),
        "requests_sent": 0,
        "execution_available": false,
        "result": { "status": "unavailable", "reason": "executor_not_implemented" },
        "note": "Read-only is a candidate classification, not a guarantee. Private operator review; do not publish."
    });
    if let Some(prior) = &plan.content.supersedes {
        document["supersedes"] = Value::String(prior.plan_hash.clone());
    }
    Ok(document)
}

fn check_hash_syntax(hash: &str) -> Result<(), ExerciseError> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(ExerciseError::InvalidInput);
    }
    Ok(())
}

impl StoredExercisePlan {
    fn edit_predecessor(&self) -> Result<EditPredecessor, ExerciseError> {
        let bytes = serde_json::to_vec(self).map_err(|_| ExerciseError::InvalidInput)?;
        Ok(EditPredecessor {
            plan_hash: self.plan_hash.clone(),
            state_digest: blake3::hash(&bytes).to_hex().to_string(),
        })
    }

    /// Check the independent draft and its cryptographic binding to this exact previous state.
    pub fn revoked_by(&self, successor: &Self) -> Result<Self, ExerciseError> {
        self.ensure_editable_at(successor.content.created_at)?;
        if successor.content.supersedes.as_ref() != Some(&self.edit_predecessor()?)
            || successor.content.binding.project_id != self.content.binding.project_id
            || successor.content.plan_id == self.content.plan_id
            || successor.plan_hash == self.plan_hash
            || !matches!(successor.phase, ExercisePhase::Draft {})
            || successor.revision != 0
        {
            return Err(ExerciseError::HashMismatch);
        }
        verify_identity(successor, successor.content.binding.project_id, &successor.plan_hash)?;
        self.with_revocation(&successor.plan_hash, successor.content.created_at)
    }

    // Reconstruct terminal state from the preserved active envelope.
    fn with_revocation(&self, replacement_hash: &str, at: u64) -> Result<Self, ExerciseError> {
        verify_identity(self, self.content.binding.project_id, &self.plan_hash)?;
        check_hash_syntax(replacement_hash)?;
        self.ensure_editable_at(at)?;
        if replacement_hash == self.plan_hash {
            return Err(ExerciseError::HashMismatch);
        }
        let mut revoked = self.clone();
        revoked.revision += 1;
        revoked.phase = ExercisePhase::Superseded {
            replacement_created_at: at,
            replacement_hash: replacement_hash.to_owned(),
            previous: Box::new(self.phase.clone()),
        };
        Ok(revoked)
    }

    /// Refuse to supersede a reserved, superseded, expired or clock-invalid plan.
    pub fn ensure_editable_at(&self, now: u64) -> Result<(), ExerciseError> {
        match self.phase {
            ExercisePhase::Consumed { .. } => Err(ExerciseError::AlreadyConsumed),
            ExercisePhase::Superseded { .. } => Err(ExerciseError::Superseded),
            _ => self.ensure_active_at(now),
        }
    }

    /// Check a trusted clock reading against the last transition and exclusive expiry.
    /// The durable adapter repeats this check around publication under its lock.
    pub fn ensure_active_at(&self, now: u64) -> Result<(), ExerciseError> {
        let latest = match self.phase {
            ExercisePhase::Draft {} => self.content.created_at,
            ExercisePhase::Reviewed { reviewed_at } => reviewed_at,
            ExercisePhase::Approved { approved_at, .. } => approved_at,
            ExercisePhase::Consumed { consumed_at } => consumed_at,
            ExercisePhase::Superseded { replacement_created_at, .. } => replacement_created_at,
        };
        if now < latest || now < self.content.created_at || now >= self.content.expires_at {
            return Err(ExerciseError::Expired);
        }
        Ok(())
    }
}

fn ensure_envelope_capacity(plan: &StoredExercisePlan) -> Result<(), ExerciseError> {
    // One item per plan. Approval has the largest encoded phase, including two
    // timestamps and the exact item UUID. The other transitions only remove bytes.
    let mut largest = plan.clone();
    largest.revision = 2;
    largest.phase = ExercisePhase::Approved {
        reviewed_at: plan.content.expires_at,
        approved_at: plan.content.expires_at,
        item_ids: vec![xtrace_exercise::canonical::item_uuid(
            &plan.plan_hash,
            &plan.content.binding.operation_id.to_string(),
        )],
    };
    if serde_json::to_vec(&largest).map_err(|_| ExerciseError::InvalidInput)?.len()
        > MAX_PLAN_DOCUMENT_BYTES
    {
        return Err(ExerciseError::InvalidInput);
    }
    Ok(())
}

fn verify_identity(
    plan: &StoredExercisePlan,
    project: ProjectId,
    hash: &str,
) -> Result<(), ExerciseError> {
    if plan.content.binding.project_id != project
        || plan.plan_hash != hash
        || checked_hash(&plan.content)? != hash
    {
        return Err(ExerciseError::HashMismatch);
    }
    let in_lifetime = plan.content.created_at..plan.content.expires_at;
    let valid_phase = match &plan.phase {
        ExercisePhase::Draft {} => plan.revision == 0,
        ExercisePhase::Reviewed { reviewed_at } => {
            plan.revision == 1 && in_lifetime.contains(reviewed_at)
        }
        ExercisePhase::Approved { reviewed_at, approved_at, item_ids } => {
            plan.revision == 2
                && in_lifetime.contains(reviewed_at)
                && in_lifetime.contains(approved_at)
                && reviewed_at <= approved_at
                && item_ids
                    == &[xtrace_exercise::canonical::item_uuid(
                        hash,
                        &plan.content.binding.operation_id.to_string(),
                    )]
                && check_ready(&plan.content, &synthesize(&plan.content)?).is_ok()
        }
        ExercisePhase::Superseded { replacement_created_at, replacement_hash, previous } => {
            if matches!(
                **previous,
                ExercisePhase::Consumed { .. } | ExercisePhase::Superseded { .. }
            ) || !(1..=3).contains(&plan.revision)
            {
                return Err(ExerciseError::HashMismatch);
            }
            let mut original = plan.clone();
            original.phase = *previous.clone();
            original.revision -= 1;
            original.with_revocation(replacement_hash, *replacement_created_at)? == *plan
        }
        ExercisePhase::Consumed { consumed_at } => {
            plan.revision == 3 && in_lifetime.contains(consumed_at)
        }
    };
    if !valid_phase {
        return Err(ExerciseError::HashMismatch);
    }
    Ok(())
}

fn checked_hash(content: &ExercisePlanContent) -> Result<String, ExerciseError> {
    validate(content)?;
    let synthesized = synthesize(content)?;
    let value = json!({
        "version": 1,
        "content": content,
        "synthesized_plan": xtrace_exercise::canonical::plan_value(&synthesized),
    });
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xtrace.exercise.owner-plan.v1\0");
    hasher.update(serde_json::to_vec(&value).map_err(|_| ExerciseError::InvalidInput)?.as_slice());
    Ok(hasher.finalize().to_hex().to_string())
}

fn synthesize(content: &ExercisePlanContent) -> Result<Plan, ExerciseError> {
    let request = &content.request;
    let op = &content.binding.selected_catalog;
    let mut plan = xtrace_exercise::synthesize(&PlanInput {
        revision_id: op.revision_id.to_string(),
        catalog_hash: op.catalog_hash.clone(),
        target: request.target.base_url.clone(),
        ops: vec![CandidateOp {
            operation_id: content.binding.operation_id.to_string(),
            method: op.method.clone(),
            route_template: op.route_template.clone(),
            change_kind: ChangeKind::Unchanged,
            observed_recording_count: Some(1),
            conflicted: op.conflicted,
            effect_hints: vec![],
            params: request
                .inputs
                .iter()
                .map(|p| CandidateParam {
                    name: p.name.clone(),
                    location: p.location.name().to_owned(),
                    required: p.required,
                    scenario_value: match &p.value {
                        InputValue::Operator { value } => Some(value.0.clone()),
                        _ => None,
                    },
                    ..CandidateParam::default()
                })
                .collect(),
        }],
        explicit_selection: Some(vec![content.binding.operation_id.to_string()]),
    })
    .map_err(|_| ExerciseError::InvalidInput)?;
    // Opaque handles live only in the private wrapper. The underlying plan sees
    // credential provenance and no literal value, including ordinary cookie names.
    for param in plan.items.iter_mut().flat_map(|i| &mut i.params) {
        if request.inputs.iter().any(|p| {
            p.name == param.name
                && p.location.name() == param.location
                && matches!(p.value, InputValue::CredentialReference { .. })
        }) {
            param.source = xtrace_exercise::ValueSource::Credential;
            param.value = None;
        }
    }
    plan.plan_hash = xtrace_exercise::canonical::recompute_hash(&plan);
    for item in &mut plan.items {
        item.item_id = xtrace_exercise::canonical::item_uuid(&plan.plan_hash, &item.operation_id);
    }
    Ok(plan)
}

fn check_ready(content: &ExercisePlanContent, synthesized: &Plan) -> Result<(), ExerciseError> {
    if matches!(content.request.body, ExerciseBody::NotRecorded {}) {
        return Err(ExerciseError::UnresolvedInput);
    }
    if content.request.inputs.iter().any(|p| matches!(p.value, InputValue::Unresolved {})) {
        return Err(ExerciseError::UnresolvedInput);
    }
    // Synthesis refuses secret-shaped literal values. Required references are
    // intentionally deferred, but only explicitly supplied opaque handles qualify.
    for param in synthesized.items.iter().flat_map(|i| &i.params) {
        if param.required && param.value.is_none() {
            let provided_reference = content.request.inputs.iter().any(|p| {
                p.name == param.name
                    && p.location.name() == param.location
                    && matches!(p.value, InputValue::CredentialReference { .. })
            });
            if !provided_reference {
                return Err(ExerciseError::UnresolvedInput);
            }
        }
    }
    Ok(())
}

fn validate(content: &ExercisePlanContent) -> Result<(), ExerciseError> {
    let req = &content.request;
    let binding = &content.binding;
    let catalog = &binding.selected_catalog;
    if content.schema_version != 1
        || uuid::Uuid::parse_str(&content.plan_id).ok().is_none_or(|u| u.get_version_num() != 7)
        || req.lifetime_seconds == 0
        || req.lifetime_seconds > MAX_PLAN_LIFETIME_SECONDS
        || content.created_at.checked_add(req.lifetime_seconds) != Some(content.expires_at)
        || content.bounds != ExecutionBounds::default()
        || catalog.revision_id != req.revision_id
        || binding.operation_id != req.operation_id
        || binding.recording_id != req.recording_id
        || catalog.operation_version_id != req.selected_operation_version_id
        || catalog.operation_version_id.is_empty()
        || catalog.operation_version_id.len() > 128
        || catalog.catalog_hash.len() != 64
        || !catalog.catalog_hash.bytes().all(|b| b.is_ascii_hexdigit())
        || catalog.application_component.len() > 256
        || catalog.binding_key.len() > 256
        || catalog.method.is_empty()
        || catalog.method.len() > 16
        || !catalog.method.bytes().all(|b| b.is_ascii_uppercase())
        || req.inputs.len() > 64
    {
        return Err(ExerciseError::InvalidInput);
    }
    if let Some(predecessor) = &content.supersedes {
        check_hash_syntax(&predecessor.plan_hash)?;
        check_hash_syntax(&predecessor.state_digest)?;
    }
    validate_target(&req.target)?;
    let route = &catalog.route_template;
    if route.len() > 2048
        || !route.starts_with('/')
        || route.starts_with("//")
        || route.contains(['\\', '?', '#'])
        || route.chars().any(char::is_control)
        || xtrace_exercise::is_secret_input("", route)
    {
        return Err(ExerciseError::InvalidInput);
    }
    let mut keys = BTreeSet::new();
    for input in &req.inputs {
        let name = &input.name;
        if name.is_empty()
            || name.len() > 128
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || !keys.insert((input.location.name(), name.to_ascii_lowercase()))
            || (input.location == InputLocation::Header
                && matches!(
                    name.to_ascii_lowercase().as_str(),
                    "host"
                        | "content-length"
                        | "transfer-encoding"
                        | "connection"
                        | "upgrade"
                        | "proxy-authorization"
                        | "proxy-connection"
                        | "trailer"
                        | "te"
                        | "expect"
                        | "content-type"
                        | "x-xtrace-exercise-item"
                        | "x-xtrace-exercise-item-id"
                        | "x-xtrace-exercise-plan-hash"
                ))
        {
            return Err(ExerciseError::InvalidInput);
        }
        let credential =
            input.location == InputLocation::Cookie || xtrace_exercise::is_secret_input(name, "");
        match &input.value {
            InputValue::Operator { value } => {
                if credential || xtrace_exercise::is_secret_input(name, &value.0) {
                    return Err(ExerciseError::CredentialValue);
                }
                if value.0.len() > 4096 || value.0.chars().any(char::is_control) {
                    return Err(ExerciseError::InvalidInput);
                }
            }
            InputValue::CredentialReference { reference } => {
                // The handle is private, syntactically bounded and screened like other input.
                if xtrace_exercise::is_secret_input("", &reference.0) {
                    return Err(ExerciseError::CredentialValue);
                }
                if !credential
                    || reference.0.is_empty()
                    || reference.0.len() > 64
                    || !reference.0.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                {
                    return Err(ExerciseError::InvalidInput);
                }
            }
            InputValue::Unresolved {} => {}
        }
    }
    // Every template placeholder must have an explicitly required path input;
    // no hidden interpolation, optional placeholder or extra path field is admitted.
    let mut placeholders = BTreeSet::new();
    for segment in route.split('/') {
        if segment.contains(['{', '}']) {
            let name = segment
                .strip_prefix('{')
                .and_then(|s| s.strip_suffix('}'))
                .ok_or(ExerciseError::InvalidInput)?;
            if name.is_empty() || !placeholders.insert(name) {
                return Err(ExerciseError::InvalidInput);
            }
        }
    }
    let path_inputs: BTreeSet<&str> = req
        .inputs
        .iter()
        .filter(|p| p.location == InputLocation::Path)
        .map(|p| p.name.as_str())
        .collect();
    if placeholders != path_inputs
        || req.inputs.iter().any(|p| p.location == InputLocation::Path && !p.required)
    {
        return Err(ExerciseError::UnresolvedInput);
    }
    if let ExerciseBody::Operator { content_type, content: body } = &req.body {
        if body.0.len() > MAX_REQUEST_BODY_BYTES
            || !matches!(content_type.as_str(), "application/json" | "text/plain")
        {
            return Err(ExerciseError::InvalidInput);
        }
        if xtrace_exercise::is_secret_input("", &body.0) {
            return Err(ExerciseError::CredentialValue);
        }
        if content_type == "application/json" {
            let parsed =
                super::body_json::parse(&body.0).map_err(|_| ExerciseError::InvalidInput)?;
            if xtrace_exercise::json_has_secret(&parsed) {
                return Err(ExerciseError::CredentialValue);
            }
        }
    }
    Ok(())
}

fn validate_target(target: &DevelopmentTarget) -> Result<(), ExerciseError> {
    if !target.operator_owned_development
        || target.base_url.len() > 128
        || !target.base_url.starts_with("http://")
        || xtrace_exercise::classify_target_host(&target.base_url)
            .map_err(|_| ExerciseError::InvalidInput)?
            != xtrace_exercise::HostClass::Loopback
    {
        return Err(ExerciseError::InvalidInput);
    }
    // Restrict to canonical literal loopback origins only. No DNS, URL path,
    // query, fragment, proxy or userinfo can become a destination in this slice.
    let authority = target.base_url.strip_prefix("http://").ok_or(ExerciseError::InvalidInput)?;
    let (host, port) = authority.rsplit_once(':').ok_or(ExerciseError::InvalidInput)?;
    if authority.contains('/')
        || (host != "127.0.0.1" && host != "[::1]")
        || port.parse::<u16>().ok().is_none_or(|p| p == 0 || p.to_string() != port)
    {
        return Err(ExerciseError::InvalidInput);
    }
    Ok(())
}
