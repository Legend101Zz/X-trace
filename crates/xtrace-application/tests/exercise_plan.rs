//! Lifecycle contract fixtures, not packaged real-application acceptance evidence.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "checked fixture assertions")]

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier, Mutex};

use xtrace_application::exercise::*;
use xtrace_domain::{CatalogRevisionId, OperationId, ProjectId, RecordingId};

#[derive(Clone)]
struct MemoryPort {
    binding: ExerciseOperationBinding,
    plans: Arc<Mutex<BTreeMap<String, StoredExercisePlan>>>,
    consume_barrier: Option<Arc<Barrier>>,
    race_approval: bool,
}
impl ExercisePlanPort for MemoryPort {
    fn observed_binding(
        &self,
        project: ProjectId,
        request: &CreateExercisePlan,
    ) -> Result<ExerciseOperationBinding, ExerciseError> {
        if project != self.binding.project_id
            || request.operation_id != self.binding.operation_id
            || request.revision_id != self.binding.selected_catalog.revision_id
            || request.recording_id != self.binding.recording_id
        {
            return Err(ExerciseError::BindingUnavailable);
        }
        Ok(self.binding.clone())
    }
    fn insert(&self, plan: &StoredExercisePlan) -> Result<(), ExerciseError> {
        let mut rows = self.plans.lock().unwrap();
        if rows.contains_key(&plan.plan_hash) {
            return Err(ExerciseError::Conflict);
        }
        rows.insert(plan.plan_hash.clone(), plan.clone());
        Ok(())
    }
    fn supersede(
        &self,
        previous: &StoredExercisePlan,
        next: &StoredExercisePlan,
    ) -> Result<(), ExerciseError> {
        let revoked = previous.revoked_by(next)?;
        if let Some(barrier) = &self.consume_barrier {
            barrier.wait();
        }
        let mut rows = self.plans.lock().unwrap();
        if rows.get(&previous.plan_hash) != Some(previous) || rows.contains_key(&next.plan_hash) {
            return Err(ExerciseError::Conflict);
        }
        rows.insert(previous.plan_hash.clone(), revoked);
        rows.insert(next.plan_hash.clone(), next.clone());
        Ok(())
    }

    fn load(&self, project: ProjectId, hash: &str) -> Result<StoredExercisePlan, ExerciseError> {
        self.plans
            .lock()
            .unwrap()
            .get(hash)
            .filter(|p| p.content.binding.project_id == project)
            .cloned()
            .ok_or(ExerciseError::NotFound)
    }
    fn replace(
        &self,
        project: ProjectId,
        hash: &str,
        revision: u64,
        next: &StoredExercisePlan,
    ) -> Result<(), ExerciseError> {
        if matches!(next.phase, ExercisePhase::Consumed { .. })
            || (self.race_approval && matches!(next.phase, ExercisePhase::Approved { .. }))
        {
            if let Some(barrier) = &self.consume_barrier {
                barrier.wait();
            }
        }
        let mut rows = self.plans.lock().unwrap();
        let previous = rows.get(hash).ok_or(ExerciseError::NotFound)?;
        if previous.content.binding.project_id != project
            || previous.revision != revision
            || previous.content != next.content
            || next.revision != revision + 1
        {
            return Err(ExerciseError::Conflict);
        }
        rows.insert(hash.to_owned(), next.clone());
        Ok(())
    }
}

fn fixture(method: &str) -> (MemoryPort, CreateExercisePlan) {
    let binding = ExerciseOperationBinding {
        project_id: ProjectId::new(),
        operation_id: OperationId::new(),
        recording_id: RecordingId::new(),
        selected_catalog: SelectedCatalogOperation {
            revision_id: CatalogRevisionId::new(),
            catalog_hash: "ab".repeat(32),
            operation_version_id: "v1".into(),
            application_component: "ordinary-local-fixture".into(),
            binding_key: "default".into(),
            method: method.into(),
            route_template: "/orders/{id}".into(),
            conflicted: false,
        },
    };
    let request = CreateExercisePlan {
        selected_operation_version_id: binding.selected_catalog.operation_version_id.clone(),
        revision_id: binding.selected_catalog.revision_id,
        operation_id: binding.operation_id,
        recording_id: binding.recording_id,
        target: DevelopmentTarget {
            base_url: "http://127.0.0.1:8080".into(),
            operator_owned_development: true,
        },
        inputs: vec![ExerciseInput {
            name: "id".into(),
            location: InputLocation::Path,
            required: true,
            value: InputValue::Operator { value: PrivateText("7".into()) },
        }],
        body: ExerciseBody::EmptyByOperator {},
        lifetime_seconds: 60,
    };
    (
        MemoryPort { binding, plans: Arc::default(), consume_barrier: None, race_approval: false },
        request,
    )
}

fn item_ids(plan: &StoredExercisePlan) -> Vec<String> {
    review_document(plan, 102).unwrap()["preview"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["item_id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn actual_synthesis_review_and_explicit_per_item_consent_for_every_effect() {
    for (method, conflict, expected) in
        [("GET", false, "read_only"), ("POST", false, "mutating"), ("GET", true, "unknown")]
    {
        let (mut port, request) = fixture(method);
        port.binding.selected_catalog.conflicted = conflict;
        let project = port.binding.project_id;
        let service = ExercisePlanService::new(port);
        let plan = service.create(project, request, 100).unwrap();
        assert!(matches!(plan.phase, ExercisePhase::Draft {}));
        let view = review_document(&plan, 100).unwrap();
        assert_eq!(view["preview"]["items"][0]["effect"], expected);
        assert_eq!(view["preview"]["items"][0]["needs_approval"], true);
        assert_eq!(view["preview"]["items_needing_approval"], 1);
        assert_eq!(view["ready_for_approval"], false);
        assert_eq!(view["requests_sent"], 0);
        assert_eq!(view["execution_available"], false);
        assert_eq!(view["result"]["reason"], "executor_not_implemented");
        assert_eq!(
            service.approve(project, &plan.plan_hash, &item_ids(&plan), true, 101),
            Err(ExerciseError::ApprovalRequired)
        );
        service.show(project, &plan.plan_hash).unwrap();
        assert!(matches!(
            service.show(project, &plan.plan_hash).unwrap().phase,
            ExercisePhase::Draft {}
        ));
        let reviewed = service.review(project, &plan.plan_hash, 101).unwrap();
        assert_eq!(review_document(&reviewed, 101).unwrap()["ready_for_approval"], true);
        assert_eq!(
            service.approve(project, &plan.plan_hash, &[], true, 102),
            Err(ExerciseError::ApprovalRequired)
        );
        assert_eq!(
            service.approve(project, &plan.plan_hash, &item_ids(&plan), false, 102),
            Err(ExerciseError::ApprovalRequired)
        );
        assert_eq!(
            service.approve(project, &plan.plan_hash, &["other-item".into()], true, 102),
            Err(ExerciseError::ApprovalRequired)
        );
        let approved =
            service.approve(project, &plan.plan_hash, &item_ids(&plan), true, 102).unwrap();
        assert_eq!(approved.revision, 2);
        assert!(matches!(
            service.show(project, &plan.plan_hash).unwrap().phase,
            ExercisePhase::Approved { .. }
        ));
        let consumed = service.consume_once(project, &plan.plan_hash, 103).unwrap();
        assert!(matches!(consumed.phase, ExercisePhase::Consumed { .. }));
        assert_eq!(
            service.consume_once(project, &plan.plan_hash, 104),
            Err(ExerciseError::AlreadyConsumed)
        );
        assert_eq!(
            service.review(project, &plan.plan_hash, 104),
            Err(ExerciseError::AlreadyConsumed)
        );
        assert_eq!(review_document(&consumed, 104).unwrap()["requests_sent"], 0);
    }
}

#[test]
fn body_and_inputs_stay_explicitly_unresolved_and_block_consent() {
    let (port, mut request) = fixture("POST");
    let project = port.binding.project_id;
    let service = ExercisePlanService::new(port);
    request.body = ExerciseBody::NotRecorded {};
    let plan = service.create(project, request.clone(), 100).unwrap();
    let view = review_document(&plan, 100).unwrap();
    assert_eq!(view["body"]["source"], "not_recorded");
    assert_eq!(view["ready_for_approval"], false);
    assert_eq!(view["preview"]["items"][0]["ready"], false);
    service.review(project, &plan.plan_hash, 101).unwrap();
    assert_eq!(
        service.approve(project, &plan.plan_hash, &item_ids(&plan), true, 102),
        Err(ExerciseError::UnresolvedInput)
    );
    request.body = ExerciseBody::EmptyByOperator {};
    request.inputs[0].value = InputValue::Unresolved {};
    let missing = service.create(project, request.clone(), 100).unwrap();
    service.review(project, &missing.plan_hash, 101).unwrap();
    assert_eq!(
        service.approve(project, &missing.plan_hash, &item_ids(&missing), true, 102),
        Err(ExerciseError::UnresolvedInput)
    );
    request.inputs[0].required = false;
    assert_eq!(service.create(project, request, 100), Err(ExerciseError::UnresolvedInput));
}

#[test]
fn edits_new_instances_and_tampering_never_inherit_approval() {
    let (port, mut request) = fixture("POST");
    let project = port.binding.project_id;
    let service = ExercisePlanService::new(port.clone());
    let first = service.create(project, request.clone(), 100).unwrap();
    service.review(project, &first.plan_hash, 101).unwrap();
    service.approve(project, &first.plan_hash, &item_ids(&first), true, 102).unwrap();
    let recreated = service.create(project, request.clone(), 100).unwrap();
    request.target.base_url = "http://127.0.0.1:8081".into();
    request.inputs[0].value = InputValue::Operator { value: PrivateText("8".into()) };
    request.body = ExerciseBody::Operator {
        content_type: "application/json".into(),
        content: PrivateText("{\"quantity\":2}".into()),
    };
    let edited = service.create(project, request, 102).unwrap();
    assert_ne!(first.plan_hash, recreated.plan_hash);
    assert_ne!(first.plan_hash, edited.plan_hash);
    assert_ne!(item_ids(&first), item_ids(&edited));
    assert_ne!(item_ids(&first), item_ids(&recreated));
    for p in [&recreated, &edited] {
        assert_eq!(
            service.consume_once(project, &p.plan_hash, 103),
            Err(ExerciseError::ApprovalRequired)
        );
    }
    port.plans.lock().unwrap().get_mut(&first.plan_hash).unwrap().content.request.target.base_url =
        "http://127.0.0.1:9090".into();
    assert_eq!(
        service.consume_once(project, &first.plan_hash, 103),
        Err(ExerciseError::HashMismatch)
    );
}

#[test]
fn exclusive_expiry_and_clock_rollback_fail_closed_without_renewal() {
    let (port, request) = fixture("GET");
    let project = port.binding.project_id;
    let service = ExercisePlanService::new(port);
    let plan = service.create(project, request, 100).unwrap();
    assert_eq!(service.review(project, &plan.plan_hash, 99), Err(ExerciseError::Expired));
    service.review(project, &plan.plan_hash, 120).unwrap();
    assert_eq!(
        service.approve(project, &plan.plan_hash, &item_ids(&plan), true, 119),
        Err(ExerciseError::Expired)
    );
    service.approve(project, &plan.plan_hash, &item_ids(&plan), true, 121).unwrap();
    let repeated_review = service.review(project, &plan.plan_hash, 150).unwrap();
    assert_eq!(repeated_review.content.expires_at, 160);
    assert_eq!(service.consume_once(project, &plan.plan_hash, 160), Err(ExerciseError::Expired));
    assert_eq!(
        review_document(&service.show(project, &plan.plan_hash).unwrap(), 160).unwrap()["expired"],
        true
    );
}

#[test]
fn private_values_are_not_debug_logged_and_credentials_are_only_handles() {
    let (port, mut request) = fixture("POST");
    let project = port.binding.project_id;
    let service = ExercisePlanService::new(port);
    request.inputs.push(ExerciseInput {
        name: "Authorization".into(),
        location: InputLocation::Header,
        required: true,
        value: InputValue::Operator { value: PrivateText("private-fixture-literal".into()) },
    });
    assert!(!format!("{request:?}").contains("private-fixture-literal"));
    let error = service.create(project, request.clone(), 100).unwrap_err();
    assert_eq!(error, ExerciseError::CredentialValue);
    assert!(!error.to_string().contains("private-fixture-literal"));
    request.inputs[1].value =
        InputValue::CredentialReference { reference: PrivateText("local_login".into()) };
    request.inputs.push(ExerciseInput {
        name: "sid".into(),
        location: InputLocation::Cookie,
        required: true,
        value: InputValue::CredentialReference { reference: PrivateText("local_cookie".into()) },
    });
    assert!(!format!("{request:?}").contains("local_login"));
    assert!(!format!("{request:?}").contains("local_cookie"));
    let mut misplaced = request.clone();
    misplaced.inputs[1].value = InputValue::CredentialReference {
        reference: PrivateText("xtrace-canary-private-handle".into()),
    };
    assert_eq!(service.create(project, misplaced, 100), Err(ExerciseError::CredentialValue));
    let plan = service.create(project, request.clone(), 100).unwrap();
    let preview = review_document(&plan, 100).unwrap();
    assert_eq!(preview["preview"]["items"][0]["unresolved_required"], serde_json::json!([]));
    assert_eq!(
        preview["preview"]["items"][0]["credentials_needed_at_run_time"],
        serde_json::json!(["sid", "Authorization"])
    );
    service.review(project, &plan.plan_hash, 101).unwrap();
    service.approve(project, &plan.plan_hash, &item_ids(&plan), true, 102).unwrap();
    for invalid in ["env:LOGIN", "../credentials", "${LOGIN}", "Bearer literal", ""] {
        request.inputs[1].value =
            InputValue::CredentialReference { reference: PrivateText(invalid.into()) };
        assert_eq!(service.create(project, request.clone(), 100), Err(ExerciseError::InvalidInput));
    }
}

#[test]
fn invalid_targets_bounds_and_unobserved_bindings_fail_without_storage() {
    let (port, request) = fixture("GET");
    let project = port.binding.project_id;
    let service = ExercisePlanService::new(port.clone());
    for target in [
        "http://localhost:8080",
        "http://127.0.0.1:8080/path",
        "http://127.0.0.1",
        "http://127.0.0.1:08080",
        "http://127.0.0.1:0",
    ] {
        let mut invalid = request.clone();
        invalid.target.base_url = target.into();
        assert_eq!(service.create(project, invalid, 100), Err(ExerciseError::InvalidInput));
    }
    for ttl in [0, MAX_PLAN_LIFETIME_SECONDS + 1, u64::MAX] {
        let mut invalid = request.clone();
        invalid.lifetime_seconds = ttl;
        assert_eq!(service.create(project, invalid, 100), Err(ExerciseError::InvalidInput));
    }
    let mut invalid = request.clone();
    invalid.recording_id = RecordingId::new();
    assert_eq!(service.create(project, invalid, 100), Err(ExerciseError::BindingUnavailable));
    assert_eq!(
        service.create(ProjectId::new(), request, 100),
        Err(ExerciseError::BindingUnavailable)
    );
    assert!(port.plans.lock().unwrap().is_empty());
}

#[test]
fn concurrent_reservation_has_one_winner_and_never_rearms_unknown_delivery() {
    let (mut port, request) = fixture("POST");
    let project = port.binding.project_id;
    port.consume_barrier = Some(Arc::new(Barrier::new(2)));
    let service = ExercisePlanService::new(port.clone());
    let plan = service.create(project, request, 100).unwrap();
    service.review(project, &plan.plan_hash, 101).unwrap();
    service.approve(project, &plan.plan_hash, &item_ids(&plan), true, 102).unwrap();
    let outcomes = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            ExercisePlanService::new(port.clone()).consume_once(project, &plan.plan_hash, 103)
        });
        let b = scope.spawn(|| {
            ExercisePlanService::new(port.clone()).consume_once(project, &plan.plan_hash, 103)
        });
        [a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(outcomes.iter().filter(|r| **r == Err(ExerciseError::Conflict)).count(), 1);
    assert_eq!(
        service.consume_once(project, &plan.plan_hash, 104),
        Err(ExerciseError::AlreadyConsumed)
    );
}

#[test]
fn bounded_bodies_and_transport_control_cannot_enter_a_plan() {
    let (port, mut request) = fixture("POST");
    let project = port.binding.project_id;
    let service = ExercisePlanService::new(port.clone());
    request.body = ExerciseBody::Operator {
        content_type: "application/json".into(),
        content: PrivateText("{\"password\":\"private-fixture-literal\"}".into()),
    };
    assert_eq!(service.create(project, request.clone(), 100), Err(ExerciseError::CredentialValue));
    request.body = ExerciseBody::Operator {
        content_type: "text/plain".into(),
        content: PrivateText("x".repeat(MAX_REQUEST_BODY_BYTES + 1)),
    };
    assert_eq!(service.create(project, request.clone(), 100), Err(ExerciseError::InvalidInput));
    request.body = ExerciseBody::EmptyByOperator {};
    for name in ["Host", "Content-Length", "Content-Type", "X-Xtrace-Exercise-Item-Id"] {
        let mut invalid = request.clone();
        invalid.inputs.push(ExerciseInput {
            name: name.into(),
            location: InputLocation::Header,
            required: false,
            value: InputValue::Operator { value: PrivateText("fixture".into()) },
        });
        assert_eq!(service.create(project, invalid, 100), Err(ExerciseError::InvalidInput));
    }
    request.inputs[0].value = InputValue::Operator { value: PrivateText("x".repeat(4097)) };
    assert_eq!(service.create(project, request, 100), Err(ExerciseError::InvalidInput));
    assert!(port.plans.lock().unwrap().is_empty());
}

#[test]
fn corrupted_phase_evidence_never_authorizes_a_reservation() {
    let (port, request) = fixture("GET");
    let project = port.binding.project_id;
    let service = ExercisePlanService::new(port.clone());
    let plan = service.create(project, request, 100).unwrap();
    let ids = item_ids(&plan);
    for (rev, phase) in [
        (0, ExercisePhase::Reviewed { reviewed_at: 101 }),
        (2, ExercisePhase::Approved { reviewed_at: 101, approved_at: 102, item_ids: vec![] }),
        (
            2,
            ExercisePhase::Approved {
                reviewed_at: 101,
                approved_at: 102,
                item_ids: vec!["unrelated".into()],
            },
        ),
        (2, ExercisePhase::Approved { reviewed_at: 102, approved_at: 101, item_ids: ids.clone() }),
        (2, ExercisePhase::Approved { reviewed_at: 99, approved_at: 102, item_ids: ids.clone() }),
        (2, ExercisePhase::Approved { reviewed_at: 101, approved_at: 160, item_ids: ids }),
        (1, ExercisePhase::Consumed { consumed_at: 103 }),
    ] {
        let mut invalid = plan.clone();
        invalid.revision = rev;
        invalid.phase = phase;
        port.plans.lock().unwrap().insert(plan.plan_hash.clone(), invalid);
        assert_eq!(service.show(project, &plan.plan_hash), Err(ExerciseError::HashMismatch));
        assert_eq!(
            service.consume_once(project, &plan.plan_hash, 105),
            Err(ExerciseError::HashMismatch)
        );
    }
}

#[test]
fn admitted_drafts_have_space_for_exact_approval_at_the_document_limit() {
    let (port, mut request) = fixture("POST");
    let project = port.binding.project_id;
    let service = ExercisePlanService::new(port);
    for i in 0..55 {
        request.inputs.push(ExerciseInput {
            name: format!("field{i}"),
            location: InputLocation::Query,
            required: true,
            value: InputValue::Operator { value: PrivateText("x".repeat(4096)) },
        });
    }
    request.body = ExerciseBody::Operator {
        content_type: "text/plain".into(),
        content: PrivateText(String::new()),
    };
    let small = service.create(project, request.clone(), 100).unwrap();
    service.review(project, &small.plan_hash, 101).unwrap();
    let approved =
        service.approve(project, &small.plan_hash, &item_ids(&small), true, 102).unwrap();
    let spare = MAX_PLAN_DOCUMENT_BYTES - serde_json::to_vec(&approved).unwrap().len();
    let set_padding = |req: &mut CreateExercisePlan, n| {
        req.body = ExerciseBody::Operator {
            content_type: "text/plain".into(),
            content: PrivateText("y".repeat(n)),
        };
    };
    assert!(spare < MAX_REQUEST_BODY_BYTES);
    set_padding(&mut request, spare + 1);
    assert_eq!(service.create(project, request.clone(), 100), Err(ExerciseError::InvalidInput));
    set_padding(&mut request, spare);
    let max = service.create(project, request, 100).unwrap();
    service.review(project, &max.plan_hash, 101).unwrap();
    let approved = service.approve(project, &max.plan_hash, &item_ids(&max), true, 102).unwrap();
    assert_eq!(serde_json::to_vec(&approved).unwrap().len(), MAX_PLAN_DOCUMENT_BYTES);
    service.consume_once(project, &max.plan_hash, 103).unwrap();
}

#[test]
fn explicit_edit_preserves_predecessor_history_and_requires_fresh_item_consent() {
    let (port, request) = fixture("POST");
    let project = port.binding.project_id;
    let service = ExercisePlanService::new(port);
    let original = service.create(project, request.clone(), 100).unwrap();
    service.review(project, &original.plan_hash, 101).unwrap();
    let prior =
        service.approve(project, &original.plan_hash, &item_ids(&original), true, 102).unwrap();
    let independent = service.create(project, request.clone(), 102).unwrap();
    assert_eq!(service.show(project, &original.plan_hash).unwrap(), prior);
    let mut invalid = request.clone();
    invalid.lifetime_seconds = 0;
    assert_eq!(
        service.edit(project, &original.plan_hash, invalid, 103),
        Err(ExerciseError::InvalidInput)
    );
    assert_eq!(
        service.edit(project, &original.plan_hash, request.clone(), 160),
        Err(ExerciseError::Expired)
    );
    assert_eq!(service.show(project, &original.plan_hash).unwrap(), prior);

    let next = service.edit(project, &original.plan_hash, request.clone(), 103).unwrap();
    assert_ne!(original.content.plan_id, next.content.plan_id);
    assert_ne!(original.plan_hash, next.plan_hash);
    assert_ne!(item_ids(&original), item_ids(&next));
    let revoked = service.show(project, &original.plan_hash).unwrap();
    let view = review_document(&revoked, 104).unwrap();
    assert_eq!(view["phase"]["phase"], "superseded");
    assert_eq!(view["phase"]["replacement_hash"], next.plan_hash);
    assert_eq!(view["phase"]["previous"], serde_json::to_value(&prior.phase).unwrap());
    assert_eq!(view["ready_for_approval"], false);
    assert_eq!(view["requests_sent"], 0);
    assert_eq!(service.review(project, &original.plan_hash, 104), Err(ExerciseError::Superseded));
    assert_eq!(
        service.approve(project, &original.plan_hash, &item_ids(&original), true, 104),
        Err(ExerciseError::Superseded)
    );
    assert_eq!(
        service.consume_once(project, &original.plan_hash, 104),
        Err(ExerciseError::Superseded)
    );
    assert_eq!(
        service.edit(project, &original.plan_hash, request.clone(), 104),
        Err(ExerciseError::Superseded)
    );
    assert_eq!(service.show(project, &independent.plan_hash).unwrap(), independent);
    assert_eq!(
        service.consume_once(project, &next.plan_hash, 104),
        Err(ExerciseError::ApprovalRequired)
    );
    service.review(project, &next.plan_hash, 105).unwrap();
    assert_eq!(
        service.approve(project, &next.plan_hash, &item_ids(&original), true, 105),
        Err(ExerciseError::ApprovalRequired)
    );
    service.approve(project, &next.plan_hash, &item_ids(&next), true, 106).unwrap();
    service.consume_once(project, &next.plan_hash, 107).unwrap();
    assert_eq!(
        service.edit(project, &next.plan_hash, request, 108),
        Err(ExerciseError::AlreadyConsumed)
    );
}

#[test]
fn explicit_edit_races_the_same_original_revision_as_approval_or_reservation() {
    for reservation in [false, true] {
        let (mut port, request) = fixture("GET");
        let project = port.binding.project_id;
        let setup = ExercisePlanService::new(port.clone());
        let original = setup.create(project, request.clone(), 100).unwrap();
        setup.review(project, &original.plan_hash, 101).unwrap();
        if reservation {
            setup.approve(project, &original.plan_hash, &item_ids(&original), true, 102).unwrap();
        }
        port.race_approval = !reservation;
        port.consume_barrier = Some(Arc::new(Barrier::new(2)));
        let service = ExercisePlanService::new(port.clone());
        let (edit, transition) = std::thread::scope(|scope| {
            let edit = scope.spawn(|| service.edit(project, &original.plan_hash, request, 103));
            let transition = if reservation {
                service.consume_once(project, &original.plan_hash, 103)
            } else {
                service.approve(project, &original.plan_hash, &item_ids(&original), true, 103)
            };
            (edit.join().unwrap(), transition)
        });
        if let Ok(next) = edit {
            assert_eq!(transition, Err(ExerciseError::Conflict));
            assert!(
                matches!(setup.show(project, &original.plan_hash).unwrap().phase, ExercisePhase::Superseded { replacement_hash, .. } if replacement_hash == next.plan_hash)
            );
            assert!(matches!(
                setup.show(project, &next.plan_hash).unwrap().phase,
                ExercisePhase::Draft {}
            ));
            assert_eq!(port.plans.lock().unwrap().len(), 2);
        } else {
            assert_eq!(edit, Err(ExerciseError::Conflict));
            assert_eq!(setup.show(project, &original.plan_hash).unwrap(), transition.unwrap());
            assert_eq!(port.plans.lock().unwrap().len(), 1);
        }
    }
}
