//! Authored catalog-read fixtures, not framework or packaged-viewer evidence.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "fixed catalog read fixtures")]

use serde_json::Value;
use xtrace_application::catalog_discovery::history::{
    ObservedOperation, OperationView, RevisionClaim, RevisionEntry,
};
use xtrace_application::{CatalogChangeKind, CatalogSourceAvailability};
use xtrace_domain::ContentHash;
use xtrace_export::catalog::{self, CatalogExportError};
use xtrace_export::{EffectiveState, ExportFormat, ExportRequest};

const FORMATS: [ExportFormat; 4] =
    [ExportFormat::OpenApi, ExportFormat::Postman, ExportFormat::Curl, ExportFormat::Bundle];

fn revision(operation_count: u32) -> RevisionEntry {
    RevisionEntry {
        revision_id: "018f0000-0000-7000-8000-000000000001".parse().unwrap(),
        ordinal: 1,
        parent_revision_id: None,
        scope_digest: ContentHash::of_bytes(b"fixture scope"),
        source_revision_id: None,
        operation_count,
        run_id: "018f0000-0000-7000-8000-000000000002".parse().unwrap(),
        created_at: "2026-11-25T00:00:00Z".to_owned(),
        completion: "complete",
        pack_status: "dev_unsigned",
    }
}

fn operation(index: u8, route: &str) -> OperationView {
    OperationView {
        operation_id: format!("018f0000-0000-7000-8000-{index:012x}").parse().unwrap(),
        operation_version_id: format!("fixture-version-{index}"),
        application_component: "orders".to_owned(),
        binding_key: "default".to_owned(),
        method: "GET".to_owned(),
        route_template: route.to_owned(),
        change_kind: CatalogChangeKind::Added,
        source_availability: CatalogSourceAvailability::Unverified,
        provenance: vec!["static_inferred".to_owned()],
        confidence_basis_points: 0,
        limitation_codes: Vec::new(),
        handlers: Vec::new(),
        handler_conflict: false,
        claim_count: 1,
        source_path: None,
        source_line: None,
        claims_available: true,
        claims: vec![RevisionClaim {
            claim_id: format!("018f0000-0000-7000-8000-{index:012x}").parse().unwrap(),
            provenance: "static_inferred".to_owned(),
            handler_symbol: None,
            confidence_basis_points: None,
            limitation_codes: Vec::new(),
            source_evidence: Vec::new(),
        }],
    }
}

fn observed(operation: &OperationView) -> ObservedOperation {
    ObservedOperation {
        application_component: operation.application_component.clone(),
        binding_key: operation.binding_key.clone(),
        method: operation.method.clone(),
        route_template: operation.route_template.clone(),
        recording_count: 1,
    }
}

#[test]
fn linked_observations_require_positive_count_and_full_scope_identity() {
    let entry = revision(1);
    let view = operation(3, "/orders/{id}");
    let matched = observed(&view);
    let state = |observation| {
        catalog::prepare(&entry, std::slice::from_ref(&view), &[observation]).operations[0]
            .effective_state
    };
    assert_eq!(state(matched.clone()), EffectiveState::Observed);
    let mut mismatches = vec![matched.clone(); 5];
    mismatches[0].application_component = "other-service".to_owned();
    mismatches[1].binding_key = "other-binding".to_owned();
    mismatches[2].method = "POST".to_owned();
    mismatches[3].route_template = "/orders/:id".to_owned();
    mismatches[4].recording_count = 0;
    for mismatch in mismatches {
        assert_eq!(state(mismatch), EffectiveState::StaticOnly);
    }
    let mut unknown = view;
    unknown.change_kind = CatalogChangeKind::Unknown;
    assert_eq!(
        catalog::prepare(&entry, &[unknown], &[matched]).operations[0].effective_state,
        EffectiveState::Unknown
    );
}

#[test]
fn live_observation_update_changes_rendered_bytes_without_changing_revision() {
    let entry = revision(1);
    let view = operation(3, "/orders/{id}");
    let before = catalog::prepare(&entry, std::slice::from_ref(&view), &[]);
    let after = catalog::prepare(&entry, std::slice::from_ref(&view), &[observed(&view)]);
    assert_eq!(before.revision, after.revision);
    for format in FORMATS {
        let request = ExportRequest::new(format);
        let preview = catalog::render(&before, &request).unwrap();
        let later = catalog::render(&after, &request).unwrap();
        assert_ne!(preview.content_hash, later.content_hash);
        assert_ne!(preview.files, later.files);
    }
}

#[test]
fn selection_uses_stable_ids_and_reports_first_missing_before_rendering() {
    let entry = revision(2);
    let first = operation(3, "/orders/{id}");
    let mut second = operation(4, "/orders/{id}");
    second.binding_key = "other-binding".to_owned();
    let input = catalog::prepare(&entry, &[first.clone(), second], &[]);
    let mut request = ExportRequest::new(ExportFormat::Postman);
    request.operation_ids = Some(vec![first.operation_id.to_string(); 2]);
    assert_eq!(catalog::render(&input, &request).unwrap().operation_count, 1);

    // A present route is not a stable operation id. Keep the first missing argument's order.
    request.operation_ids = Some(vec![first.route_template, "another-missing-id".to_owned()]);
    assert_eq!(
        catalog::render(&input, &request),
        Err(CatalogExportError::OperationNotFound { operation_id: "/orders/{id}".to_owned() })
    );
    let mut invalid_document = input;
    invalid_document.operations[0].route_template = "Bearer abcdefghijklmnopqrstuvwxyz".to_owned();
    assert!(matches!(
        catalog::render(&invalid_document, &request),
        Err(CatalogExportError::OperationNotFound { .. })
    ));

    request.operation_ids = Some(Vec::new());
    assert_eq!(catalog::render(&invalid_document, &request).unwrap().operation_count, 0);
}

#[test]
fn all_formats_are_independent_of_catalog_and_observation_read_order() {
    let entry = revision(2);
    let mut views = vec![operation(3, "/orders/{id}"), operation(4, "/users")];
    let mut observations: Vec<_> = views.iter().map(observed).collect();
    let first = catalog::prepare(&entry, &views, &observations);
    views.reverse();
    observations.reverse();
    let second = catalog::prepare(&entry, &views, &observations);
    for format in FORMATS {
        let request = ExportRequest::new(format);
        assert_eq!(catalog::render(&first, &request), catalog::render(&second, &request));
    }
}

#[test]
fn missing_claims_and_policy_remain_explicit_without_copying_summary_values() {
    let entry = revision(1);
    let mut view = operation(3, "/orders/{id}");
    view.claims_available = false;
    view.claims.clear();
    view.source_availability = CatalogSourceAvailability::Unavailable;
    view.handlers = vec!["SUMMARY_ONLY_CANARY".to_owned()];
    view.source_path = Some("SUMMARY_ONLY_CANARY.java".to_owned());
    view.confidence_basis_points = 9999;
    let input = catalog::prepare(&entry, &[view], &[]);
    assert!(input.revision.policy_digest.is_empty());
    for format in FORMATS {
        let output = catalog::render(&input, &ExportRequest::new(format)).unwrap();
        assert!(output.omissions.iter().any(|item| {
            item.what == "policy_digest" && item.reason == "not_available_in_catalog_view"
        }));
        assert!(output.omissions.iter().any(|item| item.reason == "claims_projection_unavailable"));
        for file in &output.files {
            assert!(!String::from_utf8_lossy(&file.bytes).contains("SUMMARY_ONLY_CANARY"));
        }
    }
    let output = catalog::render(&input, &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    let document: Value = serde_json::from_slice(&output.files[0].bytes).unwrap();
    let operation = &document["paths"]["/orders/{id}"]["get"];
    assert!(operation.get("requestBody").is_none());
    assert_eq!(operation["x-xtrace"]["claims_projection"], "unavailable");
    assert_eq!(document["info"]["x-xtrace"].get("policy_digest"), Some(&Value::Null));
}
