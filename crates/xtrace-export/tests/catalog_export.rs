//! Authored catalog-read fixtures, not framework or packaged-viewer evidence.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "fixed catalog read fixtures")]

use serde_json::Value;
use xtrace_application::catalog_discovery::history::{
    CatalogExportOperationIdentity, CatalogExportRevision, CatalogExportScope,
    CatalogExportSnapshot, ObservedOperation, OperationView, RevisionClaim, RevisionEntry,
};
use xtrace_application::{CatalogChangeKind, CatalogSourceAvailability};
use xtrace_domain::{ContentHash, OperationId};
use xtrace_export::catalog::{self, CatalogExportError};
use xtrace_export::viewer::{
    self, PreviewFilename, ViewerExportError, ViewerExportLimit, ViewerExportRequest,
};
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

fn snapshot(
    views: &[OperationView],
    scope: CatalogExportScope,
    linked: &[OperationId],
) -> CatalogExportSnapshot {
    CatalogExportSnapshot {
        revision: revision(u32::try_from(views.len()).unwrap()),
        catalog_identities: views
            .iter()
            .map(|view| CatalogExportOperationIdentity {
                application_component: view.application_component.clone(),
                binding_key: view.binding_key.clone(),
                method: view.method.clone(),
                route_template: view.route_template.clone(),
                operation_version_id: view.operation_version_id.clone(),
            })
            .collect(),
        operations: views
            .iter()
            .filter(|view| match scope {
                CatalogExportScope::All => true,
                CatalogExportScope::Operation(id) => view.operation_id == id,
            })
            .cloned()
            .collect(),
        linked_operation_ids: linked.iter().copied().collect(),
    }
}

fn viewer_request(format: ExportFormat, scope: CatalogExportScope) -> ViewerExportRequest {
    ViewerExportRequest { revision: CatalogExportRevision::Latest, scope, format, yaml: false }
}

#[test]
fn viewer_preview_and_approved_save_preserve_exact_cli_artifacts_for_each_scope_and_format() {
    let root = operation(3, "/");
    let mut orders = operation(4, "/fixturePrivateSegment/{id}");
    orders.application_component = "second-component".to_owned();
    let observations = [observed(&orders)];
    let orders_id = orders.operation_id;
    let views = [root, orders];
    for scope in [CatalogExportScope::All, CatalogExportScope::Operation(orders_id)] {
        let snapshot = snapshot(&views, scope, &[orders_id]);
        let cli_input = catalog::prepare(&snapshot.revision, &views, &observations);
        for (format, yaml) in
            FORMATS.map(|format| (format, false)).into_iter().chain([(ExportFormat::OpenApi, true)])
        {
            let request = ViewerExportRequest { yaml, ..viewer_request(format, scope) };
            let cli_request = ExportRequest {
                format,
                operation_ids: match scope {
                    CatalogExportScope::All => None,
                    CatalogExportScope::Operation(id) => Some(vec![id.to_string()]),
                },
                yaml,
            };
            let cli = catalog::render(&cli_input, &cli_request).unwrap();
            let preview = viewer::preview(&snapshot, request).unwrap();
            assert_eq!(preview.revision_id, snapshot.revision.revision_id);
            assert_eq!(preview.request, request);
            assert_eq!(preview.selected_operations, snapshot.operations.len());
            assert_eq!(preview.emitted_operations, cli.operation_count);
            assert_eq!(
                preview.total_bytes,
                cli.files.iter().map(|file| file.bytes.len()).sum::<usize>()
            );
            assert_eq!(preview.content_hash.to_hex().as_str(), cli.content_hash);
            assert_eq!(
                preview.omissions.iter().map(|item| item.count).sum::<usize>(),
                cli.omissions.len()
            );
            assert!(preview.omissions.iter().any(|item| item.format.is_none()
                && item.kind == "policy_digest"
                && item.reason == "not_available_in_catalog_view"));
            assert_eq!(preview.files.len(), cli.files.len());
            for (metadata, file) in preview.files.iter().zip(&cli.files) {
                assert_eq!(metadata.bytes, file.bytes.len());
                assert_eq!(metadata.mode, file.mode);
                assert_eq!(metadata.hash, blake3::hash(&file.bytes));
                match &metadata.name {
                    PreviewFilename::Available(path) => {
                        assert_eq!(path, &file.path);
                        assert!(!path.contains("fixtureprivatesegment"));
                    }
                    PreviewFilename::WithheldRecipe { ordinal } => {
                        assert_eq!(
                            *ordinal,
                            match scope {
                                CatalogExportScope::All => 2,
                                CatalogExportScope::Operation(_) => 1,
                            }
                        );
                        assert!(file.path.contains("fixtureprivatesegment"));
                    }
                }
            }
            if matches!(format, ExportFormat::Curl | ExportFormat::Bundle) {
                assert_eq!(
                    preview
                        .files
                        .iter()
                        .filter(|file| matches!(file.name, PreviewFilename::WithheldRecipe { .. }))
                        .count(),
                    1
                );
                if scope == CatalogExportScope::All {
                    let root_path = if format == ExportFormat::Curl {
                        "001-get-root.sh"
                    } else {
                        "curl/001-get-root.sh"
                    };
                    assert!(
                        preview
                            .files
                            .iter()
                            .any(|file| file.name
                                == PreviewFilename::Available(root_path.to_owned()))
                    );
                }
            }
            assert!(!format!("{preview:?}").to_ascii_lowercase().contains("fixtureprivatesegment"));
            let approved = viewer::save(&snapshot, request, preview.approval()).unwrap();
            assert_eq!(approved.into_files(), cli.files);
        }
    }
}

#[test]
fn viewer_save_refuses_changed_observations_on_the_same_revision() {
    let op = operation(3, "/orders/{id}");
    let scope = CatalogExportScope::Operation(op.operation_id);
    let before = snapshot(std::slice::from_ref(&op), scope, &[]);
    let after = snapshot(std::slice::from_ref(&op), scope, &[op.operation_id]);
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.catalog_identities, after.catalog_identities);
    for format in FORMATS {
        let request = viewer_request(format, scope);
        let first = viewer::preview(&before, request).unwrap();
        let refreshed = viewer::preview(&after, request).unwrap();
        assert_ne!(first.content_hash, refreshed.content_hash);
        assert!(matches!(
            viewer::save(&after, request, first.approval()),
            Err(ViewerExportError::StalePreview)
        ));
        assert!(viewer::save(&after, request, refreshed.approval()).is_ok());
    }
}

#[test]
fn endpoint_preview_binds_full_revision_identity_even_for_an_unselected_operation() {
    let selected = operation(3, "/orders");
    let other = operation(4, "/other");
    let scope = CatalogExportScope::Operation(selected.operation_id);
    let before = snapshot(&[selected, other], scope, &[]);
    let mut after = before.clone();
    after.catalog_identities[1].route_template = "/different".to_owned();
    assert_eq!(before.operations, after.operations);
    let request = viewer_request(ExportFormat::OpenApi, scope);
    let first = viewer::preview(&before, request).unwrap();
    let refreshed = viewer::preview(&after, request).unwrap();
    assert_ne!(first.content_hash, refreshed.content_hash);
    assert!(matches!(
        viewer::save(&after, request, first.approval()),
        Err(ViewerExportError::StalePreview)
    ));
}

#[test]
fn viewer_save_binds_visible_metadata_even_when_logical_files_are_unchanged() {
    let before = snapshot(&[operation(3, "/orders")], CatalogExportScope::All, &[]);
    let mut after = before.clone();
    after.revision.ordinal += 1;
    let request = viewer_request(ExportFormat::Curl, CatalogExportScope::All);
    let first = viewer::preview(&before, request).unwrap();
    let refreshed = viewer::preview(&after, request).unwrap();
    assert_eq!(first.content_hash, refreshed.content_hash);
    assert_eq!(first.files, refreshed.files);
    assert_ne!(first.revision_ordinal, refreshed.revision_ordinal);
    assert!(matches!(
        viewer::save(&after, request, first.approval()),
        Err(ViewerExportError::StalePreview)
    ));

    let mut wrong_omissions = first.clone();
    wrong_omissions.omissions[0].count += 1;
    assert_ne!(wrong_omissions.approval(), first.approval());
    assert!(matches!(
        viewer::save(&before, request, wrong_omissions.approval()),
        Err(ViewerExportError::StalePreview)
    ));
}

#[test]
fn viewer_save_binds_revision_policy_scope_options_and_approval_digest() {
    let op = operation(3, "/orders");
    let scope = CatalogExportScope::Operation(op.operation_id);
    let first = snapshot(std::slice::from_ref(&op), CatalogExportScope::All, &[]);
    let mut new_latest = first.clone();
    new_latest.revision.revision_id = "018f0000-0000-7000-8000-000000000099".parse().unwrap();
    let latest = viewer_request(ExportFormat::OpenApi, CatalogExportScope::All);
    let historical = ViewerExportRequest {
        revision: CatalogExportRevision::Historical(first.revision.revision_id),
        ..latest
    };
    let approval = viewer::preview(&first, latest).unwrap().approval();
    let historical_approval = viewer::preview(&first, historical).unwrap().approval();
    assert!(matches!(
        viewer::save(&new_latest, latest, approval),
        Err(ViewerExportError::StalePreview)
    ));
    assert!(matches!(
        viewer::save(&new_latest, historical, historical_approval),
        Err(ViewerExportError::RevisionUnavailable)
    ));
    assert!(viewer::save(&first, historical, historical_approval).is_ok());
    let endpoint = ViewerExportRequest { scope, ..latest };
    assert_eq!(
        viewer::preview(&first, endpoint).unwrap().content_hash,
        viewer::preview(&first, latest).unwrap().content_hash
    );
    for changed in [
        historical,
        endpoint,
        ViewerExportRequest { yaml: true, ..latest },
        viewer_request(ExportFormat::Postman, CatalogExportScope::All),
    ] {
        assert!(matches!(
            viewer::save(&first, changed, approval),
            Err(ViewerExportError::StalePreview)
        ));
    }
    let modified = viewer::ViewerExportApproval {
        digest: blake3::hash(b"fixture wrong approval"),
        ..approval
    };
    assert!(matches!(viewer::save(&first, latest, modified), Err(ViewerExportError::StalePreview)));
}

#[test]
fn viewer_preview_reports_colliding_scope_count_and_safe_omission() {
    let first = operation(3, "/orders/{id}");
    let mut second = operation(4, "/orders/{id}");
    second.binding_key = "other-binding".to_owned();
    let input = snapshot(&[first.clone(), second], CatalogExportScope::All, &[]);
    let preview =
        viewer::preview(&input, viewer_request(ExportFormat::OpenApi, CatalogExportScope::All))
            .unwrap();
    assert_eq!((preview.selected_operations, preview.emitted_operations), (2, 1));
    assert!(preview.omissions.iter().any(|item| item.format == Some("openapi")
        && item.reason == "duplicate_method_path"
        && item.count == 1));
    assert!(!format!("{:?}", preview.omissions).contains(&first.operation_id.to_string()));
}

#[test]
fn viewer_refuses_invalid_requests_incomplete_catalogs_and_sanitizer_paths_safely() {
    let op = operation(3, "/orders");
    let input = snapshot(std::slice::from_ref(&op), CatalogExportScope::All, &[]);
    let request = viewer_request(ExportFormat::OpenApi, CatalogExportScope::All);
    assert_eq!(
        viewer::preview(
            &input,
            ViewerExportRequest { format: ExportFormat::Curl, yaml: true, ..request }
        ),
        Err(ViewerExportError::InvalidOptions),
    );
    let missing = viewer_request(
        ExportFormat::OpenApi,
        CatalogExportScope::Operation(operation(4, "/other").operation_id),
    );
    assert_eq!(viewer::preview(&input, missing), Err(ViewerExportError::OperationUnavailable));
    let mut incomplete = input.clone();
    incomplete.catalog_identities.clear();
    assert_eq!(viewer::preview(&incomplete, request), Err(ViewerExportError::IncompleteCatalog));
    let mut duplicate = input.clone();
    duplicate.revision.operation_count += 1;
    duplicate.catalog_identities.push(input.catalog_identities[0].clone());
    duplicate.operations.push(op);
    assert_eq!(viewer::preview(&duplicate, request), Err(ViewerExportError::IncompleteCatalog));
    let mut oversized = input.clone();
    oversized.catalog_identities.resize(4_097, input.catalog_identities[0].clone());
    assert_eq!(
        viewer::preview(&oversized, request),
        Err(ViewerExportError::LimitExceeded(ViewerExportLimit::Operations))
    );

    let canary = "xtrace-canary-fixture-route";
    let unsafe_view = operation(7, &format!("/{canary}"));
    let unsafe_snapshot =
        snapshot(std::slice::from_ref(&unsafe_view), CatalogExportScope::All, &[]);
    let raw = catalog::render(
        &catalog::prepare(&unsafe_snapshot.revision, &[unsafe_view], &[]),
        &ExportRequest::new(ExportFormat::OpenApi),
    )
    .unwrap_err();
    assert!(format!("{raw:?}").contains(canary));
    let safe = viewer::preview(&unsafe_snapshot, request).unwrap_err();
    assert_eq!(safe, ViewerExportError::SanitizerRefused);
    assert!(!format!("{safe:?} {safe}").contains(canary));
    let prior_approval = viewer::preview(&input, request).unwrap().approval();
    assert!(matches!(
        viewer::save(&unsafe_snapshot, request, prior_approval),
        Err(ViewerExportError::SanitizerRefused)
    ));
}

#[test]
fn http_render_admission_bounds_inputs_and_structural_work_before_rendering() {
    use xtrace_export::viewer::{ViewerExportError, ViewerExportLimit, admit_http_render};
    let one = operation(3, "/orders/{id}");
    let admitted = snapshot(std::slice::from_ref(&one), CatalogExportScope::All, &[]);
    assert_eq!(admit_http_render(&admitted), Ok(()));

    let mut large = admitted.clone();
    large.operations[0].application_component = "x".repeat(8 * 1024 * 1024);
    assert_eq!(
        admit_http_render(&large),
        Err(ViewerExportError::LimitExceeded(ViewerExportLimit::Input))
    );

    let mut claims = admitted.clone();
    claims.operations[0].claims = vec![one.claims[0].clone(); 4097];
    assert_eq!(
        admit_http_render(&claims),
        Err(ViewerExportError::LimitExceeded(ViewerExportLimit::Work))
    );

    let mut entries = admitted.clone();
    entries.operations[0].claims[0].limitation_codes = vec!["fixture".to_owned(); 65_536];
    assert_eq!(
        admit_http_render(&entries),
        Err(ViewerExportError::LimitExceeded(ViewerExportLimit::Work))
    );

    let mut identities = admitted;
    identities.catalog_identities = vec![identities.catalog_identities[0].clone(); 4097];
    assert_eq!(
        admit_http_render(&identities),
        Err(ViewerExportError::LimitExceeded(ViewerExportLimit::Operations))
    );
}

#[test]
fn root_recipe_preview_names_require_source_root_without_literal_slug_collisions() {
    let root = operation(3, "/");
    for format in [ExportFormat::Curl, ExportFormat::Bundle] {
        let request = viewer_request(format, CatalogExportScope::All);
        let true_root = snapshot(std::slice::from_ref(&root), CatalogExportScope::All, &[]);
        let preview = viewer::preview(&true_root, request).unwrap();
        let root_name =
            if format == ExportFormat::Bundle { "curl/001-get-root.sh" } else { "001-get-root.sh" };
        assert!(
            preview
                .files
                .iter()
                .any(|file| file.name == PreviewFilename::Available(root_name.to_owned()))
        );
        for route in ["/root", "/ROOT", "/ROOT/", "/{root}", "//", "/---"] {
            let literal = operation(4, route);
            for views in [vec![literal.clone()], vec![root.clone(), literal.clone()]] {
                let fixture = snapshot(&views, CatalogExportScope::All, &[]);
                let preview = viewer::preview(&fixture, request).unwrap();
                let files =
                    viewer::save(&fixture, request, preview.approval()).unwrap().into_files();
                let cli_input = catalog::prepare(&fixture.revision, &views, &[]);
                let cli = catalog::render(&cli_input, &ExportRequest::new(format)).unwrap();
                assert_eq!(files, cli.files, "preview privacy must preserve CLI artifact bytes");
                let withheld = preview
                    .files
                    .iter()
                    .filter(|file| matches!(file.name, PreviewFilename::WithheldRecipe { .. }))
                    .count();
                assert_eq!(withheld, views.len(), "every ambiguous root slug must be withheld");
            }
        }
    }
}
