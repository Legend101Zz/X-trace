//! EX0 export core. Fixture input only (not row evidence).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

mod common;

use common::{spring_orders, text};
use xtrace_export::{ExportFormat, ExportRequest, export};

fn permute<T: Clone>(items: &[T], seed: u64) -> Vec<T> {
    let mut v = items.to_vec();
    let mut state = seed | 1;
    for i in (1..v.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        v.swap(i, (state % (i as u64 + 1)) as usize);
    }
    v
}

#[test]
fn export_is_independent_of_input_order() {
    let base = spring_orders();
    for format in [ExportFormat::OpenApi, ExportFormat::Curl] {
        let want = export(&base, &ExportRequest::new(format)).unwrap();
        for seed in 1..40u64 {
            let mut shuffled = base.clone();
            shuffled.operations = permute(&base.operations, seed);
            for op in &mut shuffled.operations {
                op.claims = permute(&op.claims, seed + 7);
                for claim in &mut op.claims {
                    claim.params = permute(&claim.params, seed + 11);
                    claim.responses = permute(&claim.responses, seed + 13);
                    claim.examples = permute(&claim.examples, seed + 17);
                }
            }
            let got = export(&shuffled, &ExportRequest::new(format)).unwrap();
            assert_eq!(got, want, "format {format:?} seed {seed}");
        }
    }
}

#[test]
fn export_content_hash_stable_across_runs() {
    let input = spring_orders();
    let a = export(&input, &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    let b = export(&input, &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    assert_eq!(a.content_hash, b.content_hash);
    assert_eq!(a.files[0].bytes, b.files[0].bytes);
    let mut changed = input.clone();
    changed.operations[0].route_template = "/orders/{orderId}".into();
    let c = export(&changed, &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    assert_ne!(a.content_hash, c.content_hash);
}

#[test]
fn export_has_no_secret_or_canary_values() {
    let input = spring_orders();
    for format in [ExportFormat::OpenApi, ExportFormat::Curl] {
        for yaml in [false, true] {
            let mut req = ExportRequest::new(format);
            req.yaml = yaml;
            let out = export(&input, &req).unwrap();
            for file in &out.files {
                let t = text(file);
                for needle in ["hunter2", "canary", "abcdefghijklmnopqrstuvwxyz", "Bearer "] {
                    assert!(!t.contains(needle), "{} leaked {needle}", file.path);
                }
            }
        }
    }
}

#[test]
fn export_omissions_listed_for_every_dropped_example() {
    let out = export(&spring_orders(), &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    let mut dropped: Vec<&str> = out
        .omissions
        .iter()
        .filter(|o| o.reason == "secret_shaped")
        .map(|o| o.what.as_str())
        .collect();
    dropped.sort_unstable();
    assert_eq!(dropped.len(), 3, "{dropped:?}");
    let targets: Vec<&str> = dropped.iter().map(|w| w.rsplit_once(':').unwrap().0).collect();
    assert_eq!(
        targets,
        ["example:param:Authorization", "example:request_body", "example:request_body"]
    );
    // identified by digest, never by the (possibly secret-shaped) label
    assert!(dropped.iter().all(|w| !w.contains("canary") && !w.contains("leaky")));
    // operations with no kept example say so
    assert!(out.omissions.iter().any(|o| o.operation_id == "op-delete" && o.what == "examples"));
    // and the document carries the same list
    let doc: serde_json::Value = serde_json::from_str(text(&out.files[0])).unwrap();
    let n = doc["info"]["x-xtrace"]["omissions"].as_array().unwrap().len();
    assert_eq!(n, out.omissions.len());
}

#[test]
fn unimplemented_formats_fail_with_a_typed_error() {
    for format in [ExportFormat::Bundle] {
        let err = export(&spring_orders(), &ExportRequest::new(format)).unwrap_err();
        assert!(matches!(err, xtrace_export::ExportError::FormatNotImplemented { .. }));
    }
}

#[test]
fn selection_filters_and_reports_unknown_ids() {
    let mut req = ExportRequest::new(ExportFormat::OpenApi);
    req.operation_ids = Some(vec!["op-create".into(), "op-missing".into()]);
    let out = export(&spring_orders(), &req).unwrap();
    let doc: serde_json::Value = serde_json::from_str(text(&out.files[0])).unwrap();
    let paths = doc["paths"].as_object().unwrap();
    assert_eq!(paths.len(), 1);
    assert!(paths["/orders"]["post"].is_object());
    assert!(
        out.omissions
            .iter()
            .any(|o| o.operation_id == "op-missing" && o.reason == "not_in_catalog_view")
    );
}

#[test]
fn truncated_view_is_an_explicit_omission() {
    let mut input = spring_orders();
    input.truncated = true;
    let out = export(&input, &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    assert!(out.omissions.iter().any(|o| o.reason == "catalog_view_truncated"));
}

#[test]
fn files_are_never_executable() {
    for format in [ExportFormat::OpenApi, ExportFormat::Curl] {
        let out = export(&spring_orders(), &ExportRequest::new(format)).unwrap();
        for f in out.files {
            assert_eq!(f.mode, 0o644, "{}", f.path);
        }
    }
}
