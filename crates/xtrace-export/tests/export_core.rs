//! EX0 export core. Fixture input only (not row evidence).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

mod common;

use common::{spring_orders, text};
use xtrace_export::{ExportFormat, ExportRequest, export};

#[test]
fn legacy_serialized_inputs_keep_summary_and_handler_gaps() {
    use serde_json::{Value, json};

    let input = xtrace_export::input_json::parse(&json!({
        "revision": {"policy_digest": null},
        "operations": [
            {
                "operation_id": "summary", "method": "GET", "route_template": "/summary",
                "catalog_summary": {
                    "claim_count": 2,
                    "handler_symbols": ["First.get", "Second.get"],
                    "highest_confidence_basis_points": 8200
                }
            },
            {
                "operation_id": "legacy", "method": "GET", "route_template": "/legacy",
                "claims": [{
                    "claim_id": "legacy-claim",
                    "handler": {"symbol": "Legacy.get", "path": "Legacy.java", "line_start": 4}
                }]
            }
        ]
    }))
    .unwrap();
    let out = export(&input, &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    let doc: Value = serde_json::from_slice(&out.files[0].bytes).unwrap();
    assert_eq!(doc["info"]["x-xtrace"].get("policy_digest"), Some(&Value::Null));
    let summary = &doc["paths"]["/summary"]["get"]["x-xtrace"];
    assert_eq!(summary["claims_projection"], "unavailable");
    assert_eq!(summary["handler_conflict"], true);
    assert_eq!(summary["claim_count"], 2);
    assert_eq!(summary["highest_confidence_basis_points"], 8200);
    for field in ["claims", "handlers", "confidence_basis_points"] {
        assert!(summary.get(field).is_none());
    }
    let legacy = &doc["paths"]["/legacy"]["get"]["x-xtrace"];
    assert_eq!(legacy["handlers"][0]["line_start"], 4);
    assert!(legacy["handlers"][0].get("line_end").is_none());
    assert!(legacy.get("confidence_basis_points").is_none());
    assert!(legacy.get("claims").is_none());
}

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
fn bundle_composes_the_formats_and_preserves_format_specific_omissions() {
    let input = spring_orders();
    let out = export(&input, &ExportRequest::new(ExportFormat::Bundle)).unwrap();
    assert_eq!(out.operation_count, 5);
    let manifest: serde_json::Value = serde_json::from_slice(
        &out.files.iter().find(|f| f.path == "manifest.json").unwrap().bytes,
    )
    .unwrap();
    assert_eq!(manifest["policy_digest"], input.revision.policy_digest);
    assert_eq!(manifest["catalog_hash"], input.revision.catalog_hash);
    for (format, prefix, yaml) in [
        (ExportFormat::OpenApi, "", true),
        (ExportFormat::Postman, "", false),
        (ExportFormat::Curl, "curl/", false),
    ] {
        let mut request = ExportRequest::new(format);
        request.yaml = yaml;
        let rendered = export(&input, &request).unwrap();
        for file in rendered.files {
            let path = format!("{prefix}{}", file.path);
            assert_eq!(out.files.iter().find(|f| f.path == path).unwrap().bytes, file.bytes);
        }
    }
    assert!(out.omissions.iter().any(|o| o.operation_id == "op-zdup"
        && o.what == "openapi:operation"
        && o.reason.starts_with("duplicate_method_path_of:")));
    let mut reordered = input.clone();
    reordered.operations.reverse();
    assert_eq!(out, export(&reordered, &ExportRequest::new(ExportFormat::Bundle)).unwrap());
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

#[test]
fn secret_word_routes_and_prose_descriptions_export() {
    use common::{claim, op, response};
    let routes =
        ["/oauth/token", "/api/session", "/auth/password", "/csrf-token", "/canary/deploy"];
    let mut input = spring_orders();
    input.operations = routes
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mut c = claim(&format!("c{i}"));
            c.responses = vec![response("401", "Invalid token: expired")];
            op(&format!("op{i}"), "GET", r, vec![c])
        })
        .collect();
    for format in [ExportFormat::OpenApi, ExportFormat::Curl, ExportFormat::Postman] {
        let out = export(&input, &ExportRequest::new(format))
            .map_err(|e| format!("{format:?} refused: {e}"))
            .expect("every format exports the multi-route input");
        let all: String = out.files.iter().map(|f| text(f).to_owned()).collect();
        for r in routes {
            assert!(all.contains(r), "{format:?} lost route {r}");
        }
    }
}

#[test]
fn unsafe_handler_paths_are_dropped_and_listed_as_omissions() {
    let bad_paths = ["/Users/someone/proj/Ctl.java", "../x/Ctl.java", "a\\b.java", "C:/x/Ctl.java"];
    for bad in bad_paths {
        let mut input = spring_orders();
        let handler = input
            .operations
            .iter_mut()
            .flat_map(|o| o.claims.iter_mut())
            .find_map(|c| c.handler.as_mut())
            .unwrap();
        handler.path = bad.to_owned();
        let out = export(&input, &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
        let text = String::from_utf8(out.files[0].bytes.clone()).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).expect("openapi is JSON");
        let mut stack = vec![&doc];
        while let Some(v) = stack.pop() {
            match v {
                serde_json::Value::Object(m) => {
                    if let Some(x) = m.get("x-xtrace").and_then(|x| x.as_object()) {
                        assert!(!x.contains_key("handlers"), "handlers survived for {bad}");
                    }
                    stack.extend(m.values());
                }
                serde_json::Value::Array(a) => stack.extend(a),
                _ => {}
            }
        }
        assert!(
            out.omissions
                .iter()
                .any(|o| o.what == "handler" && o.reason == "handler_path_not_repo_relative"),
            "no omission for {bad}"
        );
    }
    let mut input = spring_orders();
    let handler = input
        .operations
        .iter_mut()
        .flat_map(|o| o.claims.iter_mut())
        .find_map(|c| c.handler.as_mut())
        .unwrap();
    handler.symbol = "/Users/someone/x".to_owned();
    let out = export(&input, &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    let text = String::from_utf8(out.files[0].bytes.clone()).unwrap();
    assert!(!text.contains("/Users/someone"), "symbol leaked");
    assert!(out.omissions.iter().any(|o| o.reason == "handler_symbol_invalid"));
    let out = export(&spring_orders(), &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    let text = String::from_utf8(out.files[0].bytes.clone()).unwrap();
    assert!(text.contains("src/main/java/demo/OrderController.java"));
    assert!(!out.omissions.iter().any(|o| o.what == "handler"));
}
