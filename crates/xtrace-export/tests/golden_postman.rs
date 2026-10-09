//! Postman 2.1 projector. Fixture input only (not row evidence).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

mod common;

use common::{assert_golden, spring_orders, text};
use serde_json::Value;
use xtrace_export::{ExportFormat, ExportRequest, export};

fn run() -> xtrace_export::ExportOutput {
    export(&spring_orders(), &ExportRequest::new(ExportFormat::Postman)).unwrap()
}

#[test]
fn postman_golden_and_repeatable() {
    let a = run();
    assert_eq!(a.files.len(), 1);
    assert_eq!(a.files[0].path, "collection.postman.json");
    assert_eq!(a.files[0].mode, 0o644);
    assert_golden("postman/spring_orders.json", &a.files[0].bytes);
    assert_eq!(a.files[0].bytes, run().files[0].bytes);
    assert_eq!(a.content_hash, run().content_hash);
}

#[test]
fn postman_shape_and_no_secrets() {
    let out = run();
    let body = text(&out.files[0]);
    let doc: Value = serde_json::from_str(body).unwrap();
    assert_eq!(
        doc["info"]["schema"],
        "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    );
    assert_eq!(doc["variable"][0]["key"], "baseUrl");
    assert_eq!(doc["variable"][0]["value"], "");
    for needle in ["hunter2", "abcdefghijklmnopqrstuvwxyz", "xtrace-canary"] {
        assert!(!body.contains(needle), "{needle}");
    }
    // the required Authorization header is a placeholder, never a value
    assert!(body.contains("{{header_Authorization}}"));
    let first = &doc["item"][0]["request"];
    assert!(first["url"]["raw"].as_str().unwrap().starts_with("{{baseUrl}}/"));
    assert!(first["description"].as_str().unwrap().contains("x-xtrace-observation:"));
}
