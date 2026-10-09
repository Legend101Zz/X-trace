//! Shared fixture builders. FIXTURE INPUT ONLY: these are hand-written
//! catalog views, not evidence from a scanned application.

#![allow(dead_code, reason = "each test binary uses a subset")]
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test helpers")]

use std::path::PathBuf;

use xtrace_export::{
    ClaimInput, EffectiveState, ExampleInput, ExampleOrigin, ExportFile, ExportInput, HandlerInput,
    OperationInput, ParamInput, ResponseInput, RevisionInput,
};

pub fn param(name: &str, location: &str, ty: &str, required: bool) -> ParamInput {
    ParamInput {
        name: name.into(),
        location: location.into(),
        type_name: ty.into(),
        required,
        source: "static".into(),
    }
}

pub fn response(status: &str, description: &str) -> ResponseInput {
    ResponseInput { status: status.into(), description: description.into() }
}

pub fn example(target: &str, label: &str, origin: ExampleOrigin, value: &str) -> ExampleInput {
    ExampleInput { target: target.into(), label: label.into(), origin, value: value.into() }
}

pub fn op(id: &str, method: &str, route: &str, claims: Vec<ClaimInput>) -> OperationInput {
    OperationInput {
        operation_id: id.into(),
        method: method.into(),
        route_template: route.into(),
        application_component: "orders".into(),
        binding_key: format!("spring:{method} {route}"),
        effective_state: EffectiveState::Registered,
        claims_available: true,
        claims,
    }
}

pub fn claim(id: &str) -> ClaimInput {
    ClaimInput { claim_id: id.into(), provenance: "static_analysis".into(), ..Default::default() }
}

/// A small orders-style catalog with a conflict, a body, secrets and a
/// colliding method+path pair.
pub fn spring_orders() -> ExportInput {
    let mut get_one = claim("c-get-one");
    get_one.params = vec![
        param("id", "path", "integer", true),
        param("Authorization", "header", "string", true),
    ];
    get_one.responses = vec![response("200", "The order"), response("404", "No such order")];
    get_one.confidence_basis_points = Some(9000);
    get_one.handler = Some(HandlerInput {
        symbol: "OrderController.get".into(),
        path: "src/main/java/demo/OrderController.java".into(),
        line_start: 20,
        line_end: 31,
    });
    get_one.examples = vec![example("param:id", "typical", ExampleOrigin::Scenario, "42")];

    let mut list_a = claim("c-list-a");
    list_a.params = vec![param("page", "query", "integer", false)];
    list_a.responses = vec![response("200", "A page of orders")];
    let mut list_b = claim("c-list-b");
    list_b.provenance = "adapter_registration".into();
    list_b.params = vec![param("page", "query", "string", false)];
    list_b.responses = vec![response("200", "All orders")];
    list_b.examples = vec![example("param:page", "first", ExampleOrigin::Claim, "1")];

    let mut create = claim("c-create");
    create.request_body_media_type = Some("application/json".into());
    create.responses = vec![response("201", "Created")];
    create.examples = vec![
        example("request_body", "new-order", ExampleOrigin::Scenario, r#"{"sku":"A-1","qty":2}"#),
        example(
            "request_body",
            "leaky",
            ExampleOrigin::Claim,
            r#"{"sku":"A-1","api_key":"hunter2hunter2"}"#,
        ),
        example(
            "param:Authorization",
            "auth",
            ExampleOrigin::Claim,
            "Bearer abcdefghijklmnopqrstuvwxyz",
        ),
        example("request_body", "canary", ExampleOrigin::Claim, r#"{"note":"xtrace-canary-0042"}"#),
    ];

    let mut delete = claim("c-delete");
    delete.responses = vec![response("204", "")];
    delete.params = vec![param("id", "path", "", true)];

    let mut dup = claim("c-dup");
    dup.responses = vec![response("200", "duplicate binding")];

    let mut ops = vec![
        op("op-get-one", "GET", "/orders/{id}", vec![get_one]),
        op("op-list", "GET", "/orders", vec![list_a, list_b]),
        op("op-create", "POST", "/orders", vec![create]),
        op("op-delete", "DELETE", "/orders/:id", vec![delete]),
        op("op-zdup", "GET", "/orders", vec![dup]),
    ];
    ops[1].effective_state = EffectiveState::Conflicted;
    ops[2].effective_state = EffectiveState::Observed;
    ExportInput {
        revision: RevisionInput {
            revision_id: "rev-0001".into(),
            ordinal: 3,
            catalog_hash: "ab".repeat(32),
            policy_digest: "cd".repeat(32),
            application_name: "Orders demo".into(),
        },
        operations: ops,
        truncated: false,
    }
}

pub fn golden_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(rel)
}

/// Compares to a golden file; an existing `tests/fixtures/.bless` file rewrites it.
pub fn assert_golden(rel: &str, actual: &[u8]) {
    let path = golden_path(rel);
    if golden_path(".bless").exists() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
    }
    let expected = std::fs::read(&path).unwrap_or_else(|_| panic!("missing golden {rel}"));
    assert_eq!(String::from_utf8_lossy(actual), String::from_utf8_lossy(&expected), "golden {rel}");
}

pub fn text(file: &ExportFile) -> &str {
    std::str::from_utf8(&file.bytes).unwrap()
}
