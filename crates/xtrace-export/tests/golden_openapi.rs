//! OpenAPI projector. Fixture input only (not row evidence).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

mod common;

use common::{assert_golden, claim, op, param, response, spring_orders, text};
use serde_json::Value;
use xtrace_export::{ExportFormat, ExportInput, ExportRequest, export, validate};

fn doc(input: &ExportInput) -> Value {
    let out = export(input, &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    serde_json::from_str(text(&out.files[0])).unwrap()
}

#[test]
fn openapi_golden_spring_orders() {
    let json = export(&spring_orders(), &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    assert_eq!(json.files[0].path, "openapi.json");
    assert_golden("openapi/spring_orders.json", &json.files[0].bytes);
    let mut req = ExportRequest::new(ExportFormat::OpenApi);
    req.yaml = true;
    let yaml = export(&spring_orders(), &req).unwrap();
    assert_eq!(yaml.files[0].path, "openapi.yaml");
    assert_golden("openapi/spring_orders.yaml", &yaml.files[0].bytes);
}

#[test]
fn openapi_path_params_always_declared_required() {
    let d = doc(&spring_orders());
    // op-delete claims `id` with no type; the :id template is normalised.
    let del = &d["paths"]["/orders/{id}"]["delete"];
    let p = &del["parameters"][0];
    assert_eq!(
        (p["name"].as_str(), p["in"].as_str(), p["required"].as_bool()),
        (Some("id"), Some("path"), Some(true))
    );
    // a template parameter nobody claimed is still declared
    let mut input = spring_orders();
    input.operations.push(op("op-x", "GET", "/a/{x}/b/{y}", vec![claim("c")]));
    let d = doc(&input);
    let params = d["paths"]["/a/{x}/b/{y}"]["get"]["parameters"].as_array().unwrap();
    assert_eq!(params.len(), 2);
    assert!(params.iter().all(|p| p["in"] == "path" && p["required"] == true));
}

#[test]
fn openapi_conflicting_claims_surface_x_xtrace_conflicts_not_merged() {
    let d = doc(&spring_orders());
    let list = &d["paths"]["/orders"]["get"];
    let conflicts = list["x-xtrace"]["conflicts"].as_array().unwrap();
    let kinds: Vec<_> = conflicts
        .iter()
        .map(|c| (c["kind"].as_str().unwrap(), c["subject"].as_str().unwrap()))
        .collect();
    assert_eq!(kinds, [("param_type", "query:page"), ("response_description", "200")]);
    // not merged: no winner type, no winner description
    let page = &list["parameters"][0];
    assert!(page["schema"].get("type").is_none());
    assert_eq!(conflicts[0]["claims"][0]["claim_id"], "c-list-a");
    assert_eq!(conflicts[0]["claims"][1]["value"], "string");
    assert_eq!(list["x-xtrace"]["effective_state"], "conflicted");
}

#[test]
fn openapi_inferred_example_labelled_not_observed() {
    use xtrace_export::ExampleOrigin;
    let mut input = spring_orders();
    input.operations[0].claims[0].examples.push(common::example(
        "request_body",
        "guess",
        ExampleOrigin::Inferred,
        r#"{"a":1}"#,
    ));
    let d = doc(&input);
    let examples = d["paths"]["/orders/{id}"]["get"]["x-xtrace"]["examples"].as_array().unwrap();
    let guess = examples.iter().find(|e| e["label"] == "guess").unwrap();
    assert_eq!(guess["origin"], "inferred");
    for e in examples {
        assert_ne!(e["origin"], "observed");
    }
}

#[test]
fn openapi_operation_id_collision_resolution_stable() {
    let mut input = spring_orders();
    input.operations.push(op("op-a", "GET", "/same-thing", vec![claim("c1")]));
    input.operations.push(op("op-b", "GET", "/same_thing", vec![claim("c2")]));
    let d = doc(&input);
    let a = d["paths"]["/same-thing"]["get"]["operationId"].as_str().unwrap().to_owned();
    let b = d["paths"]["/same_thing"]["get"]["operationId"].as_str().unwrap().to_owned();
    assert_ne!(a, b);
    assert!(a.starts_with("getSameThing_") && b.starts_with("getSameThing_"));
    input.operations.reverse();
    let d2 = doc(&input);
    assert_eq!(d2["paths"]["/same-thing"]["get"]["operationId"], a.as_str());
    assert_eq!(d2["paths"]["/same_thing"]["get"]["operationId"], b.as_str());
}

#[test]
fn openapi_duplicate_method_path_is_reported_not_merged() {
    let out = export(&spring_orders(), &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    // op-dup shares GET /orders with op-list; the canonical winner keeps the slot.
    assert!(
        out.omissions
            .iter()
            .any(|o| o.operation_id == "op-zdup"
                && o.reason.starts_with("duplicate_method_path_of:"))
    );
}

#[test]
fn openapi_passes_structural_31_validator() {
    // NOTE: structural validator, not the official OpenAPI JSON Schema; see
    // validate.rs. The official-schema check needs a jsonschema dependency.
    let d = doc(&spring_orders());
    assert_eq!(validate::openapi_31(&d), Vec::<String>::new());
    assert_eq!(d["openapi"], "3.1.0");
}

#[test]
fn structural_validator_rejects_broken_documents() {
    let mut d = doc(&spring_orders());
    d["openapi"] = "3.0.3".into();
    d["paths"]["/orders/{id}"]["get"]["parameters"] = Value::Array(vec![]);
    d["paths"]["/orders"]["post"]["responses"] = serde_json::json!({});
    let problems = validate::openapi_31(&d);
    assert!(problems.iter().any(|p| p.contains("3.1.x")), "{problems:?}");
    assert!(problems.iter().any(|p| p.contains("not declared")), "{problems:?}");
    assert!(problems.iter().any(|p| p.contains("responses must be non-empty")), "{problems:?}");
}

#[test]
fn unavailable_claims_are_stated_not_guessed() {
    let mut input = spring_orders();
    let o = &mut input.operations[2];
    o.claims_available = false;
    o.claims.clear();
    let d = doc(&input);
    assert_eq!(d["paths"]["/orders"]["post"]["x-xtrace"]["claims_projection"], "unavailable");
    assert!(d["paths"]["/orders"]["post"]["responses"]["default"].is_object());
    let _ = (param("a", "query", "", false), response("200", ""));
}
