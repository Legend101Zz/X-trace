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
    assert_eq!(legacy["claims_projection"], "available");
    assert_eq!(legacy["claim_count"], 1);
    let claim = &legacy["claims"][0];
    assert_eq!(claim["claim_id"], "legacy-claim");
    assert_eq!(claim["handler_location"], legacy["handlers"][0]);
    assert_eq!(claim.get("confidence_basis_points"), Some(&Value::Null));
    assert_eq!(claim.get("provenance"), Some(&Value::Null));
    assert_eq!(claim.get("limitation_codes"), Some(&Value::Null));
    assert_eq!(claim.get("source_evidence"), Some(&Value::Null));
    assert_eq!(claim.get("handler_symbol"), Some(&Value::Null));
}

fn comment_metadata(text: &str) -> serde_json::Value {
    let metadata = text
        .lines()
        .find_map(|line| line.trim_start_matches("# ").strip_prefix("x-xtrace catalog metadata: "))
        .unwrap();
    serde_json::from_str(metadata).unwrap()
}

fn operation_metadata(
    out: &xtrace_export::ExportOutput,
    format: ExportFormat,
    route: &str,
    expected: &serde_json::Value,
) -> serde_json::Value {
    use serde_json::{Value, json};

    let file = |path| text(out.files.iter().find(|f| f.path == path).unwrap());
    let postman = || {
        let doc: Value = serde_json::from_str(file("collection.postman.json")).unwrap();
        let name = format!("GET /{route}");
        let item =
            doc["item"].as_array().unwrap().iter().find(|item| item["name"] == name).unwrap();
        comment_metadata(item["request"]["description"].as_str().unwrap())
    };
    let curl = || {
        let suffix = format!("-get-{route}.sh");
        let recipe = out.files.iter().find(|f| f.path.ends_with(&suffix)).unwrap();
        comment_metadata(text(recipe))
    };
    match format {
        ExportFormat::OpenApi => {
            let doc: Value = serde_json::from_str(file("openapi.json")).unwrap();
            doc["paths"][format!("/{route}")]["get"]["x-xtrace"].clone()
        }
        ExportFormat::Postman => postman(),
        ExportFormat::Curl => curl(),
        ExportFormat::Bundle => {
            let metadata_yaml = xtrace_export::canonical::yaml(&json!({"x-xtrace": expected}));
            let block =
                metadata_yaml.lines().map(|line| format!("      {line}\n")).collect::<String>();
            assert!(file("openapi.yaml").contains(&block), "bundle YAML for {route}");
            assert_eq!(postman(), curl());
            postman()
        }
    }
}

#[test]
fn missing_null_and_explicit_empty_catalog_facts_across_formats() {
    use serde_json::{Value, json};

    let empty_summary = json!({
        "claim_count": 0, "handler_symbols": [], "handler_conflict": false,
        "provenance": [], "limitation_codes": []
    });
    let cases = [
        (
            "rows",
            json!({"claims": [
                {"claim_id": "absent"},
                {"claim_id": "null", "provenance": null, "limitation_codes": null},
                {"claim_id": "empty", "provenance": "", "limitation_codes": []}
            ]}),
        ),
        ("summary-absent", json!({"catalog_summary": {"claim_count": 2}})),
        (
            "summary-null",
            json!({"claims": null, "catalog_summary": {
                "claim_count": 2, "handler_symbols": null, "handler_conflict": null,
                "provenance": null, "limitation_codes": null
            }}),
        ),
        ("omitted", json!({"catalog_summary": empty_summary})),
        (
            "withheld",
            json!({"claims": [], "claims_available": false, "catalog_summary": empty_summary}),
        ),
        (
            "complete",
            json!({"claims": [], "claims_available": true, "catalog_summary": empty_summary}),
        ),
        ("complete-implicit", json!({"claims": [], "catalog_summary": empty_summary})),
        (
            "empty-partial",
            json!({"claims": [], "claims_available": true, "catalog_summary": {"claim_count": 2}}),
        ),
    ];
    let operations: Vec<_> = cases
        .iter()
        .map(|(route, input)| {
            let mut op = input.clone();
            op["operation_id"] = json!(route);
            op["method"] = json!("GET");
            op["route_template"] = json!(format!("/{route}"));
            op
        })
        .collect();
    let input = xtrace_export::input_json::parse(&json!({"operations": operations})).unwrap();
    let mut openapi = Vec::new();
    for format in
        [ExportFormat::OpenApi, ExportFormat::Postman, ExportFormat::Curl, ExportFormat::Bundle]
    {
        let out = export(&input, &ExportRequest::new(format)).unwrap();
        assert_eq!(out.operation_count, cases.len());
        for (index, (route, source)) in cases.iter().enumerate() {
            let expected = openapi.get(index).unwrap_or(&Value::Null);
            let metadata = operation_metadata(&out, format, route, expected);
            let omission = |reason| {
                out.omissions.iter().any(|o| o.operation_id == *route && o.reason == reason)
            };
            match *route {
                "rows" => {
                    assert_eq!(metadata["claims_projection"], "available");
                    assert_eq!(metadata.get("handler_symbols"), Some(&Value::Null));
                    assert_eq!(metadata.get("handler_conflict"), Some(&Value::Null));
                    let rows = metadata["claims"].as_array().unwrap();
                    assert_eq!(rows.len(), 3);
                    for (id, provenance, limitations) in [
                        ("absent", Value::Null, Value::Null),
                        ("null", Value::Null, Value::Null),
                        ("empty", json!(""), json!([])),
                    ] {
                        let row = rows.iter().find(|row| row["claim_id"] == id).unwrap();
                        assert_eq!(row.get("provenance"), Some(&provenance));
                        assert_eq!(row.get("limitation_codes"), Some(&limitations));
                    }
                }
                "complete" | "complete-implicit" | "empty-partial" => {
                    let partial = *route == "empty-partial";
                    assert_eq!(
                        metadata["claims_projection"],
                        if partial { "partial" } else { "available" }
                    );
                    assert_eq!(metadata["claim_count"], 0);
                    assert_eq!(metadata.get("claims"), Some(&json!([])));
                    assert_eq!(
                        metadata.get("handler_symbols"),
                        Some(&if partial { Value::Null } else { json!([]) })
                    );
                    assert_eq!(
                        metadata.get("handler_conflict"),
                        Some(&if partial { Value::Null } else { json!(false) })
                    );
                    assert_eq!(
                        metadata["catalog_summary"]["claim_count"],
                        source["catalog_summary"]["claim_count"]
                    );
                    assert!(metadata.get("claim_confidence").is_none());
                    assert!(!omission("per_claim_confidence_unavailable"));
                    assert!(!omission("claims_projection_unavailable"));
                    assert!(!omission("claim_summary_mismatch"));
                    assert_eq!(omission("claims_projection_partial"), partial);
                }
                _ => {
                    assert_eq!(metadata["claims_projection"], "unavailable");
                    assert!(metadata.get("claims").is_none());
                    assert_eq!(metadata["claim_count"], source["catalog_summary"]["claim_count"]);
                    assert_eq!(metadata["claim_confidence"], "not available per claim");
                    assert!(omission("per_claim_confidence_unavailable"));
                    assert!(omission("claims_projection_unavailable"));
                    for field in
                        ["handler_symbols", "handler_conflict", "provenance", "limitation_codes"]
                    {
                        assert_eq!(metadata.get(field), Some(&source["catalog_summary"][field]));
                    }
                }
            }
            if format == ExportFormat::OpenApi {
                openapi.push(metadata);
            } else {
                assert_eq!(&metadata, expected, "{format:?} {route}");
            }
        }
    }
}

#[test]
fn legacy_claim_rows_and_summary_facts_agree_across_formats() {
    use serde_json::json;

    let first = json!({"symbol": "First.get", "path": "First.java", "line_start": 4});
    let second =
        json!({"symbol": "Second.get", "path": "Second.java", "line_start": 8, "line_end": 12});
    let mut doc = json!({
        "operations": [
            {
                "operation_id": "legacy", "method": "GET", "route_template": "/legacy",
                "claims": [
                    {"claim_id": "b", "provenance": "static_analysis",
                        "confidence_basis_points": 6500, "limitation_codes": ["missing_schema"],
                        "handler": second},
                    {"claim_id": "a", "provenance": "adapter_registration",
                        "confidence_basis_points": 8200, "limitation_codes": ["missing_extent"],
                        "handler": first},
                    {"claim_id": "c", "provenance": "runtime_hint"}
                ]
            },
            {
                "operation_id": "summary", "method": "GET", "route_template": "/summary",
                "catalog_summary": {
                    "claim_count": 2,
                    "handler_symbols": ["Second.get", "First.get"],
                    "highest_confidence_basis_points": 8200,
                    "provenance": ["static_analysis", "adapter_registration"],
                    "limitation_codes": ["missing_schema", "missing_extent"]
                }
            }
        ]
    });
    let summary = doc["operations"][1]["catalog_summary"].clone();
    doc["operations"][0]["catalog_summary"] = summary;
    let mut withheld = doc["operations"][0].clone();
    withheld["operation_id"] = json!("withheld");
    withheld["route_template"] = json!("/withheld");
    withheld["claims_available"] = json!(false);
    doc["operations"].as_array_mut().unwrap().push(withheld);
    let mut partial = doc["operations"][0].clone();
    partial["operation_id"] = json!("partial");
    partial["route_template"] = json!("/partial");
    partial["claims"].as_array_mut().unwrap().truncate(1);
    doc["operations"].as_array_mut().unwrap().push(partial);
    let mut consistent = doc["operations"][0].clone();
    consistent["operation_id"] = json!("consistent");
    consistent["route_template"] = json!("/consistent");
    consistent["catalog_summary"]["claim_count"] = json!(3);
    consistent["catalog_summary"]["provenance"].as_array_mut().unwrap().push(json!("runtime_hint"));
    doc["operations"].as_array_mut().unwrap().push(consistent);
    let input = xtrace_export::input_json::parse(&doc).unwrap();
    assert!(input.operations[0].claims_available);
    assert!(!input.operations[1].claims_available);
    assert!(!input.operations[2].claims_available);
    let aggregate = json!({
        "claim_count": 2,
        "handler_conflict": true, "handler_symbols": ["First.get", "Second.get"],
        "highest_confidence_basis_points": 8200,
        "provenance": ["adapter_registration", "static_analysis"],
        "limitation_codes": ["missing_extent", "missing_schema"]
    });
    let expected_legacy = json!({
        "operation_id": "legacy", "application_component": "", "binding_key": "",
        "effective_state": "unknown", "claims_projection": "inconsistent", "claim_count": 3,
        "catalog_summary": aggregate,
        "handler_conflict": true, "handler_symbols": ["First.get", "Second.get"],
        "handlers": [first, second], "confidence_basis_points": 6500,
        "provenance": ["adapter_registration", "runtime_hint", "static_analysis"],
        "limitation_codes": ["missing_extent", "missing_schema"],
        "claims": [
            {"claim_id": "a", "provenance": "adapter_registration",
                "confidence_basis_points": 8200, "limitation_codes": ["missing_extent"],
                "handler_location": first, "handler_symbol": null, "source_evidence": null},
            {"claim_id": "b", "provenance": "static_analysis",
                "confidence_basis_points": 6500, "limitation_codes": ["missing_schema"],
                "handler_location": second, "handler_symbol": null, "source_evidence": null},
            {"claim_id": "c", "provenance": "runtime_hint",
                "confidence_basis_points": null, "limitation_codes": null,
                "handler_symbol": null, "source_evidence": null}
        ]
    });
    let expected_partial = json!({
        "operation_id": "partial", "application_component": "", "binding_key": "",
        "effective_state": "unknown", "claims_projection": "partial", "claim_count": 1,
        "catalog_summary": aggregate,
        "handler_conflict": null, "handler_symbols": ["Second.get"],
        "handlers": [second], "confidence_basis_points": 6500,
        "provenance": ["static_analysis"], "limitation_codes": ["missing_schema"],
        "claims": [expected_legacy["claims"][1]]
    });
    let mut expected_consistent = expected_legacy.clone();
    expected_consistent["operation_id"] = json!("consistent");
    expected_consistent["claims_projection"] = json!("available");
    expected_consistent["catalog_summary"]["claim_count"] = json!(3);
    expected_consistent["catalog_summary"]["provenance"] =
        json!(["adapter_registration", "runtime_hint", "static_analysis"]);
    let expected_summary = json!({
        "operation_id": "summary", "application_component": "", "binding_key": "",
        "effective_state": "unknown", "claims_projection": "unavailable", "claim_count": 2,
        "handler_conflict": true, "handler_symbols": ["First.get", "Second.get"],
        "highest_confidence_basis_points": 8200,
        "provenance": ["adapter_registration", "static_analysis"],
        "limitation_codes": ["missing_extent", "missing_schema"],
        "source_locations": "per-claim locations unavailable",
        "claim_confidence": "not available per claim"
    });
    let mut expected_withheld = expected_summary.clone();
    expected_withheld["operation_id"] = json!("withheld");
    for format in
        [ExportFormat::OpenApi, ExportFormat::Postman, ExportFormat::Curl, ExportFormat::Bundle]
    {
        let out = export(&input, &ExportRequest::new(format)).unwrap();
        assert_eq!(out.operation_count, 5, "{format:?}");
        for (route, expected) in [
            ("legacy", &expected_legacy),
            ("summary", &expected_summary),
            ("withheld", &expected_withheld),
            ("partial", &expected_partial),
            ("consistent", &expected_consistent),
        ] {
            let metadata = operation_metadata(&out, format, route, expected);
            assert_eq!(&metadata, expected, "{format:?} {route}");
        }
        for reason in [
            "claims_projection_unavailable",
            "per_claim_locations_unavailable",
            "per_claim_confidence_unavailable",
        ] {
            assert!(
                out.omissions.iter().any(|o| o.operation_id == "summary" && o.reason == reason)
            );
            assert!(
                out.omissions.iter().any(|o| o.operation_id == "withheld" && o.reason == reason)
            );
            assert!(!out.omissions.iter().any(|o| {
                ["legacy", "partial", "consistent"].contains(&o.operation_id.as_str())
                    && o.reason == reason
            }));
        }
        for (operation_id, reason) in
            [("partial", "claims_projection_partial"), ("legacy", "claim_count_mismatch")]
        {
            assert!(
                out.omissions.iter().any(|o| o.operation_id == operation_id && o.reason == reason)
            );
            assert!(
                !out.omissions.iter().any(|o| o.operation_id == "consistent" && o.reason == reason)
            );
        }
        assert!(
            out.omissions
                .iter()
                .any(|o| o.operation_id == "partial" && o.reason == "handler_conflict_unresolved")
        );
    }
}

#[test]
fn complete_and_partial_rows_check_reported_summary_facts_across_formats() {
    use serde_json::{Value, json};

    let known = json!({
        "claim_id": "known", "provenance": "static_analysis", "confidence_basis_points": 8200,
        "limitation_codes": ["missing_schema"],
        "handler": {"symbol": "First.get", "path": "First.java", "line_start": 4}
    });
    let unknown = json!({"claim_id": "unknown", "provenance": null, "limitation_codes": null});
    let empty_limitations = json!({"claim_id": "empty", "limitation_codes": []});
    let summary = json!({
        "handler_symbols": ["First.get"], "provenance": ["static_analysis"],
        "highest_confidence_basis_points": 8200, "limitation_codes": ["missing_schema"]
    });
    let cases = [
        ("handler", json!([known]), json!({"handler_symbols": ["Second.get"]}), true),
        ("conflict", json!([known]), json!({"handler_conflict": true}), true),
        (
            "denied-conflict",
            json!([known, {"claim_id": "second", "handler_symbol": "Second.get"}, unknown]),
            json!({"handler_conflict": false}),
            true,
        ),
        (
            "complete-denied-symbol-conflict",
            json!([known, {"claim_id": "second", "handler_symbol": "Second.get"}]),
            json!({"handler_symbols": ["First.get", "Second.get"], "handler_conflict": false}),
            true,
        ),
        (
            "complete-agreeing-rows",
            json!([known, {"claim_id": "second", "handler_symbol": "First.get"}]),
            json!({"handler_symbols": ["First.get"], "handler_conflict": false}),
            false,
        ),
        (
            "location",
            json!([known]),
            json!({"single_claim_handler": {
                "symbol": "First.get", "path": "First.java", "line_start": 5
            }}),
            true,
        ),
        ("provenance", json!([known, unknown]), json!({"provenance": ["runtime_hint"]}), true),
        ("limitations", json!([known]), json!({"limitation_codes": []}), true),
        (
            "empty-limitations",
            json!([empty_limitations]),
            json!({"limitation_codes": ["missing_schema"]}),
            true,
        ),
        ("confidence", json!([known]), json!({"highest_confidence_basis_points": 9000}), true),
        (
            "confidence-below-known",
            json!([known, unknown]),
            json!({"highest_confidence_basis_points": 6500}),
            true,
        ),
        (
            "confidence-above-known",
            json!([known, unknown]),
            json!({"highest_confidence_basis_points": 9000}),
            false,
        ),
        ("consistent", json!([known]), summary.clone(), false),
        ("unknown-rows", json!([unknown]), summary, false),
        (
            "additional-handler",
            json!([known, unknown]),
            json!({"handler_symbols": ["First.get", "Second.get"]}),
            false,
        ),
        (
            "unknown-summary",
            json!([known]),
            json!({"handler_symbols": null, "handler_conflict": null}),
            false,
        ),
        (
            "partial-handler",
            json!([known]),
            json!({"claim_count": 2, "handler_symbols": ["Second.get"]}),
            true,
        ),
        ("complete-blank-summary", json!([known]), json!({"handler_symbols": [""]}), false),
        (
            "complete-blank-summary-extra",
            json!([known]),
            json!({"handler_symbols": ["", "Second.get"]}),
            true,
        ),
        (
            "partial-blank-summary",
            json!([known]),
            json!({"claim_count": 2, "handler_symbols": [""]}),
            false,
        ),
        (
            "partial-blank-summary-known-conflict",
            json!([known]),
            json!({"claim_count": 3, "handler_symbols": ["", "First.get", "Second.get"]}),
            false,
        ),
        (
            "partial-blank-summary-row-conflict",
            json!([known, {"claim_id": "second", "handler_symbol": "Second.get"}]),
            json!({"claim_count": 3, "handler_symbols": [""]}),
            false,
        ),
        (
            "partial-denied-conflict",
            json!([known, {"claim_id": "second", "handler_symbol": "Second.get"}]),
            json!({"claim_count": 3, "handler_conflict": false}),
            true,
        ),
        (
            "partial-provenance",
            json!([known]),
            json!({"claim_count": 2, "provenance": ["runtime_hint"]}),
            true,
        ),
        (
            "partial-limitations",
            json!([known]),
            json!({"claim_count": 2, "limitation_codes": []}),
            true,
        ),
        (
            "partial-confidence",
            json!([known]),
            json!({"claim_count": 2, "highest_confidence_basis_points": 6500}),
            true,
        ),
        (
            "partial-extras",
            json!([known]),
            json!({"claim_count": 2, "handler_symbols": ["First.get", "Second.get"],
                "handler_conflict": true, "provenance": ["runtime_hint", "static_analysis"],
                "limitation_codes": ["missing_extent", "missing_schema"],
                "highest_confidence_basis_points": 9000}),
            false,
        ),
        (
            "partial-unknowns",
            json!([unknown]),
            json!({"claim_count": 2, "handler_symbols": [], "handler_conflict": false,
                "provenance": [], "limitation_codes": [], "highest_confidence_basis_points": null}),
            false,
        ),
    ];
    let mut operations = Vec::new();
    for (route, claims, summary, _) in &cases {
        let mut summary = summary.clone();
        summary
            .as_object_mut()
            .unwrap()
            .entry("claim_count")
            .or_insert_with(|| json!(claims.as_array().unwrap().len()));
        operations.push(json!({
            "operation_id": route, "method": "GET", "route_template": format!("/{route}"),
            "claims": claims, "catalog_summary": summary
        }));
    }
    let input = xtrace_export::input_json::parse(&json!({"operations": operations})).unwrap();
    let mut openapi = Vec::new();
    for format in
        [ExportFormat::OpenApi, ExportFormat::Postman, ExportFormat::Curl, ExportFormat::Bundle]
    {
        let out = export(&input, &ExportRequest::new(format)).unwrap();
        assert_eq!(out.operation_count, cases.len());
        for (index, (route, claims, summary, inconsistent)) in cases.iter().enumerate() {
            let row_count = claims.as_array().unwrap().len();
            let summary_count = summary["claim_count"].as_u64().unwrap_or(row_count as u64);
            let partial = summary_count > row_count as u64;
            let expected = openapi.get(index).unwrap_or(&Value::Null);
            let metadata = operation_metadata(&out, format, route, expected);
            assert_eq!(
                metadata["claims_projection"],
                if *inconsistent {
                    "inconsistent"
                } else if partial {
                    "partial"
                } else {
                    "available"
                },
                "{format:?} {route}"
            );
            let fields: &[_] = if format == ExportFormat::Bundle {
                &["openapi:claims", "postman:claims", "curl:claims"]
            } else {
                &["claims"]
            };
            for field in fields {
                for (reason, reported) in [
                    ("claim_summary_mismatch", *inconsistent),
                    ("claims_projection_partial", partial),
                ] {
                    assert_eq!(
                        out.omissions
                            .iter()
                            .filter(|o| o.operation_id == *route
                                && o.what == *field
                                && o.reason == reason)
                            .count(),
                        usize::from(reported),
                        "{format:?} {route} {field} {reason}"
                    );
                }
            }
            let rows = metadata["claims"].as_array().unwrap();
            assert_eq!(rows.len(), row_count);
            assert_eq!(metadata["claim_count"], rows.len());
            let row_conflict = match *route {
                "denied-conflict"
                | "partial-denied-conflict"
                | "complete-denied-symbol-conflict"
                | "partial-blank-summary-row-conflict" => Some(true),
                "handler"
                | "conflict"
                | "complete-agreeing-rows"
                | "location"
                | "limitations"
                | "confidence"
                | "consistent"
                | "unknown-summary"
                | "complete-blank-summary"
                | "complete-blank-summary-extra" => Some(false),
                _ => None,
            };
            assert_eq!(
                metadata.get("handler_conflict"),
                Some(&json!(row_conflict)),
                "{format:?} {route}"
            );
            let unresolved = row_conflict == Some(true)
                || matches!(
                    *route,
                    "conflict"
                        | "additional-handler"
                        | "partial-extras"
                        | "partial-blank-summary-known-conflict"
                );
            assert_eq!(
                out.omissions.iter().any(|o| {
                    o.operation_id == *route && o.reason == "handler_conflict_unresolved"
                }),
                unresolved,
                "{format:?} {route}"
            );
            let aggregate = &metadata["catalog_summary"];
            assert_eq!(aggregate["claim_count"], summary_count);
            for field in [
                "handler_symbols",
                "provenance",
                "limitation_codes",
                "highest_confidence_basis_points",
            ] {
                assert_eq!(
                    aggregate.get(field),
                    Some(&summary[field]),
                    "{format:?} {route} {field}"
                );
            }
            if let Some(conflict) = summary.get("handler_conflict") {
                assert_eq!(aggregate.get("handler_conflict"), Some(conflict));
            }
            if route.contains("blank-summary") {
                let known_conflict =
                    (*route == "partial-blank-summary-known-conflict").then_some(true);
                assert_eq!(aggregate.get("handler_conflict"), Some(&json!(known_conflict)));
            }
            if let Some(location) = summary.get("single_claim_handler") {
                assert_eq!(aggregate.get("single_claim_handler"), Some(location));
            }
            for claim in claims.as_array().unwrap() {
                let row = rows.iter().find(|row| row["claim_id"] == claim["claim_id"]).unwrap();
                for (field, value) in claim.as_object().unwrap() {
                    let field = if field == "handler" { "handler_location" } else { field };
                    assert_eq!(row.get(field), Some(value), "{format:?} {route} {field}");
                }
            }
            if format == ExportFormat::OpenApi {
                openapi.push(metadata);
            } else {
                assert_eq!(&metadata, expected, "{format:?} {route}");
            }
        }
    }
}

#[test]
fn handler_summary_consistency_is_independent_of_claim_availability() {
    use serde_json::{Value, json};

    let one = json!(["First.get"]);
    let multiple = json!(["First.get", "Second.get"]);
    let cases = [
        // Symbols, supplied flag, exported flag, mismatch, unresolved conflict.
        ("denied", &multiple, json!(false), json!(false), true, true),
        ("reported", &multiple, json!(true), json!(true), false, true),
        ("derived", &multiple, Value::Null, json!(true), false, true),
        ("one-reported", &one, json!(false), json!(false), false, false),
        ("one-derived", &one, Value::Null, json!(false), false, false),
        ("one-asserted-conflict", &one, json!(true), json!(true), true, true),
        ("unknown-asserted-conflict", &Value::Null, json!(true), json!(true), false, true),
        ("unknown-denied-conflict", &Value::Null, json!(false), json!(false), false, false),
        ("unknown-conflict", &Value::Null, Value::Null, Value::Null, false, false),
    ];
    let partial_claims = json!([{"claim_id": "first", "handler_symbol": "First.get"}]);
    let operations: Vec<_> = cases
        .iter()
        .flat_map(|(name, symbols, reported, ..)| {
            [("summary", &Value::Null), ("partial", &partial_claims)].map(|(kind, claims)| {
                let route = format!("{kind}-{name}");
                json!({
                    "operation_id": route, "method": "GET", "route_template": format!("/{route}"),
                    "claims": claims, "catalog_summary": {
                        "claim_count": 2, "handler_symbols": symbols, "handler_conflict": reported
                    }
                })
            })
        })
        .collect();
    let input = xtrace_export::input_json::parse(&json!({"operations": operations})).unwrap();
    let mut openapi = std::collections::BTreeMap::new();
    for format in
        [ExportFormat::OpenApi, ExportFormat::Postman, ExportFormat::Curl, ExportFormat::Bundle]
    {
        let out = export(&input, &ExportRequest::new(format)).unwrap();
        assert_eq!(out.operation_count, 2 * cases.len());
        for (name, symbols, _, flag, mismatch, conflict) in &cases {
            for (kind, partial) in [("summary", false), ("partial", true)] {
                let route = format!("{kind}-{name}");
                let expected = openapi.get(&route).unwrap_or(&Value::Null);
                let metadata = operation_metadata(&out, format, &route, expected);
                let summary = if partial {
                    assert_eq!(
                        metadata["claims_projection"],
                        if *mismatch { "inconsistent" } else { "partial" },
                        "{format:?} {route}"
                    );
                    assert_eq!(metadata["claim_count"], 1);
                    assert_eq!(metadata["handler_symbols"], one);
                    assert_eq!(metadata.get("handler_conflict"), Some(&Value::Null));
                    assert_eq!(
                        metadata["claims"],
                        json!([{
                            "claim_id": "first", "handler_symbol": "First.get", "provenance": null,
                            "confidence_basis_points": null, "limitation_codes": null,
                            "source_evidence": null
                        }])
                    );
                    &metadata["catalog_summary"]
                } else {
                    assert_eq!(metadata["claims_projection"], "unavailable");
                    assert!(metadata.get("claims").is_none());
                    &metadata
                };
                assert_eq!(summary["claim_count"], 2);
                assert_eq!(summary.get("handler_symbols"), Some(*symbols), "{format:?} {route}");
                assert_eq!(summary.get("handler_conflict"), Some(flag), "{format:?} {route}");
                let prefixes: &[_] = if format == ExportFormat::Bundle {
                    &["openapi:", "postman:", "curl:"]
                } else {
                    &[""]
                };
                for prefix in prefixes {
                    for (field, reason, present) in [
                        ("claims", "claim_summary_mismatch", *mismatch),
                        ("claims", "claims_projection_partial", partial),
                        ("claims", "claims_projection_unavailable", !partial),
                        ("handler", "handler_conflict_unresolved", *conflict),
                    ] {
                        let what = format!("{prefix}{field}");
                        assert_eq!(
                            out.omissions
                                .iter()
                                .filter(|o| {
                                    o.operation_id == route && o.what == what && o.reason == reason
                                })
                                .count(),
                            usize::from(present),
                            "{format:?} {route} {what} {reason}"
                        );
                    }
                }
                if format == ExportFormat::OpenApi {
                    openapi.insert(route, metadata);
                } else {
                    assert_eq!(&metadata, expected, "{format:?} {route}");
                }
            }
        }
    }
}

#[test]
fn summary_handler_checks_respect_counts_location_scope_and_symbol_filtering() {
    use serde_json::{Value, json};

    let location = json!({"symbol": "First.get", "path": "First.java", "line_start": 4});
    let cases = [
        (
            "empty-with-conflict",
            json!({
                "claim_count": 2, "handler_symbols": [], "handler_conflict": true
            }),
            true,
            true,
        ),
        (
            "zero-with-handler",
            json!({
                "claim_count": 0, "handler_symbols": ["First.get"], "handler_conflict": false
            }),
            true,
            false,
        ),
        (
            "location-out-of-scope",
            json!({
                "claim_count": 2, "single_claim_handler": location
            }),
            true,
            false,
        ),
        (
            "location-missing-from-set",
            json!({
                "claim_count": 1, "handler_symbols": ["Second.get"], "single_claim_handler": location
            }),
            true,
            false,
        ),
        (
            "location-with-unknown-set",
            json!({
                "claim_count": 1, "single_claim_handler": location
            }),
            false,
            false,
        ),
        (
            "duplicate-symbols",
            json!({
                "claim_count": 2, "handler_symbols": ["First.get", "First.get"], "handler_conflict": false
            }),
            false,
            false,
        ),
        (
            "blank-symbol",
            json!({
                "claim_count": 2, "handler_symbols": ["", "First.get"]
            }),
            false,
            false,
        ),
        (
            "filtered-conflict",
            json!({
                "claim_count": 2, "handler_symbols": ["First.get", "../summary-private.java"],
                "handler_conflict": false
            }),
            true,
            true,
        ),
        (
            "count-and-summary",
            json!({
                "claim_count": 1, "handler_symbols": ["First.get"], "handler_conflict": true
            }),
            true,
            true,
        ),
    ];
    let operations: Vec<_> = cases
        .iter()
        .map(|(route, summary, ..)| {
            let mut op = json!({
                "operation_id": route, "method": "GET", "route_template": format!("/{route}"),
                "catalog_summary": summary
            });
            if *route == "count-and-summary" {
                op["claims"] = json!([
                    {"claim_id": "first", "handler_symbol": "First.get"},
                    {"claim_id": "second", "handler_symbol": "First.get"}
                ]);
            }
            op
        })
        .collect();
    let input = xtrace_export::input_json::parse(&json!({"operations": operations})).unwrap();
    let out = export(&input, &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    let rendered = text(&out.files[0]);
    assert!(!rendered.contains("summary-private.java"));
    let doc: Value = serde_json::from_str(rendered).unwrap();
    let omissions =
        |route, reason| out.omissions.iter().any(|o| o.operation_id == route && o.reason == reason);
    for (route, _, mismatch, conflict) in cases {
        assert_eq!(omissions(route, "claim_summary_mismatch"), mismatch, "{route}");
        assert_eq!(omissions(route, "handler_conflict_unresolved"), conflict, "{route}");
    }
    let metadata = |route| &doc["paths"][route]["get"]["x-xtrace"];
    assert_eq!(metadata("/location-with-unknown-set")["handlers"], json!([location]));
    for route in ["/location-with-unknown-set", "/blank-symbol"] {
        assert_eq!(metadata(route).get("handler_conflict"), Some(&Value::Null));
    }
    assert_eq!(metadata("/duplicate-symbols")["handler_symbols"], json!(["First.get"]));
    assert_eq!(metadata("/filtered-conflict")["handler_symbols"], json!(["First.get"]));
    assert_eq!(metadata("/filtered-conflict")["handler_conflict"], false);
    assert!(omissions("filtered-conflict", "handler_symbol_invalid"));
    assert!(omissions("count-and-summary", "claim_count_mismatch"));
    let inconsistent = metadata("/count-and-summary");
    assert_eq!(inconsistent["claims_projection"], "inconsistent");
    assert_eq!(inconsistent["claims"].as_array().unwrap().len(), 2);
    assert_eq!(inconsistent["catalog_summary"]["claim_count"], 1);
    assert_eq!(inconsistent.get("handler_conflict"), Some(&Value::Null));
}

#[test]
fn mixed_serialized_claims_retain_independent_handler_locations() {
    use serde_json::{Value, json};

    let symbol = format!("{}.get", "A".repeat(508));
    let oversized_symbol = "Z".repeat(513);
    let evidence = json!({"kind": "runtime_hint", "relative_path": "Hint.java", "start_line": 8, "start_column": 1});
    let input = xtrace_export::input_json::parse(&json!({
        "operations": [{
            "operation_id": "mixed", "method": "GET", "route_template": "/mixed",
            "catalog_summary": {"claim_count": 5, "handler_conflict": true},
            "claims": [
                {"claim_id": "conflicting", "handler_symbol": symbol,
                    "handler": {"symbol": "Legacy.get", "path": "Legacy.java", "line_start": 4, "line_end": 6},
                    "source_evidence": [evidence]},
                {"claim_id": "evidence-only", "source_evidence": [evidence],
                    "handler": {"symbol": "Legacy.hint", "path": "LegacyHint.java", "line_start": 12}},
                {"claim_id": "symbol-only", "handler_symbol": "Current.get",
                    "handler": {"symbol": "Legacy.other", "path": "LegacyOther.java", "line_start": 16}},
                {"claim_id": "unsafe-path", "handler_symbol": "Safe.get",
                    "handler": {"symbol": "Safe.get", "path": "../private-location.java", "line_start": 24}},
                {"claim_id": "unsafe-symbol", "handler_symbol": oversized_symbol,
                    "handler": {"symbol": "bad/symbol", "path": "UnsafeSymbol.java", "line_start": 28}}
            ]
        }]
    }))
    .unwrap();
    let mut expected = Value::Null;
    for format in
        [ExportFormat::OpenApi, ExportFormat::Postman, ExportFormat::Curl, ExportFormat::Bundle]
    {
        let out = export(&input, &ExportRequest::new(format)).unwrap();
        let file = |path| text(out.files.iter().find(|f| f.path == path).unwrap());
        let postman = || {
            let doc: Value = serde_json::from_str(file("collection.postman.json")).unwrap();
            comment_metadata(doc["item"][0]["request"]["description"].as_str().unwrap())
        };
        let curl = || {
            let recipe = out.files.iter().find(|f| f.path.ends_with("-get-mixed.sh")).unwrap();
            comment_metadata(text(recipe))
        };
        let metadata = match format {
            ExportFormat::OpenApi => {
                let doc: Value = serde_json::from_str(file("openapi.json")).unwrap();
                doc["paths"]["/mixed"]["get"]["x-xtrace"].clone()
            }
            ExportFormat::Postman => postman(),
            ExportFormat::Curl => curl(),
            ExportFormat::Bundle => {
                let yaml = file("openapi.yaml");
                for kept in [
                    symbol.as_str(),
                    "Legacy.java",
                    "LegacyHint.java",
                    "LegacyOther.java",
                    "Hint.java",
                ] {
                    assert!(yaml.contains(kept), "bundle OpenAPI lost {kept}");
                }
                let readme = file("README.md");
                assert!(
                    readme.contains("available end lines and locations from conflicting claims")
                );
                assert!(readme.contains("producer assertions"));
                assert_eq!(postman(), curl());
                postman()
            }
        };
        for f in &out.files {
            for dropped in [
                oversized_symbol.as_str(),
                "bad/symbol",
                "UnsafeSymbol.java",
                "private-location.java",
            ] {
                assert!(!text(f).contains(dropped), "{} leaked unsafe input", f.path);
            }
        }
        for reason in [
            "handler_conflict_unresolved",
            "handler_path_not_repo_relative",
            "handler_symbol_invalid",
        ] {
            assert!(out.omissions.iter().any(|o| o.reason == reason), "{format:?} lost {reason}");
        }
        if format == ExportFormat::OpenApi {
            expected = metadata.clone();
        }
        assert_eq!(metadata, expected);
    }
    let claims = expected["claims"].as_array().unwrap();
    let claim = |id: &str| claims.iter().find(|c| c["claim_id"] == id).unwrap();
    assert!(expected.get("provenance").is_none());
    assert_eq!(expected["handler_conflict"], true);
    assert_eq!(expected["catalog_summary"]["highest_confidence_basis_points"], Value::Null);
    assert!(expected.get("handlers").is_none());
    assert_eq!(
        expected["handler_symbols"],
        json!([symbol, "Current.get", "Legacy.get", "Legacy.hint", "Legacy.other", "Safe.get"])
    );
    let conflicting = claim("conflicting");
    assert_eq!(conflicting["handler_symbol"], symbol);
    assert_eq!(
        conflicting["handler_location"],
        json!({"symbol": "Legacy.get", "path": "Legacy.java", "line_start": 4, "line_end": 6})
    );
    assert_eq!(conflicting["source_evidence"][0]["relative_path"], "Hint.java");
    assert_eq!(conflicting["source_evidence"][0]["verification"], "unverified");
    assert_eq!(claim("evidence-only")["handler_symbol"], Value::Null);
    assert_eq!(
        claim("evidence-only")["handler_location"],
        json!({"symbol": "Legacy.hint", "path": "LegacyHint.java", "line_start": 12})
    );
    assert_eq!(claim("symbol-only")["handler_symbol"], "Current.get");
    assert_eq!(claim("symbol-only")["handler_location"]["symbol"], "Legacy.other");
    assert_eq!(claim("symbol-only")["source_evidence"], Value::Null);
    assert!(claim("unsafe-path").get("handler_location").is_none());
    assert!(claim("unsafe-symbol").get("handler_location").is_none());
    assert_eq!(claim("unsafe-symbol")["handler_symbol"], Value::Null);
}

#[test]
fn unsafe_claim_evidence_locations_are_omitted_across_formats() {
    use serde_json::{Value, json};

    let mut evidence = vec![json!({
        "kind": "runtime_hint", "relative_path": "OrderController.java",
        "start_line": 30, "start_column": 3, "end_line": 31, "end_column": 40
    })];
    for path in ["/outside/export-private.java", "../traversal.java", r"Q:\drive.java"] {
        let mut item = evidence[0].clone();
        item["relative_path"] = json!(path);
        evidence.push(item);
    }
    let input = xtrace_export::input_json::parse(&json!({"operations": [{
        "operation_id": "orders", "method": "GET", "route_template": "/orders",
        "claims": [{"claim_id": "get-orders", "source_evidence": evidence}]
    }]}))
    .unwrap();
    let mut expected = Value::Null;
    for format in
        [ExportFormat::OpenApi, ExportFormat::Postman, ExportFormat::Curl, ExportFormat::Bundle]
    {
        let out = export(&input, &ExportRequest::new(format)).unwrap();
        assert!(out.omissions.iter().any(|o| o.reason == "source_path_not_repo_relative"));
        for file in &out.files {
            for fragment in ["export-private.java", "traversal.java", "drive.java"] {
                assert!(!text(file).contains(fragment), "{format:?} leaked {fragment}");
            }
        }
        let metadata = operation_metadata(&out, format, "orders", &expected);
        let evidence = metadata["claims"][0]["source_evidence"].as_array().unwrap();
        assert_eq!(evidence.len(), 4);
        assert_eq!(evidence[0]["relative_path"], "OrderController.java");
        assert_eq!(evidence[0]["start_line"], 30);
        for omitted in &evidence[1..] {
            assert_eq!(omitted["location_omitted"], "path_not_repo_relative");
            for field in ["relative_path", "start_line", "start_column", "end_line", "end_column"] {
                assert!(omitted.get(field).is_none());
            }
        }
        if format == ExportFormat::OpenApi {
            expected = metadata.clone();
        }
        assert_eq!(metadata, expected);
    }
}

#[test]
fn long_claim_symbols_still_pass_through_the_secret_gate() {
    let mut input = spring_orders();
    input.operations[0].claims[0].handler_symbol =
        Some(format!("{}password=hunter2hunter2", "A".repeat(220)));
    for format in
        [ExportFormat::OpenApi, ExportFormat::Postman, ExportFormat::Curl, ExportFormat::Bundle]
    {
        assert!(
            matches!(
                export(&input, &ExportRequest::new(format)),
                Err(xtrace_export::ExportError::SecretShaped { .. })
            ),
            "{format:?} accepted a secret-shaped symbol"
        );
    }
}

#[test]
fn conflicting_claim_values_pass_through_the_secret_gate() {
    let mut input = spring_orders();
    input.operations[1].claims[1].responses[0].description = "password=hunter2hunter2".into();
    for format in
        [ExportFormat::OpenApi, ExportFormat::Postman, ExportFormat::Curl, ExportFormat::Bundle]
    {
        assert!(
            matches!(
                export(&input, &ExportRequest::new(format)),
                Err(xtrace_export::ExportError::SecretShaped { .. })
            ),
            "{format:?} accepted a secret-shaped conflicting response"
        );
    }
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
    use serde_json::{Value, json};

    let input = spring_orders();
    let out = export(&input, &ExportRequest::new(ExportFormat::Bundle)).unwrap();
    assert_eq!(out.operation_count, 5);
    let manifest: serde_json::Value = serde_json::from_slice(
        &out.files.iter().find(|f| f.path == "manifest.json").unwrap().bytes,
    )
    .unwrap();
    assert_eq!(manifest["policy_digest"], input.revision.policy_digest);
    assert_eq!(manifest["catalog_hash"], input.revision.catalog_hash);
    let file = |path| text(out.files.iter().find(|f| f.path == path).unwrap());
    let collection: Value = serde_json::from_str(file("collection.postman.json")).unwrap();
    let postman =
        comment_metadata(collection["item"][0]["request"]["description"].as_str().unwrap());
    let curl = comment_metadata(file("curl/001-get-orders.sh"));
    let spec = export(&input, &ExportRequest::new(ExportFormat::OpenApi)).unwrap();
    let spec: Value = serde_json::from_slice(&spec.files[0].bytes).unwrap();
    let mut openapi = spec["paths"]["/orders"]["get"]["x-xtrace"].as_object().unwrap().clone();
    let examples = openapi.remove("examples").unwrap();
    assert_eq!(postman, Value::Object(openapi));
    assert_eq!(curl, postman);
    assert_eq!(
        postman["conflicts"],
        json!([
            {"kind": "param_type", "subject": "query:page", "claims": [
                {"claim_id": "c-list-a", "value": "integer"},
                {"claim_id": "c-list-b", "value": "string"}
            ]},
            {"kind": "response_description", "subject": "200", "claims": [
                {"claim_id": "c-list-a", "value": "A page of orders"},
                {"claim_id": "c-list-b", "value": "All orders"}
            ]}
        ])
    );
    let mut yaml_metadata = postman;
    yaml_metadata["examples"] = examples;
    let yaml_block = xtrace_export::canonical::yaml(&json!({"x-xtrace": yaml_metadata}))
        .lines()
        .map(|line| format!("      {line}\n"))
        .collect::<String>();
    assert!(file("openapi.yaml").contains(&yaml_block));
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
                        if let Some(claims) = x.get("claims").and_then(|c| c.as_array()) {
                            assert!(claims.iter().all(|c| c.get("handler_location").is_none()));
                        }
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
