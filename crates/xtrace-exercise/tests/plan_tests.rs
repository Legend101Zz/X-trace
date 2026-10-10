//! Exercise plan construction. Fixture input only (not row evidence).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::net::TcpListener;

use xtrace_exercise::canonical::{plan_value, recompute_hash};
use xtrace_exercise::{
    CandidateOp, CandidateParam, ChangeKind, Effect, PlanError, PlanInput, ValueSource, classify,
    preview, synthesize as try_synthesize,
};

fn synthesize(i: &PlanInput) -> xtrace_exercise::Plan {
    try_synthesize(i).unwrap()
}

fn param(name: &str, location: &str, required: bool) -> CandidateParam {
    CandidateParam { name: name.into(), location: location.into(), required, ..Default::default() }
}

fn op(
    id: &str,
    method: &str,
    route: &str,
    change: ChangeKind,
    observed: Option<u32>,
) -> CandidateOp {
    CandidateOp {
        operation_id: id.into(),
        method: method.into(),
        route_template: route.into(),
        change_kind: change,
        observed_recording_count: observed,
        conflicted: false,
        effect_hints: vec![],
        params: vec![],
    }
}

fn input() -> PlanInput {
    let mut get = op("op-get", "get", "/orders/{id}", ChangeKind::Unchanged, Some(5));
    get.params = vec![
        CandidateParam {
            scenario_value: Some("7".into()),
            claim_example: Some("1".into()),
            default_value: Some("0".into()),
            ..param("id", "path", true)
        },
        CandidateParam {
            claim_example: Some("20".into()),
            default_value: Some("10".into()),
            ..param("limit", "query", false)
        },
        CandidateParam { default_value: Some("asc".into()), ..param("sort", "query", false) },
        param("page", "query", true),
        CandidateParam {
            scenario_value: Some("Bearer abcdefghijklmnopqrstu".into()),
            claim_example: Some("tok".into()),
            ..param("Authorization", "header", true)
        },
    ];
    let create = op("op-create", "POST", "/orders", ChangeKind::Added, None);
    let list = op("op-list", "GET", "/orders", ChangeKind::Changed, Some(2));
    let seen = op("op-seen", "GET", "/health", ChangeKind::Unchanged, Some(9));
    let never = op("op-never", "GET", "/ping", ChangeKind::Unchanged, Some(0));
    PlanInput {
        revision_id: "rev-1".into(),
        catalog_hash: "ab".repeat(32),
        target: "http://127.0.0.1:8080".into(),
        ops: vec![get, create, list, seen, never],
        explicit_selection: None,
    }
}

#[test]
fn plan_hash_stable_under_input_order() {
    let base = synthesize(&input());
    let mut shuffled = input();
    shuffled.ops.reverse();
    shuffled.ops.swap(0, 2);
    shuffled.ops[0].params.reverse();
    let other = synthesize(&shuffled);
    assert_eq!(base, other);
    assert_eq!(base.plan_hash, recompute_hash(&base));
    assert_eq!(base.plan_hash.len(), 64);
}

#[test]
fn plan_hash_changes_on_any_field_change() {
    let base = synthesize(&input()).plan_hash;
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(base.clone());
    let mut variants: Vec<PlanInput> = Vec::new();
    let mut v = input();
    v.revision_id = "rev-2".into();
    variants.push(v);
    let mut v = input();
    v.catalog_hash = "cd".repeat(32);
    variants.push(v);
    let mut v = input();
    v.target = "http://127.0.0.1:8081".into();
    variants.push(v);
    let mut v = input();
    v.ops[0].route_template = "/orders/{oid}".into();
    variants.push(v);
    let mut v = input();
    v.ops[0].method = "head".into();
    variants.push(v);
    let mut v = input();
    v.ops[0].params[0].scenario_value = Some("8".into());
    variants.push(v);
    let mut v = input();
    v.ops[0].params[3].required = false;
    variants.push(v);
    let mut v = input();
    v.ops[1].change_kind = ChangeKind::Unchanged;
    variants.push(v);
    let mut v = input();
    v.ops[0].effect_hints = vec![Effect::Mutating];
    variants.push(v);
    let mut v = input();
    v.explicit_selection = Some(vec!["op-get".into()]);
    variants.push(v);
    let mut v = input();
    v.ops.pop();
    variants.push(v);
    let mut v = input();
    v.ops[0].operation_id = "op-get2".into();
    variants.push(v);
    for (i, v) in variants.iter().enumerate() {
        assert!(seen.insert(synthesize(v).plan_hash), "variant {i} did not change the hash");
    }
}

#[test]
fn value_priority_scenario_then_claim_then_default_then_unresolved() {
    let plan = synthesize(&input());
    let item = plan.items.iter().find(|i| i.operation_id == "op-get").unwrap();
    let get = |n: &str| item.params.iter().find(|p| p.name == n).unwrap();
    assert_eq!((get("id").value.as_deref(), get("id").source), (Some("7"), ValueSource::Scenario));
    assert_eq!(
        (get("limit").value.as_deref(), get("limit").source),
        (Some("20"), ValueSource::ClaimExample)
    );
    assert_eq!(
        (get("sort").value.as_deref(), get("sort").source),
        (Some("asc"), ValueSource::CatalogDefault)
    );
    assert_eq!((get("page").value.as_deref(), get("page").source), (None, ValueSource::Unresolved));
}

#[test]
fn candidate_never_invents_credentials() {
    let plan = synthesize(&input());
    let item = plan.items.iter().find(|i| i.operation_id == "op-get").unwrap();
    let auth = item.params.iter().find(|p| p.name == "Authorization").unwrap();
    assert_eq!((auth.value.as_deref(), auth.source), (None, ValueSource::Credential));
    // a secret-shaped value under an innocent name is skipped, not copied
    let mut i = input();
    i.ops[0].params.push(CandidateParam {
        scenario_value: Some("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc".into()),
        claim_example: Some("fine".into()),
        ..param("ref", "query", false)
    });
    let plan = synthesize(&i);
    let item = plan.items.iter().find(|i| i.operation_id == "op-get").unwrap();
    let r = item.params.iter().find(|p| p.name == "ref").unwrap();
    assert_eq!(r.value.as_deref(), Some("fine"));
    let text = xtrace_export::canonical::json_compact(&plan_value(&plan));
    assert!(!text.contains("eyJ") && !text.contains("abcdefghijklmnopqrstu"), "{text}");
}

#[test]
fn effect_unknown_for_conflicting_evidence() {
    assert_eq!(classify("GET", &[], false), Effect::ReadOnly);
    assert_eq!(classify("POST", &[], false), Effect::Mutating);
    assert_eq!(classify("PROPFIND", &[], false), Effect::Unknown);
    assert_eq!(classify("GET", &[Effect::ReadOnly, Effect::ReadOnly], false), Effect::ReadOnly);
    assert_eq!(classify("GET", &[Effect::Mutating], false), Effect::Unknown);
    assert_eq!(classify("GET", &[Effect::ReadOnly, Effect::Mutating], false), Effect::Unknown);
    assert_eq!(classify("GET", &[], true), Effect::Unknown);
    let mut i = input();
    i.ops[2].conflicted = true; // op-list
    let plan = synthesize(&i);
    let item = plan.items.iter().find(|i| i.operation_id == "op-list").unwrap();
    assert!(item.needs_approval);
    assert_eq!(item.effect, Effect::Unknown);
}

#[test]
fn default_selection_is_new_changed_unobserved() {
    let plan = synthesize(&input());
    let sel: Vec<(&str, bool, &str)> = plan
        .items
        .iter()
        .map(|i| (i.operation_id.as_str(), i.selected, i.selection_reason.as_str()))
        .collect();
    assert!(sel.contains(&("op-create", true, "new_in_revision")));
    assert!(sel.contains(&("op-list", true, "changed_in_revision")));
    assert!(sel.contains(&("op-never", true, "never_observed")));
    assert!(sel.contains(&("op-seen", false, "already_observed_and_unchanged")));
    assert!(sel.contains(&("op-get", false, "already_observed_and_unchanged")));
    // mutating items need approval, read-only ones do not
    let create = plan.items.iter().find(|i| i.operation_id == "op-create").unwrap();
    assert!(create.needs_approval && create.effect == Effect::Mutating);
    let never = plan.items.iter().find(|i| i.operation_id == "op-never").unwrap();
    assert!(!never.needs_approval);
    // explicit selection overrides defaults
    let mut i = input();
    i.explicit_selection = Some(vec!["op-seen".into()]);
    let plan = synthesize(&i);
    let selected: Vec<_> =
        plan.items.iter().filter(|i| i.selected).map(|i| i.operation_id.as_str()).collect();
    assert_eq!(selected, ["op-seen"]);
}

#[test]
fn plan_preview_makes_zero_requests() {
    // Trap: a real loopback listener that is also the plan's target. Building
    // and previewing a plan must never connect to it.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let mut i = input();
    i.target = format!("http://{addr}");
    let plan = synthesize(&i);
    let view = preview(&plan);
    let again = preview(&plan);
    assert_eq!(view, again);
    assert_eq!(view["requests_sent"], 0);
    assert_eq!(view["target_host_class"], "loopback");
    assert_eq!(view["target"], format!("http://{addr}").as_str());
    let accepted = listener.accept();
    assert!(
        matches!(&accepted, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "preview contacted the target: {accepted:?}"
    );
}

#[test]
fn crate_source_has_no_networking_code() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        for needle in
            ["std::net", "TcpStream", "UdpSocket", "tokio", "hyper", "reqwest", "std::process"]
        {
            assert!(!text.contains(needle), "{} mentions {needle}", path.display());
        }
    }
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .unwrap();
    for dep in ["tokio", "hyper", "reqwest", "ureq", "rustls"] {
        assert!(!manifest.contains(dep), "manifest depends on {dep}");
    }
}

#[test]
fn preview_reports_unresolved_and_credentials() {
    let plan = synthesize(&input());
    let view = preview(&plan);
    let items = view["items"].as_array().unwrap();
    let get = items.iter().find(|i| i["operation_id"] == "op-get").unwrap();
    assert_eq!(get["unresolved_required"], serde_json::json!(["page"]));
    assert_eq!(get["credentials_needed_at_run_time"], serde_json::json!(["Authorization"]));
    assert_eq!(get["ready"], false);
    assert_eq!(view["selected_items"], 3);
    assert_eq!(view["items_needing_approval"], 1);
}

fn is_uuid_text(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.iter().map(|p| p.len()).collect::<Vec<_>>() == [8, 4, 4, 4, 12]
        && s.chars().all(|c| c == '-' || c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[test]
fn item_ids_are_uuid_text_and_differ_between_plans() {
    let a = synthesize(&input());
    let mut other = input();
    other.target = "http://127.0.0.1:9999".into();
    let b = synthesize(&other);
    assert_ne!(a.plan_hash, b.plan_hash);
    for item in &a.items {
        assert!(is_uuid_text(&item.item_id), "{}", item.item_id);
        let twin = b.items.iter().find(|i| i.operation_id == item.operation_id).unwrap();
        assert_ne!(item.item_id, twin.item_id, "same operation, different plan");
    }
    let again = synthesize(&input());
    assert_eq!(
        a.items.iter().map(|i| &i.item_id).collect::<Vec<_>>(),
        again.items.iter().map(|i| &i.item_id).collect::<Vec<_>>()
    );
    assert_eq!(recompute_hash(&a), a.plan_hash);
}

#[test]
fn target_with_userinfo_rejected() {
    let mut i = input();
    i.target = "http://user:pass@host/?token=abc".into();
    assert!(matches!(try_synthesize(&i), Err(PlanError::InvalidTarget(_))));
    i.target = "http://user@host".into();
    assert_eq!(try_synthesize(&i), Err(PlanError::InvalidTarget("userinfo")));
}

#[test]
fn target_with_query_secret_rejected() {
    let mut i = input();
    i.target = "http://host/api?token=hunter2".into();
    let err = try_synthesize(&i).unwrap_err();
    assert!(!err.to_string().contains("hunter2"));
    i.target = "http://host/#frag".into();
    assert!(try_synthesize(&i).is_err());
    i.target = "http://ho st".into();
    assert!(try_synthesize(&i).is_err());
}

#[test]
fn non_http_scheme_rejected() {
    for t in ["file:///etc/passwd", "ftp://host", "host:80", "http://", "http://:80"] {
        let mut i = input();
        i.target = t.into();
        assert!(try_synthesize(&i).is_err(), "{t}");
    }
    let mut i = input();
    i.target = "https://api.example.com:8443/base".into();
    assert!(try_synthesize(&i).is_ok());
}

#[test]
fn selection_reason_does_not_claim_unknown_observation() {
    let reasons = |change, observed| {
        let mut i = input();
        i.ops = vec![op("x", "GET", "/x", change, observed)];
        let p = synthesize(&i);
        (p.items[0].selected, p.items[0].selection_reason.clone())
    };
    let unknown = (true, "change_and_observation_unknown".to_owned());
    assert_eq!(reasons(ChangeKind::Unknown, None), unknown);
    assert_eq!(reasons(ChangeKind::Unchanged, None), unknown);
    assert_eq!(reasons(ChangeKind::Unknown, Some(3)), unknown);
    assert_eq!(
        reasons(ChangeKind::Unchanged, Some(3)),
        (false, "already_observed_and_unchanged".to_owned())
    );
}

#[test]
fn target_differentials_rejected() {
    for (t, why) in [
        ("http://evil.com\\@127.0.0.1/", "backslash"),
        ("http://127.0.0.1\\.evil.com/", "backslash"),
        ("http://host/a\\b", "backslash"),
        ("http://127.0.0.1%2e.evil/", "percent_encoded_authority"),
        ("http://%31%32%37.0.0.1/", "percent_encoded_authority"),
        ("http://[fe80::1%25eth0]/", "percent_encoded_authority"),
        ("http://127.1/", "malformed_authority"),
        ("http://0x7f.0.0.1/", "malformed_authority"),
        ("http://0X7f.1/", "malformed_authority"),
        ("http://0177.0.0.1/", "malformed_authority"),
        ("http://127.0.0.01/", "malformed_authority"),
        ("http://2130706433/", "malformed_authority"),
        ("http://host:99999/", "malformed_authority"),
        ("http://host:80a/", "malformed_authority"),
        ("http://host:80:90/", "malformed_authority"),
        ("http://host:/", "malformed_authority"),
        ("http://host:0/", "port_zero"),
        ("http://[::1/", "malformed_authority"),
        ("http://[::1]x/", "malformed_authority"),
        ("http://-bad.example/", "malformed_authority"),
        ("http://a..b/", "malformed_authority"),
        ("http://host./", "malformed_authority"),
        ("http://my_service/", "malformed_authority"),
        ("http:///host", "missing_host"),
    ] {
        let mut i = input();
        i.target = t.into();
        assert_eq!(
            try_synthesize(&i).err(),
            Some(PlanError::InvalidTarget(why)),
            "wrong rejection for {t}"
        );
    }
}

#[test]
fn target_host_classification() {
    use xtrace_exercise::{HostClass, classify_target_host as c};
    let cases = [
        ("http://localhost:8080", HostClass::LoopbackName),
        ("http://api.localhost/x", HostClass::LoopbackName),
        ("http://127.0.0.1:3000", HostClass::Loopback),
        ("http://127.9.9.9", HostClass::Loopback),
        ("http://[::1]:80/", HostClass::Loopback),
        ("http://[::ffff:127.0.0.1]/", HostClass::Loopback),
        ("http://10.1.2.3", HostClass::NonPublicIp),
        ("http://192.168.0.5", HostClass::NonPublicIp),
        ("http://169.254.169.254/latest", HostClass::NonPublicIp),
        ("http://0.0.0.0", HostClass::NonPublicIp),
        ("http://[fe80::1]", HostClass::NonPublicIp),
        ("http://[fd00::1]", HostClass::NonPublicIp),
        ("http://8.8.8.8", HostClass::PublicIp),
        ("https://api.example.com:8443/base", HostClass::Name),
    ];
    for (t, want) in cases {
        assert_eq!(c(t), Ok(want), "{t}");
    }
    assert!(c("http://127.1").is_err());
}
