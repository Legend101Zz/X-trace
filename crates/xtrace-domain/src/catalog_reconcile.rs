//! Catalog reconciliation: static scan results against observed recordings.
//!
//! Pure and order independent. Both sides must already be in identity form (method upper case,
//! route normalized by [`crate::endpoint_normalization`]); the function compares them exactly and
//! never guesses. A static claim whose route prefix or constant could not be resolved is kept apart
//! because its identity may be wrong: it is never auto-linked to an observation.

use std::collections::BTreeMap;

use serde::Serialize;

/// Limitation codes after which a static identity is a guess and must not be auto-linked.
///
/// `route_wildcard` is listed on purpose even though the runtime normalizes wildcards to the same
/// token: a static wildcard stands for an unknown set of routes, so a match would overstate what
/// the scan proved. `route_computed` is listed so that the rule does not depend on every analyzer
/// pairing it with another unresolved code.
pub const UNLINKABLE_LIMITATIONS: &[&str] =
    &["mount_unresolved", "route_computed", "route_constant_unresolved", "route_wildcard"];

/// One operation found by a static scan, in identity form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticEndpoint {
    /// Upper-case HTTP method.
    pub method: String,
    /// Normalized route template (identity form).
    pub route_template: String,
    /// Confidence in basis points (0..=10000) the scan assigned.
    pub confidence_basis_points: u32,
    /// Limitation codes attached to the claims behind this operation.
    pub limitation_codes: Vec<String>,
}

/// One endpoint observed at run time, in identity form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedEndpoint {
    /// Upper-case HTTP method.
    pub method: String,
    /// Normalized route template (identity form).
    pub route_template: String,
    /// Number of recordings that matched this endpoint.
    pub recording_count: usize,
}

/// How one endpoint fares across the two sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileStatus {
    /// Found statically and observed at run time.
    Confirmed,
    /// Found statically, no recording observed it.
    StaticOnly,
    /// Observed at run time but absent from the scan.
    ObservedOnly,
    /// Static identity is a guess (see [`UNLINKABLE_LIMITATIONS`]); not matched either way.
    StaticUnresolved,
}

/// One reconciled endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconcileRow {
    /// Upper-case HTTP method.
    pub method: String,
    /// Normalized route template.
    pub route_template: String,
    /// Outcome.
    pub status: ReconcileStatus,
    /// Scan confidence when a static side exists.
    pub static_confidence_basis_points: Option<u32>,
    /// Matching recordings when an observed side exists.
    pub recording_count: usize,
}

/// Result of [`reconcile`]; rows are sorted by route, method, status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reconciliation {
    /// All rows.
    pub rows: Vec<ReconcileRow>,
}

impl Reconciliation {
    /// Number of rows with `status`.
    #[must_use]
    pub fn count(&self, status: ReconcileStatus) -> usize {
        self.rows.iter().filter(|row| row.status == status).count()
    }
}

/// Compares a static scan with observed endpoints by exact `(method, route)` identity.
///
/// Callers pass de-duplicated static operations (a catalog revision holds one operation per
/// identity); duplicate static identities are reported once per input entry, in input order.
#[must_use]
pub fn reconcile(statics: &[StaticEndpoint], observed: &[ObservedEndpoint]) -> Reconciliation {
    let mut observed_by_key: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for endpoint in observed {
        *observed_by_key
            .entry((endpoint.route_template.as_str(), endpoint.method.as_str()))
            .or_default() += endpoint.recording_count;
    }
    let mut matched: BTreeMap<(&str, &str), ()> = BTreeMap::new();
    let mut rows = Vec::new();
    for endpoint in statics {
        let key = (endpoint.route_template.as_str(), endpoint.method.as_str());
        let unlinkable = endpoint
            .limitation_codes
            .iter()
            .any(|code| UNLINKABLE_LIMITATIONS.contains(&code.as_str()));
        let (status, recordings) = if unlinkable {
            (ReconcileStatus::StaticUnresolved, 0)
        } else if let Some(count) = observed_by_key.get(&key) {
            matched.insert(key, ());
            (ReconcileStatus::Confirmed, *count)
        } else {
            (ReconcileStatus::StaticOnly, 0)
        };
        rows.push(ReconcileRow {
            method: endpoint.method.clone(),
            route_template: endpoint.route_template.clone(),
            status,
            static_confidence_basis_points: Some(endpoint.confidence_basis_points),
            recording_count: recordings,
        });
    }
    for ((route, method), count) in observed_by_key {
        if !matched.contains_key(&(route, method)) {
            rows.push(ReconcileRow {
                method: method.to_owned(),
                route_template: route.to_owned(),
                status: ReconcileStatus::ObservedOnly,
                static_confidence_basis_points: None,
                recording_count: count,
            });
        }
    }
    rows.sort_by(|a, b| {
        (&a.route_template, &a.method, a.status).cmp(&(&b.route_template, &b.method, b.status))
    });
    Reconciliation { rows }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(method: &str, route: &str, limits: &[&str]) -> StaticEndpoint {
        StaticEndpoint {
            method: method.to_owned(),
            route_template: route.to_owned(),
            confidence_basis_points: 9000,
            limitation_codes: limits.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn obs(method: &str, route: &str, n: usize) -> ObservedEndpoint {
        ObservedEndpoint {
            method: method.to_owned(),
            route_template: route.to_owned(),
            recording_count: n,
        }
    }

    #[test]
    fn confirmed_static_only_observed_only_and_unresolved_are_distinguished() {
        let result = reconcile(
            &[
                stat("GET", "/owners/{id}", &[]),
                stat("POST", "/owners", &[]),
                stat("GET", "/{id}/users", &["route_constant_unresolved"]),
            ],
            &[obs("GET", "/owners/{id}", 3), obs("GET", "/{id}/users", 2), obs("GET", "/vets", 1)],
        );
        let by = |route: &str, method: &str| {
            result
                .rows
                .iter()
                .find(|r| r.route_template == route && r.method == method)
                .map(|r| (r.status, r.recording_count))
        };
        assert_eq!(by("/owners/{id}", "GET"), Some((ReconcileStatus::Confirmed, 3)));
        assert_eq!(by("/owners", "POST"), Some((ReconcileStatus::StaticOnly, 0)));
        assert_eq!(by("/vets", "GET"), Some((ReconcileStatus::ObservedOnly, 1)));
        // The unresolved static guess is never linked, and the observation stays unmatched.
        assert_eq!(result.count(ReconcileStatus::StaticUnresolved), 1);
        assert_eq!(
            result
                .rows
                .iter()
                .filter(|r| r.route_template == "/{id}/users")
                .map(|r| r.status)
                .collect::<Vec<_>>(),
            [ReconcileStatus::ObservedOnly, ReconcileStatus::StaticUnresolved]
        );
    }

    #[test]
    fn input_order_does_not_change_the_result() {
        let a = [stat("GET", "/a", &[]), stat("GET", "/b", &[])];
        let o = [obs("GET", "/b", 1), obs("GET", "/c", 4)];
        let forward = reconcile(&a, &o);
        let reversed_a = [a[1].clone(), a[0].clone()];
        let reversed_o = [o[1].clone(), o[0].clone()];
        assert_eq!(forward, reconcile(&reversed_a, &reversed_o));
        assert_eq!(forward.count(ReconcileStatus::Confirmed), 1);
        assert_eq!(forward.count(ReconcileStatus::StaticOnly), 1);
        assert_eq!(forward.count(ReconcileStatus::ObservedOnly), 1);
    }

    #[test]
    fn unlinkable_limitations_are_in_the_closed_vocabulary() {
        for code in UNLINKABLE_LIMITATIONS {
            assert!(crate::catalog_discovery::is_discovery_limitation_code(code), "{code}");
        }
    }

    #[test]
    fn computed_and_wildcard_statics_are_never_auto_linked() {
        for limitation in ["route_computed", "route_wildcard"] {
            let result = reconcile(&[stat("GET", "/x", &[limitation])], &[obs("GET", "/x", 1)]);
            assert_eq!(result.count(ReconcileStatus::StaticUnresolved), 1, "{limitation}");
            assert_eq!(result.count(ReconcileStatus::Confirmed), 0, "{limitation}");
        }
    }

    #[test]
    fn methods_are_part_of_the_identity_and_counts_add_up() {
        let result =
            reconcile(&[stat("GET", "/x", &[])], &[obs("POST", "/x", 2), obs("POST", "/x", 3)]);
        assert_eq!(result.count(ReconcileStatus::StaticOnly), 1);
        assert_eq!(
            result.rows.iter().find(|r| r.method == "POST").map(|r| r.recording_count),
            Some(5)
        );
    }
}
