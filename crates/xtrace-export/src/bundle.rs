//! Deterministic developer directory bundle; no trace objects or source snapshots.

use serde_json::{Value, json};

use crate::projection::{POLICY_DIGEST_FIELD, Prepared};
use crate::{ExportError, ExportFile, ExportOutput, Omission, canonical, sanitize};

fn omissions_json(omissions: &[Omission]) -> Vec<Value> {
    omissions
        .iter()
        .map(|o| {
            json!({
                "operation_id": o.operation_id, "what": o.what, "reason": o.reason,
            })
        })
        .collect()
}

/// Renders all three formats with hashes, format counts and explicit omissions.
///
/// # Errors
/// Returns the first renderer, validation or secret-gate failure. No partial
/// output is returned to the caller.
pub fn render(prepared: &Prepared) -> Result<ExportOutput, ExportError> {
    let mut yaml = prepared.clone();
    yaml.yaml = true;
    let outputs = [
        ("openapi", crate::openapi::render(&yaml)?),
        ("postman", crate::postman::render(prepared)?),
        ("curl", crate::curl::render(prepared)?),
    ];
    let mut files = Vec::new();
    let mut omissions: Vec<_> = prepared.policy_digest_omission().into_iter().cloned().collect();
    let mut formats = Vec::new();
    for (format, output) in outputs {
        formats.push(json!({
            "format": format,
            "operation_count": output.operation_count,
            "omissions": omissions_json(&output.omissions),
        }));
        // An OpenAPI duplicate may still be present in the other formats.
        // Keep format-specific omissions qualified. The policy digest applies to the whole bundle.
        omissions.extend(
            output
                .omissions
                .into_iter()
                .filter(|o| o.what != POLICY_DIGEST_FIELD)
                .map(|o| Omission { what: format!("{format}:{}", o.what), ..o }),
        );
        files.extend(output.files.into_iter().map(|mut file| {
            if format == "curl" {
                file.path = format!("curl/{}", file.path);
            }
            file
        }));
    }
    let policy_digest = (!prepared.revision.policy_digest.is_empty())
        .then_some(prepared.revision.policy_digest.as_str());
    omissions.sort();
    omissions.dedup();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = json!({
        "revision_id": prepared.revision.revision_id,
        "revision_ordinal": prepared.revision.ordinal,
        "catalog_hash": prepared.revision.catalog_hash,
        "policy_digest": policy_digest,
        "operation_count": prepared.ops.len(),
        "formats": formats,
        "omissions": omissions_json(&omissions),
        "file_hash_scope": "payload files; excludes manifest.json and README.md",
        "files": files.iter().map(|file| json!({
            "path": file.path,
            "bytes": file.bytes.len(),
            "blake3": blake3::hash(&file.bytes).to_hex().to_string(),
        })).collect::<Vec<_>>(),
    });
    if let Some(path) = sanitize::gate_with_metadata(&manifest, &["/omissions", "/formats"]) {
        return Err(ExportError::SecretShaped { path });
    }
    let mut readme = String::from(
        "# X-trace developer bundle\n\n\
         openapi.yaml declares routes and required path parameters.\n\
         collection.postman.json contains requests with an empty baseUrl variable.\n\
         curl/ contains private shell recipes; all.sh only prints commands.\n\n\
         Catalog state identifies declarations and linked observations. Per-claim metadata\n\
         retains recorded handler symbols, confidence, limitations and source evidence,\n\
         including available end lines and locations from conflicting claims. Unknown fields\n\
         and unavailable claim details are explicit. Source evidence reports unverified\n\
         producer assertions. No request or response bodies were observed or retained.\n\
         No trace objects or source snapshots are included. Nothing was sent or executed.\n\
         Review recipes before running them.\n\n\
         manifest.json records revision, catalog hash, policy digest (null when unavailable),\n\
         file hashes, counts per format and omissions. OpenAPI can represent only one\n\
         operation per method and path; other scopes remain in Postman and cURL.\n\n\
         Omissions (format prefixes identify where each omission applies):\n",
    );
    for omission in &omissions {
        use std::fmt::Write as _;
        // Omission text was gated above; JSON quoting keeps embedded newlines inert.
        let _ = writeln!(
            readme,
            "- {}",
            json!({
                "operation_id": omission.operation_id, "what": omission.what, "reason": omission.reason,
            })
        );
    }
    files.push(ExportFile {
        path: "manifest.json".to_owned(),
        mode: 0o644,
        bytes: canonical::json_pretty(&manifest).into_bytes(),
    });
    files.push(ExportFile {
        path: "README.md".to_owned(),
        mode: 0o644,
        bytes: readme.into_bytes(),
    });
    Ok(crate::finish(files, omissions, prepared.ops.len()))
}
