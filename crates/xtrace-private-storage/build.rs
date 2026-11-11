//! Keep the private CI channel out of release and inherited release profiles.

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CI_DIAGNOSTICS");
    println!("cargo:rerun-if-env-changed=PROFILE");
    // Cargo reports the base profile here, including for custom profiles. Unlike
    // debug_assertions, this distinction survives release profile overrides.
    if std::env::var_os("CARGO_FEATURE_CI_DIAGNOSTICS").is_some()
        && std::env::var("PROFILE").as_deref() == Ok("release")
    {
        // Preserve the diagnostic matched by the existing packaging checks.
        eprintln!(
            "ci-diagnostics requires debug_assertions; release/package builds must exclude it"
        );
        eprintln!("ci-diagnostics is forbidden in release profiles even with debug assertions");
        std::process::exit(1);
    }
}
