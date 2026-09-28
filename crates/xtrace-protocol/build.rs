//! Build script for `xtrace-protocol`.
//!
//! Compiles the checked-in `schema/proto/xtp-agent/v1/*.proto` files
//! into Rust source. The build uses the `protoc` binary embedded in
//! `protoc-bin-vendored` so it never inspects `PATH`, never sets
//! `PROTOC`, and never requires a system or Homebrew `protoc`.
//!
//! The resolved binary path is passed to
//! [`prost_build::Config::protoc_executable`], which is the safe API
//! supported by `prost-build` 0.13 and does not mutate the process
//! environment.

// Build scripts traditionally use `expect` and `unwrap` for setup
// failures: the only recovery is to halt the build, which is what a
// panic does. The crate-wide lints forbid both in library code; we
// re-allow them here so the build script stays readable.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "build scripts panic on setup failure; recovery is not possible"
)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use prost_build::Config;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    // `CARGO_MANIFEST_DIR` points at `crates/xtrace-protocol`; we
    // need the workspace root (two directories up) to find
    // `schema/proto`.
    let workspace_root = manifest_dir.parent().and_then(Path::parent).expect("workspace root");
    let proto_dir = workspace_root.join("schema/proto");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let generated_dir = out_dir.join("generated");

    fs::create_dir_all(&generated_dir).expect("create generated directory");

    let proto_files = collect_proto_files(&proto_dir);
    for path in &proto_files {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rerun-if-changed=build.rs");

    // `protoc-bin-vendored` embeds a target-specific `protoc` binary
    // and returns its absolute path on disk. `Config::protoc_executable`
    // accepts that absolute path directly; prost-build invokes it
    // without consulting `PATH` or the `PROTOC` environment variable.
    let protoc_path = protoc_bin_vendored::protoc_bin_path()
        .expect("protoc-bin-vendored must expose a protoc binary for this target");

    let mut config = Config::new();
    config
        .bytes(["."])
        .compile_well_known_types()
        .disable_comments(["."])
        .protoc_executable(protoc_path)
        .out_dir(&generated_dir)
        .file_descriptor_set_path(generated_dir.join("file_descriptor_set.bin"));

    config.compile_protos(&proto_files, &[proto_dir]).expect("compile xtp-agent protos");
}

/// Recursively collects every `.proto` file under the supplied root.
fn collect_proto_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = fs::read_dir(root).expect("read proto root");
    for entry in entries {
        let entry = entry.expect("read proto entry");
        let path = entry.path();
        if path.is_dir() {
            out.extend(collect_proto_files(&path));
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("proto") {
            out.push(path);
        }
    }
    out.sort();
    out
}
