//! Fail every build if the SDK bridge's lint exception drifts from the workspace.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = "../../Cargo.toml";
    println!("cargo:rerun-if-changed={workspace}");
    println!("cargo:rerun-if-changed=Cargo.toml");
    let root: toml::Value = std::fs::read_to_string(workspace)?.parse()?;
    let local: toml::Value = std::fs::read_to_string("Cargo.toml")?.parse()?;
    let mut expected = root["workspace"]["lints"].clone();
    if expected["rust"]["unsafe_code"].as_str() != Some("forbid") {
        return Err("workspace must forbid unsafe code".into());
    }
    expected["rust"]["unsafe_code"] = toml::Value::String("allow".into());
    if local.get("lints") != Some(&expected) {
        return Err("macOS ACL lints must match workspace except unsafe_code = allow".into());
    }
    Ok(())
}
