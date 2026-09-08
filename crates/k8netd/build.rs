//! Bakes the build-time `K8NETD_VERSION` / `K8NETD_REVISION` env vars (set by
//! the Containerfile from `--build-arg VERSION/REVISION`) into the binary.
//! `VERSION` is the full image ref (`v0.1.2`, `edge`, `dev`); the binary
//! reports semver style, so a leading `v` before a digit is stripped and
//! non-release strings pass through unchanged. Unset or empty values fall
//! back to the crate version and "unknown" so a bare `cargo build` outside
//! the image still self-identifies.

use std::env;

/// Strips the leading `v` from a release version string (`v0.1.2` ->
/// `0.1.2`); anything else (`edge`, `dev`, plain semver) passes through.
fn normalize_version(raw: &str) -> &str {
    match raw.strip_prefix('v') {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => raw,
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=K8NETD_VERSION");
    println!("cargo:rerun-if-env-changed=K8NETD_REVISION");

    let version = env::var("K8NETD_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| normalize_version(&v).to_string())
        .unwrap_or_else(|| env::var("CARGO_PKG_VERSION").unwrap_or_default());
    let revision = env::var("K8NETD_REVISION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=K8NETD_VERSION={version}");
    println!("cargo:rustc-env=K8NETD_REVISION={revision}");
}
