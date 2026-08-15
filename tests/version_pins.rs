//! One version, three files that each claim it.
//!
//! The crate version is the real one — it names the GitHub release the artifacts are published
//! under. Two other files repeat it, and each repetition is load-bearing:
//!
//!   * `npm/package.json` — the npm launcher downloads `releases/download/v<its own version>/…`, so
//!     a stale number fetches a release that may not exist and `npx @uxlint-net/uxlint` dies on 404.
//!   * `plugin/.claude-plugin/plugin.json` — the Claude Code plugin's launcher reads that version and
//!     installs exactly it (`UXLINT_VERSION`), which is what makes `/plugin update` update the CLI
//!     underneath. A stale number pins every plugin user to an old binary while the marketplace shows
//!     them a new one.
//!
//! None of this fails at build time, and none of it fails on the machine of whoever forgets — it
//! fails for a stranger installing for the first time. So it fails here instead.

const CARGO_VERSION: &str = env!("CARGO_PKG_VERSION");
const NPM_PACKAGE: &str = include_str!("../npm/package.json");
const PLUGIN_MANIFEST: &str = include_str!("../plugin/.claude-plugin/plugin.json");

/// The `"version": "x.y.z"` a JSON manifest declares. Deliberately a scan rather than a JSON parse:
/// this test must not need a dependency, and the field is unambiguous in both files.
fn declared_version(json: &str, what: &str) -> String {
    json.split("\"version\"")
        .nth(1)
        .and_then(|rest| rest.split('"').nth(1))
        .unwrap_or_else(|| panic!("{what} has no \"version\" field"))
        .to_string()
}

#[test]
fn every_manifest_claims_the_crate_version() {
    for (what, json) in [
        ("npm/package.json", NPM_PACKAGE),
        ("plugin/.claude-plugin/plugin.json", PLUGIN_MANIFEST),
    ] {
        assert_eq!(
            declared_version(json, what),
            CARGO_VERSION,
            "{what} is out of step with Cargo.toml — the launcher in that package downloads \
             v<its own version> from the releases, so this ships users a version that may not exist"
        );
    }
}

#[test]
fn the_plugin_launcher_installs_the_version_the_plugin_declares() {
    // The mechanism the test above protects. Without the pin, the launcher installs whatever
    // `latest` means on the day of first run and then never looks again — plugin updates would
    // silently leave the CLI behind, which is the one thing a plugin is supposed to handle.
    let sh = include_str!("../plugin/bin/uxlint-mcp");
    assert!(
        sh.contains("UXLINT_VERSION=\"v$version\""),
        "the plugin launcher must pin the download to the plugin's own version"
    );
    assert!(
        sh.contains("$data/bin/${version:-latest}/uxlint"),
        "the install path must be version-scoped, or a new version reuses the old binary"
    );
}
