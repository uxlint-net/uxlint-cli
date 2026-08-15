//! `server.json` — what the MCP Registry publishes about us, checked against the registry's rules
//! and against the package it points at.
//!
//! The registry validates on PUBLISH, which is a manual workflow run against a tag that already
//! shipped: a rejection there costs a release cycle to notice and another to fix. Both things checked
//! here failed or could fail silently — the first publish attempt was rejected with
//! `expected length <= 100` on `description`, after the artifacts were already public.

const SERVER_JSON: &str = include_str!("../server.json");
const NPM_PACKAGE: &str = include_str!("../npm/package.json");

/// The value of a top-level `"key": "…"` string field. A scan, not a parse, so this test needs no
/// dependency; both files are ours and flat enough for it to be unambiguous.
fn field(json: &str, key: &str, what: &str) -> String {
    json.split(&format!("\"{key}\""))
        .nth(1)
        .and_then(|rest| rest.split('"').nth(1))
        .unwrap_or_else(|| panic!("{what} has no \"{key}\""))
        .to_string()
}

#[test]
fn the_registry_description_fits_the_registry_limit() {
    let d = field(SERVER_JSON, "description", "server.json");
    // Chars AND bytes: the limit is enforced server-side and an em dash is one char but three bytes,
    // so a description that measures 99 either way is the only one that's certainly safe.
    assert!(
        d.chars().count() <= 100 && d.len() <= 100,
        "server.json description is {} chars / {} bytes — the registry rejects over 100 and does it \
         at publish time, i.e. after the release is already public: {d}",
        d.chars().count(),
        d.len()
    );
}

#[test]
fn the_registry_entry_and_the_npm_package_vouch_for_each_other() {
    // This pairing IS the ownership proof: the registry matches its server name against `mcpName`
    // inside the npm package it's told to point at. If they drift, publishing either fails or — worse
    // — starts describing someone else's package.
    assert_eq!(
        field(SERVER_JSON, "name", "server.json"),
        field(NPM_PACKAGE, "mcpName", "npm/package.json"),
        "the registry proves namespace ownership by matching these two"
    );
    let identifier = SERVER_JSON
        .split("\"identifier\"")
        .nth(1)
        .and_then(|rest| rest.split('"').nth(1))
        .expect("server.json has no package identifier");
    assert_eq!(
        identifier,
        field(NPM_PACKAGE, "name", "npm/package.json"),
        "server.json must point at the package we actually publish"
    );
}
