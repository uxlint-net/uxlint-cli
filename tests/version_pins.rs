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

/// RUN the launcher, with the network stubbed out, and report what actually happened.
///
/// Grepping the script for the pin was not enough, and the way it failed is the reason this exists:
/// the text `UXLINT_VERSION="v$version"` was present and correct, and the install still died with
/// `UXLINT_VERSION=v0.1.27: command not found` — an expanded `VAR=value` is a COMMAND NAME, because
/// bash decides what is an assignment before it expands anything. A string assertion cannot see that.
/// So: fake `curl` (prints an installer instead of fetching one), fake release (the installer drops a
/// stub binary that echoes its argv), and then look at what the launcher ran and with which env.
///
/// `path_uxlint` optionally puts a `uxlint` of that version on PATH, to exercise the branch that
/// decides between it and the pinned build.
fn run_launcher(plugin_version: &str, path_uxlint: Option<&str>) -> (bool, String, String) {
    run_launcher_opt(plugin_version, path_uxlint, false)
}

fn run_launcher_opt(
    plugin_version: &str,
    path_uxlint: Option<&str>,
    pinned_missing: bool,
) -> (bool, String, String) {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let tmp = std::env::temp_dir().join(format!(
        "uxlint-launcher-{}-{}",
        std::process::id(),
        plugin_version.replace('.', "_")
            + path_uxlint
                .map(|v| format!("-path{v}"))
                .unwrap_or_default()
                .as_str()
            + if pinned_missing { "-nopin" } else { "" }
    ));
    let _ = fs::remove_dir_all(&tmp);
    let (root, data, fakebin) = (tmp.join("root"), tmp.join("data"), tmp.join("bin"));
    fs::create_dir_all(root.join(".claude-plugin")).unwrap();
    fs::create_dir_all(&fakebin).unwrap();
    fs::write(
        root.join(".claude-plugin/plugin.json"),
        format!("{{\n\t\"name\": \"uxlint\",\n\t\"version\": \"{plugin_version}\"\n}}\n"),
    )
    .unwrap();
    fs::copy("plugin/bin/uxlint-mcp", root.join("uxlint-mcp")).unwrap();

    let exe = |p: &std::path::Path, body: &str| {
        fs::write(p, body).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
    };
    // Stands in for the release download: writes a `uxlint` that reports where it came from.
    // `pinned_missing` makes the installer refuse a PINNED version and accept an unpinned one — what
    // the release channel looks like in the minutes between a version bump merging and its binaries
    // finishing their build.
    let refuse = if pinned_missing {
        "if [ -n \"${UXLINT_VERSION:-}\" ]; then echo 'no such release' >&2; exit 1; fi\n"
    } else {
        ""
    };
    exe(
        &fakebin.join("curl"),
        &format!(
            "#!/usr/bin/env bash\ncat <<'INSTALLER'\n{refuse}mkdir -p \"$UXLINT_INSTALL_DIR\"\nprintf '#!/usr/bin/env bash\\necho ran=%s version=%s args=\"$*\"\\n' \"$([ -n \"${{UXLINT_VERSION:-}}\" ] && echo pinned || echo fallback)\" \"${{UXLINT_VERSION:-latest}}\" > \"$UXLINT_INSTALL_DIR/uxlint\"\nchmod +x \"$UXLINT_INSTALL_DIR/uxlint\"\nINSTALLER\n"
        ),
    );
    if let Some(v) = path_uxlint {
        exe(
            &fakebin.join("uxlint"),
            &format!("#!/usr/bin/env bash\n[ \"$1\" = --version ] && {{ echo \"uxlint {v}\"; exit 0; }}\necho \"ran=path version={v} args=$*\"\n"),
        );
    }

    let out = std::process::Command::new("bash")
        .arg(root.join("uxlint-mcp"))
        .env("PATH", format!("{}:/usr/bin:/bin", fakebin.display()))
        .env("CLAUDE_PLUGIN_ROOT", &root)
        .env("CLAUDE_PLUGIN_DATA", &data)
        .env_remove("UXLINT_BIN")
        .output()
        .expect("the launcher must be runnable");
    let (o, e) = (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    );
    let _ = fs::remove_dir_all(&tmp);
    (out.status.success(), o, e)
}

#[test]
fn the_plugin_launcher_installs_the_version_the_plugin_declares() {
    // Without the pin, the launcher installs whatever `latest` means on the day of first run and then
    // never looks again — plugin updates would silently leave the CLI behind, which is the one thing a
    // plugin is supposed to handle.
    let (ok, out, err) = run_launcher("9.9.9", None);
    assert!(ok, "the launcher failed: {err}");
    assert!(
        out.contains("ran=pinned") && out.contains("version=v9.9.9"),
        "it must install the version the manifest declares, not `latest`: {out}{err}"
    );
    assert!(
        out.contains("args=mcp"),
        "and then hand over to it as the MCP server: {out}"
    );
}

#[test]
fn a_stale_uxlint_on_path_does_not_shadow_the_pinned_build() {
    // Found by installing the real plugin: a mise-managed uxlint 0.1.24 on PATH silently answered for
    // a 0.1.27 plugin. That re-opens the exact trap the pin closes — /plugin update moves the plugin,
    // the binary it actually runs stays behind, and the server tells the user to upgrade something
    // they have no way to upgrade.
    let (ok, out, err) = run_launcher("9.9.9", Some("0.1.24"));
    assert!(ok, "the launcher failed: {err}");
    assert!(
        out.contains("ran=pinned"),
        "an older PATH build must not win: {out}{err}"
    );
    assert!(
        err.contains("older than this plugin"),
        "and it must say why it ignored what's on PATH: {err}"
    );

    // A NEWER one is the user tracking releases ahead of us — installing a second copy behind their
    // back would be waste, not safety.
    let (ok, out, err) = run_launcher("9.9.9", Some("10.0.0"));
    assert!(ok, "the launcher failed: {err}");
    assert!(
        out.contains("ran=path"),
        "a newer PATH build should be used as-is: {out}{err}"
    );
}

#[test]
fn a_version_whose_release_isnt_published_yet_still_starts() {
    // The marketplace serves the plugin manifest from `main`, so the moment a version bump merges it
    // advertises a version whose binaries are still building — a few minutes per release in which a
    // first install would otherwise just fail. It falls back to the newest release and says so; the
    // pinned path is tried first on every later start, so it self-heals when the release lands.
    let (ok, out, err) = run_launcher_opt("9.9.9", None, true);
    assert!(
        ok,
        "the launcher must not die when the pin isn't published: {err}"
    );
    assert!(
        out.contains("ran=fallback"),
        "it should fall back to the newest release: {out}{err}"
    );
    assert!(
        err.contains("isn't published yet"),
        "and say plainly that it did: {err}"
    );
}
