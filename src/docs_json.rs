//! `uxlint docs-json` — emit the CLI's own command reference as JSON by walking the LIVE clap
//! command tree, so the published reference can never drift from what the binary actually accepts.
//!
//! The docs site (`/docs/cli`) renders this. The release workflow runs `uxlint docs-json` on the
//! freshly-built binary and attaches the result as the `cli-reference.json` release asset; the
//! server serves the latest release's copy (cached ~1 day), so the reference on the site always
//! matches the newest uxlint with no web redeploy. Because it introspects `Cli::command()` rather
//! than a hand-written mirror, adding a flag or subcommand updates the docs for free.

use clap::{Arg, Command};
use serde_json::{json, Value};

/// One argument, in the shape the docs render: the `--long`/`-short` spelling (or nothing, for a
/// positional), its help line, default(s), and backing env var. Mirrors what `--help` prints.
fn arg_json(a: &Arg) -> Value {
    json!({
        "long": a.get_long(),
        "short": a.get_short().map(|c| c.to_string()),
        // Positionals have no flag; the value name (e.g. REPORT_ID) is how they're shown instead.
        "value": a.get_value_names().map(|ns| ns.iter().map(|n| n.to_string()).collect::<Vec<_>>()),
        "help": a.get_help().map(|h| h.to_string()),
        "default": a
            .get_default_values()
            .iter()
            .map(|v| v.to_string_lossy().to_string())
            .collect::<Vec<_>>(),
        "env": a.get_env().map(|e| e.to_string_lossy().to_string()),
        "positional": a.is_positional(),
        "required": a.is_required_set(),
    })
}

/// A command and its subcommands, recursively. `path` is the space-joined ancestry so the page can
/// print full command lines (`uxlint auth login`, `uxlint site create`). Hidden commands/args and
/// clap's auto `help`/`version` pseudo-args are dropped — the reference documents the public surface.
fn command_json(cmd: &Command, path: &str) -> Value {
    let name = cmd.get_name();
    let full = if path.is_empty() {
        name.to_string()
    } else {
        format!("{path} {name}")
    };
    let args: Vec<Value> = cmd
        .get_arguments()
        .filter(|a| !a.is_hide_set() && a.get_id() != "help" && a.get_id() != "version")
        .map(arg_json)
        .collect();
    let subcommands: Vec<Value> = cmd
        .get_subcommands()
        .filter(|c| !c.is_hide_set())
        .map(|c| command_json(c, &full))
        .collect();
    json!({
        "name": name,
        "path": full,
        // `about` is the one-liner shown in a parent's subcommand list; `longAbout` is the fuller
        // paragraph `<cmd> --help` prints. The page prefers longAbout and falls back to about.
        "about": cmd.get_about().map(|s| s.to_string()),
        "longAbout": cmd.get_long_about().map(|s| s.to_string()),
        "args": args,
        "subcommands": subcommands,
    })
}

/// The whole reference, rooted at `uxlint`, stamped with the binary's version so the page can show
/// which build it reflects. Root args are the global options (`--server`, `--api-key`).
pub(crate) fn emit(root: &Command) -> Value {
    let mut v = command_json(root, "");
    v["version"] = json!(root.get_version().unwrap_or("unknown"));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn reference() -> Value {
        emit(&crate::Cli::command())
    }

    #[test]
    fn stamps_the_binary_version() {
        let v = reference();
        assert_eq!(v["name"], "uxlint");
        // A real semver from the crate, not the "unknown" fallback.
        let ver = v["version"].as_str().unwrap();
        assert_ne!(ver, "unknown");
        assert!(ver.split('.').count() >= 2, "not a version: {ver}");
    }

    #[test]
    fn carries_the_global_options() {
        let v = reference();
        let globals: Vec<_> = v["args"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|a| a["long"].as_str())
            .collect();
        assert!(globals.contains(&"server"), "global --server missing");
        assert!(globals.contains(&"api-key"), "global --api-key missing");
    }

    #[test]
    fn documents_public_commands_and_hides_the_rest() {
        let v = reference();
        let names: Vec<_> = v["subcommands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        for want in [
            "signup", "auth", "audit", "mcp", "diff", "test", "init", "site", "update", "feedback",
        ] {
            assert!(names.contains(&want), "public command {want} missing");
        }
        // The introspection-only helper and the back-compat `ci` alias are `hide = true`; the
        // published reference must not leak them.
        assert!(!names.contains(&"docs-json"), "hidden docs-json leaked");
        assert!(!names.contains(&"ci"), "hidden ci alias leaked");
    }

    #[test]
    fn walks_nested_subcommands_and_arg_metadata() {
        let v = reference();
        let cmd = |n: &str| {
            v["subcommands"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == n)
                .unwrap()
                .clone()
        };
        // `auth` is a group — its login/logout/status children must be walked, not flattened away.
        let auth_subs: Vec<_> = cmd("auth")["subcommands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap().to_string())
            .collect();
        assert!(auth_subs.contains(&"login".to_string()));
        // Arg metadata the page renders: help text + the stored default.
        let audit = cmd("audit");
        let routes = audit["args"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["long"] == "routes")
            .unwrap();
        assert_eq!(routes["default"][0], "/");
        assert!(!routes["help"].as_str().unwrap().is_empty());
    }
}
