//! `uxlint mcp install` / `uninstall` — register or remove uxlint's own MCP stdio server (this
//! binary + `mcp`) with a coding-agent tool that has a real MCP-registration CLI.
//!
//! Only tools actually found on PATH are offered — there's no sane way to register with an
//! editor/agent that isn't installed, and a PATH probe is cheap and portable. VERIFIED against
//! the real CLIs on this dev machine: both Claude Code (`claude`) and Codex (`codex`) are
//! installed here, and `claude mcp add/get/remove --help` / `codex mcp add/get/remove --help`
//! confirm identical shapes for what we need:
//!   `<bin> mcp add <name> -- <command> [args...]`   (stdio server, `--` before the command)
//!   `<bin> mcp get <name>`                            (exit 0 iff it exists)
//!   `<bin> mcp remove <name>`                         (removes from whichever scope it's in —
//!                                                       `claude mcp remove --help` documents
//!                                                       this explicitly; codex has no scopes)
//! If a third tool is added later with a different syntax, give its `Tool` its own arg-builder
//! fns instead of the shared `args_*` ones below.
//!
//! Idempotency: `claude mcp add` does NOT error when the name already exists in a *different*
//! scope than the one it's about to write — it silently creates a second, conflicting
//! registration under the same name (confirmed live: adding to "local" scope while "uxlint"
//! already existed in "project" scope left `claude mcp list` showing both, flagged by claude
//! itself as "Conflicting scopes"). So install always pre-checks `get` itself rather than
//! relying on the tool's own "already exists" error, which only fires for a same-scope clash.

use std::process::{Command, Output};

use anyhow::{Context, Result};
use inquire::Select;

use crate::style::Stream;

/// One coding-agent tool uxlint can register its MCP server with.
#[derive(Debug)]
struct Tool {
    /// Stable id for `--tool` and internal matching.
    id: &'static str,
    /// Shown in the picker / messages.
    label: &'static str,
    /// The CLI binary this tool exposes — also the PATH-detection probe.
    bin: &'static str,
    get_args: fn(&str) -> Vec<String>,
    add_args: fn(&str, &str) -> Vec<String>,
    remove_args: fn(&str) -> Vec<String>,
}

// `claude mcp` and `codex mcp` happen to share the exact same add/get/remove shape (verified
// against both --help outputs above) — one arg-builder set covers both today.
fn args_get(name: &str) -> Vec<String> {
    vec!["mcp".into(), "get".into(), name.into()]
}
fn args_add(name: &str, exe: &str) -> Vec<String> {
    vec![
        "mcp".into(),
        "add".into(),
        name.into(),
        "--".into(),
        exe.into(),
        "mcp".into(),
    ]
}
fn args_remove(name: &str) -> Vec<String> {
    vec!["mcp".into(), "remove".into(), name.into()]
}

const TOOLS: &[Tool] = &[
    Tool {
        id: "claude-code",
        label: "Claude Code",
        bin: "claude",
        get_args: args_get,
        add_args: args_add,
        remove_args: args_remove,
    },
    Tool {
        id: "codex",
        label: "Codex",
        bin: "codex",
        get_args: args_get,
        add_args: args_add,
        remove_args: args_remove,
    },
];

/// Default registration name — the same across every tool, so `claude mcp list` / `codex mcp
/// list` both read "uxlint" and there's exactly one name to remember (and to `--name` around,
/// for the rare case something else already owns it, or for a disposable test registration).
pub(crate) const DEFAULT_NAME: &str = "uxlint";

/// Is `bin` an executable file in any dir of `path` (a PATH-style value)? A direct search rather
/// than shelling out to `which`/`command -v` (not guaranteed present either) or running the tool's
/// own `--version` (slow, and some CLIs do first-run setup on any invocation). PURE — the PATH value
/// is passed in, not read from the global env, so tests exercise it against a synthetic PATH without
/// mutating the process environment (which races other threads in a parallel test run).
fn path_contains(bin: &str, path: Option<&std::ffi::OsStr>) -> bool {
    path.is_some_and(|paths| {
        std::env::split_paths(paths).any(|dir| {
            dir.join(bin).is_file() || (cfg!(windows) && dir.join(format!("{bin}.exe")).is_file())
        })
    })
}

fn find_tool(id: &str) -> Result<&'static Tool> {
    TOOLS.iter().find(|t| t.id == id).with_context(|| {
        format!(
            "unknown --tool {id:?} — known tools: {}",
            TOOLS.iter().map(|t| t.id).collect::<Vec<_>>().join(", ")
        )
    })
}

/// Resolve which tool to act on: the explicit `--tool` id if given (must be detected on PATH),
/// otherwise an interactive picker offering ONLY the tools actually found — undetected ones get
/// a dim note above the picker instead of a selectable (but useless) entry, matching `init`'s
/// prompt style (arrow-key `Select`, `inquire`).
fn resolve_tool(tool: Option<&str>, path: Option<&std::ffi::OsStr>) -> Result<&'static Tool> {
    if let Some(id) = tool {
        let t = find_tool(id)?;
        anyhow::ensure!(
            path_contains(t.bin, path),
            "{} (`{}`) isn't on PATH — install it first, then retry",
            t.label,
            t.bin
        );
        return Ok(t);
    }
    let (detected, missing): (Vec<&Tool>, Vec<&Tool>) =
        TOOLS.iter().partition(|t| path_contains(t.bin, path));
    anyhow::ensure!(
        !detected.is_empty(),
        "no supported coding-agent tool found on PATH (looked for: {}) — install one, or pass --tool once it's on PATH",
        TOOLS.iter().map(|t| format!("{} (`{}`)", t.label, t.bin)).collect::<Vec<_>>().join(", ")
    );
    let st = Stream::Err;
    for t in &missing {
        eprintln!(
            "{}",
            st.dim(&format!("  {} not found on PATH — skipping", t.label))
        );
    }
    if detected.len() == 1 {
        eprintln!("Tool: {} (only one detected)", detected[0].label);
        return Ok(detected[0]);
    }
    let labels: Vec<String> = detected.iter().map(|t| t.label.to_string()).collect();
    let choice = Select::new("Register uxlint's MCP server with", labels).prompt()?;
    Ok(detected
        .into_iter()
        .find(|t| t.label == choice)
        .expect("choice came from the offered list"))
}

fn run(bin: &str, args: &[String]) -> Result<Output> {
    Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("could not run `{bin}` — is it really on PATH?"))
}

fn exists(t: &Tool, name: &str) -> Result<bool> {
    Ok(run(t.bin, &(t.get_args)(name))?.status.success())
}

/// `uxlint mcp install [--tool <id>] [--name <name>]` — idempotent: a second run finds the
/// existing registration via `get` and no-ops instead of re-adding.
pub(crate) fn install(tool: Option<&str>, name: &str) -> Result<()> {
    let t = resolve_tool(tool, std::env::var_os("PATH").as_deref())?;
    let st = Stream::Out;
    if exists(t, name)? {
        println!(
            "{}",
            st.dim(&format!(
                "{name:?} is already registered with {} — nothing to do.",
                t.label
            ))
        );
        println!(
            "{}",
            st.dim(&format!(
                "(to re-point it, first `uxlint mcp uninstall --tool {} --name {name}`)",
                t.id
            ))
        );
        return Ok(());
    }
    let exe = std::env::current_exe().context("could not resolve this uxlint binary's own path")?;
    let exe = exe
        .to_str()
        .context("this uxlint binary's path isn't valid UTF-8")?;
    let out = run(t.bin, &(t.add_args)(name, exe))?;
    if out.status.success() {
        println!(
            "{} registered {name:?} with {} — runs `{exe} mcp`",
            st.green("✓"),
            t.label
        );
        println!("{}", st.dim(&format!("verify: {} mcp list", t.bin)));
        Ok(())
    } else {
        let msg = String::from_utf8_lossy(&out.stderr);
        let msg = if msg.trim().is_empty() {
            String::from_utf8_lossy(&out.stdout).to_string()
        } else {
            msg.to_string()
        };
        anyhow::bail!(
            "`{} {}` failed to register {name:?}:\n{}",
            t.bin,
            (t.add_args)(name, exe).join(" "),
            msg.trim()
        );
    }
}

/// `uxlint mcp uninstall [--tool <id>] [--name <name>]` — a friendly no-op when there's nothing
/// registered under `name` (checked ourselves via `get`, since `claude mcp remove` on an absent
/// name exits non-zero while `codex mcp remove` doesn't — a uniform no-op either way beats
/// depending on that difference).
pub(crate) fn uninstall(tool: Option<&str>, name: &str) -> Result<()> {
    let t = resolve_tool(tool, std::env::var_os("PATH").as_deref())?;
    let st = Stream::Out;
    if !exists(t, name)? {
        println!(
            "{}",
            st.dim(&format!(
                "{name:?} isn't registered with {} — nothing to do.",
                t.label
            ))
        );
        return Ok(());
    }
    let out = run(t.bin, &(t.remove_args)(name))?;
    if out.status.success() {
        println!("{} removed {name:?} from {}", st.green("✓"), t.label);
        Ok(())
    } else {
        let msg = String::from_utf8_lossy(&out.stderr);
        let msg = if msg.trim().is_empty() {
            String::from_utf8_lossy(&out.stdout).to_string()
        } else {
            msg.to_string()
        };
        anyhow::bail!(
            "`{} {}` failed to remove {name:?}:\n{}",
            t.bin,
            (t.remove_args)(name).join(" "),
            msg.trim()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_add_puts_a_double_dash_before_the_command_and_appends_the_mcp_subcommand() {
        assert_eq!(
            args_add("uxlint", "/usr/local/bin/uxlint"),
            vec!["mcp", "add", "uxlint", "--", "/usr/local/bin/uxlint", "mcp"]
        );
    }

    #[test]
    fn args_get_and_remove_are_just_the_name() {
        assert_eq!(args_get("uxlint"), vec!["mcp", "get", "uxlint"]);
        assert_eq!(args_remove("uxlint"), vec!["mcp", "remove", "uxlint"]);
    }

    #[test]
    fn find_tool_knows_both_verified_tools_and_rejects_unknown_ids() {
        assert_eq!(find_tool("claude-code").unwrap().bin, "claude");
        assert_eq!(find_tool("codex").unwrap().bin, "codex");
        let err = find_tool("cursor").unwrap_err();
        assert!(err.to_string().contains("unknown --tool"), "{err}");
        assert!(
            err.to_string().contains("claude-code"),
            "should list the known ids: {err}"
        );
    }

    /// `--tool` names a real tool id, but it isn't on the (synthetic) PATH — resolve_tool must
    /// refuse rather than silently trying to run a binary that doesn't exist. The PATH is passed IN
    /// (an empty temp dir), never set on the process, so the assertion holds regardless of what's
    /// installed on the runner and without racing other tests.
    #[test]
    fn resolve_tool_refuses_an_explicit_tool_not_on_path() {
        let empty_dir =
            std::env::temp_dir().join(format!("uxlint-test-empty-path-{}", std::process::id()));
        std::fs::create_dir_all(&empty_dir).unwrap();
        let err = resolve_tool(Some("claude-code"), Some(empty_dir.as_os_str())).unwrap_err();
        assert!(err.to_string().contains("isn't on PATH"), "{err}");
    }

    /// A directory containing an executable file named `bin` makes `path_contains` see it — proves
    /// the detection logic itself (searching PATH dirs for an entry named after the binary) against a
    /// synthetic PATH value, without depending on what's installed or mutating the process env.
    #[test]
    fn path_contains_detects_an_executable_placed_on_a_synthetic_path() {
        let dir = std::env::temp_dir().join(format!(
            "uxlint-test-path-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("uxlint-test-fake-tool");
        std::fs::write(&fake, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&fake).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&fake, perms).unwrap();
        }
        let path = dir.as_os_str();
        assert!(
            path_contains("uxlint-test-fake-tool", Some(path)),
            "should find the fake tool placed on the synthetic PATH"
        );
        assert!(
            !path_contains("uxlint-test-definitely-not-a-real-binary", Some(path)),
            "should not find a binary that was never placed on PATH"
        );
    }
}
