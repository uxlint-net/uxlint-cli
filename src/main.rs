//! uxlint — the thin driver. A single static Rust binary (mise/brew/curl installable, no
//! Node): drives your local Chrome over CDP, evaluates its BAKED-IN collector script (compiled
//! into this binary, not fetched — so the source fully vouches for what a capture uploads), POSTs
//! snapshots (geometry + text, secret-scrubbed — never your code), prints the report.
//!
//!   uxlint signup --email you@example.com
//!   uxlint audit --base http://localhost:5173 --routes /,/about
//!   uxlint audit --base https://staging.app --header "Cookie: session=…" --storage token=abc
//!   uxlint mcp        # stdio MCP server: exposes audit_url to Claude Code / Cursor

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::json;

mod audit;
mod commands;
mod docs_json;
mod fix_preview;
mod guidance;
mod init;
mod login;
mod mcp;
mod mcp_install;
mod otel;
mod passes;
mod progress;
mod project;
mod reaper;
mod redact;
/// Test-only guard: no shipped default may point at a developer's machine or a domain we don't own.
#[cfg(test)]
mod shipped_defaults;
mod site;
mod source_map;
mod style;
mod test_run;
mod update;
mod worker;

use audit::run_audit;
use commands::{check_rule, print_fix_plan, print_report, run_ci, run_diff, signup};
use mcp::run_mcp;
use test_run::run_test_command;

#[derive(Parser, Clone)]
#[command(
    name = "uxlint",
    about = "Design-taste linter: audit any site's UX",
    version
)]
pub(crate) struct Cli {
    /// uxlint server (the brain). Defaults to the hosted service; override with `--server` /
    /// `UXLINT_SERVER` to point at your own (local dev runs it at `http://127.0.0.1:49800`).
    #[arg(
        long,
        global = true,
        default_value = "https://uxlint.net",
        env = "UXLINT_SERVER"
    )]
    pub(crate) server: String,
    /// API key (from `uxlint signup`)
    #[arg(long, global = true, env = "UXLINT_API_KEY")]
    pub(crate) api_key: Option<String>,
    #[command(subcommand)]
    pub(crate) cmd: Cmd,
}

/// `uxlint auth …` — everything about who the CLI is signed in as. One credential, one place:
/// the token lands in ~/.config/uxlint/credentials and is the fallback below --api-key /
/// UXLINT_API_KEY, so once you're logged in nothing else has to carry a key.
#[derive(Subcommand, Clone)]
enum AuthCmd {
    /// Log in via the browser — mints a token and saves it to ~/.config/uxlint/credentials
    Login {
        /// The web app to open (override with --web / UXLINT_WEB_URL; local dev runs it at
        /// http://127.0.0.1:49173)
        ///
        /// This defaults to the HOSTED app, not a dev port. It used to default to
        /// `http://127.0.0.1:49173`, which meant a released binary sent every real user's
        /// `uxlint auth login` to a localhost port nothing was serving — login simply did not work
        /// outside this repo. Same class of bug as `--server` defaulting to a domain we don't own:
        /// a developer's convenience baked in as everyone's default. Working locally? Set
        /// `UXLINT_WEB_URL=http://127.0.0.1:49173`.
        #[arg(long, env = "UXLINT_WEB_URL", default_value = "https://uxlint.net")]
        web: String,
    },
    /// Forget the saved token (~/.config/uxlint/credentials)
    Logout,
    /// Who (if anyone) this CLI is signed in as, and against which server
    Status,
}

#[derive(Subcommand, Clone)]
enum Cmd {
    /// Create an account and print your API key
    Signup {
        #[arg(long)]
        email: String,
    },
    /// Sign in and out — the token is stored at ~/.config/uxlint/credentials
    Auth {
        #[command(subcommand)]
        cmd: AuthCmd,
    },
    /// Audit a site. `--ci` runs the full CI flow: start the dev server from
    /// uxlint.toml [dev], wait until ready, audit, then stop it (`uxlint ci` still works too, as
    /// a hidden back-compat alias for this same behavior).
    Audit(Box<AuditArgs>),
    /// Run as an MCP stdio server (tool: audit_url); `mcp install`/`mcp uninstall` instead wire
    /// this binary up with a coding-agent tool (Claude Code, Codex) so IT runs the server.
    Mcp {
        #[command(subcommand)]
        action: Option<McpCmd>,
        /// Default base URL for audits when a tool call omits `base` and no uxlint.toml supplies one.
        /// Lets a coding agent launch the server already pointed at the site under review
        /// (`uxlint mcp --base http://localhost:5173`). A per-call `base` still wins; without either,
        /// it falls back to uxlint.toml's `base`.
        #[arg(long)]
        base: Option<String>,
    },
    /// Re-audit a past report's site and show what changed: fixed, new/regressed, still open
    Diff {
        /// A report id (the trailing id of a report URL, .../sites/{site}/r/<id>) as the baseline
        report_id: String,
    },
    /// Run this project's declared tests like a first-time user (the server's judge picks the
    /// controls, this client clicks them). `uxlint test "<name-or-index>"` runs one; bare
    /// `uxlint test` lists the plan and lets you pick; `uxlint test list` just lists them.
    Test(Box<RunTestArgs>),
    /// Set up this project: sign in, pick an org + site, capture login creds, write uxlint.toml
    Init {
        /// Org name — skips the picker (as in Settings)
        #[arg(long)]
        org: Option<String>,
        /// Site host — skips the picker, e.g. staging.acme.com
        #[arg(long)]
        site: Option<String>,
        /// Default routes to audit
        #[arg(long, default_value = "/")]
        routes: String,
        /// The URL `uxlint audit` should point at (stored as `base` in uxlint.toml). Skips the
        /// prompt when given; required for a fully non-interactive `--offline` run to store a base.
        #[arg(long)]
        url: Option<String>,
        /// Web app to open for sign-in. Defaults to the HOSTED app for the same reason `auth login
        /// --web` does — a dev port baked in as everyone's default makes `uxlint init` unable to
        /// sign anyone in outside this repo. Working locally? Set `UXLINT_WEB_URL`.
        #[arg(long, env = "UXLINT_WEB_URL", default_value = "https://uxlint.net")]
        web: String,
        /// Write uxlint.toml from --org/--site without contacting the server or prompting (CI)
        #[arg(long)]
        offline: bool,
    },
    /// Manage sites: create, delete, list, and their members
    Site {
        #[command(subcommand)]
        action: SiteCmd,
    },
    /// CI mode: start the dev server from uxlint.toml [dev], wait until ready, audit, stop.
    /// Hidden — this is the pre-reshape spelling of `uxlint audit --ci`, kept working as a
    /// back-compat alias; prefer `audit --ci` going forward.
    #[command(hide = true)]
    Ci,
    /// Self-update: download and install a release over the running binary — the latest by
    /// default, or `--to <version>` for a specific one (what your server asked for). Verifies the
    /// tarball's sha256 BEFORE replacing anything; a checksum mismatch aborts with the installed
    /// binary untouched. `--check` reports the version delta without installing.
    Update {
        /// Report whether a newer version exists (and which) without downloading or installing it
        #[arg(long)]
        check: bool,
        /// Install this exact version instead of the latest, e.g. `--to 0.1.11`. Use it when an
        /// audit says the server it points at expects a different CLI: a self-hosted or pinned
        /// deployment can be aligned with an OLDER release than the newest public one, so this
        /// may install a downgrade — deliberately.
        #[arg(long, value_name = "VERSION")]
        to: Option<String>,
    },
    /// Emit the CLI's own command reference as JSON — what the docs site (/docs/cli) renders.
    /// Hidden: it's a docs-build/introspection helper (walks the live clap tree so the published
    /// reference can't drift), not part of the user-facing surface. The release workflow runs it
    /// to attach `cli-reference.json` to each GitHub release.
    #[command(hide = true)]
    DocsJson,
    /// Report a widget set uxlint failed to recognise (feeds the recognition corpus)
    Feedback {
        /// Name of the widget set / component library, e.g. "framework7"
        #[arg(long)]
        widget_set: String,
        /// Site where you saw it
        #[arg(long)]
        url: Option<String>,
        /// What was missed
        #[arg(long)]
        note: Option<String>,
    },
}

/// `uxlint mcp install` / `uninstall` — register or remove this binary's own MCP server (this
/// exe + the `mcp` subcommand) with a coding-agent tool. Only tools found on PATH are ever
/// offered (interactively or via `--tool`); see `mcp_install.rs` for the verified per-tool CLI.
#[derive(Subcommand, Clone)]
enum McpCmd {
    /// Register uxlint's MCP server with a coding-agent tool (interactive picker if --tool is
    /// omitted, restricted to tools detected on PATH). Idempotent: running it twice no-ops.
    Install {
        /// Skip the picker and register with this tool directly: claude-code, codex
        #[arg(long)]
        tool: Option<String>,
        /// Registration name (rarely needed — mainly so a test run doesn't clobber an existing
        /// "uxlint" registration)
        #[arg(long, default_value_t = crate::mcp_install::DEFAULT_NAME.to_string())]
        name: String,
    },
    /// Remove uxlint's MCP server registration from a coding-agent tool. A friendly no-op if
    /// it isn't registered.
    Uninstall {
        /// Skip the picker and target this tool directly: claude-code, codex
        #[arg(long)]
        tool: Option<String>,
        /// Registration name to remove (must match the one used at install time)
        #[arg(long, default_value_t = crate::mcp_install::DEFAULT_NAME.to_string())]
        name: String,
    },
}

#[derive(Subcommand, Clone)]
enum SiteCmd {
    /// Create a site (defaults to your personal workspace)
    Create {
        /// Host, e.g. staging.acme.com or localhost:5173
        host: String,
        #[arg(long)]
        org: Option<String>,
    },
    /// Delete a site
    Delete {
        host: String,
        #[arg(long)]
        org: Option<String>,
    },
    /// List your sites, grouped by org
    List,
    /// Add an org member to a site (they must already be in the org)
    AddUser {
        host: String,
        email: String,
        #[arg(long, default_value = "member")]
        role: String,
        #[arg(long)]
        org: Option<String>,
    },
    /// Remove a member from a site
    RemoveUser {
        host: String,
        email: String,
        #[arg(long)]
        org: Option<String>,
    },
}

#[derive(Parser, Clone)]
pub(crate) struct RunTestArgs {
    /// Base URL
    #[arg(long)]
    pub(crate) base: String,
    /// Which declared test to run: its name or 1-based list index (e.g. `uxlint test 2` or
    /// `uxlint test "sign in"`) — inherits that test's expect/audience/viewport. Any other text
    /// runs as an ad-hoc test instead. The literal `list`, or omitting it entirely, lists this
    /// project's declared tests (and, on a tty, lets you pick one interactively).
    #[arg(default_value = "")]
    pub(crate) test: String,
    /// The site whose declared tests to list/select from (host) — resolved the same way an audit
    /// resolves its site: this flag (or UXLINT_SITE) → uxlint.toml's `site` → the --base URL's own
    /// host. Only matters for the no-goal list and the name/index lookup; an ad-hoc free-text
    /// goal doesn't need it.
    #[arg(long, env = "UXLINT_SITE")]
    pub(crate) site: Option<String>,
    /// Optional ADVISORY hint about where the goal lives (a word likely on the destination). No
    /// longer a success gate — whether the goal is reached is the server judge's content-based call
    /// from the live page state, not a substring match on this. A declared test's own
    /// `expect` is inherited the same way; safe to omit entirely.
    #[arg(long)]
    pub(crate) expect: Option<String>,
    /// Max hops (judge calls) before the walk gives up — one action per hop. The default is tuned
    /// for a real multi-step flow; raise it for a long journey, e.g. `--hops 16`.
    #[arg(long, default_value_t = crate::test_run::DEFAULT_WALK_HOPS)]
    pub(crate) hops: usize,
    #[arg(long = "header")]
    pub(crate) headers: Vec<String>,
    #[arg(long = "storage")]
    pub(crate) storage: Vec<String>,
    /// The crawled site map (route, title) — populated by the audit goals pass so the
    /// planner navigates with knowledge of what pages exist. Not a CLI arg.
    #[arg(skip)]
    pub(crate) site_map: Vec<(String, String)>,
    /// Role login: (login-page URL, email/username, password). When set, the walk signs in via
    /// the login form before pursuing the goal, so it runs as a user of that role. Not a CLI arg.
    #[arg(skip)]
    pub(crate) login: Option<(String, String, String)>,
    /// Viewport to run the test at: "mobile" uses a phone window, anything else uses desktop.
    /// Lets a task be validated where it's actually expected (some tasks are desktop-only).
    #[arg(long, default_value = "desktop")]
    pub(crate) viewport: String,
}

#[derive(Parser, Clone)]
pub(crate) struct AuditArgs {
    /// Base URL of the site to audit. Optional — defaults to `base` in uxlint.toml (set by
    /// `uxlint init`); pass this to override for a one-off.
    #[arg(long, default_value = "")]
    pub(crate) base: String,
    /// Comma-separated routes
    #[arg(long, default_value = "/")]
    pub(crate) routes: String,
    /// Viewports as name:WxH, comma-separated
    #[arg(long, default_value = "desktop:1440x900,mobile:390x844")]
    pub(crate) viewports: String,
    /// Extra HTTP header for authenticated sites, "Name: value" (repeatable)
    #[arg(long = "header")]
    pub(crate) headers: Vec<String>,
    /// localStorage entry for token-auth sites, "key=value" (repeatable; set before load)
    #[arg(long = "storage")]
    pub(crate) storage: Vec<String>,
    /// Sign in with a username/password login FORM before auditing, so the whole crawl runs
    /// authenticated. `--login-url` is the login page (path or absolute); pair with --username /
    /// --password. Better than a raw cookie: it re-logs-in each run and can't go stale.
    #[arg(long = "login-url")]
    pub(crate) login_url: Option<String>,
    #[arg(long)]
    pub(crate) username: Option<String>,
    #[arg(long)]
    pub(crate) password: Option<String>,
    /// Also drive interaction states (hover + keyboard focus) on desktop pages
    #[arg(long)]
    pub(crate) states: bool,
    /// Fault-injection: fail the page's data (XHR/fetch) requests and check the error UX
    #[arg(long)]
    pub(crate) probe_errors: bool,
    /// Resilience: emulate adverse conditions (no-JS, reduced-motion, 320px reflow, offline,
    /// forced-colors, CPU throttle, timezone). Fast checks only.
    #[arg(long)]
    pub(crate) resilience: bool,
    /// Slow-network probe: inject 5s latency and check a primary action gives loading feedback.
    /// Opt-in and separate from --resilience — the 5s wait adds up across many routes.
    #[arg(long)]
    pub(crate) slow_network: bool,
    /// Overall audit timeout in seconds — the cap on the BROWSER phases (crawl + tests). When
    /// it passes, no NEW routes or probes start; the audit still FINALIZES (posts what it captured,
    /// runs the server judge) and flags the report "timed out — results may be incomplete", so a run
    /// is never left a silent void. Default 5 minutes; also settable in uxlint.toml as `timeout`
    /// (this flag wins). A stuck target can slow an audit, but it can never hang one. (Hosted,
    /// web-triggered audits use a fixed 1-minute browser cap this flag can't change — the finalize
    /// step always runs there too, so a funnel visitor always gets a report.) The old `deadline`
    /// flag name still works, as a hidden back-compat alias.
    #[arg(long = "timeout", alias = "deadline")]
    pub(crate) timeout: Option<u64>,
    /// Crawl budget: max pages discovered by following internal links from the seed
    /// routes. Crawling is how the graph is built — this caps it, never disables it.
    #[arg(long, default_value_t = 12)]
    pub(crate) crawl: usize,
    /// Concurrent worker browsers loading routes (1 = strictly serial). Default: 8 for
    /// local targets (your own dev server — full throttle), 4 for public hosts. The pool
    /// drops to serial automatically if the site answers 429/503 — politeness beats speed.
    #[arg(long)]
    pub(crate) parallel: Option<usize>,
    /// Skip the LLM judge tier (deterministic rules only) — fast CI runs for fixtures that
    /// don't assert judged findings.
    #[arg(long)]
    pub(crate) no_judge: bool,
    /// Skip tests: don't walk the site's declared [[tests]] (each is a full browser walk —
    /// the slowest part of an audit, and — server-side — a paid-plan feature). Use for the tight
    /// lint fix→re-audit loop, where only the deterministic/judged findings matter, not goal
    /// reachability.
    #[arg(long)]
    pub(crate) no_tests: bool,
    /// Check a SINGLE rule and turn the exit code into a pass/fail for it: 0 = clear, 1 = still
    /// fires. Scopes the printed output to just that rule and skips the goal-walk tests (they're
    /// irrelevant to one lint). This is the tight "did my fix land?" loop — pair with
    /// `--routes /pricing --crawl 0` to check one page in ~2s. e.g. `--rule contrast`.
    #[arg(long)]
    pub(crate) rule: Option<String>,
    /// Declare the site type (e.g. "saas") — overrides uxlint.toml site_type. Drives
    /// type-specific lints like pricing-page-missing.
    #[arg(long = "site-type")]
    pub(crate) site_type: Option<String>,
    /// The site this audit belongs to (host). Required unless uxlint.toml declares one (or the
    /// base host is a real public host). Falls back to the UXLINT_SITE env var.
    #[arg(long, env = "UXLINT_SITE")]
    pub(crate) site: Option<String>,
    /// The org that owns the site (for team sites). Falls back to UXLINT_ORG.
    #[arg(long, env = "UXLINT_ORG")]
    pub(crate) org: Option<String>,
    /// Label this report for later search (repeatable), e.g. `--label release --label pr-1284`.
    /// Normalized (lowercased/trimmed) and capped server-side.
    #[arg(long = "label")]
    pub(crate) labels: Vec<String>,
    /// Print the raw report JSON instead of the human summary (for the hosted door / CI)
    #[arg(long)]
    pub(crate) json: bool,
    /// Link to the change (a GitHub PR or commit URL) this audit covers — the report links out to
    /// it as "Change: …". Falls back to GitHub Actions' own env vars (GITHUB_REPOSITORY/_SHA/_REF)
    /// when omitted, so a CI run needs no extra config; still absent outside GitHub Actions.
    #[arg(long = "change-url")]
    pub(crate) change_url: Option<String>,
    /// Emit findings as an ordered fix plan (cheap-high-impact first) — a task list ready
    /// to paste into a coding agent's todo, grouped by page.
    #[arg(long = "fix-plan")]
    pub(crate) fix_plan: bool,
    /// Skip before/after fix previews. Previews are ON by default (independent of --no-judge): after
    /// the audit, each finding's element is re-opened, outlined in a screenshot, and fixable ones get
    /// the fix applied live and an "after" captured — this is what puts screenshots in the report.
    /// `UXLINT_NO_PREVIEWS` sets this for a whole harness run.
    #[arg(long = "no-previews")]
    pub(crate) no_previews: bool,
    /// CI mode: run the full CI flow. Starts the dev server from uxlint.toml
    /// [dev], waits until it's ready, runs the audit, then stops it — every other flag on this
    /// struct is ignored when this is set; uxlint.toml's [dev] section is authoritative for what
    /// and how to run. (`uxlint ci` still works too, as a hidden back-compat alias.)
    #[arg(long)]
    pub(crate) ci: bool,
    /// Privacy preview: capture the site EXACTLY as a real audit would, then, instead of uploading,
    /// write the precise POST body to a folder (`./uxlint-dry-run/` by default, or the path you
    /// give) — `request.json` plus each page's screenshot as a `.jpg` — and exit. Nothing is sent to
    /// the server. Use it to see exactly what would leave your machine before auditing a sensitive or
    /// authenticated site.
    #[arg(long = "dry-run", num_args = 0..=1, default_missing_value = "uxlint-dry-run")]
    pub(crate) dry_run: Option<String>,
    /// Don't send project provenance (git commit sha + branch, machine hostname, CI change link)
    /// with the report. Provenance is a convenience for telling runs apart in the dashboard; drop it
    /// if a branch name or hostname would itself be sensitive.
    #[arg(long = "no-provenance")]
    pub(crate) no_provenance: bool,
}

fn main() -> Result<()> {
    // Logging policy: OFF by default (a local `uxlint audit` stays quiet — the report is on stdout,
    // progress on stderr via note!). But when RUST_LOG IS set — the hosted worker forwards it — keep a
    // global INFO baseline and layer the operator's directives ON TOP, so a targeted filter like
    // `headless_chrome=debug` ADDS the CDP transport trace WITHOUT silencing everything else (job
    // progress, our own info logs). Mirrors the worker's own filter (audit-worker otel.rs). Set
    // `RUST_LOG=info,headless_chrome=debug` and you now get both; `headless_chrome=debug` alone also
    // keeps info, because the baseline below is unconditional whenever RUST_LOG is present.
    {
        let mut b = env_logger::Builder::new();
        match std::env::var("RUST_LOG") {
            Ok(spec) if !spec.trim().is_empty() => {
                b.filter_level(log::LevelFilter::Info);
                b.parse_filters(&spec);
            }
            _ => {
                b.filter_level(log::LevelFilter::Off);
            }
        }
        b.init();
    }
    let mut cli = Cli::parse();
    // An EMPTY key is no key. `UXLINT_API_KEY: ${{ secrets.UXLINT_API_KEY }}` with the secret unset
    // is an empty string, not an absent variable — and treating that as a credential sent the whole
    // run down the authenticated path with nothing to authenticate: a 401 from the server instead of
    // the sign-in link (or, in CI, instead of "set this secret"). Same for a blank `--api-key ""`.
    cli.api_key = normalise_key(cli.api_key.take());
    // A token saved by `uxlint auth login` is the fallback credential below --api-key / UXLINT_API_KEY.
    if cli.api_key.is_none() {
        cli.api_key = login::stored_credential();
    }
    // Best-effort "a newer uxlint exists" notice — never blocks, never fails the command,
    // silent in CI/non-tty/opted-out. Skipped only for the MCP stdio server: stdout there is the
    // JSON-RPC channel and progress.rs already routes ALL of its output through `Silent` for the
    // same reason, so an unsolicited stderr line has no reason to appear there either.
    if !matches!(cli.cmd, Cmd::Mcp { action: None, .. }) {
        update::maybe_print_update_notice();
    }
    match &cli.cmd {
        Cmd::Signup { email } => signup(&cli, email),
        Cmd::Auth { cmd } => match cmd {
            AuthCmd::Login { web } => login::run_login(web, &cli.server),
            AuthCmd::Logout => login::run_logout(),
            AuthCmd::Status => login::run_status(&cli.server),
        },
        Cmd::Audit(args) => {
            if args.ci {
                return run_ci(&cli);
            }
            // Stand up the trace exporter for the duration of the audit (no-op unless
            // OTEL_EXPORTER_OTLP_ENDPOINT is set). Held to the end of this arm so its drop flushes the
            // batched spans; `run_audit` opens the root `audit` span and its phase children under it.
            let _otel = otel::Session::start();
            // `--rule` is the tight fix-loop: only one lint matters, so the goal-walk tests (slow,
            // paid) are irrelevant — force them off regardless of what else was passed.
            let effective;
            let args = if args.rule.is_some() && !args.no_tests {
                effective = AuditArgs {
                    no_tests: true,
                    ..(**args).clone()
                };
                &effective
            } else {
                &**args
            };
            // Exit-code contract for `audit` (so CI can tell "graded, has issues" from "couldn't
            // grade"): 0 = graded clean, 1 = graded WITH errors (findings), 2 = couldn't grade at all
            // (a fatal: network/auth failure, or the server refused because every route was image-only).
            // The default `Result` bubble would exit 1 on a fatal too, colliding with the has-findings
            // signal — so map an audit fatal to 2 explicitly here.
            let report = match run_audit(&cli, args, &crate::progress::Stderr) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {e:?}");
                    std::process::exit(2);
                }
            };
            // A dry run POSTed nothing and returns only a marker — `run_audit` already printed where
            // it wrote the payload; there's no report to summarize and no findings to exit on.
            if args.dry_run.is_some() {
                if args.json {
                    println!("{report}");
                }
                return Ok(());
            }
            // `--rule`: scope output to that one rule and exit 0 (clear) / 1 (still fires) — the
            // "did my fix land?" check. Replaces the normal summary + errors-based exit.
            if let Some(rule) = args.rule.as_deref() {
                return check_rule(&report, rule);
            }
            if args.json {
                println!("{report}");
            } else if args.fix_plan {
                print_fix_plan(&report);
            } else {
                print_report(&report);
            }
            if report["errors"].as_u64().unwrap_or(0) > 0 {
                std::process::exit(1);
            }
            Ok(())
        }
        Cmd::Mcp { action, base } => match action {
            None => run_mcp(&cli, base.clone()),
            Some(McpCmd::Install { tool, name }) => mcp_install::install(tool.as_deref(), name),
            Some(McpCmd::Uninstall { tool, name }) => mcp_install::uninstall(tool.as_deref(), name),
        },
        Cmd::Diff { report_id } => run_diff(&cli, report_id),
        Cmd::Test(args) => run_test_command(&cli, args.as_ref(), &crate::progress::Stderr),
        Cmd::Init {
            org,
            site,
            routes,
            url,
            web,
            offline,
        } => init::run_init(
            &cli,
            &init::InitArgs {
                org: org.clone(),
                site: site.clone(),
                routes: routes.clone(),
                url: url.clone(),
                web: web.clone(),
                offline: *offline,
            },
        ),
        Cmd::Site { action } => match action {
            SiteCmd::Create { host, org } => site::create(&cli, host, org.as_deref()),
            SiteCmd::Delete { host, org } => site::delete(&cli, host, org.as_deref()),
            SiteCmd::List => site::list(&cli),
            SiteCmd::AddUser {
                host,
                email,
                role,
                org,
            } => site::add_user(&cli, host, email, role, org.as_deref()),
            SiteCmd::RemoveUser { host, email, org } => {
                site::remove_user(&cli, host, email, org.as_deref())
            }
        },
        Cmd::Ci => run_ci(&cli),
        Cmd::DocsJson => {
            use clap::CommandFactory;
            // Introspect the very command tree clap just parsed against — the reference is the
            // binary's own truth, so `--help` and the docs site can never disagree.
            println!(
                "{}",
                serde_json::to_string_pretty(&docs_json::emit(&Cli::command()))?
            );
            Ok(())
        }
        Cmd::Update { check, to } => update::run_update(*check, to.as_deref()),
        Cmd::Feedback {
            widget_set,
            url,
            note,
        } => {
            let resp = reqwest::blocking::Client::new()
                .post(format!("{}/v1/feedback/widgets", cli.server))
                .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
                .json(&json!({ "widget_set": widget_set, "url": url, "note": note }))
                .send()?;
            anyhow::ensure!(
                resp.status().is_success(),
                "feedback failed: {}",
                resp.status()
            );
            println!("recorded — thanks, this feeds the widget-recognition corpus");
            Ok(())
        }
    }
}

/// An EMPTY credential is no credential.
///
/// `UXLINT_API_KEY: ${{ secrets.UXLINT_API_KEY }}` with the secret unset is an empty STRING, not an
/// absent variable, and clap hands it over as `Some("")`. Taking that at face value sent the run down
/// the authenticated path with nothing to authenticate — a 401 from the server rather than the
/// sign-in link, or in CI rather than "that secret isn't set". Same for `--api-key ""` and for a
/// value that is nothing but whitespace.
fn normalise_key(k: Option<String>) -> Option<String> {
    k.filter(|k| !k.trim().is_empty())
}

#[cfg(test)]
mod key_tests {
    use super::normalise_key;

    #[test]
    fn an_empty_or_blank_key_is_no_key() {
        // The CI shape that found this: a secret that isn't set expands to "", and clap reports
        // Some(""), so every downstream check thought we were signed in.
        assert_eq!(normalise_key(Some(String::new())), None);
        assert_eq!(normalise_key(Some("   ".into())), None);
        assert_eq!(normalise_key(None), None);
    }

    #[test]
    fn a_real_key_is_left_exactly_as_given() {
        assert_eq!(
            normalise_key(Some("uxt_abc123".into())),
            Some("uxt_abc123".into())
        );
    }
}
