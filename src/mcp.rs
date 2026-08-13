//! MCP stdio mode: the audit_url / lint_feedback tools for agent callers.
//!
//! Uses the official `rmcp` async server over stdio. Every blocking call (`run_audit`, the
//! `reqwest::blocking` feedback POSTs) runs on `tokio::task::spawn_blocking` so a multi-minute
//! crawl never starves the stdio transport and the caller's connection stays alive.

use std::sync::Arc;

use base64::Engine;
use serde_json::{json, Value};

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, ContentBlock, Meta, ProgressNotificationParam, ServerCapabilities,
        ServerInfo,
    },
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError, Peer, RoleServer, ServerHandler, ServiceExt,
};

use crate::audit::{run_audit, run_audit_ext};
use crate::{AuditArgs, Cli};

/// Percent-encode a route for a query value (keeps `/` readable — it's legal in a query).
fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// The report_id from a report URL — the segment after the last `/r/` (works for the private
/// `/sites/{site}/r/{id}` form and the legacy `/r/{id}` one).
fn report_id_of(report: &Value) -> &str {
    report["report_url"]
        .as_str()
        .unwrap_or("")
        .rsplit_once("/r/")
        .map(|(_, b)| b.split(['/', '?']).next().unwrap_or(b))
        .unwrap_or("")
}

/// The annotated-screenshot URL for a finding (the flagged element boxed on its page), when it has a
/// rect. Points at the server's public-by-report-id /annot endpoint.
fn shot_url(
    server: &str,
    report_id: &str,
    route: &str,
    viewport: &str,
    rect: &Value,
) -> Option<String> {
    let r = rect.as_array()?;
    if r.len() != 4 {
        return None;
    }
    let coords = r
        .iter()
        .map(|v| format!("{:.0}", v.as_f64().unwrap_or(0.0)))
        .collect::<Vec<_>>()
        .join(",");
    Some(format!(
        "{}/r/{report_id}/annot?route={}&viewport={viewport}&rect={coords}",
        server.trim_end_matches('/'),
        pct(route)
    ))
}

/// The machine-readable half of an audit_url result: report identity, counts, and every finding with
/// its location, fix, and the annotated screenshot URL — so a caller never re-parses the text or
/// hunts through report JSON for images.
fn audit_structured(report: &Value, server: &str) -> Value {
    let report_id = report_id_of(report);
    let empty = vec![];
    let mut findings = Vec::new();
    for page in report["pages"].as_array().unwrap_or(&empty) {
        let route = page["route"].as_str().unwrap_or("");
        let viewport = page["viewport"].as_str().unwrap_or("");
        for f in page["findings"].as_array().unwrap_or(&empty) {
            let edit = f["marks"].as_array().and_then(|ms| {
                ms.iter().find_map(|m| {
                    (m["t"].as_str() == Some("rewrite"))
                        .then(|| json!({"from": m["from"], "to": m["to"]}))
                })
            });
            findings.push(json!({
                "rule": f["rule"], "severity": f["severity"], "route": route, "viewport": viewport,
                "message": f["msg"], "fix": f["fix"], "best_practice": f["best_practice"],
                "selector": f["sel"], "source": f["source"],
                "rect": f["rect"], "edit": edit,
                "screenshot_url": shot_url(server, report_id, route, viewport, &f["rect"]),
            }));
        }
    }
    let summary = &report["summary"];
    json!({
        "report_url": report["report_url"], "report_id": report_id,
        "grade": summary["grade"], "score": summary["score"], "verdict": summary["verdict"],
        "counts": { "errors": report["errors"], "warnings": report["warnings"], "info": report["infos"] },
        "styleguide": report["styleguide"],
        // True when the browser-phase cap fired — the audit is honestly incomplete. `timeout`
        // carries what was cut (planned vs. captured pages, planned vs. finished walks). Absent/false
        // on a clean run, so a caller can trust the finding set is complete.
        "timed_out": report["timed_out"].as_bool().unwrap_or(false),
        "timeout": report["timeout_detail"],
        "findings": findings,
        "dry": report["source_dry"],
        // Cross-audit delta vs the previous comparable crawl (resolved/new/persisting + samples);
        // null when there's no comparable prior audit to diff against.
        "delta": report["delta"],
    })
}

/// Compact end-of-result nudge — appended to the PROSE half only (never the structured JSON the
/// caller parses), and only when there were findings to react to. The CALLER gates this on
/// `self.feedback_enabled` — absent entirely on a project that hasn't opted in, since the `lint_feedback`
/// tool it points at isn't even in that project's tool list. Keep this short: it rides every
/// audit_url/verify_fix reply's token bill.
fn feedback_solicitation(report_id: &str, rules: &[String]) -> String {
    format!(
        "\nReply per rule via lint_feedback (kind=verdict; verdict useful / not_useful; harmful if it'd \
         worsen the UX — not_useful and harmful also need a one-line `note` saying what fired and why \
         it's wrong) — report_id {report_id}: {}. Spotted a lint uxlint is missing, or a way an \
         existing one could be better? Call lint_feedback (kind=suggestion) — general, \
         application-agnostic terms only, never your app's specifics.\n",
        rules.join(", ")
    )
}

/// The bar a negative verdict's `note` must clear. This MIRRORS the server's `substantive_reason`
/// (`server/src/feedback.rs`) — a clause, not a token: "wrong", "n/a" and a single long
/// hyphenated-token teach a rule nothing, so length alone isn't the test. Keep the two in step:
/// a LOOSER bar here is worse than no check at all, because it waves through a note the server then
/// refuses, and the agent gets told the rule twice with two different answers.
const MIN_REASON_CHARS: usize = 20;
const MIN_REASON_WORDS: usize = 4;
fn substantive_reason(note: &str) -> bool {
    let note = note.trim();
    note.chars().count() >= MIN_REASON_CHARS && note.split_whitespace().count() >= MIN_REASON_WORDS
}

/// `Some(explanation)` when a verdict is negative and its `note` doesn't explain it. A
/// false_positive/harmful verdict without prose can't be turned into a guard — we'd know a rule is
/// wrong but not which element it hit or why — so the server refuses it. Checking here too means the
/// agent is told WHAT to write while it still has the context, instead of spending a round trip to
/// be handed a status code. A positive verdict needs nothing: "it was right" is the whole signal.
fn missing_verdict_reason(verdict: &LintVerdict, note: &str) -> Option<String> {
    if !matches!(verdict, LintVerdict::FalsePositive | LintVerdict::Harmful)
        || substantive_reason(note)
    {
        return None;
    }
    // Same two asks the server's 400 makes, so an agent that hits either gate reads one requirement.
    let what = match verdict {
        LintVerdict::Harmful => {
            "what you changed because of the finding and HOW that made the UX worse (which users, \
             which flow)"
        }
        _ => "why the rule is wrong on that element — what it missed that makes this correct as-is",
    };
    Some(format!(
        "feedback failed: a \"{}\" verdict needs a `note` of at least {MIN_REASON_CHARS} \
         characters — name what fired (the rule and the element/selector it hit), then {what}. The \
         note is the only thing that can fix the rule, so a bare negative verdict is refused and \
         NOT recorded. General, application-agnostic terms only.",
        verdict.as_str()
    ))
}

/// A failed feedback POST, rendered for the AGENT that made it. The server's 4xx body carries the
/// actionable part (e.g. exactly what a negative verdict's reason must contain) — a bare "400 Bad
/// Request" just gets the same call retried blind, so relay the `error` field when there is one.
fn failure_text(r: reqwest::blocking::Response) -> String {
    let status = r.status();
    let detail = r
        .text()
        .ok()
        .and_then(|b| serde_json::from_str::<Value>(&b).ok())
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_default();
    if detail.is_empty() {
        format!("feedback failed: {status}")
    } else {
        format!("feedback failed ({status}): {detail}")
    }
}

/// Shown when the MCP server has no API key — the common first-run state for someone who just
/// installed uxlint from a marketplace. A clean, agent-relayable onboarding funnel beats the raw
/// 401 JSON the server would otherwise surface.
fn signup_hint(server: &str) -> String {
    crate::login::credential_help(server, crate::login::CredentialProblem::Missing, true)
}

/// The project directory's name — the site suggestion for an app that isn't deployed yet
/// (`myapp.local`), so the agent has a concrete value to put in the file rather than a blank.
fn project_dir_name() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "app".to_string())
}

/// The uxlint.toml an agent should write for a project that has none. `audit_url` returns this
/// INSTEAD of the audit when there is nothing to file a report under (a localhost base with no
/// declared site is a hard error deep in `resolve_target`, whose CLI-shaped "run `uxlint init`"
/// advice an agent can't act on — `init` is an interactive wizard), and ALONGSIDE it when the audit
/// could still run unpinned. That file is the project's IDENTITY: without it a report is auto-filed
/// under a personal-org site named after whatever host was audited, so nothing accumulates — no
/// history, no cross-audit delta — and none of the project's checked-in routes/excludes/personas/
/// tests apply.
///
/// Values the account can settle (which orgs exist, which sites they already have) come from
/// `/v1/me` so the agent writes a config that VALIDATES instead of guessing an org name and being
/// bounced by `prevalidate_org` on the next call. Pure over that payload, so the wording is testable
/// without a server.
fn project_setup_instructions(
    base: &str,
    me: Option<&Value>,
    dir: &str,
    blocked: bool,
    existing_file: bool,
) -> String {
    let orgs_json = me.and_then(|m| m["orgs"].as_array());
    let orgs: Vec<&str> = orgs_json
        .map(|a| a.iter().filter_map(|o| o["name"].as_str()).collect())
        .unwrap_or_default();
    let hosts: Vec<&str> = orgs_json
        .map(|a| {
            a.iter()
                .flat_map(|o| o["sites"].as_array().map(|s| s.as_slice()).unwrap_or(&[]))
                .filter_map(|s| s["host"].as_str())
                .collect()
        })
        .unwrap_or_default();

    // Name the real orgs rather than a placeholder: an org this account isn't a member of fails the
    // NEXT audit before the crawl, which reads as the tool being broken twice.
    let org_line = match orgs.as_slice() {
        [only] => format!("org = {only:?}   # the only org on this account"),
        [] => "org = \"…\"   # ASK THE USER which org owns this project".to_string(),
        many => format!(
            "org = {:?}   # ASK THE USER which of these it belongs to: {}",
            many[0],
            many.join(", ")
        ),
    };
    // A public base already names the site; a local one can't, which is exactly why the audit
    // couldn't run — suggest a stable `<project>.local` and say what the name is FOR.
    let local = crate::project::is_local_target(base);
    let host = crate::project::base_host(base);
    let suggested = if !local && !host.is_empty() {
        host.clone()
    } else {
        format!("{dir}.local")
    };
    let reuse = if hosts.is_empty() {
        String::new()
    } else {
        format!(
            "\n# This account already has: {} — reuse one of those if this project is it.",
            hosts.join(", ")
        )
    };

    let head = if blocked {
        let why = if existing_file {
            "this project's uxlint.toml declares no `org`/`site`"
        } else {
            "this project has no uxlint.toml"
        };
        format!(
            "SETUP REQUIRED — the audit did NOT run: {why}, and a local target ({base}) has no public \
             hostname to file a report under. The site name is the one thing that has to be checked in.\n\n"
        )
    } else {
        format!(
            "NO uxlint.toml — this project isn't pinned to a uxlint site, so the report below was \
             auto-filed under a personal-org site for {host} and none of the project's own defaults \
             (routes, excludes, sign-in personas, tests) applied. Pin it so audits accumulate and \
             each one diffs against the last.\n\n"
        )
    };

    format!(
        "{head}\
         CREATE uxlint.toml in the repo root and check it in. Read the codebase for what you can \
         know (the router for `routes`, the deploy config/README for the hostname) and ASK THE USER \
         for the rest — don't invent a value you could look up. Replace every `…`:\n\n\
         # uxlint.toml — this project's identity on uxlint (check this in).\n\
         {org_line}\n\n\
         # Where this project's reports file, for good: the app's PRODUCTION hostname if it has one,\n\
         # else <project>.local while it isn't deployed. Pick it deliberately — the history hangs off\n\
         # this name.{reuse}\n\
         site = {suggested:?}\n\n\
         # CREATE THE SITE FIRST if it isn't one of the existing hosts above — a site is made\n\
         # deliberately, by its owner, not as a side effect of an audit. ASK THE USER to run:\n\
         #   uxlint site create {suggested}\n\n\
         # The default audit target (audit_url's `base` still overrides it), and the real top-level\n\
         # routes from the router/pages dir — 3-8 a visitor actually lands on; the crawl follows\n\
         # links from these. `crawl` caps pages per audit (0 = only the routes below).\n\
         base = {base:?}\n\
         routes = [\"/\"]   # …and the rest\n\
         crawl = 12\n\n\
         Optional — add one only when it applies, never as a guess:\n  \
         site_type = \"saas\"          # saas | marketing | ecommerce | content | portfolio | aggregator\n  \
         styleguide = \"/styleguide\"  # the design-system page, if this project has one\n  \
         exclude = [\"/admin/*\"]      # routes the audit must never open (demos, fixtures, destructive tools)\n  \
         desktop_only = [\"/editor/*\"] # desktop-primary surfaces, so mobile findings there stay info-level\n\n\
         If the app is behind a login, add a persona — the local client replays it, so no secret \
         reaches this tool or the transcript. Ask the user for the credential; a real secret goes in \
         a gitignored .env as ${{VAR}}, only a throwaway dev login is ever inlined:\n\n  \
         login_url       = \"/login\"\n  \
         default_persona = \"user\"\n  \
         [personas.user]\n  \
         username = \"dev@example.com\"\n  \
         password = \"${{DEV_PW}}\"\n\n\
         `feedback = true` opts this project into sharing anonymized signals about which lints helped \
         (never your app's content). It is OFF by default — ask the user before setting it.\n\n\
         Then call audit_url again: the report files under that site, and every later audit diffs \
         against it.\n"
    )
}

/// `Some(instructions)` when uxlint.toml names an org/site this account doesn't have — the audit must
/// NOT run. Left to itself the server would mint the site on the spot (the never-orphan-a-report
/// rule): the report lands somewhere real, but under a site nobody chose, in whatever org the
/// fallback picked. A site is a deliberate thing its owner creates, so the agent gets the one CLI
/// command that creates it instead of a report filed against a name that appeared by accident.
///
/// FAIL OPEN on anything less than a clear answer — an unreachable or signed-out `/v1/me` (`None`,
/// or `authenticated != true`) leaves this quiet and lets the audit and the server's own guardrail
/// decide. Pure over the payload; `org`/`site` come from the project config.
fn missing_site_instructions(org: &str, site: &str, me: Option<&Value>) -> Option<String> {
    let me = me?;
    if me["authenticated"].as_bool() != Some(true) {
        return None;
    }
    let orgs = me["orgs"].as_array()?;
    let hosts_of = |o: &Value| -> Vec<String> {
        o["sites"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s["host"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let Some(found) = orgs.iter().find(|o| {
        o["name"]
            .as_str()
            .is_some_and(|n| n.eq_ignore_ascii_case(org))
    }) else {
        // The org itself is wrong — creating the site can't help until that's settled, and only the
        // user knows which of their orgs this project belongs to.
        let yours: Vec<&str> = orgs.iter().filter_map(|o| o["name"].as_str()).collect();
        return Some(format!(
            "ORG NOT FOUND — the audit did NOT run. This project's uxlint.toml files reports under org {org:?}, \
             which this account isn't a member of. ASK THE USER which of their orgs this project belongs to \
             ({}) and set `org` in uxlint.toml to it, then call audit_url again.",
            if yours.is_empty() { "none on this account".to_string() } else { yours.join(", ") }
        ));
    };
    let hosts = hosts_of(found);
    if hosts.iter().any(|h| h == site) {
        return None;
    }
    let existing = if hosts.is_empty() {
        format!("Org {org:?} has no sites yet.")
    } else {
        format!("Sites org {org:?} already has: {}.", hosts.join(", "))
    };
    Some(format!(
        "SITE NOT SET UP — the audit did NOT run. This project's uxlint.toml files its reports under site \
         {site:?} in org {org:?}, and that site doesn't exist. Creating one is a deliberate act by its \
         owner, not a side effect of an audit — otherwise this report would land under a site name nobody \
         chose and the project's history would start in the wrong place.\n\n\
         ASK THE USER to create it:\n  uxlint site create {site} --org {org:?}\n\n\
         {existing} If one of those IS this project, point `site` in uxlint.toml at it instead — that's \
         the better fix, since a second name for the same app splits its history in two.\n\n\
         Then call audit_url again."
    ))
}

/// Shown when the server REFUSED a key we did send — a revoked token, not a missing one. Distinct
/// wording matters here: an agent told "uxlint isn't signed in yet" will walk the user through
/// first-run setup they already did, when what actually happened is that their credential was
/// invalidated and has to be replaced.
fn credential_rejected(server: &str) -> String {
    crate::login::credential_help(server, crate::login::CredentialProblem::Rejected, true)
}

// ── Tool input schemas ────────────────────────────────────────────────────────
// Field descriptions live in `///` doc comments (schemars reads them into the JSON Schema).
// Defaults are `#[serde(default)]` + `Option<T>`, applied with `.unwrap_or(...)` in the handler
// to match the previous hand-rolled `as_bool().unwrap_or(...)` / `as_u64().unwrap_or(...)` logic.

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct AuditUrlArgs {
    /// Base URL to audit — an ORIGIN like http://localhost:5173, NOT a path (a path gets appended to
    /// every route and mis-crawls). Optional: omit to use the `base` in the project's uxlint.toml.
    #[serde(default)]
    base: Option<String>,
    /// Comma-separated routes (default /)
    #[serde(default)]
    routes: Option<String>,
    /// Drive hover/focus/keyboard interaction states — catches dead hover styles, hover-only content unreachable by touch/keyboard, illogical focus order, keyboard traps, form-validation gaps. ON by default; set false to skip it (faster) on large public crawls.
    #[serde(default)]
    states: Option<bool>,
    /// Run the AI copy/design judge (prose quality, test-run navigation). ON by default; set false for a fast, deterministic-only pass while iterating.
    #[serde(default)]
    judge: Option<bool>,
    /// Max routes to discover and audit from the seeds (default 12). Set 0 to audit only the given routes.
    #[serde(default)]
    crawl: Option<u64>,
    /// Run the site's declared tests (whole-site reachability). ON by default; auto-scoped to crawling audits. Set false to skip for speed. Tests are a paid-plan feature — on a free plan, tests declared but not run print a one-line skip warning instead.
    #[serde(default)]
    tests: Option<bool>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct UxGuidanceArgs {
    /// Which area to get guidance for: layout, forms, lists, navigation, components, performance,
    /// accessibility, content. Omit for the index of topics; "all" for everything. Accepts aliases
    /// (copy, nav, a11y, perf, dry, …) and falls back to the index for anything unrecognized.
    #[serde(default)]
    topic: Option<String>,
}

// ONE feedback tool, ONE kind field — `lint_feedback` and `report_widget_gap` (plus the new
// suggestion capability) all live behind this single struct/enum pair now. Which fields matter
// depends on `kind`; unused ones are simply ignored by the handler (schemars can't express
// per-variant-required across one flat struct, so the handler validates at runtime and returns a
// plain-text error — same as any other bad-args case here).
#[derive(serde::Deserialize, schemars::JsonSchema)]
struct FeedbackArgs {
    /// Which signal this is: verdict, suggestion, or widget_gap — see the tool description.
    kind: FeedbackKind,
    /// verdict: the finding's RULE name, e.g. panel-widths, contrast. suggestion: OPTIONAL — name
    /// the existing rule you're proposing an improvement to; omit for a wholly missing lint.
    /// widget_gap: unused.
    #[serde(default)]
    rule: Option<String>,
    /// verdict only, REQUIRED: beneficial (alias useful) = a real issue worth fixing; false_positive
    /// (alias not_useful) = fired but not a problem here; harmful = following it would worsen the UX.
    #[serde(default)]
    verdict: Option<LintVerdict>,
    /// verdict only: the report the finding came from, if known.
    #[serde(default)]
    report_id: Option<String>,
    /// verdict only: the finding's selector, if known.
    #[serde(default)]
    selector: Option<String>,
    /// verdict: REQUIRED for false_positive / harmful — a sentence naming what fired (rule + the
    /// element it hit) and why it's wrong there, or, for harmful, how acting on it made the UX
    /// worse. This is the only thing that can fix the rule, so a reasonless negative is REFUSED.
    /// Optional for beneficial. suggestion, REQUIRED: the missing lint or the improvement. In
    /// GENERAL, application-agnostic terms — never your app's names, content, routes, data, or
    /// screenshots.
    #[serde(default)]
    note: Option<String>,
    /// widget_gap only, REQUIRED: name of the widget set, e.g. framework7, kendo, devextreme.
    #[serde(default)]
    widget_set: Option<String>,
    /// widget_gap only: site where it was seen.
    #[serde(default)]
    url: Option<String>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum FeedbackKind {
    /// Was a lint finding worth it? (rule + verdict)
    Verdict,
    /// A lint uxlint is missing, or how an existing one could be improved (free-text note).
    Suggestion,
    /// An unrecognized widget set / component library (widget_set).
    WidgetGap,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum LintVerdict {
    /// "useful" is an accepted alias — the short verdict the report solicitation asks for.
    #[serde(alias = "useful")]
    Beneficial,
    /// "not_useful" is an accepted alias — the short verdict the report solicitation asks for.
    #[serde(alias = "not_useful")]
    FalsePositive,
    Harmful,
}

impl LintVerdict {
    fn as_str(&self) -> &'static str {
        match self {
            LintVerdict::Beneficial => "beneficial",
            LintVerdict::FalsePositive => "false_positive",
            LintVerdict::Harmful => "harmful",
        }
    }
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct VerifyFixArgs {
    /// Base URL — an ORIGIN like http://localhost:5173, NOT a path. Optional: omit to use the `base`
    /// in the project's uxlint.toml.
    #[serde(default)]
    base: Option<String>,
    /// The route to check, e.g. /pricing (default /)
    #[serde(default)]
    route: Option<String>,
    /// The rule to verify is gone, e.g. contrast, tap-target, unlabelled-field
    rule: String,
    /// Drive interaction states (needed for state/form/interaction rules)
    #[serde(default)]
    states: Option<bool>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct GetShotArgs {
    /// The `screenshot_url` from an audit_url / verify_fix finding — the annotated shot with the
    /// flagged element boxed. A full URL or a `/r/…` path on your uxlint server.
    screenshot_url: String,
}

/// Resolve the base URL for a tool call: an explicit per-call `base` wins (a blank one is treated as
/// absent), then the server's launch `--base` (`default_base`), then empty — and an empty base lets
/// `run_audit` fall back to the uxlint.toml `base`. Shared by audit_url and verify_fix so the
/// precedence is defined once.
fn resolve_base(call: Option<String>, default: Option<&str>) -> String {
    call.filter(|b| !b.trim().is_empty())
        .or_else(|| default.map(str::to_string))
        .unwrap_or_default()
}

// ── MCP stdio server ──────────────────────────────────────────────────────────
// One tool set: audit_url and friends. This is how a coding agent gets design taste: call the
// tool, read the findings, apply the fixes, call again until green.
#[derive(Clone)]
pub(crate) struct UxlintMcp {
    cli: Arc<Cli>,
    tool_router: ToolRouter<Self>,
    /// The project's opt-in to sharing feedback signals (`feedback = true` in uxlint.toml;
    /// default FALSE). Drives both the `lint_feedback` tool's presence (removed from the router entirely
    /// in `new` when this is false — see `ToolRouter::remove_route`) and whether the report-nudge
    /// text ever mentions it.
    feedback_enabled: bool,
    /// Default base URL from `uxlint mcp --base <url>` at launch. Slots BETWEEN a per-call `base`
    /// (which wins) and the uxlint.toml `base` fallback, so an agent can point the server at the
    /// site under review without repeating the URL on every tool call. `None` when not launched with
    /// one (empty is normalised to None in `run_mcp`).
    default_base: Option<String>,
}

#[tool_router(router = tool_router)]
impl UxlintMcp {
    fn new(cli: Arc<Cli>, default_base: Option<String>) -> Self {
        let feedback_enabled = crate::project::project_feedback_enabled();
        let mut tool_router = Self::tool_router();
        // Off by default and not exposed at all when off. `remove_route` drops the route from
        // the macro-generated router that BOTH `list_tools` and `call_tool` go through, so this one
        // call hides the tool from discovery AND rejects a call to it — no second enforcement point
        // to keep in sync.
        if !feedback_enabled {
            // Must match the tool's registered name (set explicitly via `#[tool(name = "lint_feedback")]`),
            // NOT the fn name — a stale "feedback" here would silently no-op and EXPOSE the tool to a
            // project that never opted in.
            tool_router.remove_route("lint_feedback");
        }
        Self {
            cli,
            tool_router,
            feedback_enabled,
            default_base,
        }
    }

    #[tool(
        description = "Audit a website's UX/design: contrast, tap targets, type scale, colour discipline, copy clarity, scan patterns. Each finding returns its RULE name (pass it to verify_fix), a SOURCE file:line hint (for local audits, grepped from the project you're in), the SELECTOR, the concrete FIX, and — for copy issues — the exact text EDIT (replace X with Y).\n\nWORKFLOW: (1) Before you change anything, call ux_guidance for the area(s) the findings touch (forms, lists, layout, copy, …) so you fix toward the idiomatic, DRY pattern — not a one-off patch. If the result names a STYLEGUIDE, open it first and build to the components/tokens it shows. (2) Open the source line and apply the SMALLEST fix that reuses the project's existing components/tokens and voice (don't add a new one-off to silence the finding) without regressing the quality floor — responsive, visible keyboard focus, reduced motion, no new layout shift — then verify_fix. (3) For EACH finding you act on, call lint_feedback with a verdict — beneficial, false_positive, or harmful — so uxlint learns which rules to keep, tune, or retire. Iterate until green.\n\nSAFETY: with no test plan declared, audit_url only NAVIGATES and READS. If the project's uxlint.toml declares tests that sign in as a persona, running them may SUBMIT forms and DELETE items on the target — that's what a test does (it exercises create/delete flows on your own app). Point it only at an app you own / a throwaway env, never a site you don't control.\n\nSETUP: in a project with no uxlint.toml, this returns the exact config to write first (org/site/base/routes) — write that file, check it in, then call again. Without it a local target can't be audited at all and a public one files its report under a site nobody chose.\n\nAUTH: for a logged-in site, DON'T pass secrets here — credentials come from the project's uxlint.toml [personas] (the local client replays them; nothing touches this tool call or the transcript). If the audit hits a login wall, this tool returns the exact setup instructions."
    )]
    async fn audit_url(
        &self,
        Parameters(a): Parameters<AuditUrlArgs>,
        meta: Meta,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if self.cli.api_key.is_none() {
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                signup_hint(&self.cli.server),
            )]));
        }
        let base = resolve_base(a.base, self.default_base.as_deref());
        // An unpinned project is the fresh-install failure: with no `org`/`site` checked in, a local
        // base has no site to file under (a hard error the agent reads as "the tool is broken") and a
        // public one mints a personal-org site nobody chose. Both are the same missing file, so hand
        // the agent the config to write — with the account's REAL orgs/sites in it — rather than an
        // error whose only advice is an interactive wizard it can't drive.
        // A PINNED project has the opposite failure: it names a site, and if that site doesn't exist
        // the server quietly creates it (no report is ever orphaned) — so a typo, or a name the user
        // never agreed to, silently becomes where this project's history lives. Both cases need the
        // same one `/v1/me`, so ask once and let the answer decide.
        let project = crate::project::project_config();
        let cli = self.cli.clone();
        let me = tokio::task::spawn_blocking(move || crate::audit::setup::fetch_me(&cli))
            .await
            .map_err(|e| McpError::internal_error(format!("setup probe panicked: {e}"), None))?;
        let me = match me {
            // A key the server REFUSED is the truer problem: setup advice would send the agent to fix
            // the wrong thing, and the next call would fail exactly the same way.
            Err(_) => {
                return Ok(CallToolResult::success(vec![ContentBlock::text(
                    credential_rejected(&self.cli.server),
                )]))
            }
            Ok(me) => me,
        };
        let setup_prefix = match &project {
            Some(p) => {
                if let Some(advice) = missing_site_instructions(&p.org, &p.site, me.as_ref()) {
                    return Ok(CallToolResult::success(vec![ContentBlock::text(advice)]));
                }
                None
            }
            None => {
                // No base at all is the same bind as a local one: nothing to name a site after
                // (`run_audit` would fall back to the toml `base` that doesn't exist either).
                let blocked = base.trim().is_empty() || crate::project::is_local_target(&base);
                let text = project_setup_instructions(
                    &base,
                    me.as_ref(),
                    &project_dir_name(),
                    blocked,
                    crate::project::find_project_toml().is_some(),
                );
                // Blocked: the audit cannot produce a report, so the instructions ARE the answer.
                // Otherwise it still runs, and they ride along as a prefix.
                if blocked {
                    return Ok(CallToolResult::success(vec![ContentBlock::text(text)]));
                }
                Some(text)
            }
        };
        let args = AuditArgs {
            base,
            routes: a.routes.unwrap_or_else(|| "/".to_string()),
            viewports: "desktop:1440x900,mobile:390x844".into(),
            // Auth (if any) comes from uxlint.toml [personas], never from the MCP call —
            // secrets stay out of the tool args and the transcript.
            headers: Vec::new(),
            storage: Vec::new(),
            login_url: None,
            username: None,
            password: None,
            // Interaction states ON by default for the MCP: an agent auditing its own UI
            // should get the hover/focus/keyboard checks without asking. Explicit false skips.
            states: a.states.unwrap_or(true),
            crawl: a.crawl.unwrap_or(12) as usize,
            parallel: None, // auto: full throttle locally, polite on public hosts
            probe_errors: false,
            resilience: false,
            slow_network: false,
            timeout: None,
            fix_plan: false,
            no_previews: true,
            // Judge/tests default ON (an agent auditing its own UI wants the full picture),
            // but both are switchable so the fast deterministic pass I reach for is one call.
            no_judge: !a.judge.unwrap_or(true),
            // Goals auto-scope (a crawling audit runs them, a targeted one skips) and run in
            // parallel; `tests:false` forces them off entirely for speed.
            no_tests: !a.tests.unwrap_or(true),
            rule: None,
            site_type: None,
            org: None,
            site: None,
            labels: Vec::new(),
            json: false,
            change_url: None,
            ci: false,
            dry_run: None,
            no_provenance: false,
        };
        let cli = self.cli.clone();
        // MCP progress notifications: rmcp 2.2.0 DOES support `notifications/progress` — a
        // client that wants them sends a `progressToken` in the tool call's `_meta`; `meta` above is
        // exactly that (rmcp hands it to any #[tool] method that asks for it, via `FromContextPart`).
        // When one is present, poll the audit's shared progress state (the same crawl/walks/phase
        // counters the hosted partial payload uses) and forward it as `notifications/progress` while
        // the blocking audit runs, so a caller that opted in sees live counts instead of a silent
        // multi-minute wait. A caller that doesn't send a token gets no notifications (this whole
        // branch is skipped) but the audit itself is unaffected either way.
        let progress_token = meta.get_progress_token();
        let partial = progress_token
            .is_some()
            .then(|| Arc::new(crate::worker::PartialState::default()));
        let partial_for_audit = partial.clone();
        let mut audit_task = tokio::task::spawn_blocking(move || {
            run_audit_ext(&cli, &args, &crate::progress::Silent, partial_for_audit)
        });
        let report = if let (Some(token), Some(partial)) = (progress_token, partial) {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let (pages_done, pages_total, walks_done, walks_total, phase) = partial.snapshot();
                        let (done, total, message) = if phase == "walks" && walks_total > 0 {
                            (walks_done as f64, walks_total as f64, format!("tests: {walks_done}/{walks_total}"))
                        } else if pages_total > 0 {
                            let label = if phase.is_empty() { "crawl".to_string() } else { phase.clone() };
                            (pages_done as f64, pages_total as f64, format!("{label}: {pages_done}/{pages_total} pages"))
                        } else {
                            continue;
                        };
                        let _ = client
                            .notify_progress(ProgressNotificationParam::new(token.clone(), done).with_total(total).with_message(message))
                            .await;
                    }
                    res = &mut audit_task => break res,
                }
            }
        } else {
            (&mut audit_task).await
        }
        .map_err(|e| McpError::internal_error(format!("audit task panicked: {e}"), None))?;
        let mut structured = Value::Null;
        let text = match report {
            Ok(report) => {
                let mut t = String::new();
                if let Some(blocked) = report["auth_blocked_routes"].as_array() {
                    let routes: Vec<&str> = blocked
                        .iter()
                        .filter_map(|r| r.as_str())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !routes.is_empty() {
                        t.push_str(&format!(
                        "AUTH WALL DETECTED on: {}. Only the public/login view was audited.\n\
                         To audit the authenticated app, set up credentials in the project's uxlint.toml \
                         — the local client replays them, so nothing passes through this tool or the chat. \
                         ASK THE USER to add a [personas.<name>] block and point default_persona at it \
                         (put secrets in the environment via ${{VAR}}; throwaway dev creds can sit inline):\n\n\
                         default_persona = \"ci\"\n\
                         [personas.ci]\n\
                         headers = [\"Cookie: session=${{SESSION}}\"]   # or storage = [\"token=...\"]\n\
                         # or sign in via the login form each run:\n\
                         # login_url       = \"/login\"\n\
                         # default_persona = \"user\"\n\
                         # [personas.user]\n\
                         # username = \"dev@example.com\"\n\
                         # password = \"${{DEV_PW}}\"\n\n\
                         Then re-run audit_url. Until then, treat these results as the logged-out experience only.\n\n",
                        routes.join(", ")
                    ));
                    }
                }
                if let Some(unrec) = report["unrecognized_widgets"].as_array() {
                    if !unrec.is_empty() {
                        let sigs: Vec<&str> = unrec.iter().filter_map(|s| s.as_str()).collect();
                        t.push_str(&format!(
                            "UNRECOGNIZED CUSTOM CONTROLS (signatures: {}). If you can identify the \
                             widget set, call report_widget_gap so uxlint learns it.\n\n",
                            sigs.join(", ")
                        ));
                    }
                }
                // Lead with the deterministic verdict and the block-grouped action plan
                // (the synthesis layer). The agent reads "here's what to fix, by block, in
                // priority order" before wading into the raw finding list.
                let summary = &report["summary"];
                if let Some(grade) = summary["grade"].as_str() {
                    t.push_str(&format!(
                        "Grade {grade} ({}/100) — {}\n",
                        summary["score"].as_i64().unwrap_or(0),
                        summary["verdict"].as_str().unwrap_or("")
                    ));
                }
                t.push_str(&format!(
                    "{} errors, {} warnings, {} info\nFull report: {}\n\n",
                    report["errors"],
                    report["warnings"],
                    report["infos"],
                    report["report_url"].as_str().unwrap_or("-")
                ));
                // Cross-audit delta — the iterate-loop signal: what your last round of fixes moved.
                // Present only when this crawl has a comparable prior crawl to diff against.
                if let Some(d) = report["delta"].as_object() {
                    let g = |k: &str| d.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
                    t.push_str(&format!(
                        "Since your last audit: {} resolved, {} new, {} still open.",
                        g("resolved"),
                        g("new"),
                        g("persisting")
                    ));
                    // Name the newly-INTRODUCED findings first — most likely caused by your last edit.
                    if let Some(nf) = d
                        .get("new_findings")
                        .and_then(|v| v.as_array())
                        .filter(|a| !a.is_empty())
                    {
                        let list = nf
                            .iter()
                            .take(5)
                            .filter_map(|f| {
                                Some(format!(
                                    "{} ({})",
                                    f["rule"].as_str()?,
                                    f["route"].as_str()?
                                ))
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        t.push_str(&format!(
                            " New since last time: {list} — check these are yours."
                        ));
                    }
                    t.push_str("\n\n");
                }
                // Warn the agent up front when the audit hit its time cap — the finding set
                // below may be partial, so "clean" here doesn't mean the whole site was checked.
                if report["timed_out"].as_bool() == Some(true) {
                    let d = &report["timeout_detail"];
                    t.push_str(&format!(
                        "⚠ TIMED OUT — this audit hit its {}s time cap; results may be incomplete ({}/{} pages captured, {}/{} tests finished). Findings below are what was gathered before the cap.\n\n",
                        d["cap_secs"].as_u64().unwrap_or(0),
                        d["pages_captured"].as_u64().unwrap_or(0), d["pages_planned"].as_u64().unwrap_or(0),
                        d["walks_done"].as_u64().unwrap_or(0), d["walks_planned"].as_u64().unwrap_or(0),
                    ));
                }
                // Stay on-script: if the site has a styleguide/design-system page, tell the
                // agent to build to it BEFORE touching UI, so fixes reuse its components/tokens
                // instead of drifting.
                if let Some(sg) = report["styleguide"].as_str().filter(|s| !s.is_empty()) {
                    t.push_str(&format!(
                        "STYLEGUIDE: {sg} — this site documents its components, tokens and patterns here. Before changing any UI, open it and build to what it shows; reuse those components/tokens rather than reinventing styles.\n\n"
                    ));
                }
                if let Some(narr) = summary["narrative"].as_str().filter(|n| !n.is_empty()) {
                    t.push_str(&format!(
                        "Action plan (fix by block, in priority order):\n{narr}\n\n"
                    ));
                }
                let report_id = report_id_of(&report);
                // Every distinct rule id shown below — feeds the closing feedback solicitation
                // (deduped, insertion order; empty iff nothing was reported).
                let mut rules_seen: Vec<String> = Vec::new();
                for page in report["pages"].as_array().unwrap_or(&vec![]) {
                    let route = page["route"].as_str().unwrap_or("");
                    let viewport = page["viewport"].as_str().unwrap_or("");
                    for f in page["findings"]
                        .as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .take(30)
                    {
                        // rule name (for verify_fix), location, the problem, and the fix.
                        let rule = f["rule"].as_str().unwrap_or("");
                        if !rule.is_empty() && !rules_seen.iter().any(|r| r.as_str() == rule) {
                            rules_seen.push(rule.to_string());
                        }
                        let sel = f["sel"].as_str().unwrap_or("");
                        // Prefer the source hint (file:line, from the local grep) as the
                        // location; fall back to the DOM selector.
                        let where_ = match (f["source"].as_str(), sel) {
                            (Some(src), _) => format!(" · source: {src}"),
                            (None, s) if !s.is_empty() && s != "page" && s != "site" => {
                                format!(" · selector: {s}")
                            }
                            _ => String::new(),
                        };
                        t.push_str(&format!(
                            "[{}] {} ({}·{}){}\n  {}\n  fix: {}\n",
                            f["severity"].as_str().unwrap_or(""),
                            rule,
                            route,
                            viewport,
                            where_,
                            f["msg"].as_str().unwrap_or(""),
                            f["fix"].as_str().unwrap_or(""),
                        ));
                        // The flagged element boxed on its page screenshot — look before you fix.
                        if let Some(url) =
                            shot_url(&self.cli.server, report_id, route, viewport, &f["rect"])
                        {
                            t.push_str(&format!("  shot: {url}\n"));
                        }
                        // Exact applicable edit for copy findings: a literal find-and-replace
                        // the agent can grep for and apply, then confirm with verify_fix.
                        if let Some(marks) = f["marks"].as_array() {
                            for m in marks {
                                if m["t"].as_str() == Some("rewrite") {
                                    if let (Some(from), Some(to)) =
                                        (m["from"].as_str(), m["to"].as_str())
                                    {
                                        t.push_str(&format!(
                                            "  edit: replace \"{from}\" with \"{to}\"\n"
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                // DRY / componentization (local source, never sent to the server): card/panel
                // class clusters retyped across the tree — each a component waiting to be
                // extracted. Call ux_guidance("components") before acting, then extract once.
                if let Some(dry) = report["source_dry"].as_array().filter(|d| !d.is_empty()) {
                    let total: i64 = dry.iter().map(|d| d["count"].as_i64().unwrap_or(0)).sum();
                    t.push_str(&format!(
                        "\nDRY (local source): {total} inlined card/panel(s) across {} repeated cluster(s) — extract a shared component instead of retyping the classes:\n",
                        dry.len()
                    ));
                    for d in dry.iter().take(5) {
                        t.push_str(&format!(
                            "  ×{} in {} file(s) · from {}: \"{}\"\n",
                            d["count"].as_i64().unwrap_or(0),
                            d["files"].as_i64().unwrap_or(0),
                            d["source"].as_str().unwrap_or("-"),
                            d["cluster"].as_str().unwrap_or(""),
                        ));
                    }
                }
                // Free-plan upsell: the server withheld the Pro findings and gave us a count
                // + two real samples. Show the teasers and instruct the model to tell the
                // user — carefully, without inventing the withheld findings.
                if let Some(up) = report["upsell"].as_object() {
                    let locked = up.get("locked_count").and_then(|v| v.as_i64()).unwrap_or(0);
                    if locked > 0 {
                        let url = up.get("upgrade_url").and_then(|v| v.as_str()).unwrap_or("");
                        t.push_str(&format!(
                            "\n─── {locked} more finding(s) available on Pro ───\n\
                             Your free plan covers accessibility. {locked} further findings \
                             (visual, copy, structure, resilience) plus the AI copy/design judge \
                             were withheld. Two real examples of what's there:\n"
                        ));
                        if let Some(samples) = up.get("samples").and_then(|s| s.as_array()) {
                            for s in samples {
                                t.push_str(&format!(
                                    "  [pro] {} ({}): {}\n    fix: {}\n",
                                    s["rule"].as_str().unwrap_or(""),
                                    s["route"].as_str().unwrap_or(""),
                                    s["msg"].as_str().unwrap_or(""),
                                    s["fix"].as_str().unwrap_or(""),
                                ));
                            }
                        }
                        t.push_str(&format!(
                            "\nNOTIFY THE USER: {locked} additional findings were identified but \
                             need a Pro plan to view and act on — the two above are only a sample. \
                             Suggest upgrading at {url}. Do NOT invent or guess the withheld \
                             findings; only the samples above are real.\n"
                        ));
                    }
                    // A taste of the AI reviewer — one grounded judge finding the server ran
                    // for this free first-audit (best-effort; absent most of the time).
                    if let Some(teaser) = up.get("judge_teaser") {
                        t.push_str(&format!(
                            "\n✨ A taste of Pro's AI reviewer — it read your landing copy and flagged:\n  \
                             [{}] {}: {}\n    fix: {}\n  This copy/design judgment is Pro-only; mention it to the user.\n",
                            teaser["rule"].as_str().unwrap_or(""),
                            teaser["route"].as_str().unwrap_or(""),
                            teaser["msg"].as_str().unwrap_or(""),
                            teaser["fix"].as_str().unwrap_or(""),
                        ));
                    }
                }
                // Quota soft-nudge: warn before the hard 402 wall (last ~20% or <=2 left).
                if let Some(q) = report["quota"].as_object() {
                    let remaining = q.get("remaining").and_then(|v| v.as_i64()).unwrap_or(-1);
                    let cap = q.get("cap").and_then(|v| v.as_i64()).unwrap_or(0);
                    let used = q.get("used").and_then(|v| v.as_i64()).unwrap_or(0);
                    let url = q.get("upgrade_url").and_then(|v| v.as_str()).unwrap_or("");
                    if remaining >= 0 && cap > 0 && remaining <= (cap / 5).max(2) {
                        t.push_str(&format!(
                            "\nQUOTA: {used} of {cap} audits used this month — only {remaining} left. \
                             Tell the user, and suggest upgrading at {url} before they hit the limit.\n"
                        ));
                    }
                }
                t.push_str(
                    "\nFixes and edits are concrete suggestions to apply or adapt to your codebase's voice — guidance, not a mandated redesign. Verify each with verify_fix.\n",
                );
                if self.feedback_enabled && !rules_seen.is_empty() {
                    t.push_str(&feedback_solicitation(report_id, &rules_seen));
                }
                structured = audit_structured(&report, &self.cli.server);
                t
            }
            Err(e) => format!("audit failed: {e}"),
        };
        // Lead with the setup ask when the project is unpinned (`None` when it isn't): the agent
        // should read "check this file in" before it starts fixing findings nothing will track.
        let text = match setup_prefix {
            Some(p) => format!("{p}{text}"),
            None => text,
        };
        if structured.is_null() {
            Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
        } else {
            // CallToolResult is #[non_exhaustive] in rmcp 2.x — build via the constructor, then
            // attach structured content by field (allowed on an owned value, unlike a struct literal).
            let mut r = CallToolResult::success(vec![ContentBlock::text(text)]);
            r.structured_content = Some(structured);
            Ok(r)
        }
    }

    #[tool(
        description = "After editing to fix a finding, re-check ONE rule on ONE page — the fast (~2s) 'did my fix land?' loop, no full re-audit. Returns whether the rule still fires, AND names any OTHER deterministic findings now on that page (the regression guard — so a fix that clears your rule but breaks something else here doesn't read as all-clear). It's a fast deterministic pass: for the whole-page picture incl. judge/state checks, re-run audit_url."
    )]
    async fn verify_fix(
        &self,
        Parameters(a): Parameters<VerifyFixArgs>,
    ) -> Result<CallToolResult, McpError> {
        let rule = a.rule;
        let route = a.route.unwrap_or_else(|| "/".to_string());
        let args = AuditArgs {
            base: resolve_base(a.base, self.default_base.as_deref()),
            routes: route.clone(),
            viewports: "desktop:1440x900,mobile:390x844".into(),
            // Auth (if any) comes from uxlint.toml [personas], never from the MCP call.
            headers: Vec::new(),
            storage: Vec::new(),
            login_url: None,
            username: None,
            password: None,
            states: a.states.unwrap_or(false),
            crawl: 1,
            rule: None,
            parallel: None,
            probe_errors: false,
            resilience: false,
            slow_network: false,
            timeout: None,
            fix_plan: false,
            no_previews: true,
            no_judge: true,
            no_tests: true,
            site_type: None,
            org: None,
            site: None,
            labels: Vec::new(),
            json: false,
            change_url: None,
            ci: false,
            dry_run: None,
            no_provenance: false,
        };
        if self.cli.api_key.is_none() {
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                signup_hint(&self.cli.server),
            )]));
        }
        let cli = self.cli.clone();
        let rule_for_task = rule.clone();
        let route_for_task = route.clone();
        let feedback_enabled = self.feedback_enabled;
        // Run the audit AND the best-effort "accept" POST on the blocking pool — both are
        // blocking, and keeping them together lets the POST fire while off the transport thread.
        let outcome = tokio::task::spawn_blocking(move || {
            let rule = rule_for_task;
            let route = route_for_task;
            let mut structured = Value::Null;
            let text = match run_audit(&cli, &args, &crate::progress::Silent) {
                Ok(report) => {
                    // Free plan: a Pro rule is redacted from the report, so a plain hit count
                    // would read a still-firing Pro finding as "cleared". The server lists what
                    // it withheld — if this rule is there, it fired but is Pro-gated.
                    let withheld = report["upsell"]["withheld_rules"].as_array()
                        .map(|a| a.iter().any(|r| r.as_str() == Some(rule.as_str())))
                        .unwrap_or(false);
                    let up_url = report["upsell"]["upgrade_url"].as_str().unwrap_or("").to_string();
                    let hits = report["pages"].as_array().map(|ps| ps.iter()
                        .flat_map(|p| p["findings"].as_array().cloned().unwrap_or_default())
                        .filter(|f| f["rule"].as_str() == Some(rule.as_str()))
                        .count()).unwrap_or(0);
                    // The still-firing occurrences, each with its annotated screenshot — so a failed
                    // verify shows exactly what's left, not just a count.
                    let report_id = report_id_of(&report);
                    let mut remaining: Vec<Value> = Vec::new();
                    // OTHER rules firing on this page — the regression guard. verify_fix only knows
                    // about `rule`, so a fix that clears it while introducing (or leaving) a DIFFERENT
                    // problem here would otherwise read as a clean "✓ CLEAR". Aggregate the distinct
                    // other rules (insertion order, worst severity, count) so "cleared" is never a
                    // false all-clear. Deterministic-only, same as this fast check — labelled as such.
                    let mut others: Vec<(String, String, u64)> = Vec::new();
                    let sev_rank = |s: &str| match s {
                        "error" => 2,
                        "warn" => 1,
                        _ => 0,
                    };
                    {
                        let empty = vec![];
                        for p in report["pages"].as_array().unwrap_or(&empty) {
                            let r = p["route"].as_str().unwrap_or("");
                            let vp = p["viewport"].as_str().unwrap_or("");
                            for f in p["findings"].as_array().unwrap_or(&empty) {
                                let fr = f["rule"].as_str().unwrap_or("");
                                if fr == rule.as_str() {
                                    remaining.push(json!({
                                        "route": r, "viewport": vp, "message": f["msg"], "selector": f["sel"],
                                        "source": f["source"], "rect": f["rect"],
                                        "screenshot_url": shot_url(&cli.server, report_id, r, vp, &f["rect"]),
                                    }));
                                } else if !fr.is_empty() {
                                    let sev = f["severity"].as_str().unwrap_or("info");
                                    if let Some(e) = others.iter_mut().find(|(rr, _, _)| rr == fr) {
                                        e.2 += 1;
                                        if sev_rank(sev) > sev_rank(&e.1) {
                                            e.1 = sev.to_string();
                                        }
                                    } else {
                                        others.push((fr.to_string(), sev.to_string(), 1));
                                    }
                                }
                            }
                        }
                    }
                    // Worst-first, so the model sees the most urgent regression at the top.
                    others.sort_by_key(|e| std::cmp::Reverse(sev_rank(&e.1)));
                    let others_json: Vec<Value> = others
                        .iter()
                        .map(|(rr, sev, n)| json!({"rule": rr, "severity": sev, "count": n}))
                        .collect();
                    structured = json!({
                        "report_url": report["report_url"], "report_id": report_id,
                        "rule": rule, "route": route, "cleared": hits == 0 && !withheld, "hits": hits, "withheld": withheld,
                        "remaining": remaining, "other_findings": others_json,
                    });
                    // One compact line naming the other rules still on the page (worst first, capped).
                    let others_line = |lead: &str| -> String {
                        if others.is_empty() {
                            return String::new();
                        }
                        let list = others
                            .iter()
                            .take(6)
                            .map(|(rr, sev, n)| {
                                if *n > 1 {
                                    format!("{rr} ({sev}, ×{n})")
                                } else {
                                    format!("{rr} ({sev})")
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        let more = others.len().saturating_sub(6);
                        let tail = if more > 0 {
                            format!(" +{more} more")
                        } else {
                            String::new()
                        };
                        format!("\n{lead} {} other deterministic finding(s) on this page: {list}{tail}. Re-run audit_url for the full picture (incl. judge/state checks this fast pass skips) before calling {route} done.", others.len())
                    };
                    if withheld {
                        format!("▲ {rule} is a Pro finding and still fires on {route} — it's withheld on the free plan, so it can't be fully verified here. Upgrade at {up_url} to see every occurrence and confirm the fix. (Tell the user.)")
                    } else if hits == 0 {
                        // A verified fix is an implicit "accept" — the finding was worth acting
                        // on. Best-effort, stable-keyed (source "fix"), never blocks the reply.
                        if let Some(key) = &cli.api_key {
                            let _ = reqwest::blocking::Client::new()
                                .post(format!("{}/v1/feedback", cli.server))
                                .bearer_auth(key)
                                .json(&json!({"rule": rule, "verdict": "accept", "source": "fix", "reason": "verified via verify_fix"}))
                                .send();
                        }
                        // Cleared — but name any OTHER findings still on the page so this isn't read
                        // as "the page is done." That's the whack-a-mole guard.
                        format!(
                            "✓ {rule} is CLEAR on {route} — fix verified.{}",
                            others_line("Heads-up:")
                        )
                    } else {
                        let mut m = format!("▲ {rule} STILL FIRES on {route} ({hits} occurrence(s)) — the fix hasn't landed yet.");
                        for rf in &remaining {
                            if let Some(u) = rf["screenshot_url"].as_str() {
                                m.push_str(&format!("\n  shot: {u}"));
                            }
                        }
                        m.push_str(&others_line("Also:"));
                        if feedback_enabled {
                            m.push_str(&feedback_solicitation(report_id, std::slice::from_ref(&rule)));
                        }
                        m
                    }
                }
                Err(e) => format!("verify failed: {e}"),
            };
            (text, structured)
        })
        .await
        .map_err(|e| McpError::internal_error(format!("verify task panicked: {e}"), None))?;
        let (text, structured) = outcome;
        if structured.is_null() {
            Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
        } else {
            // CallToolResult is #[non_exhaustive] in rmcp 2.x — build via the constructor, then
            // attach structured content by field (allowed on an owned value, unlike a struct literal).
            let mut r = CallToolResult::success(vec![ContentBlock::text(text)]);
            r.structured_content = Some(structured);
            Ok(r)
        }
    }

    #[tool(
        description = "View a report's annotated screenshot — the flagged element boxed on its page. Reports are PRIVATE, so a finding's screenshot_url can't be fetched with a plain GET; this tool fetches it with your uxlint login. Pass the finding's `screenshot_url` (from audit_url / verify_fix). Returns the image inline (if your client renders MCP images) and always writes it to a local file whose path you can open/Read."
    )]
    async fn get_shot(
        &self,
        Parameters(a): Parameters<GetShotArgs>,
    ) -> Result<CallToolResult, McpError> {
        if self.cli.api_key.is_none() {
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                signup_hint(&self.cli.server),
            )]));
        }
        let cli = self.cli.clone();
        let result = tokio::task::spawn_blocking(move || {
            let server = cli.server.trim_end_matches('/').to_string();
            let raw = a.screenshot_url.trim();
            // Only ever fetch a report-image URL on OUR server — never send the login token anywhere
            // else (a stray host in screenshot_url would otherwise leak the bearer).
            let url = if raw.starts_with(&server) {
                raw.to_string()
            } else if raw.starts_with('/') {
                format!("{server}{raw}")
            } else {
                return Err(format!("screenshot_url must be a report image URL on {server}"));
            };
            if !url.contains("/r/") {
                return Err("that isn't a report screenshot URL".to_string());
            }
            let resp = reqwest::blocking::Client::new()
                .get(&url)
                .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
                .send();
            match resp {
                Ok(r) if r.status().is_success() => {
                    let mime = r
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("image/jpeg")
                        .to_string();
                    let ext = if mime.contains("png") { "png" } else { "jpg" };
                    let bytes = r.bytes().map_err(|e| format!("could not read the image: {e}"))?.to_vec();
                    // Derive a stable-ish filename from the report id in the path.
                    let stem = url.split("/r/").nth(1).and_then(|s| s.split('/').next()).unwrap_or("shot");
                    let path = std::env::temp_dir().join(format!("uxlint-shot-{stem}.{ext}"));
                    std::fs::write(&path, &bytes).map_err(|e| format!("could not save the image: {e}"))?;
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                    Ok((b64, mime, path.display().to_string()))
                }
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => Err(credential_rejected(&cli.server)),
                Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                    Err("no such screenshot — check the report_id/route/viewport, or you may not have access to that report".to_string())
                }
                Ok(r) => Err(format!("could not fetch the screenshot: {}", r.status())),
                Err(e) => Err(format!("could not fetch the screenshot: {e}")),
            }
        })
        .await
        .map_err(|e| McpError::internal_error(format!("get_shot task panicked: {e}"), None))?;
        match result {
            Ok((b64, mime, path)) => Ok(CallToolResult::success(vec![
                ContentBlock::image(b64, mime),
                ContentBlock::text(format!(
                    "Saved to {path} — open or Read it if the image didn't render inline."
                )),
            ])),
            Err(msg) => Ok(CallToolResult::success(vec![ContentBlock::text(msg)])),
        }
    }

    #[tool(
        description = "Best-practice UI guidance to read BEFORE building or changing UI — usability, consistency, and performance patterns distilled from uxlint's audit corpus, so you build idiomatic, DRY, testable components the first time instead of getting audited after. Covers whole-row click targets, single-column labelled forms, tabs/radiogroup vs plain buttons, one shared width scale + aligned panels, pagination by scroll length, CLS-safe layout, and copy that reads as UI (active voice, honest labels, useful empty/error states). Each item names the uxlint rule that catches a miss, so the loop is: read the topic, build to it, then audit_url to confirm."
    )]
    async fn ux_guidance(
        &self,
        Parameters(a): Parameters<UxGuidanceArgs>,
    ) -> Result<CallToolResult, McpError> {
        let topic = a.topic.as_deref().unwrap_or("");
        Ok(CallToolResult::success(vec![ContentBlock::text(
            crate::guidance::guidance(topic),
        )]))
    }

    // ONE feedback tool, gated by ONE opt-in setting (`feedback = true` in uxlint.toml,
    // default FALSE). `UxlintMcp::new` removes this route entirely from the tool router when the
    // project hasn't opted in, so it's invisible to `list_tools` AND rejected by `call_tool` — the
    // description below is only ever seen by a project that's on.
    // NB name is set EXPLICITLY to `lint_feedback` — audit_url's workflow tells the agent to call
    // `lint_feedback`, and .claude/settings.json allow-lists it under that name; without this the tool
    // would register as `feedback` (the fn name) and neither would match.
    #[tool(
        name = "lint_feedback",
        description = "PRIVACY FIRST: this shares a signal with uxlint to help improve the product. \
Describe everything in GENERAL, application-agnostic terms ONLY — NEVER your app's names, content, \
routes, data, or screenshots (e.g. \"a check for the X pattern,\" not \"your /billing page does Y\"). \
Same rule as audit_url's credentials guidance: DON'T pass secrets, PII, or anything identifying here.\n\n\
Three kinds, chosen with `kind`:\n\
- verdict — was a lint finding worth it? Needs `rule` + `verdict` (beneficial/useful = a real issue \
worth fixing; false_positive/not_useful = fired but not a problem here; harmful = following it would \
worsen the UX), optionally report_id/selector. Call this for EACH finding you act on — it trains \
which rules to keep, tune, or retire. A NEGATIVE verdict (false_positive / not_useful / harmful) \
also REQUIRES `note`: one SENTENCE naming what fired (rule + the element/selector it hit) and why \
it's wrong there — for harmful, what you changed and how that made the UX worse. The note is the \
only thing that can fix the rule, so a bare verdict — or a token like \"wrong\" / \"n/a\" — is \
refused and NOT recorded; write the sentence while you still have the finding in front of you.\n\
- suggestion — a lint uxlint is MISSING, or how an EXISTING one could be IMPROVED. Needs `note` (the \
idea, general terms only) and, for an improvement, the existing `rule`.\n\
- widget_gap — a component library / widget set uxlint failed to recognise. Needs `widget_set`, \
optionally url/note."
    )]
    async fn feedback(
        &self,
        Parameters(a): Parameters<FeedbackArgs>,
    ) -> Result<CallToolResult, McpError> {
        let cli = self.cli.clone();
        let text = tokio::task::spawn_blocking(move || match a.kind {
            FeedbackKind::Verdict => {
                let Some(verdict) = a.verdict else {
                    return "feedback failed: kind=verdict needs a `verdict` (beneficial/useful, false_positive/not_useful, or harmful)".to_string();
                };
                let Some(rule) = a.rule.filter(|r| !r.trim().is_empty()) else {
                    return "feedback failed: kind=verdict needs a `rule`".to_string();
                };
                let note = a.note.unwrap_or_default();
                if let Some(msg) = missing_verdict_reason(&verdict, &note) {
                    return msg;
                }
                let resp = reqwest::blocking::Client::new()
                    .post(format!("{}/v1/feedback", cli.server))
                    .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
                    .json(&json!({
                        "kind": "verdict", "rule": rule, "verdict": verdict.as_str(),
                        "report_id": a.report_id.unwrap_or_default(), "sel": a.selector.unwrap_or_default(),
                        "reason": note, "source": "agent"
                    }))
                    .send();
                match resp {
                    Ok(r) if r.status().is_success() => "recorded — this trains which uxlint rules to keep, tune, or retire".to_string(),
                    Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => credential_rejected(&cli.server),
                    Ok(r) => failure_text(r),
                    Err(e) => format!("feedback failed: {e}"),
                }
            }
            FeedbackKind::Suggestion => {
                let Some(note) = a.note.filter(|n| !n.trim().is_empty()) else {
                    return "feedback failed: kind=suggestion needs a `note` describing the missing/improvable lint (general terms only)".to_string();
                };
                let resp = reqwest::blocking::Client::new()
                    .post(format!("{}/v1/feedback", cli.server))
                    .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
                    .json(&json!({ "kind": "suggestion", "rule": a.rule.unwrap_or_default(), "reason": note }))
                    .send();
                match resp {
                    Ok(r) if r.status().is_success() => "recorded — thanks, this feeds uxlint's lint-suggestion backlog".to_string(),
                    Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => credential_rejected(&cli.server),
                    Ok(r) => failure_text(r),
                    Err(e) => format!("feedback failed: {e}"),
                }
            }
            FeedbackKind::WidgetGap => {
                let Some(widget_set) = a.widget_set.filter(|w| !w.trim().is_empty()) else {
                    return "feedback failed: kind=widget_gap needs a `widget_set`".to_string();
                };
                let resp = reqwest::blocking::Client::new()
                    .post(format!("{}/v1/feedback/widgets", cli.server))
                    .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
                    .json(&json!({ "widget_set": widget_set, "url": a.url, "note": a.note }))
                    .send();
                match resp {
                    Ok(r) if r.status().is_success() => "recorded — this feeds uxlint's widget-recognition corpus".to_string(),
                    Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => credential_rejected(&cli.server),
                    Ok(r) => failure_text(r),
                    Err(e) => format!("feedback failed: {e}"),
                }
            }
        })
        .await
        .map_err(|e| McpError::internal_error(format!("feedback task panicked: {e}"), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for UxlintMcp {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo/Implementation are #[non_exhaustive] in rmcp 2.x. Default already sets
        // protocol_version = LATEST and server_info = Implementation::from_build_env() (name
        // "uxlint" from CARGO_PKG_NAME, version from CARGO_PKG_VERSION); override the rest by field.
        let mut info = ServerInfo::default();
        // Default's server_info comes from rmcp's OWN build env (name "rmcp"); report ours instead.
        info.server_info.name = "uxlint".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        // Step 3 (feedback) only exists to mention when the `lint_feedback` tool is actually in
        // this project's tool list — telling the agent to call a tool that isn't there would just
        // produce a confusing "no such tool" failure.
        let feedback_step = if self.feedback_enabled {
            " 3) call feedback (kind=verdict) for each finding you act on (beneficial / false_positive \
/ harmful) — this is how the rules improve."
        } else {
            ""
        };
        info.instructions = Some(format!("uxlint audits and improves a site's UX. Workflow when acting on a report: \
1) call ux_guidance for the relevant area(s) BEFORE changing UI, so fixes follow the idiomatic, DRY, \
testable pattern rather than one-off patches (and if the audit names a STYLEGUIDE page, open it and \
build to its components/tokens); 2) fix INTENTIONALLY — reuse the project's existing \
components/tokens and match its voice, don't bolt on a new one-off to silence the finding; make the \
smallest change that clears it WITHOUT regressing the quality floor (responsive to mobile, visible \
keyboard focus, reduced motion respected, no new layout shift), then verify_fix;{feedback_step} \
Loop until green."));
        info
    }
}

// Newline-delimited JSON-RPC over stdio, via the official rmcp async server. One tool set:
// audit_url and friends. This is how a coding agent gets design taste: call the tool, read the
// findings, apply the fixes, call again until green.
pub(crate) fn run_mcp(cli: &Cli, base: Option<String>) -> anyhow::Result<()> {
    let cli = Arc::new(cli.clone());
    // A blank `--base ""` is the same as not passing one (fall through to per-call / uxlint.toml).
    let base = base.filter(|b| !b.trim().is_empty());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let service = UxlintMcp::new(cli, base).serve(stdio()).await?;
        service.waiting().await?;
        Ok::<_, anyhow::Error>(())
    })
}

#[cfg(test)]
mod verdict_reason_tests {
    use super::{missing_verdict_reason, substantive_reason, LintVerdict};

    #[test]
    fn a_negative_verdict_without_prose_is_stopped_before_the_round_trip() {
        for v in [LintVerdict::FalsePositive, LintVerdict::Harmful] {
            for note in ["", "   ", "wrong", "n/a", "false positive"] {
                let msg = missing_verdict_reason(&v, note)
                    .unwrap_or_else(|| panic!("{} + {note:?} must be refused", v.as_str()));
                assert!(msg.contains("`note`"), "{msg}");
                assert!(msg.contains(v.as_str()), "{msg}");
            }
        }
        // Harmful is the one verdict that says a fix made things WORSE — ask for that specifically.
        let harm = missing_verdict_reason(&LintVerdict::Harmful, "").expect("refused");
        assert!(harm.contains("worse"), "{harm}");
    }

    /// The whole point of checking locally is to spare the agent a round trip, so the local bar must
    /// be the server's bar. These are the notes that clear ONE of its two conditions: if we ever
    /// drop the word count (or the length), they start passing here and 400ing there — the agent is
    /// told the requirement twice, differently, which is worse than never having checked.
    #[test]
    fn the_local_bar_is_the_servers_bar_not_a_looser_one() {
        for note in [
            "not-a-real-problem-on-this-element", // long enough, but one token, not a sentence
            "definitely_a_false_positive_here",
            "false positive sorry", // clears the length bar on three words
            "rule is just wrong",   // four words, but too terse to name what fired
        ] {
            assert!(!substantive_reason(note), "{note:?} is not an explanation");
            assert!(
                missing_verdict_reason(&LintVerdict::FalsePositive, note).is_some(),
                "{note:?} passes here but the server would refuse it"
            );
        }
    }

    #[test]
    fn an_explained_negative_and_any_positive_go_through() {
        for note in [
            "fired on a decorative icon that is aria-hidden",
            "  the contrast rule hit a disabled control, where 3:1 is the target  ",
        ] {
            assert!(missing_verdict_reason(&LintVerdict::FalsePositive, note).is_none());
            assert!(missing_verdict_reason(&LintVerdict::Harmful, note).is_none());
        }
        // "it was right" carries its own signal — never gate the positive path.
        assert!(missing_verdict_reason(&LintVerdict::Beneficial, "").is_none());
    }
}

#[cfg(test)]
mod setup_instructions_tests {
    use super::project_setup_instructions;
    use serde_json::json;

    fn me(orgs: serde_json::Value) -> serde_json::Value {
        json!({ "authenticated": true, "orgs": orgs })
    }

    /// Every flavour must carry a WRITEABLE file: the four keys that make a project auditable, plus
    /// the base it was called with. A block that merely says "configure uxlint" is the error we
    /// already had.
    #[test]
    fn the_block_is_a_config_the_agent_can_write_not_an_instruction_to_configure() {
        for blocked in [true, false] {
            let t =
                project_setup_instructions("http://localhost:5173", None, "myapp", blocked, false);
            for key in ["org = ", "site = ", "base = ", "routes = ", "uxlint.toml"] {
                assert!(t.contains(key), "{key} missing from:\n{t}");
            }
            assert!(t.contains("\"http://localhost:5173\""), "{t}");
            // An app with no hostname yet still gets a concrete name, from the project directory.
            assert!(t.contains("\"myapp.local\""), "{t}");
        }
    }

    /// Guessing an org name gets the NEXT audit bounced by `prevalidate_org` before the crawl, so
    /// the block names the account's real ones — and asks when the choice isn't ours to make.
    #[test]
    fn orgs_come_from_the_account_and_a_choice_is_handed_to_the_user() {
        let one = project_setup_instructions(
            "http://localhost:3000",
            Some(&me(json!([{ "name": "Personal" }]))),
            "app",
            true,
            false,
        );
        assert!(one.contains("org = \"Personal\""), "{one}");
        assert!(!one.contains("ASK THE USER which"), "{one}");

        let many = project_setup_instructions(
            "http://localhost:3000",
            Some(&me(json!([{ "name": "Personal" }, { "name": "Acme" }]))),
            "app",
            true,
            false,
        );
        assert!(many.contains("ASK THE USER which"), "{many}");
        assert!(many.contains("Personal, Acme"), "{many}");

        // No /v1/me (server down, signed out) — still a template, with the org left to ask about.
        let none = project_setup_instructions("http://localhost:3000", None, "app", true, false);
        assert!(none.contains("ASK THE USER which org"), "{none}");
    }

    /// Minting a stray site is the thing this whole block exists to prevent — offer the ones the
    /// account already has before suggesting a new name.
    #[test]
    fn existing_sites_are_offered_for_reuse() {
        let t = project_setup_instructions(
            "http://localhost:3000",
            Some(&me(
                json!([{ "name": "Personal", "sites": [{ "host": "acme.com" }, { "host": "app.acme.com" }] }]),
            )),
            "app",
            true,
            false,
        );
        assert!(t.contains("acme.com, app.acme.com"), "{t}");
    }

    /// The two flavours must not lie about what happened: blocked means no report exists, unblocked
    /// means one does — filed somewhere the user didn't choose.
    #[test]
    fn the_blocked_and_unpinned_flavours_report_what_actually_happened() {
        let blocked = project_setup_instructions("http://localhost:5173", None, "app", true, false);
        assert!(blocked.contains("did NOT run"), "{blocked}");
        assert!(blocked.contains("no uxlint.toml"), "{blocked}");

        // A file that exists but declares no org/site fails identically — say so, don't tell the
        // agent to create a file it can already see.
        let half = project_setup_instructions("http://localhost:5173", None, "app", true, true);
        assert!(half.contains("declares no `org`/`site`"), "{half}");

        // Public host: the audit ran, so name where the report landed and suggest that host.
        let unpinned = project_setup_instructions("https://acme.com", None, "app", false, false);
        assert!(!unpinned.contains("did NOT run"), "{unpinned}");
        assert!(unpinned.contains("acme.com"), "{unpinned}");
        assert!(unpinned.contains("site = \"acme.com\""), "{unpinned}");
    }
}

#[cfg(test)]
mod missing_site_tests {
    use super::missing_site_instructions;
    use serde_json::json;

    fn me(orgs: serde_json::Value) -> serde_json::Value {
        json!({ "authenticated": true, "orgs": orgs })
    }

    /// The whole point: a site is created by its owner, deliberately. Left alone the server mints one
    /// on the spot, so a typo in uxlint.toml becomes where the project's history lives.
    #[test]
    fn a_site_the_account_does_not_have_stops_the_audit_and_names_the_command() {
        let m = me(json!([{ "name": "Personal", "sites": [{ "host": "uxlint.net" }] }]));
        let t = missing_site_instructions("Personal", "mtg-deck.local", Some(&m)).expect("blocked");
        assert!(t.contains("did NOT run"), "{t}");
        assert!(
            t.contains("uxlint site create mtg-deck.local --org \"Personal\""),
            "the exact command, ready to run: {t}"
        );
        // The sites that DO exist are offered — repointing at one beats minting a second name for
        // the same app, which splits its history.
        assert!(t.contains("uxlint.net"), "{t}");
    }

    #[test]
    fn a_site_that_exists_is_silent() {
        let m = me(json!([{ "name": "Personal", "sites": [{ "host": "mtg-deck.local" }] }]));
        assert!(missing_site_instructions("Personal", "mtg-deck.local", Some(&m)).is_none());
        // Org names are matched case-insensitively, same as `prevalidate_org` and the server.
        assert!(missing_site_instructions("personal", "mtg-deck.local", Some(&m)).is_none());
    }

    #[test]
    fn an_org_the_account_is_not_in_is_reported_as_the_org_problem_it_is() {
        let m = me(json!([{ "name": "Personal", "sites": [] }, { "name": "Acme", "sites": [] }]));
        let t = missing_site_instructions("Ghost", "x.test", Some(&m)).expect("blocked");
        assert!(t.contains("ORG NOT FOUND"), "{t}");
        assert!(
            t.contains("Personal, Acme"),
            "the real ones are listed: {t}"
        );
        // Creating a site can't be the advice when the org itself is wrong.
        assert!(!t.contains("uxlint site create"), "{t}");
    }

    /// FAIL OPEN: this gate blocks an audit, so it must only fire on a clear, authenticated "no".
    /// A server that's down or a signed-out payload leaves the audit (and the server's own
    /// guardrail) to decide — otherwise a network blip reads as "your site doesn't exist".
    #[test]
    fn an_unclear_answer_never_blocks() {
        assert!(missing_site_instructions("Personal", "a.test", None).is_none());
        assert!(missing_site_instructions(
            "Personal",
            "a.test",
            Some(&json!({"authenticated": false}))
        )
        .is_none());
        assert!(
            missing_site_instructions("Personal", "a.test", Some(&json!({"authenticated": true})))
                .is_none(),
            "an authenticated payload with no orgs array is still not an answer"
        );
    }
}

#[cfg(test)]
mod resolve_base_tests {
    use super::resolve_base;

    #[test]
    fn per_call_base_wins_over_the_launch_base() {
        assert_eq!(
            resolve_base(Some("http://call".into()), Some("http://launch")),
            "http://call"
        );
    }

    #[test]
    fn falls_back_to_the_launch_base_when_the_call_omits_or_blanks_it() {
        assert_eq!(resolve_base(None, Some("http://launch")), "http://launch");
        // A blank/whitespace per-call base is treated as absent, not as "audit the empty string".
        assert_eq!(
            resolve_base(Some("   ".into()), Some("http://launch")),
            "http://launch"
        );
    }

    #[test]
    fn empty_when_neither_is_set_so_the_toml_base_takes_over() {
        // run_audit reads an empty base as "use uxlint.toml's base".
        assert_eq!(resolve_base(None, None), "");
        assert_eq!(resolve_base(Some(String::new()), None), "");
    }
}
