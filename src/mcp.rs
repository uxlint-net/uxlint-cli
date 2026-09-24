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

/// The report id a caller handed `get_report`, and whether it named a DIFFERENT uxlint server than
/// the one this MCP talks to. Accepts what a person actually pastes: the dashboard URL
/// (`/sites/{site}/r/{id}`), the legacy `/r/{id}`, either with a query or a trailing path
/// (`/annot?…`), or the bare id. The other-server check matters because the id is only meaningful on
/// the server that minted it — a dev.uxlint.net link read against prod would 404 and look like "no
/// such report" when the report is fine and the question went to the wrong place.
fn parse_report_ref(raw: &str, server: &str) -> Result<String, String> {
    let raw = raw.trim();
    let is_id = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    if is_id(raw) {
        return Ok(raw.to_string());
    }
    if let Some(rest) = raw
        .strip_prefix("http://")
        .or_else(|| raw.strip_prefix("https://"))
    {
        let host = rest.split('/').next().unwrap_or("");
        let ours = server
            .trim_end_matches('/')
            .split("://")
            .nth(1)
            .unwrap_or(server);
        if !host.eq_ignore_ascii_case(ours) {
            return Err(format!(
                "that report is on {host}, but this uxlint MCP is connected to {ours} — a report id only means something on the server that made it. Point the MCP at {host} (UXLINT_SERVER) to read it."
            ));
        }
    }
    raw.rsplit_once("/r/")
        .map(|(_, b)| b.split(['/', '?', '#']).next().unwrap_or(b))
        .filter(|id| is_id(id))
        .map(str::to_string)
        .ok_or_else(|| "pass a report URL (…/r/<id>) or a report id".to_string())
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
fn audit_structured(report: &Value, server: &str, full: bool) -> Value {
    let guidance = agent_summary(report);
    let report_id = report_id_of(report);
    let empty = vec![];
    let mut findings = Vec::new();
    // Compact by default. Every finding stays (an agent maps them to code), but the long text that
    // repeats — a rule's fix and its best-practice paragraph are the same for every instance — is
    // said ONCE per rule in `fixes`, and best practice only with `detail: "full"`. Field report,
    // 2026-09-24: the full form was ~66k characters, past the client's output limit, so it spilled to a
    // file and the agent had to parse it with scripts. On that report: 70k → 32k structured, and the
    // whole result (with the prose) from ~102k to ~65k characters — back under the default limit.
    let mut fixes = serde_json::Map::new();
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
            if full {
                findings.push(json!({
                    "rule": f["rule"], "severity": f["severity"], "route": route, "viewport": viewport,
                    "message": f["msg"], "fix": f["fix"], "best_practice": f["best_practice"],
                    "selector": f["sel"], "source": f["source"],
                    "rect": f["rect"], "edit": edit,
                    "screenshot_url": shot_url(server, report_id, route, viewport, &f["rect"]),
                }));
                continue;
            }
            if let (Some(rule), Some(fix)) = (f["rule"].as_str(), f["fix"].as_str()) {
                fixes.entry(rule.to_string()).or_insert_with(|| json!(fix));
            }
            let msg: String = f["msg"].as_str().unwrap_or("").chars().take(160).collect();
            let mut c = json!({
                "rule": f["rule"], "severity": f["severity"], "route": route, "viewport": viewport,
                "message": msg, "selector": f["sel"],
            });
            if !f["source"].is_null() {
                c["source"] = f["source"].clone();
            }
            if let Some(e) = edit {
                c["edit"] = e;
            }
            findings.push(c);
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
        // What to read FIRST: the report link, warnings, how each page was read, the action plan, and
        // each root cause as one line. Claude Code shows the agent this structured result rather than
        // the text, so this is where the guidance has to be. Null from a server that predates it.
        "summary": guidance,
        "findings": findings,
        // Compact form: each rule's fix, once. (Full form carries it on every finding instead.)
        "fixes": if full { Value::Null } else { Value::Object(fixes) },
        "detail": if full { "full" } else { "compact — pass detail: \"full\" for every finding's fix, best practice, rect and screenshot URL" },
        "dry": report["source_dry"],
        // Cross-audit delta vs the previous comparable crawl (resolved/new/persisting + samples);
        // null when there's no comparable prior audit to diff against.
        "delta": report["delta"],
    })
}

/// The prose an agent reads for a report. The SERVER renders it (`agent_text`) so presentation ships
/// with a deploy rather than a CLI release — this only adds what the server can't know: the LOCAL
/// source hint for each finding group (source never leaves the machine; the server leaves a
/// `{{where:N}}` token and says which finding it belongs to), the warnings this client raised about
/// the run, the local-source DRY advisory, and the feedback prompt. A server too old to send
/// `agent_text` gets the built-in renderer, `report_text`, exactly as before.
fn agent_prose(report: &Value, server: &str, feedback_enabled: bool) -> String {
    let Some(text) = report["agent_text"].as_str() else {
        return report_text(report, server, feedback_enabled);
    };
    let mut t = local_warnings(report);
    t.push_str(&fill_where(text, report));
    t.push_str(&local_dry(report));
    if feedback_enabled {
        let mut rules: Vec<String> = Vec::new();
        for f in report["pages"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|p| p["findings"].as_array().into_iter().flatten())
        {
            if let Some(r) = f["rule"]
                .as_str()
                .filter(|r| !r.is_empty() && !rules.iter().any(|x| x == r))
            {
                rules.push(r.to_string());
            }
        }
        if !rules.is_empty() {
            t.push_str(&feedback_solicitation(report_id_of(report), &rules));
        }
    }
    t
}

/// The server's compact summary (`agent_summary`), completed the same way as the full prose — for the
/// STRUCTURED result, which is what Claude Code actually hands the agent (it doesn't show a tool's
/// text when structured content is present; found 2026-09-25). `None` from a server too old to send it.
fn agent_summary(report: &Value) -> Option<String> {
    let text = report["agent_summary"].as_str()?;
    let mut t = local_warnings(report);
    t.push_str(&fill_where(text, report));
    t.push_str(&local_dry(report));
    Some(t)
}

/// Replace each `{{where:N}}` the server left with the finding's LOCAL source hint (source never leaves
/// the machine), or the selector fallback the server gave when there's none.
fn fill_where(text: &str, report: &Value) -> String {
    let mut body = text.to_string();
    for (n, w) in report["agent_where"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let finding = &report["pages"][w["page"].as_u64().unwrap_or(0) as usize]["findings"]
            [w["finding"].as_u64().unwrap_or(0) as usize];
        let at = match finding["source"].as_str() {
            Some(src) => format!(" · source: {src}"),
            None => w["fallback"].as_str().unwrap_or("").to_string(),
        };
        body = body.replace(&format!("{{{{where:{n}}}}}"), &at);
    }
    body
}

/// What this client found wrong with the RUN itself — a config that audits signed out, thin seed
/// data, pages captured without their interaction checks. Raised locally, so rendered locally, and
/// put first: every finding below is about the wrong experience if it applies.
fn local_warnings(report: &Value) -> String {
    let mut t = String::new();
    if let Some(ws) = report["config_warnings"]
        .as_array()
        .filter(|w| !w.is_empty())
    {
        t.push_str("⚠ CONFIG — this audit may not have seen what you meant it to:\n");
        for w in ws.iter().filter_map(|w| w.as_str()) {
            t.push_str(&format!("  · {w}\n"));
        }
        t.push_str("Fix that and re-run before acting on the findings below.\n\n");
    }
    if let Some(n) = report["depth_trimmed"].as_u64().filter(|n| *n > 0) {
        t.push_str(&format!(
            "⏱ Time was short, so {n} page(s) were captured at rest without their interaction checks (hover, focus, dialogs, fault probes) — every page was still seen. Raise the time cap (--timeout, or uxlint.toml `timeout`) for full depth.\n\n"
        ));
    }
    t
}

/// DRY / componentization from the LOCAL source (never sent to the server): card/panel class clusters
/// retyped across the tree — each a component waiting to be extracted.
fn local_dry(report: &Value) -> String {
    let mut t = String::new();
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
    t
}

/// The prose half of an audit result, for the agent: setup asks, the grade, what moved since last
/// time, a TIMED OUT warning, the action plan, then every finding with its fix and screenshot. Shared
/// by `audit_url` (a run it just finished) and `get_report` (one that already exists), so a report
/// read back later is exactly the report the agent would have been handed at the time.
fn report_text(report: &Value, server: &str, feedback_enabled: bool) -> String {
    let mut t = String::new();
    // Before anything else: a config that made this run audit SIGNED OUT when it meant not to. Every
    // finding below is about the wrong experience if this fires, so it can't sit under them.
    if let Some(ws) = report["config_warnings"]
        .as_array()
        .filter(|w| !w.is_empty())
    {
        t.push_str("⚠ CONFIG — this audit may not have seen what you meant it to:\n");
        for w in ws.iter().filter_map(|w| w.as_str()) {
            t.push_str(&format!("  · {w}\n"));
        }
        t.push_str("Fix that and re-run before acting on the findings below.\n\n");
    }
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
    // The link goes FIRST, with an instruction to relay it. Everything below this line is
    // written for the agent — it fixes the code and the user never sees most of it — but
    // the report itself is for the PERSON: annotated screenshots of their own pages, every
    // finding, the score over time. Buried as a bare line halfway down a wall of findings
    // it got summarised away, and people didn't know a report page existed at all.
    if let Some(url) = report["report_url"].as_str().filter(|u| !u.is_empty()) {
        t.push_str(&format!(
            "REPORT: {url}\nGive the user this link — it's the full report on the web \
             (annotated screenshots of each finding, the whole list, and how this run \
             compares with their last one).\n\n"
        ));
    }
    if let Some(grade) = summary["grade"].as_str() {
        t.push_str(&format!(
            "Grade {grade} ({}/100) — {}\n",
            summary["score"].as_i64().unwrap_or(0),
            summary["verdict"].as_str().unwrap_or("")
        ));
    }
    t.push_str(&format!(
        "{} errors, {} warnings, {} info\n\n",
        report["errors"], report["warnings"], report["infos"],
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
        if g("not_verified") > 0 {
            t.push_str(&format!(" {} previous finding(s) were absent without passing evidence and remain unverified.", g("not_verified")));
        }
        if let Some(changes) = d.get("occurrence_changes").and_then(|v| v.as_array()) {
            for change in changes.iter().take(6) {
                t.push_str(&format!(
                    "\n  {} on {} ({}): {} → {} observed occurrences.",
                    change["rule"].as_str().unwrap_or("?"),
                    change["route"].as_str().unwrap_or("?"),
                    change["viewport"].as_str().unwrap_or("?"),
                    change["before"],
                    change["after"]
                ));
            }
        }
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
    // Coverage was protected by skipping depth: every page was captured, but some without their
    // interaction checks. Say so, so "no hover/dialog findings" there isn't read as "clean".
    if let Some(n) = report["depth_trimmed"].as_u64().filter(|n| *n > 0) {
        t.push_str(&format!(
            "⏱ Time was short, so {n} page(s) were captured at rest without their interaction checks (hover, focus, dialogs, fault probes) — every page was still seen. Raise the time cap (--timeout, or uxlint.toml `timeout`) for full depth.\n\n"
        ));
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
    let report_id = report_id_of(report);
    // Every distinct rule id shown below — feeds the closing feedback solicitation
    // (deduped, insertion order; empty iff nothing was reported).
    let mut rules_seen: Vec<String> = Vec::new();
    let groups = finding_groups(report);
    for g in groups.iter().take(MAX_GROUPS) {
        let f = g.first;
        // rule name (for verify_fix), location, the problem, and the fix.
        if !rules_seen.contains(&g.rule) {
            rules_seen.push(g.rule.clone());
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
        let places = g
            .places
            .iter()
            .take(4)
            .map(|(r, v)| format!("{r}·{v}"))
            .collect::<Vec<_>>()
            .join(", ");
        let at = if g.places.len() == 1 {
            format!("({places})")
        } else {
            let more = g.places.len().saturating_sub(4);
            format!(
                "— {} places, fix once: {places}{}",
                g.places.len(),
                if more > 0 {
                    format!(" +{more} more")
                } else {
                    String::new()
                }
            )
        };
        t.push_str(&format!(
            "[{}] {} {at}{where_}\n  {}\n  fix: {}\n",
            g.severity,
            g.rule,
            f["msg"].as_str().unwrap_or(""),
            f["fix"].as_str().unwrap_or(""),
        ));
        // The flagged element boxed on its page screenshot — look before you fix.
        let (route, viewport) = &g.places[0];
        if let Some(url) = shot_url(server, report_id, route, viewport, &f["rect"]) {
            t.push_str(&format!("  shot: {url}\n"));
        }
        // Exact applicable edit for copy findings: a literal find-and-replace
        // the agent can grep for and apply, then confirm with verify_fix.
        if let Some(marks) = f["marks"].as_array() {
            for m in marks {
                if m["t"].as_str() == Some("rewrite") {
                    if let (Some(from), Some(to)) = (m["from"].as_str(), m["to"].as_str()) {
                        t.push_str(&format!("  edit: replace \"{from}\" with \"{to}\"\n"));
                    }
                }
            }
        }
    }
    if groups.len() > MAX_GROUPS {
        t.push_str(&format!(
            "…and {} more (lower-severity, narrower) — every finding is in the structured result and on the report page.\n",
            groups.len() - MAX_GROUPS
        ));
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
    if feedback_enabled && !rules_seen.is_empty() {
        t.push_str(&feedback_solicitation(report_id, &rules_seen));
    }
    t
}

/// The line an MCP caller sees while an audit runs: what it is doing, how far through, and how long
/// it has been going against its cap — `crawl: 3/12 pages · 1m 40s of 5m`. Before the route set is
/// known it still says something ("finding pages to audit"): that silence is what a field report on
/// 2026-09-24 read as a hung audit. `None` only before the audit has started at all.
fn progress_message(
    (pages_done, pages_total, walks_done, walks_total, phase): (usize, usize, usize, usize, String),
    elapsed: u64,
    cap: u64,
) -> Option<String> {
    let what = match phase.as_str() {
        "" => return None,
        "walks" if walks_total > 0 => format!("tests: {walks_done}/{walks_total}"),
        "server" => "AI review of the captured pages".to_string(),
        "previews" => "rendering fix previews".to_string(),
        "done" => "finishing".to_string(),
        _ if pages_total > 0 => format!("crawl: {pages_done}/{pages_total} pages"),
        _ => "finding pages to audit".to_string(),
    };
    let dur = |s: u64| match (s / 60, s % 60) {
        (0, s) => format!("{s}s"),
        (m, 0) => format!("{m}m"),
        (m, s) => format!("{m}m {s}s"),
    };
    Some(if cap > 0 && elapsed <= cap {
        format!("{what} · {} of {}", dur(elapsed), dur(cap))
    } else {
        format!("{what} · {}", dur(elapsed))
    })
}

/// What `archive_feedback` says it closed. The COUNT goes back to the caller — one that meant to close a
/// single reason and closed the whole rule finds out here, not by the digest quietly going empty — and
/// it counts BOTH halves: it used to report verdicts only, so closing a lint idea read "archived 0
/// verdicts on  as fixed", a success that looked exactly like a no-op (the server 404s a real no-op).
/// The empty rule is a wholly new lint idea and is named as one.
fn archive_confirmation(v: &Value) -> String {
    let n = |k: &str| v[k].as_i64().unwrap_or(0);
    let plural = |n: i64, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    let mut closed = Vec::new();
    if n("archived") > 0 || n("suggestions") == 0 {
        closed.push(plural(n("archived"), "verdict", "verdicts"));
    }
    if n("suggestions") > 0 {
        closed.push(plural(n("suggestions"), "lint idea", "lint ideas"));
    }
    let on = match v["rule"].as_str() {
        Some("") => "new lint".to_string(),
        Some(r) => r.to_string(),
        None => "?".to_string(),
    };
    format!(
        "archived {} on {on} as {} ({} scope). Anything filed after now stays live — including this \
         same complaint if it comes back.",
        closed.join(" and "),
        v["outcome"].as_str().unwrap_or("?"),
        v["scope"].as_str().unwrap_or("?"),
    )
}

/// How many root causes the prose lists before pointing at the rest (the structured half always
/// carries every finding).
const MAX_GROUPS: usize = 60;

/// One root cause: the same rule on the same element (or source line, or — for a page-level finding —
/// the same message with its numbers masked) wherever it turned up, across pages and viewports.
struct FindingGroup<'a> {
    rule: String,
    severity: String,
    first: &'a Value,
    places: Vec<(String, String)>,
}

/// The findings as an agent should work them: grouped by root cause, most severe first, then the ones
/// that turn up in the most places. The prose used to list them page by page, up to 30 a page, so a
/// shared header's hover gap was a separate entry on every route — 71 warnings for one run (a field
/// report, 2026-09-24) — when it is one edit. "Fix once, not N times" is what positive verdicts praise
/// most; this puts it at the top of the result instead of leaving the agent to discover it.
fn finding_groups(report: &Value) -> Vec<FindingGroup<'_>> {
    let rank = |s: &str| match s {
        "error" => 0,
        "warn" => 1,
        _ => 2,
    };
    let mut groups: Vec<FindingGroup> = Vec::new();
    let mut index: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    for page in report["pages"].as_array().into_iter().flatten() {
        let route = page["route"].as_str().unwrap_or("").to_string();
        let viewport = page["viewport"].as_str().unwrap_or("").to_string();
        for f in page["findings"].as_array().into_iter().flatten() {
            let rule = f["rule"].as_str().unwrap_or("").to_string();
            if rule.is_empty() {
                continue; // a paywall-locked stub: no rule, nothing to act on
            }
            let sel = f["sel"].as_str().unwrap_or("");
            let key = match f["source"].as_str() {
                Some(src) => format!("src:{src}"),
                None if !sel.is_empty() && sel != "page" && sel != "site" => format!("sel:{sel}"),
                // Page-level: the message IS the identity, but "3 requests failed" and "2 requests
                // failed" are the same problem on two pages.
                None => format!(
                    "msg:{}",
                    f["msg"]
                        .as_str()
                        .unwrap_or("")
                        .chars()
                        .map(|c| if c.is_ascii_digit() { '#' } else { c })
                        .collect::<String>()
                ),
            };
            let sev = f["severity"].as_str().unwrap_or("").to_string();
            match index.get(&(rule.clone(), key.clone())) {
                Some(&i) => {
                    let g = &mut groups[i];
                    if rank(&sev) < rank(&g.severity) {
                        g.severity = sev;
                    }
                    if !g.places.contains(&(route.clone(), viewport.clone())) {
                        g.places.push((route.clone(), viewport.clone()));
                    }
                }
                None => {
                    index.insert((rule.clone(), key), groups.len());
                    groups.push(FindingGroup {
                        rule,
                        severity: sev,
                        first: f,
                        places: vec![(route.clone(), viewport.clone())],
                    });
                }
            }
        }
    }
    // Stable: equal groups keep report order, which is the server's own priority within a page.
    groups.sort_by_key(|g| (rank(&g.severity), std::cmp::Reverse(g.places.len())));
    groups
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
///
/// It is a LIVE link, not instructions. This process opens the callback port before answering, so one
/// click does the whole thing: sign in (or sign up), token minted, token saved here. The alternative
/// — "create a token in settings, then copy it into your MCP config" — is four steps across two apps
/// with a secret carried by hand, and it's where first-run installs are lost.
fn signup_hint(server: &str) -> String {
    let web = crate::login::web_base(server);
    let Ok(url) = crate::login::pending_login_url(&web, server) else {
        // No local port to listen on (locked-down box, exhausted ports). The manual route still
        // works, so fall back to it rather than turning a setup step into a dead end.
        return crate::login::credential_help(
            server,
            crate::login::CredentialProblem::Missing,
            true,
        );
    };
    format!(
        "uxlint isn't signed in yet, so it can't reach the server.\n\n\
         Show the user this link and ask them to open it — you can't open it yourself, and they \
         don't have to copy anything back:\n\n  {url}\n\n\
         It signs them in (creating an account if they don't have one), mints an access token, and \
         saves it here automatically. Then call this tool again — it picks the token up on the next \
         call, with nothing to restart.\n\n\
         The link is live for 15 minutes. The `port=` in it is THIS server listening for the token, \
         not a site to visit; if it expires, calling the tool again issues a fresh one."
    )
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
         # DATA SHARING — ASK THE USER, in words, before you write this line, and write `true` only\n\
         # if they say yes. `feedback = true` shares general, anonymized signals about which lints\n\
         # helped (never your app's content or its URLs), and in exchange gives you the lint_feedback\n\
         # tool, so a wrong finding can be reported while you still have the context. It is OFF by\n\
         # default and it is THEIR call, not yours: leave the line out if they decline or don't answer.\n\
         # They can change it later with `uxlint init`.\n\
         feedback = false\n\n\
         Optional — add one only when it applies, never as a guess:\n  \
         site_type = \"saas\"          # saas | marketing | ecommerce | content | portfolio | aggregator\n  \
         styleguide = \"/styleguide\"  # the design-system page, if this project has one\n  \
         exclude = [\"/admin/*\"]      # routes the audit must never open (demos, fixtures, destructive tools)\n  \
         desktop_only = [\"/editor/*\"] # desktop-primary surfaces, so mobile findings there stay info-level\n\n  \
         [page_kinds]                 # only if a report shows a page read as the wrong kind\n  \
         \"/projects/*/edit\" = \"app-workspace\"  # marketing | document | auth | app | app-collection | app-record | app-workspace | app-form\n\n\
         If the app is behind a login, add a persona — the local client replays it, so no secret \
         reaches this tool or the transcript. Ask the user for the credential; a real secret goes in \
         a gitignored .env as ${{VAR}}, only a throwaway dev login is ever inlined:\n\n  \
         login_url       = \"/login\"\n  \
         default_persona = \"user\"\n  \
         [personas.user]\n  \
         username = \"dev@example.com\"\n  \
         password = \"${{DEV_PW}}\"\n\n\
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
    let web = crate::login::web_base(server);
    let Ok(url) = crate::login::pending_login_url(&web, server) else {
        return crate::login::credential_help(
            server,
            crate::login::CredentialProblem::Rejected,
            true,
        );
    };
    // Same one-click replacement as first run — a revoked token isn't a harder problem, it's the same
    // mint with a different explanation — but the explanation has to lead, or the agent restarts an
    // onboarding this person finished long ago.
    format!(
        "uxlint's saved credential was refused by the server — it has most likely been revoked (an \
         admin can invalidate tokens, and incident response rotates them). Nothing is wrong with \
         the setup; the token just needs replacing, and a revoked one never comes back, so \
         re-running as-is fails identically.\n\n\
         Show the user this link and ask them to open it — it signs them in, mints a REPLACEMENT \
         token, and saves it here automatically:\n\n  {url}\n\n\
         Then call this tool again; it picks the new token up on the next call, with nothing to \
         restart. The link is live for 15 minutes, and the `port=` in it is THIS server listening \
         for the token, not a site to visit."
    )
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
    /// `full` for every finding's fix, best practice, rect and screenshot URL in the structured
    /// result. Default is compact: every finding, with each rule's fix said once — the full form can
    /// run past a client's output limit on a big site.
    #[serde(default)]
    detail: Option<String>,
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

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct GetReportArgs {
    /// The report to read: its URL as the dashboard shows it (`https://uxlint.net/sites/8/r/abc123`),
    /// a `/r/…` path, or the bare report id.
    report: String,
    /// `full` for every finding's fix, best practice, rect and screenshot URL in the structured
    /// result; compact by default (see audit_url).
    #[serde(default)]
    detail: Option<String>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct GetFeedbackArgs {
    /// How far back to look, and the size of the window it is compared against: `7d`, `14d`
    /// (default), `30d`, `90d`, or `all`.
    #[serde(default)]
    window: Option<String>,
    /// A `cursor` from a previous call — returns only what has changed since then, still measured
    /// against the same-length window before it. This is how you keep a running watch without
    /// re-reading everything you have already triaged.
    #[serde(default)]
    since: Option<String>,
    /// One rule name, for its full pushback prose and the elements it hit. Omit for the digest.
    #[serde(default)]
    rule: Option<String>,
    /// How many rules the digest lists (default 10, max 50). Whatever it hides is counted in the
    /// footer, never dropped silently.
    #[serde(default)]
    limit: Option<u32>,
    /// Show complaints that have already been archived as well — the audit view for "what is the
    /// archive currently hiding?", and the way to find an entry that was recorded wrongly.
    #[serde(default)]
    include_archived: Option<bool>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct ArchiveFeedbackArgs {
    /// The rule whose complaints you have dealt with — or `new lint` for an idea the digest shows as
    /// `[new lint]` (it has no rule yet; pass its exact text as `reason`).
    rule: String,
    /// The exact reason text as `get_feedback` printed it — closes just that complaint. Omit to close
    /// EVERY complaint on the rule, which is a much bigger claim: only do it when you have read them.
    #[serde(default)]
    reason: Option<String>,
    /// What was done: `fixed` (the rule was wrong and now isn't), `wont_fix` (the rule is right on
    /// that element after all), `retired` (the rule is gone).
    #[serde(default)]
    outcome: Option<String>,
    /// What you actually did — which guard you added and where, or why the rule is right after all.
    /// Required, and held to a real sentence: in aggregate these notes are the changelog of why each
    /// lint looks the way it does.
    #[serde(default)]
    note: Option<String>,
    /// Close complaints up to this instant (default: now). Anything filed later stays live.
    #[serde(default)]
    through: Option<String>,
    /// Undo instead: remove the archive entries for this rule (and `reason`, if given), putting those
    /// complaints back in the digest.
    #[serde(default)]
    revert: Option<bool>,
    /// Where the fix lives — REQUIRED for `outcome=fixed`: the uxlint commit sha that fixed it, or the
    /// CLI release that ships it (`cli v0.1.37`). The digest uses it to say whether the fix is live on
    /// prod yet, so "fixed" stops meaning "fixed somewhere".
    #[serde(default)]
    fix_ref: Option<String>,
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
    /// The credential was given explicitly (`--api-key` / `UXLINT_API_KEY`) rather than read from the
    /// credentials file, so it must NOT be re-read per call. See `call_cli`.
    key_is_explicit: bool,
}

/// Only an explicit execution receipt can establish a pass. Old servers, unknown rule names,
/// site/judge/interaction checks and missing captures must never turn zero hits into success.
fn verification_status(
    report: &Value,
    rule: &str,
    route: &str,
    hits: usize,
    withheld: bool,
) -> &'static str {
    if hits > 0 || withheld {
        return "failed";
    }
    let Some(checks) = report["verification"]["checks"]
        .as_array()
        .filter(|_| report["verification"]["schema"] == 1)
    else {
        return "not_evaluated";
    };
    let matching: Vec<_> = checks
        .iter()
        .filter(|c| c["rule"] == rule && c["route"] == route)
        .collect();
    if matching.iter().any(|c| c["status"] == "failed") {
        return "failed";
    }
    if report["timed_out"] == true {
        return "inconclusive";
    }
    if matching.is_empty() {
        return "not_evaluated";
    }
    if matching.iter().any(|c| c["status"] != "passed") {
        return "inconclusive";
    }
    // verify_fix requests both viewports. A missing mobile capture is not a mobile pass.
    for viewport in ["desktop", "mobile"] {
        let Some(pages) = report["pages"].as_array() else {
            return "inconclusive";
        };
        let pages: Vec<_> = pages
            .iter()
            .filter(|p| p["route"] == route && p["viewport"] == viewport)
            .collect();
        if pages.is_empty()
            || pages.iter().any(|p| {
                !matching.iter().any(|c| {
                    c["viewport"] == viewport
                        && c["state"].as_str().unwrap_or("anonymous")
                            == p["state"].as_str().unwrap_or("anonymous")
                })
            })
        {
            return "inconclusive";
        }
    }
    "passed"
}

fn cleared_text(rule: &str, route: &str, others: &str) -> String {
    format!("✓ {rule} is CLEAR on {route} — verified for THIS PAGE in the captured desktop/mobile states. This confirms the check cleared; it does not establish that the edit improved the UX. Re-run audit_url to check the wider site.{others}")
}

#[tool_router(router = tool_router)]
impl UxlintMcp {
    fn new(cli: Arc<Cli>, default_base: Option<String>, admin_tools: bool) -> Self {
        let feedback_enabled = crate::project::project_feedback_enabled();
        // Did the credential come from --api-key/UXLINT_API_KEY, or from the file `uxlint auth login`
        // writes? main.rs falls back to the file, so "differs from the file" IS the explicit case —
        // and only the file-sourced one may be re-read per call (see `call_cli`).
        let key_is_explicit =
            cli.api_key.is_some() && cli.api_key != crate::login::stored_credential();
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
        // Same mechanism, different switch: the staff digest is absent from `list_tools` AND
        // rejected by `call_tool` on any launch that didn't ask for it.
        if !admin_tools {
            tool_router.remove_route("get_feedback");
            tool_router.remove_route("archive_feedback");
        }
        Self {
            cli,
            tool_router,
            feedback_enabled,
            default_base,
            key_is_explicit,
        }
    }

    /// The config for THIS call, with the credential re-read from the credentials file.
    ///
    /// An MCP server is long-lived — an editor starts it once and keeps it for the whole session —
    /// and the sign-in link `signup_hint` hands out completes DURING that session. Resolving the key
    /// once at startup meant the token landed on disk and the very next call still said "not signed
    /// in", which is why the old copy had to end with "restart your editor": a setup step that reads
    /// as "it didn't work". The same applies to a REVOKED token being replaced — the stale key would
    /// otherwise be re-sent until the editor restarted, so the re-mint appears to have done nothing.
    ///
    /// An explicit `--api-key`/`UXLINT_API_KEY` is left exactly as given: that's an operator's
    /// deliberate choice (CI, a second account) and must not be silently swapped for whatever the
    /// file happens to hold. Only a file-sourced credential tracks the file.
    fn call_cli(&self) -> Arc<Cli> {
        if self.key_is_explicit {
            return self.cli.clone();
        }
        let stored = crate::login::stored_credential();
        if stored == self.cli.api_key {
            return self.cli.clone();
        }
        let mut cli = (*self.cli).clone();
        cli.api_key = stored;
        Arc::new(cli)
    }

    #[tool(
        description = "Audit a website's UX/design: contrast, tap targets, type scale, colour discipline, copy clarity, scan patterns. Each finding returns its RULE name (pass it to verify_fix), a SOURCE file:line hint (for local audits, grepped from the project you're in), the SELECTOR, the concrete FIX, and — for copy issues — the exact text EDIT (replace X with Y).\n\nWORKFLOW: (1) Before you change anything, call ux_guidance for the area(s) the findings touch (forms, lists, layout, copy, …) so you fix toward the idiomatic, DRY pattern — not a one-off patch. If the result names a STYLEGUIDE, open it first and build to the components/tokens it shows. (2) Open the source line and apply the SMALLEST fix that reuses the project's existing components/tokens and voice (don't add a new one-off to silence the finding) without regressing the quality floor — responsive, visible keyboard focus, reduced motion, no new layout shift — then verify_fix. (3) Iterate until green. If a lint_feedback tool is in your tool list, also send a verdict for each finding you act on — it's how rules get kept, tuned or retired. It is absent unless the project set `feedback = true` (via `uxlint init`), so don't go looking for it: this result tells you when it's there.\n\nSAFETY: interaction probes navigate, read, and click candidate menu/disclosure/dialog controls. Discovery skips recognised action words — delete, remove, accept, leave, revoke, pay, publish, add, create, save — using the full label. Labels cannot guarantee a click has no side effects; use an environment you control with disposable data. the write probes (which click Add/Create, and Delete through its confirm dialog) need the CLI's own --allow-mutation flag, which is not reachable from here. Declared tests are the exception and the only one: if the project's uxlint.toml declares tests that sign in as a persona, running them will SUBMIT forms and may DELETE items — that's what a test does, and it exercises create/delete flows on your own app. Point it only at an app you own / a throwaway env, never a site you don't control.\n\nSETUP: in a project with no uxlint.toml, this returns the exact config to write first (org/site/base/routes) — write that file, check it in, then call again. Without it a local target can't be audited at all and a public one files its report under a site nobody chose.\n\nAUTH: for a logged-in site, DON'T pass secrets here — credentials come from the project's uxlint.toml [personas] (the local client replays them; nothing touches this tool call or the transcript). If the audit hits a login wall, this tool returns the exact setup instructions."
    )]
    async fn audit_url(
        &self,
        Parameters(a): Parameters<AuditUrlArgs>,
        meta: Meta,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let full = a.detail.as_deref() == Some("full");
        if self.call_cli().api_key.is_none() {
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
        let cli = self.call_cli();
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
            // crawl=0 means EXACTLY the routes asked for: no crawl, no project default routes, and no
            // pages the tests wander through (field report, 2026-09-24).
            exact_routes: a.crawl == Some(0),
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
            // …but NEVER the mutating half. States are something you look at; Add/Create/Delete are
            // something you do, and an agent calling this tool has made no such choice on its user's
            // behalf. This is the surface whose own description promised "only NAVIGATES and READS",
            // and it is now the surface that keeps that promise unconditionally.
            allow_mutation: false,
            accept_target: false,
            crawl: a.crawl.unwrap_or(12) as usize,
            parallel: None, // auto: full throttle locally, polite on public hosts
            probe_errors: false,
            resilience: false,
            slow_network: false,
            timeout: None,
            fix_plan: false,
            // Previews ON, same as a hand-run audit. They cost real time — measured at 13.7s → 42.8s
            // on a one-page audit — and the AGENT reads text, so this looks like pure overhead from
            // the tool's side. It isn't: the report we hand the user is the artifact they open, and a
            // finding with a before/after crop is the fastest way for either of them to see what it
            // means. An audit whose report looks different depending on who ran it is the kind of
            // inconsistency nobody remembers when the screenshots are missing months later.
            no_previews: false,
            // Judge/tests default ON (an agent auditing its own UI wants the full picture),
            // but both are switchable so the fast deterministic pass I reach for is one call.
            no_judge: !a.judge.unwrap_or(true),
            // Goals auto-scope (a crawling audit runs them, a targeted one skips) and run in
            // parallel; `tests:false` forces them off entirely for speed.
            no_tests: !a.tests.unwrap_or(true),
            rule: None,
            preview_rule: None, // a full audit previews every finding

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
        let cli = self.call_cli();
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
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let (elapsed, cap) = partial.clock();
                        let Some(message) = progress_message(partial.snapshot(), elapsed, cap) else {
                            continue;
                        };
                        // `progress` is the CLOCK, not the page count: MCP requires it to rise with
                        // every notification, and the clock is the one measure that always does — a
                        // page count sits still through discovery and through one slow route, which
                        // is exactly when a caller decides the audit has hung. The cap is the
                        // honest total while the browser phase runs; past it (the server's AI
                        // review) there is no bound to promise, so none is sent.
                        let mut n = ProgressNotificationParam::new(token.clone(), elapsed as f64).with_message(message);
                        if cap > elapsed {
                            n = n.with_total(cap as f64);
                        }
                        let _ = client.notify_progress(n).await;
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
                structured = audit_structured(&report, &self.cli.server, full);
                agent_prose(&report, &self.cli.server, self.feedback_enabled)
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
        description = "After editing to fix a finding, re-check ONE rule on ONE page — the 'did my fix land?' loop, far quicker than a full re-audit (one route, no crawl, no judge). Returns whether the rule still fires, AND names any OTHER deterministic findings now on that page (the regression guard — so a fix that clears your rule but breaks something else here doesn't read as all-clear). Returns status passed, failed, not_evaluated or inconclusive. A pass requires explicit server evidence for the requested route and both viewports. Currently supported passing checks: page-title-missing, html-lang-missing, horizontal-overflow. Other rules can report observed failures but cannot pass without execution evidence; re-run audit_url for judge, interaction and site checks. Unknown rules and missing evidence never clear. A cleared finding is not a user endorsement of the fix."
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
            exact_routes: true,
            viewports: "desktop:1440x900,mobile:390x844".into(),
            // Auth (if any) comes from uxlint.toml [personas], never from the MCP call.
            headers: Vec::new(),
            storage: Vec::new(),
            login_url: None,
            username: None,
            password: None,
            states: a.states.unwrap_or(false),
            allow_mutation: false, // verify_fix re-checks a page; it never rehearses its delete flow
            accept_target: false,
            crawl: 1,
            rule: None,
            // Crops scoped to the rule under test; the audit still reports everything it finds on
            // the page, which is what makes the regression guard work.
            preview_rule: Some(rule.clone()),

            parallel: None,
            probe_errors: false,
            resilience: false,
            slow_network: false,
            timeout: None,
            fix_plan: false,
            // Previews here too: a re-check writes a report like any other audit, and a report whose
            // screenshots depend on which tool produced it is a trap for whoever opens it later.
            // It costs seconds the tight fix loop used to save (measured 14s → 29s on a page with
            // seven contrast instances), which is why `preview_rule` scopes the crops to the rule
            // under test. The stale "~2s" the description used to promise was never true anyway.
            no_previews: false,
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
        if self.call_cli().api_key.is_none() {
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                signup_hint(&self.cli.server),
            )]));
        }
        let cli = self.call_cli();
        let rule_for_task = rule.clone();
        let route_for_task = route.clone();
        let feedback_enabled = self.feedback_enabled;
        // Browser capture and report submission block; keep them off the MCP transport thread.
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
                        .filter(|p| p["route"] == route)
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
                            if p["route"] != route { continue; }
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
                    let status = verification_status(&report, &rule, &route, hits, withheld);
                    structured = json!({
                        "report_url": report["report_url"], "report_id": report_id,
                        // `scope` is the caveat in machine-readable form: `cleared` is a claim about
                        // this PAGE, and a site-scoped rule needs a full audit to be settled.
                        "rule": rule, "route": route, "cleared": status == "passed", "status": status, "execution": report["verification"], "scope": "page", "hits": hits, "withheld": withheld,
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
                    } else if status == "not_evaluated" || status == "inconclusive" {
                        format!("▲ {rule}: {status} on {route}. No passing execution evidence covers this rule on both requested viewports. The finding is NOT verified as cleared. Re-run audit_url with the original routes, personas and required probes; inspect its evidence before declaring the fix complete.{}", others_line("Also:"))
                    } else if status == "passed" {
                        // Cleared — but name any OTHER findings still on the page so this isn't read
                        // as "the page is done." That's the whack-a-mole guard.
                        cleared_text(&rule, &route, &others_line("Heads-up:"))
                    } else {
                        let mut m = format!("▲ {rule} STILL FIRES on {route} — the check observed a failure ({hits} visible occurrence(s); grouped findings may appear elsewhere in the report).");
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
        if self.call_cli().api_key.is_none() {
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                signup_hint(&self.cli.server),
            )]));
        }
        let cli = self.call_cli();
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
        description = "Read an EXISTING report's findings — one the user started from the dashboard, a run whose audit_url call you lost, or one that TIMED OUT (it keeps whatever it found before the cap, and says so). Pass the report's URL as the user sees it (…/r/<id>) or its id. Returns the same thing audit_url does: the grade, what moved since the last run, and every finding with its rule, location, source hint, fix and screenshot_url — so you can act on it and confirm each fix with verify_fix. Reports are private; this reads them with your uxlint login."
    )]
    async fn get_report(
        &self,
        Parameters(a): Parameters<GetReportArgs>,
    ) -> Result<CallToolResult, McpError> {
        let full = a.detail.as_deref() == Some("full");
        if self.call_cli().api_key.is_none() {
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                signup_hint(&self.cli.server),
            )]));
        }
        let cli = self.call_cli();
        let result = tokio::task::spawn_blocking(move || {
            let server = cli.server.trim_end_matches('/').to_string();
            let id = parse_report_ref(&a.report, &server)?;
            // The id is the ONLY thing taken from the caller: the request always goes to our own
            // server, so the login token can't be steered at another host by a crafted URL.
            let resp = reqwest::blocking::Client::new()
                .get(format!("{server}/v1/reports/{id}"))
                .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
                .send();
            let mut report: Value = match resp {
                Ok(r) if r.status().is_success() => r
                    .json()
                    .map_err(|e| format!("the report came back unreadable: {e}"))?,
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    return Err(credential_rejected(&cli.server))
                }
                Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND || r.status() == reqwest::StatusCode::FORBIDDEN => {
                    return Err(format!("no report {id} that this login can read — check the id, and that you're signed in to the org that owns it"))
                }
                Ok(r) => return Err(failure_text(r)),
                Err(e) => return Err(format!("could not fetch the report: {e}")),
            };
            // The stored report doesn't always carry its own URL (it's minted when the POST
            // returns), and the screenshot links and verify_fix hints are keyed off it.
            if report["report_url"].as_str().is_none_or(str::is_empty) {
                report["report_url"] = json!(format!("{server}/r/{id}"));
            }
            Ok(report)
        })
        .await
        .map_err(|e| McpError::internal_error(format!("get_report task panicked: {e}"), None))?;
        match result {
            Ok(report) => {
                let text = agent_prose(&report, &self.cli.server, self.feedback_enabled);
                let mut r = CallToolResult::success(vec![ContentBlock::text(text)]);
                r.structured_content = Some(audit_structured(&report, &self.cli.server, full));
                Ok(r)
            }
            Err(msg) => Ok(CallToolResult::success(vec![ContentBlock::text(msg)])),
        }
    }

    // uxlint STAFF only, and absent from the router unless the server was launched with `--admin`
    // (`UXLINT_ADMIN_TOOLS=1`) — the same `remove_route` mechanism `lint_feedback` uses, so the tool
    // is hidden from `list_tools` AND rejected by `call_tool` with no second enforcement point. The
    // flag is only about VISIBILITY: the server checks the admin role on every call, so a
    // non-staff account that passes the flag gets a tool that politely says no.
    #[tool(
        name = "get_feedback",
        description = "uxlint STAFF: read what has CHANGED in the lint feedback other agents and users are filing on uxlint's own rules — not the whole log.\n\nReturns a ranked digest for a window compared against the window before it: rules that started drawing pushback, rules drawing MORE of it, rules that went quiet after a guard shipped, each with this window's deduped reasons (the same sentence from five agents is one bug with a count of five), plus any new lint suggestions. Harmful verdicts — where acting on one of our findings made a real site worse — are always shown in full, first, whatever the limit.\n\nUSE IT: at the start of a lint-tuning session, to decide where the hour goes; after shipping a guard, to confirm the pushback actually stopped.\n\nARGS: `window` (7d / 14d default / 30d / all) · `rule=<name>` for one rule's full prose and the elements it hit · `limit` for how many rules the digest lists (what it hides is counted, never dropped silently) · `since=<cursor from a previous response>` for only what has changed since — the digest ends with the cursor to use next · `include_archived=true` to also see complaints already closed by archive_feedback.\n\nNOTE the counts say a rule is disputed; only the reasons say what to change. A complaint older than the rule's last edit may already be answered — the digest's footer names the command that checks. And when you HAVE dealt with one, call archive_feedback: that is the only thing that closes a feedback row, and anything you leave open comes back at you next window as if it were new."
    )]
    async fn get_feedback(
        &self,
        Parameters(a): Parameters<GetFeedbackArgs>,
    ) -> Result<CallToolResult, McpError> {
        if self.call_cli().api_key.is_none() {
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                signup_hint(&self.cli.server),
            )]));
        }
        let cli = self.call_cli();
        let result = tokio::task::spawn_blocking(move || {
            let server = cli.server.trim_end_matches('/').to_string();
            let mut q: Vec<String> = Vec::new();
            let mut add = |k: &str, v: Option<&str>| {
                if let Some(v) = v.map(str::trim).filter(|v| !v.is_empty()) {
                    q.push(format!("{k}={}", pct(v)));
                }
            };
            add("window", a.window.as_deref());
            add("since", a.since.as_deref());
            add("rule", a.rule.as_deref());
            let limit = a.limit.map(|n| n.to_string());
            add("limit", limit.as_deref());
            if a.include_archived.unwrap_or(false) {
                q.push("include_archived=true".to_string());
            }
            let query = if q.is_empty() {
                String::new()
            } else {
                format!("?{}", q.join("&"))
            };
            let resp = reqwest::blocking::Client::new()
                .get(format!("{server}/v1/lints/feedback/trends{query}"))
                .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
                .send();
            match resp {
                Ok(r) if r.status().is_success() => {
                    let v: Value = r
                        .json()
                        .map_err(|e| format!("could not read the digest: {e}"))?;
                    // The server renders the page (one ranking, one place); the structured arrays
                    // ride in the same body for anything that needs to compute on them. Falling
                    // back to the raw JSON keeps an older/newer server readable rather than blank.
                    Ok(v["report"]
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| serde_json::to_string_pretty(&v).unwrap_or_default()))
                }
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    Err(credential_rejected(&cli.server))
                }
                Ok(r) if r.status() == reqwest::StatusCode::FORBIDDEN => Err(format!(
                    "the lint-feedback digest is uxlint staff only — {server} says this account \
                     doesn't have the admin role. Nothing is wrong with your setup; this tool is \
                     simply not for this account."
                )),
                Ok(r) => Err(failure_text(r)),
                Err(e) => Err(format!("could not reach {server}: {e}")),
            }
        })
        .await
        .map_err(|e| McpError::internal_error(format!("get_feedback task panicked: {e}"), None))?;
        // Both arms are text for the agent to read — a refusal it can act on beats a protocol error.
        let text = match result {
            Ok(t) | Err(t) => t,
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    // The write half of the staff loop, behind the same `--admin` switch as `get_feedback`.
    #[tool(
        name = "archive_feedback",
        description = "uxlint STAFF: close a lint complaint OR a lint idea you have EVALUATED — record what you did about it so it stops coming back.\n\nNothing else closes one. A complaint you fixed last month is still in the digest, indistinguishable from one filed this morning, and re-triaging already-answered rows is the single biggest waste in this loop. Archive it and the next digest is only what's actually open.\n\nCALL IT after you have acted, once per thing you dealt with: `rule` plus the exact `reason` text from the digest closes THAT item — a verdict's reason or a suggestion's text, both matched the same way (an idea the digest shows as `[new lint]` has no rule yet: pass `rule=\"new lint\"`, and its text is then required); omitting `reason` closes every complaint AND idea on the rule, which is a much bigger claim — only do it when you have read them all.\n\nIt REFUSES (404) when nothing matches, rather than reporting success for having closed nothing: if you get that, check the rule name and that `reason` is the exact text the digest printed — it is matched whole, never by substring. `outcome` is fixed | wont_fix | retired, and `note` (required, a real sentence) says what you actually did: which guard you added and where, or why the rule is right on that element after all. A `fixed` also needs `fix_ref` — the uxlint commit sha, or `cli vX.Y.Z` for a CLI fix — so the digest can say whether it is live on prod yet.\n\nSAFE BY DESIGN: nothing is deleted. The rows stay, `get_feedback include_archived=true` shows what the archive is hiding, `revert: true` undoes an entry — and a complaint REFILED after you archived it comes back live on its own, which is exactly the signal you want if the guard didn't work."
    )]
    async fn archive_feedback(
        &self,
        Parameters(a): Parameters<ArchiveFeedbackArgs>,
    ) -> Result<CallToolResult, McpError> {
        if self.call_cli().api_key.is_none() {
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                signup_hint(&self.cli.server),
            )]));
        }
        let cli = self.call_cli();
        let result = tokio::task::spawn_blocking(move || {
            let server = cli.server.trim_end_matches('/').to_string();
            let revert = a.revert.unwrap_or(false);
            let body = json!({
                "rule": a.rule,
                "reason": a.reason.unwrap_or_default(),
                "outcome": a.outcome.unwrap_or_default(),
                "note": a.note.unwrap_or_default(),
                "through": a.through.unwrap_or_default(),
                "revert": revert,
                "fix_ref": a.fix_ref.unwrap_or_default(),
            });
            let resp = reqwest::blocking::Client::new()
                .post(format!("{server}/v1/lints/feedback/archive"))
                .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
                .json(&body)
                .send();
            match resp {
                Ok(r) if r.status().is_success() => {
                    let v: Value = r
                        .json()
                        .map_err(|e| format!("could not read the response: {e}"))?;
                    if revert {
                        return Ok(format!(
                            "reverted {} archive entr{} on {} — those complaints are back in the digest.",
                            v["reverted"].as_i64().unwrap_or(0),
                            if v["reverted"].as_i64() == Some(1) { "y" } else { "ies" },
                            v["rule"].as_str().unwrap_or("?")
                        ));
                    }
                    Ok(archive_confirmation(&v))
                }
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    Err(credential_rejected(&cli.server))
                }
                Ok(r) if r.status() == reqwest::StatusCode::FORBIDDEN => Err(format!(
                    "archiving lint feedback is uxlint staff only — {server} says this account \
                     doesn't have the admin role."
                )),
                Ok(r) => Err(failure_text(r)),
                Err(e) => Err(format!("could not reach {server}: {e}")),
            }
        })
        .await
        .map_err(|e| {
            McpError::internal_error(format!("archive_feedback task panicked: {e}"), None)
        })?;
        let text = match result {
            Ok(t) | Err(t) => t,
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(
        description = "Project design memory and best-practice UI guidance to read BEFORE building or changing UI — usability, consistency, and performance patterns distilled from uxlint's audit corpus, so you build idiomatic, DRY, testable components the first time instead of getting audited after. Reads the nearest project’s uxlint.design.json on each call; only explicitly approved versioned decisions guide edits. Never auto-approve or rewrite that contract to silence a lint. Covers whole-row click targets, single-column labelled forms, tabs/radiogroup vs plain buttons, one shared width scale + aligned panels, pagination by scroll length, CLS-safe layout, and copy that reads as UI (active voice, honest labels, useful empty/error states). Each item names the uxlint rule that catches a miss, so the loop is: read the topic, build to it, then audit_url to confirm."
    )]
    async fn ux_guidance(
        &self,
        Parameters(a): Parameters<UxGuidanceArgs>,
    ) -> Result<CallToolResult, McpError> {
        let topic = a.topic.as_deref().unwrap_or("");
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{}{}",
            crate::design_memory::guidance(),
            crate::guidance::guidance(topic)
        ))]))
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
        let cli = self.call_cli();
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
pub(crate) fn run_mcp(cli: &Cli, base: Option<String>, admin_tools: bool) -> anyhow::Result<()> {
    let cli = Arc::new(cli.clone());
    // A blank `--base ""` is the same as not passing one (fall through to per-call / uxlint.toml).
    let base = base.filter(|b| !b.trim().is_empty());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let service = UxlintMcp::new(cli, base, admin_tools)
            .serve(stdio())
            .await?;
        service.waiting().await?;
        Ok::<_, anyhow::Error>(())
    })
}

#[cfg(test)]
mod report_tool_tests {
    use super::{parse_report_ref, report_text};
    use serde_json::json;

    const PROD: &str = "https://uxlint.net";

    #[test]
    fn takes_what_a_person_actually_pastes() {
        // THE 2026-09-24 report: the agent was handed this exact dashboard link and had no tool that
        // could read it — get_shot on it returned the SPA shell.
        assert_eq!(
            parse_report_ref("https://uxlint.net/sites/8/r/wmwtdtwoa5sa", PROD).unwrap(),
            "wmwtdtwoa5sa"
        );
        assert_eq!(
            parse_report_ref("wmwtdtwoa5sa", PROD).unwrap(),
            "wmwtdtwoa5sa"
        );
        assert_eq!(parse_report_ref("  /r/abc123  ", PROD).unwrap(), "abc123");
        // A screenshot link or a query on the end still names the same report.
        assert_eq!(
            parse_report_ref("https://uxlint.net/r/abc123/annot?route=/x", PROD).unwrap(),
            "abc123"
        );
        assert_eq!(
            parse_report_ref("https://uxlint.net/sites/8/r/abc123?tab=all#f3", PROD).unwrap(),
            "abc123"
        );
    }

    #[test]
    fn a_report_on_another_server_says_so_instead_of_404ing() {
        let err = parse_report_ref("https://dev.uxlint.net/sites/2/r/abc123", PROD).unwrap_err();
        assert!(
            err.contains("dev.uxlint.net") && err.contains("uxlint.net"),
            "{err}"
        );
        // …and a local server's own links are accepted against the local server.
        assert_eq!(
            parse_report_ref("http://127.0.0.1:49800/r/abc123", "http://127.0.0.1:49800/").unwrap(),
            "abc123"
        );
    }

    #[test]
    fn junk_is_refused_before_anything_is_fetched() {
        assert!(parse_report_ref("", PROD).is_err());
        assert!(parse_report_ref("https://uxlint.net/dashboard", PROD).is_err());
        assert!(
            parse_report_ref("../../v1/me", PROD).is_err(),
            "a path must never become the id"
        );
    }

    #[test]
    fn a_timed_out_report_reads_back_with_its_findings_and_the_warning() {
        // What get_report exists for: the run hit its cap, but what it found is in the report.
        let report = json!({
            "report_url": "https://uxlint.net/sites/8/r/abc123",
            "timed_out": true,
            "timeout_detail": {"cap_secs": 300, "pages_captured": 3, "pages_planned": 9, "walks_done": 0, "walks_planned": 2},
            "errors": 1, "warnings": 0, "infos": 0,
            "pages": [{"route": "/timeline", "viewport": "desktop", "findings": [
                {"rule": "contrast", "severity": "error", "msg": "Low contrast", "fix": "darken it", "sel": ".x", "rect": [1, 2, 3, 4]}
            ]}]
        });
        let t = report_text(&report, PROD, false);
        assert!(t.contains("TIMED OUT") && t.contains("3/9 pages"), "{t}");
        assert!(t.contains("[error] contrast (/timeline·desktop)"), "{t}");
        assert!(
            t.contains("https://uxlint.net/r/abc123/annot?route=/timeline"),
            "{t}"
        );
    }

    #[test]
    fn progress_speaks_before_the_first_page_and_always_shows_the_clock() {
        use super::progress_message;
        let snap = |d, t, phase: &str| (d, t, 0, 0, phase.to_string());
        // THE 2026-09-24 report: minutes of silence before any page landed read as a hang.
        assert_eq!(
            progress_message(snap(0, 0, "crawl"), 12, 300).unwrap(),
            "finding pages to audit · 12s of 5m"
        );
        assert_eq!(
            progress_message(snap(3, 24, "crawl"), 100, 300).unwrap(),
            "crawl: 3/24 pages · 1m 40s of 5m"
        );
        assert_eq!(
            progress_message((24, 24, 1, 2, "walks".into()), 200, 300).unwrap(),
            "tests: 1/2 · 3m 20s of 5m"
        );
        // Past the cap the server is still working — no "of 5m" it has already overrun.
        assert_eq!(
            progress_message(snap(12, 24, "server"), 330, 300).unwrap(),
            "AI review of the captured pages · 5m 30s"
        );
        // Nothing has started: say nothing rather than something made up.
        assert_eq!(progress_message(snap(0, 0, ""), 0, 0), None);
    }

    #[test]
    fn closing_a_lint_idea_says_so_instead_of_zero_verdicts() {
        use super::archive_confirmation;
        // THE 2026-09-24 confusion: a successful close of a new-lint idea printed "archived 0 verdicts on  as fixed".
        let idea = json!({"rule": "", "outcome": "fixed", "archived": 0, "suggestions": 1, "scope": "reason"});
        assert!(archive_confirmation(&idea)
            .starts_with("archived 1 lint idea on new lint as fixed (reason scope)"));
        let both = json!({"rule": "contrast", "outcome": "fixed", "archived": 3, "suggestions": 2, "scope": "rule"});
        assert!(archive_confirmation(&both)
            .starts_with("archived 3 verdicts and 2 lint ideas on contrast"));
        let one = json!({"rule": "contrast", "outcome": "wont_fix", "archived": 1, "suggestions": 0, "scope": "reason"});
        assert!(
            archive_confirmation(&one).starts_with("archived 1 verdict on contrast as wont_fix")
        );
    }

    /// Compact structured output keeps every finding but says each rule's fix once; `full` restores
    /// the per-finding fix, best practice and screenshot URL.
    #[test]
    fn structured_output_is_compact_unless_full_is_asked_for() {
        use super::audit_structured;
        let f = |sel: &str| json!({"rule": "contrast", "severity": "error", "msg": "Low contrast 3.1:1", "fix": "darken it", "best_practice": "a long paragraph", "sel": sel, "rect": [1, 2, 3, 4]});
        let report = json!({"report_url": "https://uxlint.net/r/abc", "pages": [{"route": "/", "viewport": "desktop", "findings": [f(".a"), f(".b")]}]});
        let compact = audit_structured(&report, "https://uxlint.net", false);
        assert_eq!(
            compact["findings"].as_array().unwrap().len(),
            2,
            "every finding stays"
        );
        assert!(
            compact["findings"][0].get("fix").is_none()
                && compact["findings"][0].get("best_practice").is_none()
        );
        assert_eq!(
            compact["fixes"]["contrast"], "darken it",
            "the fix, once per rule"
        );
        let full = audit_structured(&report, "https://uxlint.net", true);
        assert_eq!(full["findings"][1]["fix"], "darken it");
        assert!(full["findings"][0]["screenshot_url"]
            .as_str()
            .unwrap()
            .contains("/r/abc/annot"));
    }

    /// The server's prose is used as-is; only the LOCAL parts are filled in here — the source hint
    /// replaces its token, the selector fallback is used where there's none, and client warnings lead.
    #[test]
    fn server_prose_is_passed_through_with_local_source_filled_in() {
        use super::agent_prose;
        let report = json!({
            "agent_text": "Grade B\n[warn] a (/x·desktop){{where:0}}\n[warn] b (/y·desktop){{where:1}}\nend\n",
            "agent_where": [{"page": 0, "finding": 0, "fallback": " · selector: .a"},
                            {"page": 1, "finding": 0, "fallback": " · selector: .b"}],
            "pages": [{"findings": [{"rule": "a", "source": "src/A.svelte:12"}]},
                      {"findings": [{"rule": "b"}]}],
            "config_warnings": ["uxlint.toml: default_persona \"x\" names no [personas.x]"],
        });
        let t = agent_prose(&report, "https://uxlint.net", false);
        assert!(t.starts_with("⚠ CONFIG"), "client warnings lead: {t}");
        assert!(
            t.contains("[warn] a (/x·desktop) · source: src/A.svelte:12"),
            "{t}"
        );
        assert!(t.contains("[warn] b (/y·desktop) · selector: .b"), "{t}");
        assert!(!t.contains("{{where"), "no token survives: {t}");
        // The structured result carries the summary, completed the same way.
        let mut r = report.clone();
        r["agent_summary"] = json!("Grade B\n[warn] a (/x·desktop){{where:0}}\n");
        let sm = super::audit_structured(&r, "https://uxlint.net", false)["summary"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            sm.starts_with("⚠ CONFIG")
                && sm.contains("[warn] a (/x·desktop) · source: src/A.svelte:12"),
            "{sm}"
        );
    }

    #[test]
    fn one_cause_on_many_pages_is_one_entry_listed_first() {
        use super::report_text;
        // THE 2026-09-24 run: 71 warnings, most of them one shared header control repeated per page.
        let hover = |route: &str| {
            json!({"route": route, "viewport": "desktop", "findings": [
                {"rule": "state-hover-feedback", "severity": "warn", "sel": "A|nav-brand", "msg": "no hover", "fix": "add one", "rect": [1, 2, 3, 4]}
            ]})
        };
        let mut pages: Vec<serde_json::Value> = ["/a", "/b", "/c", "/d", "/e"]
            .iter()
            .map(|r| hover(r))
            .collect();
        pages.push(json!({"route": "/a", "viewport": "desktop", "findings": [
            {"rule": "request-failed", "severity": "warn", "sel": "page", "msg": "3 network requests failed", "fix": "check it"},
        ]}));
        pages.push(json!({"route": "/b", "viewport": "desktop", "findings": [
            {"rule": "request-failed", "severity": "warn", "sel": "page", "msg": "2 network requests failed", "fix": "check it"},
            {"rule": "contrast", "severity": "error", "sel": ".x", "msg": "Low contrast", "fix": "darken"},
        ]}));
        let t = report_text(
            &json!({"report_url": "https://uxlint.net/r/abc", "errors": 1, "warnings": 7, "infos": 0, "pages": pages}),
            "https://uxlint.net",
            false,
        );
        let lines: Vec<&str> = t.lines().filter(|l| l.starts_with('[')).collect();
        assert_eq!(lines.len(), 3, "{t}");
        assert!(
            lines[0].starts_with("[error] contrast (/b·desktop)"),
            "errors first: {t}"
        );
        assert!(lines[1].starts_with("[warn] state-hover-feedback — 5 places, fix once: /a·desktop, /b·desktop, /c·desktop, /d·desktop +1 more"), "{t}");
        // Page-level findings with different counts are still one cause.
        assert!(
            lines[2].starts_with("[warn] request-failed — 2 places"),
            "{t}"
        );
    }
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

#[cfg(test)]
mod admin_tool_tests {
    use super::UxlintMcp;
    use crate::Cli;
    use clap::Parser;
    use std::sync::Arc;

    fn router_offers(tool: &str, admin: bool) -> bool {
        let cli = Arc::new(Cli::parse_from(["uxlint", "mcp"]));
        UxlintMcp::new(cli, None, admin).tool_router.has_route(tool)
    }

    /// The staff digest reads OTHER accounts' pushback, so it is not part of the tool set an ordinary
    /// project gets. `remove_route` is the single enforcement point — it hides the tool from
    /// `list_tools` and rejects `call_tool` — so this pins the switch that drives it. (The server
    /// still checks the admin role on every call; this only decides whether the tool is offered.)
    #[test]
    fn the_staff_digest_is_absent_unless_the_launch_asked_for_it() {
        for tool in ["get_feedback", "archive_feedback"] {
            assert!(
                !router_offers(tool, false),
                "a default launch must not advertise {tool}"
            );
            assert!(
                router_offers(tool, true),
                "`uxlint mcp --admin` (UXLINT_ADMIN_TOOLS=1) offers {tool}"
            );
        }
    }

    /// Every argument these tools' descriptions tell an agent to pass must actually be IN the schema.
    /// A missing one is not an error at any layer: the arg is dropped on the floor, the call succeeds,
    /// and the answer is quietly the default. `include_archived` shipped that way for exactly one
    /// build, which is what this test is here to stop happening twice.
    #[test]
    fn the_staff_tools_accept_every_argument_they_advertise() {
        let cli = Arc::new(Cli::parse_from(["uxlint", "mcp"]));
        let tools = UxlintMcp::new(cli, None, true).tool_router.list_all();
        for (name, args) in [
            (
                "get_feedback",
                &["window", "since", "rule", "limit", "include_archived"][..],
            ),
            (
                "archive_feedback",
                &["rule", "reason", "outcome", "note", "through", "revert"][..],
            ),
        ] {
            let tool = tools
                .iter()
                .find(|t| t.name == name)
                .unwrap_or_else(|| panic!("{name} is registered"));
            let schema = serde_json::to_string(&tool.input_schema).expect("schema serializes");
            for arg in args {
                assert!(
                    schema.contains(&format!("\"{arg}\"")),
                    "{name} advertises `{arg}` but its schema doesn't accept it: {schema}"
                );
            }
        }
    }

    /// The switch is about ONE tool. A stale name in `remove_route` fails silently (it just doesn't
    /// match), so the way that bug shows up is the wrong tool disappearing — pin the rest as present.
    #[test]
    fn the_everyday_tools_are_untouched_by_the_switch() {
        for tool in ["audit_url", "verify_fix", "get_shot", "ux_guidance"] {
            for admin in [false, true] {
                assert!(
                    router_offers(tool, admin),
                    "{tool} must survive admin={admin}"
                );
            }
        }
    }
}

#[cfg(test)]
mod cleared_text_tests {
    use super::cleared_text;

    #[test]
    fn a_pass_names_the_scope_of_what_it_checked() {
        // THE report: a site-scoped rule "cleared" on one page, then fired again in the full pass —
        // and the agent had already stopped fixing. The verdict must carry its own scope even on the
        // happy path, where there is no other finding to hang the "re-run audit_url" advice on.
        let t = cleared_text("page-title-missing", "/", "");
        assert!(t.starts_with("✓ page-title-missing is CLEAR on /"), "{t}");
        assert!(t.contains("THIS PAGE"), "{t}");
        assert!(
            t.contains("audit_url"),
            "the way to settle a site-scoped rule must be named: {t}"
        );
    }

    #[test]
    fn the_regression_guard_still_rides_along() {
        // The other half of a pass: whatever else is on the page is appended verbatim, so naming the
        // scope has not displaced the whack-a-mole guard.
        let t = cleared_text(
            "contrast",
            "/",
            "\nHeads-up: 2 other deterministic finding(s)",
        );
        assert!(
            t.contains("Heads-up: 2 other deterministic finding(s)"),
            "{t}"
        );
    }
}

#[cfg(test)]
mod verification_status_tests {
    use super::*;
    fn report() -> Value {
        json!({"verification":{"schema":1,"checks":[
            {"route":"/","viewport":"desktop","state":"anonymous","rule":"page-title-missing","status":"passed"},
            {"route":"/","viewport":"mobile","state":"anonymous","rule":"page-title-missing","status":"passed"}
        ]}, "pages":[{"route":"/","viewport":"desktop"},{"route":"/","viewport":"mobile"}]})
    }
    #[test]
    fn requires_positive_evidence_on_both_requested_viewports() {
        let mut r = report();
        assert_eq!(
            verification_status(&r, "page-title-missing", "/", 0, false),
            "passed"
        );
        r["verification"]["checks"].as_array_mut().unwrap().pop();
        assert_eq!(
            verification_status(&r, "page-title-missing", "/", 0, false),
            "inconclusive"
        );
    }
    #[test]
    fn unknown_rules_old_servers_and_other_routes_do_not_clear() {
        for rule in [
            "typo",
            "styleguide-coverage",
            "prose-clarity",
            "dialog-escape",
        ] {
            assert_eq!(
                verification_status(&report(), rule, "/", 0, false),
                "not_evaluated"
            );
        }
        assert_eq!(
            verification_status(&json!({}), "page-title-missing", "/", 0, false),
            "not_evaluated"
        );
        assert_eq!(
            verification_status(&report(), "page-title-missing", "/settings", 0, false),
            "not_evaluated"
        );
    }
    #[test]
    fn withheld_grouped_and_incomplete_checks_do_not_clear() {
        let mut r = report();
        assert_eq!(
            verification_status(&r, "page-title-missing", "/", 0, true),
            "failed"
        );
        r["verification"]["checks"][0]["status"] = json!("failed");
        assert_eq!(
            verification_status(&r, "page-title-missing", "/", 0, false),
            "failed"
        );
        let mut r = report();
        r["timed_out"] = json!(true);
        assert_eq!(
            verification_status(&r, "page-title-missing", "/", 0, false),
            "inconclusive"
        );
        let mut r = report();
        r["pages"][0]["state"] = json!("member");
        assert_eq!(
            verification_status(&r, "page-title-missing", "/", 0, false),
            "inconclusive"
        );
    }
}
