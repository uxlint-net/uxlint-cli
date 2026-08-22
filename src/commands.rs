//! CLI command bodies (signup, audit, ci, report printing) — main.rs stays a
//! thin parser + dispatcher.

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::audit::run_audit;
use crate::project::find_project_toml;
use crate::{AuditArgs, Cli};

pub(crate) fn signup(cli: &Cli, email: &str) -> Result<()> {
    let resp: Value = reqwest::blocking::Client::new()
        .post(format!("{}/v1/accounts", cli.server))
        .json(&json!({ "email": email }))
        .send()?
        .json()?;
    // An error body has no api_key — say what went wrong instead of printing "api key: ?"
    // (which callers then paste into requests and get a baffling 401).
    let Some(key) = resp["api_key"].as_str() else {
        anyhow::bail!(
            "signup failed: {}",
            resp["error"]
                .as_str()
                .unwrap_or("unexpected server response")
        );
    };
    use crate::style::Stream;
    let st = Stream::Out;
    println!("{}  {}", st.bold("api key"), st.cyan(key));
    println!(
        "{}     {} {}",
        st.bold("plan"),
        resp["plan"],
        st.dim(&format!("({} audits/month)", resp["free_audits_per_month"]))
    );
    println!("\n{}", st.dim(&format!("export UXLINT_API_KEY={key}")));
    Ok(())
}

/// Audit + print + fail-on-errors, shared by `audit` (via main) and `ci`.
pub(crate) fn run_audit_cmd(cli: &Cli, args: &AuditArgs) -> Result<()> {
    let report = run_audit(cli, args, &crate::progress::Stderr)?;
    print_report(&report);
    anyhow::ensure!(
        report["errors"].as_u64().unwrap_or(0) == 0,
        "audit found errors — failing CI"
    );
    Ok(())
}

/// CI entrypoint: the repo says how to run itself ([dev] in uxlint.toml); we start it,
/// wait for readiness, audit through the normal pipeline, and shut it down.
/// Re-audit a past report's site and diff: what got FIXED, what's NEW (a regression or a
/// freshly-surfaced issue), and what's STILL open. The agent loop's "did my change work?".
pub(crate) fn run_diff(cli: &Cli, report_id: &str) -> Result<()> {
    let http = reqwest::blocking::Client::new();
    // Fetch the baseline report (public JSON — the id is the capability).
    let base_report: Value = http
        .get(format!("{}/v1/reports/{report_id}", cli.server))
        .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
        .send()
        .context("server unreachable")?
        .json()
        .context("report not found or not JSON")?;
    let base_url = base_report["base_url"].as_str().unwrap_or("");
    anyhow::ensure!(
        !base_url.is_empty() && base_url != "unknown",
        "baseline report has no base URL to re-audit"
    );
    // Re-audit the same site + route set as the baseline.
    let routes: Vec<String> = base_report["pages"]
        .as_array()
        .map(|ps| {
            ps.iter()
                .filter(|p| p["viewport"] == "desktop")
                .filter_map(|p| p["route"].as_str().map(String::from))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    let routes_arg = if routes.is_empty() {
        "/".to_string()
    } else {
        routes.join(",")
    };
    eprintln!(
        "re-auditing {base_url} ({} route(s)) against report {report_id}…",
        routes.len().max(1)
    );
    let fresh = run_audit(
        cli,
        &AuditArgs {
            base: base_url.to_string(),
            routes: routes_arg,
            ..default_audit_args()
        },
        &crate::progress::Stderr,
    )?;

    // Key each finding by (route, rule, sel) so the same issue lines up across runs.
    let key_set = |report: &Value| -> std::collections::HashSet<String> {
        let mut set = std::collections::HashSet::new();
        for p in report["pages"].as_array().unwrap_or(&vec![]) {
            let route = p["route"].as_str().unwrap_or("");
            let vp = p["viewport"].as_str().unwrap_or("");
            if vp != "desktop" && vp != "cross" {
                continue;
            }
            for f in p["findings"].as_array().unwrap_or(&vec![]) {
                set.insert(format!(
                    "{route}|{}|{}",
                    f["rule"].as_str().unwrap_or(""),
                    f["sel"].as_str().unwrap_or("")
                ));
            }
        }
        set
    };
    let before = key_set(&base_report);
    let after = key_set(&fresh);
    let label = |k: &str| -> String {
        let mut it = k.splitn(3, '|');
        let route = it.next().unwrap_or("");
        let rule = it.next().unwrap_or("");
        format!("{rule}  ({route})")
    };
    let mut fixed: Vec<_> = before.difference(&after).collect();
    let mut newly: Vec<_> = after.difference(&before).collect();
    fixed.sort();
    newly.sort();
    let still = before.intersection(&after).count();

    {
        use crate::style::Stream;
        let st = Stream::Out;
        println!("\n{}\n", st.bold(&format!("Diff vs {report_id}")));
        println!(
            "  {}   {}",
            st.green(&format!("✓ fixed {}", fixed.len())),
            st.dim("(gone since the baseline)")
        );
        println!(
            "  {}     {}",
            st.yellow(&format!("▲ new {}", newly.len())),
            st.dim("(a regression, or freshly surfaced)")
        );
        println!("  {}\n", st.dim(&format!("· still {still}")));
    }
    if !fixed.is_empty() {
        println!("{}", crate::style::Stream::Out.bold("Fixed"));
        for k in &fixed {
            println!("  {} {}", crate::style::Stream::Out.green("✓"), label(k));
        }
        println!();
    }
    if !newly.is_empty() {
        println!("{}", crate::style::Stream::Out.bold("New"));
        for k in &newly {
            println!("  {} {}", crate::style::Stream::Out.yellow("▲"), label(k));
        }
        println!();
    }
    let (be, ae) = (
        base_report["errors"].as_i64().unwrap_or(0),
        fresh["errors"].as_i64().unwrap_or(0),
    );
    let (bw, aw) = (
        base_report["warnings"].as_i64().unwrap_or(0),
        fresh["warnings"].as_i64().unwrap_or(0),
    );
    println!(
        "{}",
        crate::style::Stream::Out.dim(&format!("errors {be} → {ae}   warnings {bw} → {aw}"))
    );
    // Regressions are the actionable signal — nonzero exit so CI can gate on "no new issues".
    if !newly.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

/// `uxlint audit --rule <rule>`: scope an already-run audit to ONE rule and turn it into a pass/fail
/// — the tight "did my fix land?" check. Exit 0 = the rule is clear (fix landed); exit 1 = it still
/// fires (with the offending messages). Split out of the audit handler so the reporting stays there.
pub(crate) fn check_rule(report: &Value, rule: &str) -> Result<()> {
    let empty = vec![];
    let hits: Vec<&Value> = report["pages"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .flat_map(|p| {
            p["findings"]
                .as_array()
                .map(|a| a.as_slice())
                .unwrap_or(&[])
        })
        .filter(|f| f["rule"].as_str() == Some(rule))
        .collect();
    if hits.is_empty() {
        println!(
            "{}",
            crate::style::Stream::Out.green(&format!("✓ {rule} is clear — fix verified"))
        );
        Ok(())
    } else {
        println!(
            "{}",
            crate::style::Stream::Out.yellow(&format!(
                "▲ {rule} still fires ({} occurrence(s)):",
                hits.len()
            ))
        );
        for f in hits.iter().take(5) {
            println!("  · {}", f["msg"].as_str().unwrap_or(""));
            if let Some(sel) = f["sel"].as_str().filter(|s| !s.is_empty() && *s != "page") {
                println!("    where: {sel}");
            }
        }
        std::process::exit(1);
    }
}

fn default_audit_args() -> AuditArgs {
    AuditArgs {
        base: String::new(),
        routes: "/".into(),
        viewports: "desktop:1440x900,mobile:390x844".into(),
        headers: vec![],
        storage: vec![],
        login_url: None,
        username: None,
        password: None,
        states: false,
        probe_errors: false,
        resilience: false,
        slow_network: false,
        timeout: None,
        crawl: 12,
        parallel: None,
        no_judge: true,
        no_tests: false,
        rule: None,
        preview_rule: None,
        site_type: None,
        org: None,
        site: None,
        labels: Vec::new(),
        json: false,
        fix_plan: false,
        no_previews: true,
        change_url: None,
        ci: false,
        dry_run: None,
        no_provenance: false,
    }
}

pub(crate) fn run_ci(cli: &Cli) -> Result<()> {
    let (dir, v) = find_project_toml().context("no uxlint.toml found — run `uxlint init` first")?;
    let dev = v
        .get("dev")
        .context("uxlint.toml has no [dev] section (command + url)")?;
    let command = dev
        .get("command")
        .and_then(|c| c.as_str())
        .context("[dev] command missing")?;
    let url = dev
        .get("url")
        .and_then(|u| u.as_str())
        .context("[dev] url missing")?;
    let timeout = dev
        .get("ready_timeout_secs")
        .and_then(|t| t.as_integer())
        .unwrap_or(120) as u64;
    eprintln!("  dev server: {command}");
    let mut child = std::process::Command::new("sh")
        .args(["-c", command])
        .current_dir(&dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("could not start dev command")?;
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;
    let start = std::time::Instant::now();
    let ready = loop {
        if http
            .get(url)
            .send()
            .map(|r| r.status().as_u16() < 500)
            .unwrap_or(false)
        {
            break true;
        }
        if start.elapsed().as_secs() > timeout {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    };
    let result = if ready {
        eprintln!("  ready in {:.1}s", start.elapsed().as_secs_f32());
        run_audit_cmd(
            cli,
            &AuditArgs {
                base: url.to_string(),
                routes: "/".into(), // uxlint.toml routes take over
                viewports: "desktop:1440x900,mobile:390x844".into(),
                headers: Vec::new(),
                storage: Vec::new(),
                login_url: None,
                username: None,
                password: None,
                states: false,
                probe_errors: false,
                resilience: false,
                slow_network: false,
                timeout: None,
                fix_plan: false,
                no_previews: true,
                crawl: 12, // budget cap; the toml can widen it
                rule: None,
                preview_rule: None,
                parallel: None, // auto: full throttle locally, polite on public hosts
                no_judge: false,
                no_tests: false,
                site_type: None,
                org: None,
                site: None,
                labels: Vec::new(),
                json: false,
                change_url: None,
                ci: false,
                dry_run: None,
                no_provenance: false,
            },
        )
    } else {
        Err(anyhow::anyhow!(
            "dev server not ready on {url} after {timeout}s"
        ))
    };
    let _ = child.kill();
    let _ = child.wait();
    result
}

/// Selector → source hint: pull a probable component name out of a CSS selector, but ONLY
/// when the class clearly names a component (PascalCase, or a CSS-module `Name_part__hash`).
/// Utility classes (Tailwind's `block`, `truncate`) and element selectors yield nothing —
/// a wrong guess is worse than none.
fn component_hint(sel: &str) -> Option<String> {
    for tok in sel.split(['.', ' ', '>', ':', '#']) {
        let tok = tok.trim();
        if tok.is_empty() || tok.contains("nth-child") {
            continue;
        }
        // CSS-module: `Button_root__x7f2` or `button-module__root___x7f2` → the head.
        if let Some((head, _)) = tok.split_once("__").or_else(|| tok.split_once("-module")) {
            let name = head.trim_end_matches(['_', '-']);
            if name.len() >= 3 && name.chars().next().is_some_and(|c| c.is_alphabetic()) {
                return Some(name.to_string());
            }
        }
        // PascalCase component class: `PricingCard`, `NavBar`.
        if tok.len() >= 3
            && tok.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && tok.chars().any(|c| c.is_ascii_lowercase())
            && tok.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return Some(tok.to_string());
        }
    }
    None
}

/// Emit findings as an ordered fix plan: cheap-high-impact first, grouped by page, ready to
/// paste into a coding agent's todo list. Ordering = impact desc, then effort cheapest first.
pub(crate) fn print_fix_plan(report: &Value) {
    let effort_glyph = |e: &str| match e {
        "css-tweak" => "🎨 css",
        "copy-edit" => "✍ copy",
        "markup" => "🏷 markup",
        _ => "🧱 structural",
    };
    let empty = vec![];
    // Flatten (route, finding) so we can order the whole plan, not just within a page.
    let mut items: Vec<(String, &Value)> = Vec::new();
    for page in report["pages"].as_array().unwrap_or(&empty) {
        let route = page["route"].as_str().unwrap_or("").to_string();
        let viewport = page["viewport"].as_str().unwrap_or("desktop");
        if viewport != "desktop" && viewport != "cross" {
            continue; // one entry per finding — desktop/cross carry the canonical set
        }
        for f in page["findings"].as_array().unwrap_or(&empty) {
            items.push((route.clone(), f));
        }
    }
    // Impact desc, then cheapest effort first, then error>warn>info.
    items.sort_by(|a, b| {
        let ia = a.1["impact"].as_i64().unwrap_or(0);
        let ib = b.1["impact"].as_i64().unwrap_or(0);
        let ra = a.1["effortRank"].as_i64().unwrap_or(9);
        let rb = b.1["effortRank"].as_i64().unwrap_or(9);
        ib.cmp(&ia).then(ra.cmp(&rb))
    });
    use crate::style::Stream;
    let st = Stream::Out;
    let n = items.len();
    println!(
        "\n{} {}\n",
        st.bold(&format!(
            "Fix plan — {n} finding{}",
            if n == 1 { "" } else { "s" }
        )),
        st.dim("(cheap, high-impact first)")
    );
    if n == 0 {
        println!("{}\n", st.green("Nothing to fix — 0 findings. ✓"));
        return;
    }
    for (idx, (route, f)) in items.iter().enumerate() {
        let rule = f["rule"].as_str().unwrap_or("");
        let sev = f["severity"].as_str().unwrap_or("info");
        let eff = f["effort"].as_str().unwrap_or("markup");
        let msg = f["msg"].as_str().unwrap_or("");
        let fix = f["fix"].as_str().unwrap_or("");
        let sel = f["sel"].as_str().unwrap_or("");
        let mark = match sev {
            "error" => st.red("●"),
            "warn" => st.yellow("▲"),
            _ => st.dim("·"),
        };
        println!(
            "{} {mark} {msg}  {}",
            st.bold(&format!("{:>2}.", idx + 1)),
            st.dim(&format!("[{} · {rule} on {route}]", effort_glyph(eff))),
        );
        if !fix.is_empty() {
            println!("     {}", st.dim(&format!("fix → {fix}")));
        }
        if !sel.is_empty() && sel != "page" && sel != "site" && sel != "form" {
            match component_hint(sel) {
                Some(c) => println!(
                    "     {}",
                    st.dim(&format!("where → {sel}  (likely component: {c})"))
                ),
                None => println!("     {}", st.dim(&format!("where → {sel}"))),
            }
        }
        println!();
    }
    let errs = report["errors"].as_u64().unwrap_or(0);
    println!(
        "{}",
        st.dim(&format!(
            "Work top-down. {errs} error(s) block; fix those first."
        ))
    );
}

pub(crate) fn print_report(report: &Value) {
    use crate::style::Stream;
    let st = Stream::Out;
    println!();
    // Only when routes were ACTUALLY blocked. `auth_blocked_routes` is always present and usually
    // `[]`, so matching on the key alone announced an auth wall after every single audit — "⚠ AUTH
    // WALL on  —" with an empty route list, on a run that was perfectly signed in. A permanent
    // false alarm is worse than no warning: it trains you to ignore the real one. (The MCP path
    // already filtered this correctly; the CLI print didn't.)
    let blocked: Vec<&str> = report["auth_blocked_routes"]
        .as_array()
        .map(|b| {
            b.iter()
                .filter_map(|r| r.as_str())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if !blocked.is_empty() {
        println!(
            "{}",
            st.yellow(&format!(
                "⚠ AUTH WALL on {} — only the public/login view was audited.",
                blocked.join(", ")
            ))
        );
        println!("{}\n", st.dim("  To audit the app itself: add [credentials.login] to uxlint.toml, or --header \"Cookie: session=…\""));
    }
    // Timed out: the browser-phase cap fired, so this report is honestly incomplete. Say so up
    // top — and quantify the cut when the detail is present — before the findings, so it's never read
    // as the whole picture.
    if report["timed_out"].as_bool() == Some(true) {
        println!(
            "{}",
            st.yellow("⚠ TIMED OUT — this audit hit its time cap; results may be incomplete.")
        );
        let d = &report["timeout_detail"];
        if d.is_object() {
            let (pp, pc) = (
                d["pages_planned"].as_u64().unwrap_or(0),
                d["pages_captured"].as_u64().unwrap_or(0),
            );
            let (wp, wd) = (
                d["walks_planned"].as_u64().unwrap_or(0),
                d["walks_done"].as_u64().unwrap_or(0),
            );
            let mut parts: Vec<String> = Vec::new();
            if pp > pc {
                parts.push(format!("{pc}/{pp} pages captured"));
            }
            if wp > wd {
                parts.push(format!("{wd}/{wp} tests finished"));
            }
            if !parts.is_empty() {
                println!("{}", st.dim(&format!("  {}", parts.join(", "))));
            }
        }
        println!(
            "{}\n",
            st.dim("  Raise --timeout (or uxlint.toml `timeout`) to give a slow target more time.")
        );
    }
    // Degraded run: the org's AI budget was spent, so the copy/layout/AI-review tier was skipped. Say
    // so up front — otherwise a paying user past their cap just sees fewer findings and assumes their
    // site improved. (Signalled by the persisted `ai_degraded` flag or the live `ai_quota.exhausted`.)
    if report["ai_degraded"].as_bool() == Some(true)
        || report["ai_quota"]["exhausted"].as_bool() == Some(true)
    {
        println!(
            "{}",
            st.yellow(
                "⚠ AI budget spent — the copy, layout and AI-review findings were skipped; this run is deterministic-only."
            )
        );
        let q = &report["ai_quota"];
        if let (Some(used), Some(cap)) = (q["used"].as_i64(), q["cap"].as_i64()) {
            let basis = q["basis"].as_str().unwrap_or("period");
            println!(
                "{}",
                st.dim(&format!(
                    "  {used}/{cap} AI calls used this {basis}. Upgrade or wait for the next window to restore the full audit."
                ))
            );
        }
        println!();
    }
    for page in report["pages"].as_array().unwrap_or(&vec![]) {
        let findings = page["findings"].as_array().cloned().unwrap_or_default();
        if findings.is_empty() {
            continue;
        }
        let n = findings.len();
        println!(
            "{} {}  {}",
            st.cyan("▎"),
            st.bold(page["route"].as_str().unwrap_or("?")),
            st.dim(&format!(
                "{} · {} finding{}",
                page["viewport"].as_str().unwrap_or("?"),
                n,
                if n == 1 { "" } else { "s" }
            )),
        );
        println!();
        for f in findings.iter().take(12) {
            let sym = match f["severity"].as_str() {
                Some("error") => st.red("✖"),
                Some("warn") => st.yellow("▲"),
                _ => st.dim("·"),
            };
            let src = f["source"]
                .as_str()
                .map(|s| format!("  {}", st.dim(&format!("({s})"))))
                .unwrap_or_default();
            println!(
                "  {sym} {}{src}  {}",
                st.dim(&format!("[{}]", f["rule"].as_str().unwrap_or(""))),
                f["msg"].as_str().unwrap_or("")
            );
            if let Some(fix) = f["fix"].as_str() {
                println!("    {}", st.dim(&format!("fix → {fix}")));
            }
            if let Some(bp) = f["best_practice"].as_str() {
                println!("    {}", st.dim(&format!("best practice → {bp}")));
            }
            println!();
        }
        if findings.len() > 12 {
            println!(
                "  {}\n",
                st.dim(&format!(
                    "… and {} more (see the full report)",
                    findings.len() - 12
                ))
            );
        }
    }
    // Closing summary: grade first — the one-glance answer — then counts, link, filing.
    let summary = &report["summary"];
    if let (Some(grade), Some(score)) = (summary["grade"].as_str(), summary["score"].as_i64()) {
        let letter = match grade.chars().next().unwrap_or('C') {
            'A' | 'B' => st.green(&st.bold(grade)),
            'C' => st.yellow(&st.bold(grade)),
            _ => st.red(&st.bold(grade)),
        };
        let verdict = summary["verdict"]
            .as_str()
            .map(|v| format!(" — {v}"))
            .unwrap_or_default();
        println!(
            "{}  {letter} {}",
            st.bold("Grade"),
            st.dim(&format!("· {score}/100{verdict}"))
        );
    }
    let (e, w, i) = (
        report["errors"].as_u64().unwrap_or(0),
        report["warnings"].as_u64().unwrap_or(0),
        report["infos"].as_u64().unwrap_or(0),
    );
    // `plural` false for uncountable words ("info"), true for the countable ones.
    let count = |n: u64, word: &str, plural: bool, paint: fn(Stream, &str) -> String| {
        let s = format!("{n} {word}{}", if plural && n != 1 { "s" } else { "" });
        if n > 0 {
            paint(st, &s)
        } else {
            st.dim(&s)
        }
    };
    println!(
        "{}  {} · {} · {}",
        st.bold("Found"),
        count(e, "error", true, |s, t| s.red(t)),
        count(w, "warning", true, |s, t| s.yellow(t)),
        count(i, "info", false, |s, t| s.dim(t)),
    );
    // Cross-audit delta — the iterate-loop signal, shown when there's a comparable prior crawl to
    // diff against ("since last audit: N resolved, M new, P still open"). Server-computed.
    if let Some(d) = report["delta"].as_object() {
        let g = |k: &str| d.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
        let (res, new, per) = (g("resolved"), g("new"), g("persisting"));
        let (res_s, new_s, per_s) = (
            format!("{res} resolved"),
            format!("{new} new"),
            format!("{per} still open"),
        );
        println!(
            "{}  {} · {} · {}",
            st.bold("Since last audit"),
            if res > 0 {
                st.green(&res_s)
            } else {
                st.dim(&res_s)
            },
            if new > 0 {
                st.yellow(&new_s)
            } else {
                st.dim(&new_s)
            },
            st.dim(&per_s),
        );
        // Name the newly-introduced findings — most likely from the last edit.
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
            println!("{}", st.dim(&format!("  new: {list}")));
        }
    }
    if let Some(url) = report["report_url"].as_str() {
        println!("\n{}  {}", st.bold("Report"), st.link(url));
    }
    if let Some(att) = report["attached_site"].as_object() {
        println!(
            "{}",
            st.dim(&format!(
                "        filed under {} ({}) — via {}",
                att["site"].as_str().unwrap_or("?"),
                att["org"].as_str().unwrap_or("?"),
                att["how"].as_str().unwrap_or("?")
            ))
        );
    } else if let Some(err) = report["attach_error"].as_str() {
        println!(
            "{}",
            st.yellow(&format!("        not attached to any org site: {err}"))
        );
    }
    // Soft-nudge before the hard quota wall (last ~20% or <=2 left this month).
    if let Some(q) = report["quota"].as_object() {
        let remaining = q.get("remaining").and_then(|v| v.as_i64()).unwrap_or(-1);
        let cap = q.get("cap").and_then(|v| v.as_i64()).unwrap_or(0);
        let used = q.get("used").and_then(|v| v.as_i64()).unwrap_or(0);
        if remaining >= 0 && cap > 0 && remaining <= (cap / 5).max(2) {
            let url = q.get("upgrade_url").and_then(|v| v.as_str()).unwrap_or("");
            println!(
                "\n{}",
                st.yellow(&format!(
                    "⚠ {used}/{cap} audits used this month — {remaining} left. Upgrade: {url}"
                ))
            );
        }
    }
    println!();
}
