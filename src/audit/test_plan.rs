//! The test-run phase and its helpers: resolving declared tests (uxlint.toml + server), plan
//! gating, the outcome cache, task fan-out, login-page detection, and the concurrent walker.
//! Pure decision cores are unit-tested; the browser/HTTP walk shell is covered by the dogfood/e2e.

use super::provenance::git_provenance;
use crate::progress::{note, Progress};
use crate::project::{norm_route, project_config};
use crate::test_run::run_test;
use crate::worker::{AuditWorker, PassShared};
use crate::{AuditArgs, Cli, RunTestArgs};
use serde_json::{json, Value};

/// Cache file for a site's test-run outcomes, keyed by (site, git sha) — `~/.cache/uxlint/goals/`
/// (XDG_CACHE_HOME honoured), mirroring where the CLI keeps credentials. Returns `None` (→ no cache,
/// always re-walk) unless the working tree is CLEAN at a known commit: a dirty tree means uncommitted
/// edits that could change reachability without moving the sha, so those must always be walked fresh.
fn test_cache_file(host: &str) -> Option<(std::path::PathBuf, String)> {
    let sha = git_provenance().0?;
    let clean = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| o.status.success() && o.stdout.is_empty())
        .unwrap_or(false);
    if !clean {
        return None;
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache")))?;
    let safe: String = host
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    Some((
        base.join("uxlint")
            .join("tests")
            .join(format!("{safe}-{sha}.json")),
        sha,
    ))
}

/// Are tests in scope for this audit at all? Goals validate WHOLE-SITE reachability, so
/// they only make sense on a full-site audit (a crawl, or more than one seed route) — a single
/// route with no crawl is a targeted check, and walking every declared test there would be the
/// mismatch this gate avoids. `--no-goals` (also accepted as `--no-wayfind`) forces it off. Pure so
/// it's unit-testable without a server or a browser.
pub(crate) fn tests_in_scope(no_tests: bool, seed_count: usize, crawl_cap: usize) -> bool {
    !no_tests && (seed_count > 1 || crawl_cap > seed_count)
}

/// Should the test-outcome cache even be CONSULTED this run? `goals` is already `[]` by the time
/// this is checked — either nothing was declared, or the paywall check just cleared it because the
/// resolved plan is free. Reading the cache in either case would hand back a walk result
/// from a PRIOR (possibly paid) run — the cache key is (host, git sha) only, oblivious to plan — so
/// a downgraded org could see stale success/lost outcomes it never re-earned. Pure so it's
/// unit-testable without touching the filesystem or git.
pub(crate) fn test_cache_readable(goals_len: usize) -> bool {
    goals_len > 0
}

/// A test run is a paid-plan feature: the server refuses `/v1/tests/step` for a
/// free billing org with a distinct labeled 402. Mirrored client-side ONLY for the warning below —
/// the server remains the actual gate. `free` (any case) is the one plan that can't walk; every
/// other resolved plan (pro/team/enterprise/admin) can.
pub(crate) fn plan_allows_tests(plan: &str) -> bool {
    !plan.eq_ignore_ascii_case("free")
}

/// The one-line warning printed when goals are declared but the resolved plan can't walk them:
/// names the skipped count and the upgrade path, so a free user is never left wondering why no
/// test-run output showed up. Pure so it's unit-testable.
pub(crate) fn test_paywall_warning(goal_count: usize, web_url: &str) -> String {
    format!(
        "skipping {goal_count} declared test{} — tests need a paid plan; upgrade at {}/pricing",
        if goal_count == 1 { "" } else { "s" },
        web_url.trim_end_matches('/'),
    )
}

/// Merge a site's declared tests: uxlint.toml `[[tests]]` (checked-in, so they run for every
/// contributor from this project) plus server-declared tests (`GET /v1/sites/{host}/goals` — goals
/// an org declares once against a hosted site, e.g. via `uxlint site` or the web app, so they ride
/// every audit of that site regardless of who's checked out what). Deduped by goal text; a
/// uxlint.toml goal wins a name collision (declared-in-the-repo takes precedence over
/// declared-on-the-server). This is THE resolution: the audit's test-run phase and `uxlint
/// test`'s goal list/select both call this so they always agree on exactly what's declared, in
/// the same order.
pub(crate) fn merged_tests(cli: &Cli, host: &str) -> Vec<Value> {
    let local: Vec<Value> = project_config()
        .map(|p| {
            p.tests
                .iter()
                .map(|g| json!({"test": g.test, "expect": g.expect, "importance": g.importance, "persona": g.persona, "viewport": g.viewport}))
                .collect()
        })
        .unwrap_or_default();
    let server_tests: Vec<Value> = reqwest::blocking::Client::new()
        .get(format!("{}/v1/sites/{}/tests", cli.server, host))
        .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
        .send()
        .ok()
        .and_then(|r| r.json::<Value>().ok())
        .and_then(|v| v["tests"].as_array().cloned())
        .unwrap_or_default();
    dedup_tests(local, server_tests)
}

/// The actual merge/dedup step of `merged_tests`, split out as a pure function so it's
/// unit-testable without a server: `local` (uxlint.toml) wins a goal-text collision over `server`
/// (an org's server-declared tests) — checked-in requirements take precedence over ones a team
/// declared through the app/API.
pub(crate) fn dedup_tests(mut local: Vec<Value>, server: Vec<Value>) -> Vec<Value> {
    for g in server {
        if !local.iter().any(|t| t["test"] == g["test"]) {
            local.push(g);
        }
    }
    local
}

/// Best-effort client-side resolution of the signed-in account's BILLING-org plan, straight off
/// `/v1/me` (`plan` there is the strongest plan across the account's orgs — the same billing-org
/// rank order the server's gate uses, see `store::billing_org`/`effective_plan`). UX only: this
/// only decides whether to print the paywall warning and skip the walk phase locally; the server's
/// `/v1/tests/step` gate is what actually enforces it. Fails open (returns `None`, walk proceeds
/// as before) on anything that isn't a clean, authenticated 200 — signed-out or unreachable is left
/// for the walk itself (and ultimately the 402) to surface, same posture as `prevalidate_org`.
fn account_plan(cli: &Cli) -> Option<String> {
    let http = reqwest::blocking::Client::new();
    let resp = http
        .get(format!("{}/v1/me", cli.server))
        .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
        .send()
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let me: Value = resp.json().ok()?;
    if me["authenticated"].as_bool() != Some(true) {
        return None;
    }
    me["plan"].as_str().map(str::to_string)
}

/// Flatten declared tests × their viewport fan-out into independent walk tasks: (goal, expect,
/// importance, persona, viewport). NO cap here — paid plans walk every declared test; the real
/// bounds are the 25-goal declaration cap, each walk's own hop budget, the
/// server's per-(account,goal) hop ceiling, and the AI budget. (viewport rule: "mobile" → phone
/// only; "both"/"all" → desktop AND mobile; anything else → desktop only.) Pure so the fan-out —
/// and the absence of a subset cap — is unit-testable without a server or a browser.
pub(crate) fn test_tasks(goals: &[Value]) -> Vec<(String, String, String, String, &'static str)> {
    goals
        .iter()
        .flat_map(|g| {
            let goal = g["test"].as_str().unwrap_or("").to_string();
            let expect = g["expect"].as_str().unwrap_or("").to_string();
            if goal.is_empty() || expect.is_empty() {
                return Vec::new();
            }
            let importance = g["importance"].as_str().unwrap_or("important").to_string();
            let persona = g["persona"].as_str().unwrap_or("").to_string();
            let targets: &[&'static str] = match g["viewport"]
                .as_str()
                .unwrap_or("")
                .to_ascii_lowercase()
                .as_str()
            {
                "both" | "all" => &["desktop", "mobile"],
                "mobile" => &["mobile"],
                _ => &["desktop"],
            };
            targets
                .iter()
                .map(|&vp| {
                    (
                        goal.clone(),
                        expect.clone(),
                        importance.clone(),
                        persona.clone(),
                        vp,
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The crawled site map (route → doc title), deduped and capped at 30, from the desktop captures —
/// handed to the test runer so it can plan with the graph, not just the current page. Pure.
pub(crate) fn site_map(pages: &[Value]) -> Vec<(String, String)> {
    let mut seen = std::collections::HashSet::new();
    pages
        .iter()
        .filter(|p| p["viewport"].as_str() == Some("desktop"))
        .filter_map(|p| {
            let route = p["route"].as_str()?.to_string();
            if route.is_empty() || !seen.insert(route.clone()) {
                return None;
            }
            let title = p["snapshot"]["docTitle"]
                .as_str()
                .unwrap_or("")
                .trim()
                .to_string();
            Some((route, title))
        })
        .take(30)
        .collect()
}

/// Where the test runer signs in from, detected name-agnostically: the Sign-in link a logged-out
/// visitor sees → where a logged-out visitor got bounced (the login page) → a crawled login-ish
/// route → the shallowest signed-in route as a rough app entry. Pure.
pub(crate) fn login_route(
    anon_checks: &[Value],
    pages: &[Value],
    anon_routes: &[String],
) -> Option<String> {
    // Resolve a sign-in link's href to a same-site route path.
    let href_to_route = |h: &str| -> Option<String> {
        let h = h.trim();
        if h.is_empty()
            || h.starts_with('#')
            || h.starts_with("javascript:")
            || h.starts_with("mailto:")
        {
            return None;
        }
        let path = if h.starts_with("http") {
            reqwest::Url::parse(h).ok()?.path().to_string()
        } else if h.starts_with('/') {
            h.to_string()
        } else {
            format!("/{h}")
        };
        let r = norm_route(&path);
        (r.len() > 1).then_some(r)
    };
    anon_checks
        // Primary: the Sign in link a logged-out visitor sees — the way a real user finds login.
        .iter()
        .filter_map(|c| c["login_href"].as_str())
        .find_map(href_to_route)
        // Else: where a logged-out visitor got bounced (the login page, if the app hard-redirects).
        .or_else(|| {
            anon_checks
                .iter()
                .find(|c| c["signin"].as_bool() == Some(true))
                .and_then(|c| c["final_path"].as_str())
                .filter(|p| p.len() > 1)
                .map(str::to_string)
        })
        // Else: a crawled login-ish route name, then the shallowest signed-in route.
        .or_else(|| {
            pages
                .iter()
                .filter(|p| p["viewport"].as_str() == Some("desktop"))
                .filter_map(|p| p["route"].as_str())
                .find(|r| {
                    let r = r.to_lowercase();
                    r.contains("login") || r.contains("signin") || r.contains("sign-in")
                })
                .map(str::to_string)
        })
        .or_else(|| {
            anon_routes
                .iter()
                .filter(|r| r.as_str() != "/")
                .min_by_key(|r| (r.matches('/').count(), r.len()))
                .cloned()
        })
}

/// Inputs to the test-run phase (borrowed run state).
pub(crate) struct TestRunInputs<'a> {
    pub(crate) cli: &'a Cli,
    pub(crate) args: &'a AuditArgs,
    pub(crate) progress: &'a (dyn Progress + Sync),
    pub(crate) site: Option<&'a str>,
    pub(crate) run_goals: bool,
    pub(crate) pages: &'a [Value],
    pub(crate) anon_checks: &'a [Value],
    pub(crate) anon_routes: &'a [String],
    pub(crate) was_authed: bool,
    pub(crate) partial_state: Option<&'a std::sync::Arc<crate::worker::PartialState>>,
    pub(crate) shared: &'a PassShared,
    pub(crate) workers: &'a [AuditWorker],
    pub(crate) deadline: std::time::Instant,
    pub(crate) t_crawl: std::time::Instant,
}

/// Results of the test-run phase, threaded back to the orchestrator. `crawl_ms`/`goals_ms` are set
/// here because this phase is the boundary between the Chrome crawl and the LLM walks.
pub(crate) struct TestRunOutcome {
    pub(crate) test_outcomes: Vec<Value>,
    /// Full snapshots of the novel states the walks landed on (post-click / post-submit / JS-nav
    /// pages the link-crawl never captured), for the deterministic lints. Deduped vs the crawl by
    /// the orchestrator before they're merged into the report's pages.
    pub(crate) walk_pages: Vec<Value>,
    pub(crate) walks_planned: usize,
    pub(crate) crawl_ms: u128,
    pub(crate) goals_ms: u128,
}

/// The test-run phase (I/O shell): resolve the site's declared tests (uxlint.toml + server), gate on
/// plan, reuse cached outcomes on a clean tree, else walk each goal×viewport concurrently as its
/// persona (logged-out / a named role / unspecified). Uses the pure `login_route` and `site_map`
/// cores.
pub(crate) fn run_tests(input: TestRunInputs) -> TestRunOutcome {
    let TestRunInputs {
        cli,
        args,
        progress,
        site,
        run_goals,
        pages,
        anon_checks,
        anon_routes,
        was_authed,
        partial_state,
        shared,
        workers,
        deadline,
        t_crawl,
    } = input;
    let past_deadline = || std::time::Instant::now() >= deadline;
    let mut test_outcomes: Vec<Value> = Vec::new();
    // Full snapshots the tests captured of novel interaction-reached states, to be linted like
    // crawl pages (deduped against the crawl in the orchestrator).
    let mut walk_pages: Vec<Value> = Vec::new();
    // How many tests this audit intended to run — captured for the timeout detail (walks it
    // planned vs. finished), so a timed-out report can say exactly what was cut.
    let mut walks_planned = 0usize;
    let mut crawl_ms: u128 = 0;
    let mut goals_ms: u128 = 0;
    if let Ok(u) = reqwest::Url::parse(&args.base) {
        // The project's declared site (uxlint.toml) is the identity — the base host is only
        // the fallback (localhost vs 127.0.0.1 must both find the goals).
        let host = site.map(str::to_string).unwrap_or_else(|| {
            u.host_str()
                .map(|h| match u.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_string(),
                })
                .unwrap_or_default()
        });
        // run_goals gates the (slow) tests: skipped for targeted/verify audits and --no-goals.
        let mut goals: Vec<Value> = if !run_goals {
            Vec::new()
        } else {
            merged_tests(cli, &host)
        };
        // Tests are a paid-plan feature server-side: `/v1/tests/step`
        // refuses a free billing org with a distinct 402. Rather than let that happen once per
        // goal per hop — spamming 402s and still paying for a browser launch per walk — resolve
        // the plan HERE, up front, and warn ONCE: name the count being skipped and where to
        // upgrade. This is UX only (the server call below is best-effort and fails OPEN on a
        // signed-out/unreachable /v1/me, same as `prevalidate_org`) — the walk phase's own 402
        // handling is what actually enforces it either way.
        if !goals.is_empty() {
            if let Some(plan) = account_plan(cli) {
                if !plan_allows_tests(&plan) {
                    let web = std::env::var("UXLINT_WEB_URL")
                        .unwrap_or_else(|_| "https://uxlint.net".into());
                    note!(
                        progress,
                        "  {}",
                        crate::style::Stream::Err.yellow(&test_paywall_warning(goals.len(), &web))
                    );
                    goals.clear();
                }
            }
        }
        // Everything up to here (viewport passes, signed-out re-check) is Chrome crawl/capture; the
        // tests that follow are LLM-bound (test-run steps hit the judge).
        crawl_ms = t_crawl.elapsed().as_millis();
        {
            use std::sync::atomic::Ordering::Relaxed;
            let secs = |ms: u64| format!("{:.0}s", ms as f64 / 1000.0);
            // Phase times are SUMMED across the parallel workers, so they total to roughly
            // (wall-clock crawl) × worker count — the RATIO is what shows where the time goes.
            note!(progress,
                "{}", crate::style::Stream::Err.dim(&format!("  crawl phases (across {} workers): nav {} · settle {} · capture {} · states {} (hover {} · tab-order {}) · spinner {} · resilience {}",
                workers.len(),
                secs(shared.t_nav.load(Relaxed)),
                secs(shared.t_settle.load(Relaxed)),
                secs(shared.t_capture.load(Relaxed)),
                secs(shared.t_states.load(Relaxed)),
                secs(shared.t_hover.load(Relaxed)),
                secs(shared.t_forms.load(Relaxed)),
                secs(shared.t_spinner.load(Relaxed)),
                secs(shared.t_resilience.load(Relaxed)),
            )));
            note!(progress,
                "{}", crate::style::Stream::Err.dim(&format!(
                    "  concurrency peak: {} workers in a route, {} in the states pass (of {} workers)",
                    shared.route_peak.load(Relaxed),
                    shared.states_peak.load(Relaxed),
                    workers.len(),
                ))
            );
        }
        let t_goals = std::time::Instant::now();
        // Reuse prior goal outcomes when the committed code is unchanged. The walks depend only on the
        // site's routing/affordances, so on the SAME commit with a CLEAN tree they reproduce — skip the
        // ~18s walk and reuse. A dirty tree (any uncommitted edit) always re-walks (test_cache_file
        // returns None), so a dev iteration is never served a stale result.
        // Gate the READ on `goals` being non-empty: it's already empty here when there's nothing
        // declared, OR when the paywall check above just cleared it for a free plan — reading
        // the cache in either case would hand back a STALE walk result from before an org downgraded
        // (the cache key is (host, sha) only, oblivious to plan), silently un-paywalling old outcomes.
        let test_cache = test_cache_file(&host);
        let mut cache_hit = false;
        if test_cache_readable(goals.len()) {
            if let Some((path, sha)) = &test_cache {
                if let Some(v) = std::fs::read_to_string(path)
                    .ok()
                    .and_then(|t| serde_json::from_str::<Vec<Value>>(&t).ok())
                {
                    note!(progress, "  goals: reusing cached outcomes for {sha} (clean tree — unchanged since last audit)");
                    test_outcomes = v;
                    cache_hit = true;
                }
            }
        }
        // The site's login page: an explicit `login_url` in uxlint.toml wins, else detect it
        // name-agnostically (see `login_route`). Made absolute for the walker to submit against.
        let login_url = crate::project::login_url()
            .or_else(|| {
                login_route(anon_checks, pages, anon_routes)
                    .as_deref()
                    .map(str::to_string)
            })
            .map(|r| {
                if r.starts_with("http") {
                    r
                } else {
                    format!("{}{}", args.base.trim_end_matches('/'), r)
                }
            });
        // The declared personas; a task whose `persona` names one signs in as it (see [personas]).
        let personas = crate::project::project_personas();
        // The crawled site map (route → title), so the walker can plan with the graph.
        let smap = site_map(pages);
        // Banner only when there's something to walk — an empty phase header is clutter.
        if !goals.is_empty() {
            let st = crate::style::Stream::Err;
            note!(progress, "\n{}", st.header("▸ tests"));
            if let Some(u) = &login_url {
                note!(progress, "{}", st.dim(&format!("  login page: {u}")));
            }
        }
        // Flatten goals × viewports into independent walk tasks, then run them CONCURRENTLY — each
        // each test run launches its own browser, so the walks share no state. This is the audit's slowest
        // phase; parallelising it turns "sum of the walks" into "the slowest walk". (viewport rule:
        // "mobile" → phone; "both"/"all" → desktop AND mobile; else desktop only.) Paid plans walk
        // EVERY declared test (no client-side subset cap) — the 25-goal declaration cap, each
        // walk's own hop budget, the server's per-goal hop ceiling, and the AI budget are the real
        // bounds now, not a silent `take(3)`.
        let walk_tasks: Vec<(String, String, String, String, &'static str)> = test_tasks(&goals);
        walks_planned = walk_tasks.len();
        if !cache_hit && !walk_tasks.is_empty() {
            if let Some(ps) = partial_state {
                ps.set_phase("walks");
                ps.set_walks_total(walk_tasks.len());
            }
            // One Chrome per concurrent walk — capped (the crawl workers' browsers are still open too).
            let conc = walk_tasks.len().clamp(1, 3);
            let next = std::sync::atomic::AtomicUsize::new(0);
            let walks_done_ctr = std::sync::atomic::AtomicUsize::new(0);
            let outcomes: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());
            // Full snapshots of the NOVEL states the walks land on (see `run_test`) — pooled across
            // the concurrent walks, deduped against the crawl upstream, then linted like any page.
            let walk_page_sink: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());
            let stash = |mut pages: Vec<Value>| {
                if !pages.is_empty() {
                    walk_page_sink.lock().unwrap().append(&mut pages);
                }
            };
            // One walk → its goal outcome (None if it couldn't run — e.g. a role task with no login page).
            let run_one = |goal: &str,
                           expect: &str,
                           importance: &str,
                           persona: &str,
                           viewport: &str|
             -> Option<Value> {
                let mk =
                    |base: String,
                     headers: Vec<String>,
                     storage: Vec<String>,
                     login: Option<(String, String, String)>| RunTestArgs {
                        base,
                        test: goal.to_string(),
                        site: None,
                        expect: Some(expect.to_string()),
                        hops: crate::test_run::AUDIT_PROBE_HOPS,
                        headers,
                        storage,
                        site_map: smap.clone(),
                        login,
                        viewport: viewport.to_string(),
                    };
                let matched = personas.iter().find(|p| p.name == persona);
                // (reached, hops, flow URL, give-up reason, which persona) — inferred from the walk
                // result + the persona label; annotating the 5-tuple trips clippy::type_complexity.
                let (success, hops, flow_url, lost_reason, surface) = if let Some(p) = matched {
                    // A persona task: become that persona, then pursue the goal. A form persona signs
                    // in through the login page; a session persona replays its headers/storage.
                    let wf = if p.is_form() {
                        let url = login_url.clone()?;
                        mk(
                            url.clone(),
                            Vec::new(),
                            Vec::new(),
                            Some((url, p.username.clone(), p.password.clone())),
                        )
                    } else {
                        mk(
                            args.base.clone(),
                            p.headers.clone(),
                            p.storage.clone(),
                            None,
                        )
                    };
                    match run_test(cli, &wf, progress) {
                        Ok((s, h, f, lr, wp)) => {
                            stash(wp);
                            (s, h, f, lr, format!("a signed-in {}", p.name))
                        }
                        Err(_) => return None,
                    }
                } else if persona == "anonymous" {
                    // A logged-out visitor task: no session, from the public entry.
                    match run_test(
                        cli,
                        &mk(args.base.clone(), Vec::new(), Vec::new(), None),
                        progress,
                    ) {
                        Ok((s, h, f, lr, wp)) => {
                            stash(wp);
                            (s, h, f, lr, "a logged-out visitor".to_string())
                        }
                        Err(_) => return None,
                    }
                } else {
                    // Unspecified audience — a logged-out visitor first, then (if the audit holds a
                    // session) a signed-in user via the injected credentials.
                    let (mut s, mut h, mut f, mut lr, wp0) = run_test(
                        cli,
                        &mk(args.base.clone(), Vec::new(), Vec::new(), None),
                        progress,
                    )
                    .ok()?;
                    stash(wp0);
                    let mut who = "a logged-out visitor".to_string();
                    if !s && was_authed && !past_deadline() {
                        if let Some(url) = login_url.clone() {
                            let wf2 = mk(url, args.headers.clone(), args.storage.clone(), None);
                            if let Ok((s2, h2, f2, lr2, wp2)) = run_test(cli, &wf2, progress) {
                                stash(wp2);
                                if s2 {
                                    (s, h, f, lr, who) =
                                        (true, h2, f2, None, "a signed-in user".to_string());
                                } else {
                                    // Both personas got lost — the signed-in attempt is the more
                                    // complete one, so its give-up reason is the one to report.
                                    lr = lr2;
                                    who = "a logged-out visitor or a signed-in user".to_string();
                                }
                            }
                        }
                    }
                    (s, h, f, lr, who)
                };
                Some(json!({
                    "test": goal, "importance": importance, "viewport": viewport,
                    "outcome": if success { "success" } else { "lost" },
                    "hops": hops, "flow_url": flow_url, "surface": surface,
                    "lost_reason": lost_reason,
                }))
            };
            std::thread::scope(|sc| {
                for _ in 0..conc {
                    sc.spawn(|| loop {
                        if past_deadline() {
                            // A timeout only if walks are still UNCLAIMED — if the last one just
                            // finished a hair past the deadline, that's late, not incomplete.
                            if next.load(std::sync::atomic::Ordering::Relaxed) < walk_tasks.len() {
                                shared.timed_out.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            break;
                        }
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some((goal, expect, importance, persona, viewport)) = walk_tasks.get(i) else {
                            break;
                        };
                        note!(progress,
                            "  {} {}",
                            crate::style::Stream::Err.bold(&format!("[walk {}/{}] \"{goal}\"", i + 1, walk_tasks.len())),
                            crate::style::Stream::Err.dim(&format!(
                                "({importance}, {}, {viewport}) …",
                                if persona.is_empty() { "unspecified" } else { persona.as_str() }
                            ))
                        );
                        let outcome = run_one(goal, expect, importance, persona, viewport);
                        // Walks run CONCURRENTLY, so "done" is a completion counter,
                        // not tied to start order — fed to both the stderr line and the hosted partial.
                        let done_n = walks_done_ctr.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        if let Some(ps) = partial_state {
                            ps.note_walk_done();
                        }
                        let st = crate::style::Stream::Err;
                        match outcome {
                            Some(o) => {
                                let reached = o["outcome"] == "success";
                                let hops = o["hops"].as_u64().unwrap_or(0);
                                note!(progress, "  {} walk {done_n}/{} \"{goal}\" — {} in {hops} hop(s)",
                                    if reached { st.green("✓") } else { st.red("✖") },
                                    walk_tasks.len(),
                                    if reached { "reached" } else { "lost" },
                                );
                                outcomes.lock().unwrap().push(o);
                            }
                            None => note!(progress, "  {} walk {done_n}/{} \"{goal}\" — couldn't run (no login page for this persona)",
                                st.yellow("·"), walk_tasks.len()),
                        }
                    });
                }
            });
            test_outcomes = outcomes.into_inner().unwrap();
            walk_pages = walk_page_sink.into_inner().unwrap();
        }
        // Persist for next time so a later audit on this same clean commit can skip the walk. Only
        // when we actually produced outcomes — never cache an empty run (walking no goals is instant).
        if !cache_hit && !test_outcomes.is_empty() {
            if let Some((path, _)) = &test_cache {
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                let _ = std::fs::write(
                    path,
                    serde_json::to_string(&test_outcomes).unwrap_or_default(),
                );
            }
        }
        goals_ms = t_goals.elapsed().as_millis();
    }
    TestRunOutcome {
        test_outcomes,
        walk_pages,
        walks_planned,
        crawl_ms,
        goals_ms,
    }
}
