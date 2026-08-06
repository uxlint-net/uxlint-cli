//! Target resolution and the browser I/O phase shells, plus the audit's pure decision cores
//! (route/seed/viewport/pool/timeout/credential/sampling logic). The pure cores are unit-tested
//! (see `decision_tests` in mod.rs); the thin shells drive the worker pool and are covered by
//! the dogfood/e2e.

use super::probes::ANON_PROBE_JS;
use super::test_plan::tests_in_scope;
use crate::progress::{note, Progress};
use crate::project::{base_host, is_local_target, norm_route, project_config, route_excluded};
use crate::worker::{
    base_chrome_flags, browser_discoverable, missing_browser_message, worker_loop, AuditWorker,
    PassCtx, PassShared, NAV_TIMEOUT_SECS,
};
use crate::{AuditArgs, Cli};
use anyhow::Result;
use headless_chrome::{Browser, LaunchOptions};
use serde_json::{json, Value};
use std::sync::Mutex;

/// How many instances of one distinct structure (route template × structure fingerprint) we
/// deep-audit. The user picked "up to 5": enough to catch data-dependent issues (a title that
/// overflows on one row, contrast on user content) without re-auditing covered ground.
pub(crate) const SAMPLE_PER_STRUCTURE: usize = 5;

/// The server rejects an audit with more than this many page captures in one POST. The crawl's
/// route budget is capped so route × viewport captures stay under it. Keep in sync with the server.
pub(crate) const MAX_AUDIT_PAGES: usize = 40;

/// From a page type's discovered instances `(structure fingerprint, route)`, pick up to `n` routes
/// that maximise STRUCTURAL diversity: first one route per distinct fingerprint (so an empty list
/// and a populated one, a report with a site-map and one without, are each represented), then fill
/// with remaining instances for data variety. Order is deterministic (input order).
pub(crate) fn diverse_sample(insts: Vec<(u64, String)>, n: usize) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut picked: Vec<String> = Vec::new();
    for (fp, r) in &insts {
        if picked.len() >= n {
            break;
        }
        if seen.insert(*fp) {
            picked.push(r.clone());
        }
    }
    for (_, r) in &insts {
        if picked.len() >= n {
            break;
        }
        if !picked.contains(r) {
            picked.push(r.clone());
        }
    }
    picked
}

/// Reject a `--base` whose scheme isn't http/https BEFORE the browser is pointed at it. uxlint drives
/// a real Chrome to this URL, so a `file:`/`data:`/`javascript:`/`chrome:`/`ftp:` base is a
/// footgun/SSRF hazard, not a website to audit. A bare host (no scheme) is allowed — `Url::parse`
/// rejects it and downstream navigation prepends `http://` — so this only hard-fails an EXPLICIT
/// non-http scheme. Pure, so the guard is unit-testable.
pub(crate) fn require_http_base(base: &str) -> Result<()> {
    if let Ok(u) = reqwest::Url::parse(base) {
        let scheme = u.scheme();
        if scheme != "http" && scheme != "https" {
            anyhow::bail!(
                "--base must be an http(s) URL, not {scheme:?}: {base:?}\n  → uxlint audits websites over a browser; point it at http(s)://your-site"
            );
        }
    }
    Ok(())
}

/// If `--base` carries a path (it should be an ORIGIN), return the one-line nudge toward `--routes`
/// — a path on the base gets appended to every route and usually mis-crawls (e.g. `--base .../r/ID`
/// audits the origin's home, not that report). `None` when the base is a bare origin (or unparseable,
/// left for navigation to handle). Pure so the wording is unit-testable. Port is preserved so the
/// suggested `--base` still points at the right dev server.
pub(crate) fn base_path_hint(base: &str) -> Option<String> {
    let u = reqwest::Url::parse(base).ok()?;
    if u.path().len() <= 1 {
        return None;
    }
    let host = u.host_str().map(|h| match u.port() {
        Some(p) => format!("{h}:{p}"),
        None => h.to_string(),
    })?;
    Some(format!(
        "note: --base has a path ('{}') — that audits the site's routes, not that page. To audit it, use: --base {}://{} --routes {}",
        u.path(),
        u.scheme(),
        host,
        u.path()
    ))
}

/// The audit's ONE pre-flight `GET /v1/me`, before any browser work. Two callers ride on it —
/// `prevalidate_org` (is this uxlint.toml's org/site filable?) and the CLI-alignment check (is this
/// binary the one THIS server expects? — `update::print_server_alignment`) — and neither is worth a
/// second round trip. Best-effort by design: unreachable, non-2xx or unparseable all collapse to
/// `None`, and the post-audit POST is left to surface the real error.
pub(crate) fn fetch_me(cli: &Cli) -> Option<Value> {
    let http = reqwest::blocking::Client::new();
    let resp = http
        .get(format!("{}/v1/me", cli.server))
        .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
        .send()
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Value>().ok()
}

/// Pre-flight the declared org/site against an already-fetched `/v1/me` (see `fetch_me`) so a
/// misconfigured uxlint.toml fails BEFORE the crawl instead of after. Mirrors the server-side
/// guardrail in `audit::audit`; the server stays the source of truth, so this only hard-fails on a
/// clear, authenticated "no" — a signed-out (or, via `fetch_me`, unreachable) /v1/me is left for
/// the post-audit call to surface. Pure over `me`, so the guardrail is unit-testable.
pub(crate) fn prevalidate_org(me: &Value, org: &str, site: Option<&str>) -> Result<()> {
    if me["authenticated"].as_bool() != Some(true) {
        return Ok(()); // not signed in — let the post step raise the auth error, not a confusing one
    }
    let orgs = me["orgs"].as_array().cloned().unwrap_or_default();
    let Some(found) = orgs.iter().find(|o| {
        o["name"]
            .as_str()
            .is_some_and(|n| n.eq_ignore_ascii_case(org))
    }) else {
        let yours: Vec<&str> = orgs.iter().filter_map(|o| o["name"].as_str()).collect();
        anyhow::bail!(
            "uxlint.toml names org {org:?}, which this account isn't a member of\n  → set `org` to one of [{}], or run `uxlint init`",
            yours.join(", ")
        );
    };
    if let Some(site_host) = site {
        let has_site = found["sites"]
            .as_array()
            .map(|a| a.iter().any(|s| s["host"].as_str() == Some(site_host)))
            .unwrap_or(false);
        let can_add =
            found["role"].as_str() == Some("admin") || found["kind"].as_str() == Some("personal");
        if !has_site && !can_add {
            anyhow::bail!(
                "org {org:?} has no site {site_host:?}, and only an org admin can add it\n  → ask an org admin to add it in Settings, or point uxlint.toml at an existing site"
            );
        }
    }
    Ok(())
}

// ── Pure decision cores ─────────────────────────────────────────────────────────────────────────
// The audit's *decisions* — what to crawl, how many workers, which credentials win, when goals are
// in scope, what the payload contains — are pure functions of plain data, so they're unit-tested
// (see `decision_tests`). The browser/HTTP I/O lives in the thin phase shells below and in the
// orchestrator; it is exercised by the dogfood/e2e, not these unit tests. ("Humble object" split.)

/// The routes to seed the crawl: CLI `--routes` unless it's the bare default "/", in which case the
/// project's declared routes win (when it declares any). Pure.
pub(crate) fn effective_routes(cli_routes: &str, toml_routes: Option<&str>) -> String {
    match toml_routes {
        Some(r) if cli_routes == "/" => r.to_string(),
        _ => cli_routes.to_string(),
    }
}

/// The site this audit files under: `--site` → uxlint.toml site → the base host for a real public
/// host. `None` (a hard error at the call site) for a local/generic host with no declared site. Pure.
pub(crate) fn resolve_site(
    arg_site: Option<&str>,
    toml_site: Option<&str>,
    base: &str,
) -> Option<String> {
    arg_site
        .map(str::to_string)
        .or_else(|| toml_site.map(str::to_string))
        .or_else(|| (!is_local_target(base)).then(|| base_host(base)))
        .filter(|s| !s.is_empty())
}

/// The org that owns the site: `--org` → uxlint.toml org. Pure.
pub(crate) fn resolve_org(arg_org: Option<&str>, toml_org: Option<&str>) -> Option<String> {
    arg_org
        .map(str::to_string)
        .or_else(|| toml_org.map(str::to_string))
}

/// The seed routes: split declared routes on commas, normalise each, drop any matching an exclude
/// pattern. Pure.
pub(crate) fn compute_seeds(effective_routes: &str, excludes: &[String]) -> Vec<String> {
    effective_routes
        .split(',')
        .map(|r| norm_route(r.trim()))
        .filter(|r| !route_excluded(r, excludes))
        .collect()
}

/// Crawl budget: the largest of `--crawl`, the uxlint.toml `crawl`, and the seed count (never fewer
/// pages than were explicitly asked for). Pure.
pub(crate) fn resolve_crawl_cap(cli_crawl: usize, toml_cap: usize, seed_count: usize) -> usize {
    cli_crawl.max(toml_cap).max(seed_count)
}

/// Parse `--viewports` ("name:WxH,..." ) into (name, w, h) triples, silently dropping malformed
/// entries — same behaviour as the split_once/parse chain it replaces. Pure.
pub(crate) fn parse_viewports(spec: &str) -> Vec<(String, u32, u32)> {
    spec.split(',')
        .filter_map(|v| {
            let (name, dims) = v.split_once(':')?;
            let (w, h) = dims.split_once('x')?;
            Some((name.to_string(), w.parse().ok()?, h.parse().ok()?))
        })
        .collect()
}

/// Worker-pool size: `hw_cap` = cores-2 clamped to [4,24]; default is full-throttle (`hw_cap`) for a
/// local target, else 4; `--parallel` overrides; then clamp to [1,hw_cap] and never exceed the crawl
/// budget (no point launching more browsers than pages). Pure.
pub(crate) fn pool_size(
    parallel: Option<usize>,
    cores: usize,
    local: bool,
    crawl_cap: usize,
) -> usize {
    let hw_cap = cores.saturating_sub(2).clamp(4, 24);
    let default_k = if local { hw_cap } else { 4 };
    parallel
        .unwrap_or(default_k)
        .clamp(1, hw_cap)
        .min(crawl_cap)
        .max(1)
}

/// Overall browser-phase timeout in seconds: `--timeout` wins, else uxlint.toml, else 300; floored
/// at 1 (a 0 would be a degenerate instant-timeout). Pure.
pub(crate) fn resolve_timeout(flag: Option<u64>, toml: Option<u64>) -> u64 {
    flag.or(toml).unwrap_or(300).max(1)
}

/// Merge backfilled credentials onto `args` — CLI flags already present always win. `extra_headers`/
/// `extra_storage` are newline-lists from the hosted-door env vars; `login_env` is "url\nuser\npass"
/// from `UXLINT_LOGIN`; `cred` is resolved from uxlint.toml `[personas]`. Precedence: CLI (already on `args`) >
/// env > toml. Returns the merged args and whether any uxlint.toml credential was applied (so the
/// shell can print the note). Pure.
pub(crate) fn merge_credentials(
    mut args: AuditArgs,
    extra_headers: Option<&str>,
    extra_storage: Option<&str>,
    login_env: Option<&str>,
    cred: crate::project::ProjectCredentials,
) -> (AuditArgs, bool) {
    // Hosted-door credential injection: env vars keep secrets out of argv/process lists.
    if let Some(extra) = extra_headers {
        args.headers
            .extend(extra.lines().filter(|l| !l.is_empty()).map(str::to_string));
    }
    if let Some(extra) = extra_storage {
        args.storage
            .extend(extra.lines().filter(|l| !l.is_empty()).map(str::to_string));
    }
    // A stored username/password login credential, injected by the hosted door as "url\nuser\npass"
    // (CLI flags win if both are given).
    if args.login_url.is_none() {
        if let Some(v) = login_env {
            let p: Vec<&str> = v.splitn(3, '\n').collect();
            if p.len() == 3 && !p[0].is_empty() && !p[1].is_empty() {
                args.login_url = Some(p[0].to_string());
                args.username = Some(p[1].to_string());
                args.password = Some(p[2].to_string());
            }
        }
    }
    // uxlint.toml [personas]: local-dev creds checked in with the project. CLI flags and the env
    // vars above win; the toml backfills.
    let applied = !cred.headers.is_empty() || !cred.storage.is_empty() || cred.login.is_some();
    args.headers.extend(cred.headers);
    args.storage.extend(cred.storage);
    if args.login_url.is_none() {
        if let Some((url, user, pass)) = cred.login {
            args.login_url = Some(url);
            args.username = Some(user);
            args.password = Some(pass);
        }
    }
    (args, applied)
}

/// The timeout detail sent when the browser-phase deadline actually CUT work: what was planned vs.
/// captured/finished, so a timed-out report can say exactly what was cut. `None` on a clean run. Pure.
pub(crate) fn compute_timeout_detail(
    timed_out: bool,
    cap_secs: u64,
    pages_planned: usize,
    pages_captured: usize,
    walks_planned: usize,
    walks_done: usize,
) -> Option<Value> {
    timed_out.then(|| {
        json!({
            "cap_secs": cap_secs,
            "pages_planned": pages_planned, "pages_captured": pages_captured,
            "walks_planned": walks_planned, "walks_done": walks_done,
        })
    })
}

/// Routes whose capture came back `auth_blocked` (deduped, sorted) — surfaced on the report so a
/// user knows which pages the audit couldn't reach signed-in. Includes routes that `collapse_auth_walls`
/// folded into a representative wall (their `auth_blocked_also` list), so the full set survives the
/// collapse. Pure.
pub(crate) fn auth_blocked_routes(pages: &[Value]) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for p in pages
        .iter()
        .filter(|p| p["auth_blocked"].as_bool() == Some(true))
    {
        if let Some(r) = p["route"].as_str() {
            set.insert(r.to_string());
        }
        if let Some(also) = p["auth_blocked_also"].as_array() {
            set.extend(also.iter().filter_map(Value::as_str).map(str::to_string));
        }
    }
    set.into_iter().collect()
}

/// Multiple gated URLs crawled anonymously all render the SAME auth wall (a login page, or a 401/403),
/// so counting + linting each as its own page is noise — the user sees "30 pages" for a handful of real
/// ones. Collapse every auth-blocked page onto ONE representative route (kept at each viewport it was
/// captured), dropping the rest; the folded-away routes are recorded on the representative as
/// `auth_blocked_also` so `auth_blocked_routes` still lists every gated URL and the report can show
/// them. No-op unless there are ≥2 distinct blocked routes. The representative is the FIRST blocked page
/// in crawl order (stable within a run). Pure — mutates the page list in place.
pub(crate) fn collapse_auth_walls(pages: &mut Vec<Value>) {
    let blocked: std::collections::BTreeSet<String> = pages
        .iter()
        .filter(|p| p["auth_blocked"].as_bool() == Some(true))
        .filter_map(|p| p["route"].as_str().map(str::to_string))
        .collect();
    if blocked.len() < 2 {
        return; // 0 or 1 wall — nothing to collapse
    }
    let Some(rep) = pages
        .iter()
        .find(|p| p["auth_blocked"].as_bool() == Some(true))
        .and_then(|p| p["route"].as_str())
        .map(str::to_string)
    else {
        return;
    };
    let also: Vec<String> = blocked.iter().filter(|r| **r != rep).cloned().collect();
    // Keep non-walls and the representative's own captures; drop every OTHER auth wall.
    pages.retain(|p| {
        p["auth_blocked"].as_bool() != Some(true) || p["route"].as_str() == Some(rep.as_str())
    });
    // Stamp the folded-away routes onto the representative (one capture per viewport).
    for p in pages
        .iter_mut()
        .filter(|p| p["auth_blocked"].as_bool() == Some(true))
    {
        if let Some(o) = p.as_object_mut() {
            o.insert(
                "auth_blocked_also".to_string(),
                serde_json::json!(also.clone()),
            );
        }
    }
}

/// The pure sampling core of the discovery phase: from discovered `(route, layoutSkeleton)` pairs,
/// cluster by page-type template, pick structurally-diverse samples per type, then fill a route
/// budget COVERAGE-first (one of every type) then DEPTH (round-robin extra instances). Returns
/// (route_list, page_type_count, types_covered, route_budget). Pure — the browser crawl is the shell.
pub(crate) fn sample_routes(
    discovered: &[(String, String)],
    seeds: &[String],
    crawl_cap: usize,
    viewports_len: usize,
) -> (Vec<String>, usize, usize, usize) {
    let mut by_type: std::collections::BTreeMap<String, Vec<(u64, String)>> =
        std::collections::BTreeMap::new();
    for (route, skel) in discovered {
        by_type
            .entry(crate::project::route_template(route))
            .or_default()
            .push((crate::project::structure_fingerprint(skel), route.clone()));
    }
    let type_count = by_type.len();
    // Each page type contributes up to SAMPLE_PER_STRUCTURE instances, diverse by structure.
    let clusters: Vec<Vec<String>> = by_type
        .into_values()
        .map(|insts| diverse_sample(insts, SAMPLE_PER_STRUCTURE))
        .collect();
    // Route budget: the deep audit posts route×viewport captures and the server caps ONE audit at
    // MAX_AUDIT_PAGES. So we can audit at most that ÷ viewports routes — and never more than the
    // caller's --crawl. COVERAGE FIRST: one representative of every page TYPE (depth 0), then spend
    // any remaining budget on DEPTH (a 2nd, 3rd… diverse instance), round-robin.
    let route_budget = crawl_cap.min(MAX_AUDIT_PAGES / viewports_len.max(1)).max(1);
    let mut chosen: std::collections::HashSet<String> = seeds.iter().cloned().collect();
    let mut sampled: Vec<String> = Vec::new();
    let max_depth = clusters.iter().map(|c| c.len()).max().unwrap_or(0);
    'fill: for depth in 0..max_depth {
        for c in &clusters {
            if seeds.len() + sampled.len() >= route_budget {
                break 'fill;
            }
            if let Some(r) = c.get(depth) {
                if chosen.insert(r.clone()) {
                    sampled.push(r.clone());
                }
            }
        }
    }
    // Seeds always first (they're explicit intent), then the sampled representatives.
    let route_list: Vec<String> = seeds.iter().cloned().chain(sampled).collect();
    let route_set: std::collections::HashSet<&String> = route_list.iter().collect();
    let covered = clusters
        .iter()
        .filter(|c| c.iter().any(|r| route_set.contains(r)))
        .count();
    (route_list, type_count, covered, route_budget)
}

// ── Phase shells (thin I/O over the pure cores above) ───────────────────────────────────────────

/// The resolved audit target — the outcome of the pure config decisions plus the browser/org
/// preflight. Assembled by `resolve_target`.
pub(crate) struct TargetConfig {
    pub(crate) project: Option<crate::project::ProjectConfig>,
    pub(crate) site: Option<String>,
    pub(crate) org: Option<String>,
    pub(crate) excludes: Vec<String>,
    pub(crate) seeds: Vec<String>,
    pub(crate) crawl_cap: usize,
    pub(crate) run_goals: bool,
}

/// Resolve + preflight the target (I/O shell): validate `--base`, read uxlint.toml, resolve site/org,
/// compute seeds + crawl budget, and fail fast on a missing site, a bad org (`/v1/me`), or no
/// browser — before any crawl work. Prints the opening banner.
pub(crate) fn resolve_target(
    cli: &Cli,
    args: &AuditArgs,
    progress: &(dyn Progress + Sync),
) -> Result<TargetConfig> {
    // Guard the scheme: uxlint navigates a real browser to `--base`, so a non-http(s) scheme
    // (file:, data:, chrome:, javascript:, ftp:) is a foot-gun/SSRF hazard — reject it up front
    // rather than hand it to Chrome.
    require_http_base(&args.base)?;
    // --base should be an ORIGIN; a path there gets appended to routes and usually mis-crawls
    // (e.g. `--base .../r/ID` audits the origin's home, not the report). Nudge toward --routes.
    if let Some(hint) = base_path_hint(&args.base) {
        note!(progress, "  {hint}");
    }
    // uxlint.toml pins this project to an org site and provides default routes.
    let project = project_config();
    let effective = effective_routes(
        &args.routes,
        project.as_ref().and_then(|p| p.routes.as_deref()),
    );
    // Opening banner: what's being audited, then the dimmed setup facts under it.
    {
        let st = crate::style::Stream::Err;
        note!(
            progress,
            "\n{}  {}",
            st.header("▸ uxlint"),
            st.bold(args.base.trim_end_matches('/'))
        );
    }
    if let Some(p) = &project {
        let st = crate::style::Stream::Err;
        note!(
            progress,
            "{}",
            st.dim(&format!(
                "  project: {} ({}) via uxlint.toml",
                p.site, p.org
            ))
        );
    }
    // Routes the project asks us never to audit (e.g. throwaway demo pages).
    let excludes: Vec<String> = project
        .as_ref()
        .map(|p| p.exclude.clone())
        .unwrap_or_default();
    // Every audit names its site (SITES.md). Order of precedence: --site/--org (or UXLINT_SITE/
    // UXLINT_ORG env) → uxlint.toml → the base host itself for a real public host. A local/generic
    // host with no declared site is a hard error — be explicit rather than mint stray sites.
    let site = resolve_site(
        args.site.as_deref(),
        project.as_ref().map(|p| p.site.as_str()),
        &args.base,
    );
    let org = resolve_org(
        args.org.as_deref(),
        project.as_ref().map(|p| p.org.as_str()),
    );
    if site.is_none() {
        anyhow::bail!(
            "no site for this audit of {}. Pass --site <host> (or set UXLINT_SITE), pin it with `uxlint init`, or create it: `uxlint site create <host>`.",
            args.base
        );
    }
    // ONE /v1/me for the whole run, before the crawl — two pre-flights ride on it:
    //
    //  1. Is this CLI the one THIS SERVER is aligned with? Not "is there a newer release" — a
    //     self-hosted or pinned-back deployment expects the CLI IT was built against, which may be
    //     older than latest. It matters here rather than after the audit because the capture (and
    //     so any wrong finding from a stale collector) happens BEFORE the POST — by then the user
    //     has already paid for a whole crawl. Runs on every audit, org declared or not.
    //  2. Fail fast on a bad org/site. The server enforces that too (it's the source of truth), but
    //     catching it here spares a full browser run when uxlint.toml points at an org you can't
    //     file under.
    //
    // Best-effort throughout: an unreachable /v1/me yields None and the post step reports it.
    if let Some(me) = fetch_me(cli) {
        crate::update::print_server_alignment(me.get("cli"));
        if let Some(org_name) = &org {
            prevalidate_org(&me, org_name, site.as_deref())?;
        }
    }
    // Fail fast if there's no Chrome/Chromium to launch AT ALL — before spending time on route
    // discovery or spinning up a whole worker pool just to watch every spawn fail alike. Uses the
    // same discovery `Browser::new` itself relies on (see `browser_discoverable`), so this never
    // misfires "missing" in a case where the actual launch below would have succeeded.
    if !browser_discoverable() {
        anyhow::bail!(missing_browser_message());
    }
    // Route discovery: BFS over internal links from the seeds. The IA lints (depth, orphans, dead
    // ends) are only as honest as the route set — crawling widens it.
    let toml_cap = project.as_ref().map(|p| p.crawl).unwrap_or(0);
    let seeds = compute_seeds(&effective, &excludes);
    if !excludes.is_empty() {
        note!(
            progress,
            "{}",
            crate::style::Stream::Err.dim(&format!(
                "  excluding {} route pattern(s) from the audit: {}",
                excludes.len(),
                excludes.join(", ")
            ))
        );
    }
    let crawl_cap = resolve_crawl_cap(args.crawl, toml_cap, seeds.len());
    // Goals validate WHOLE-SITE reachability, so only walk them on a full-site audit — a crawl or a
    // multi-route run. A single-route, no-crawl audit (a targeted check / verify) skips them, and
    // --no-goals (also accepted as --no-wayfind) forces off.
    let run_goals = tests_in_scope(args.no_tests, seeds.len(), crawl_cap);
    Ok(TargetConfig {
        project,
        site,
        org,
        excludes,
        seeds,
        crawl_cap,
        run_goals,
    })
}

/// Backfill credentials onto the args (I/O shell): read the hosted-door env vars + uxlint.toml
/// `[personas]`, merge them via `merge_credentials` (CLI > env > toml), print the note if a toml
/// credential was applied.
pub(crate) fn inject_credentials(args: &AuditArgs, progress: &(dyn Progress + Sync)) -> AuditArgs {
    let extra_headers = std::env::var("UXLINT_EXTRA_HEADERS").ok();
    let extra_storage = std::env::var("UXLINT_EXTRA_STORAGE").ok();
    let login_env = std::env::var("UXLINT_LOGIN").ok();
    let cred = crate::project::project_credentials();
    let (args, applied) = merge_credentials(
        args.clone(),
        extra_headers.as_deref(),
        extra_storage.as_deref(),
        login_env.as_deref(),
        cred,
    );
    if applied {
        note!(
            progress,
            "{}",
            crate::style::Stream::Err.dim("  credentials: applied from uxlint.toml [personas]")
        );
    }
    args
}

/// Preliminary discovery + structural sampling (I/O shell). Before the expensive per-viewport audit,
/// do a CHEAP crawl (navigate + scrape links + grab the layout skeleton, NO captures/screenshots) to
/// map the site, then hand the discovered pages to the pure `sample_routes` to pick the route set.
/// Returns the routes to deep-audit (seeds first).
#[allow(clippy::too_many_arguments)]
pub(crate) fn discover_and_sample(
    workers: &[AuditWorker],
    shared: &PassShared,
    args: &AuditArgs,
    collector: &str,
    viewports: &[(String, u32, u32)],
    seeds: &[String],
    crawl_cap: usize,
    progress: &(dyn Progress + Sync),
) -> Vec<String> {
    let mut route_list: Vec<String> = seeds.to_vec();
    if crawl_cap > seeds.len() && !viewports.is_empty() {
        let (dname, dw, dh) = (&viewports[0].0, viewports[0].1, viewports[0].2);
        for wk in workers {
            let _ =
                wk.slot
                    .lock()
                    .unwrap()
                    .tab
                    .set_bounds(headless_chrome::types::Bounds::Normal {
                        left: None,
                        top: None,
                        width: Some(dw as f64),
                        height: Some(dh as f64),
                    });
        }
        // Probe more broadly than we'll audit, so every page type is found even behind several lists.
        let discover_cap = crawl_cap.saturating_mul(4).clamp(40, 200);
        {
            let mut q = shared.queue.lock().unwrap();
            q.pending = seeds.iter().cloned().enumerate().collect();
            q.seen = seeds.to_vec();
            q.next_ord = seeds.len();
            q.inflight = 0;
            q.templates.clear();
            q.tmpl_skipped = 0;
            for r in seeds {
                *q.templates
                    .entry(crate::project::route_template(r))
                    .or_insert(0) += 1;
            }
        }
        let ctx = PassCtx {
            args,
            collector,
            name: dname,
            w: dw,
            h: dh,
            discover: true,
            discover_only: true,
            crawl_cap: discover_cap,
            per_template_cap: SAMPLE_PER_STRUCTURE * 2,
            sample_per_structure: SAMPLE_PER_STRUCTURE,
            progress,
        };
        {
            let st = crate::style::Stream::Err;
            note!(
                progress,
                "\n{}  {}",
                st.header("▸ discover"),
                st.dim(&format!(
                    "{dw}x{dh} — mapping the site (cheap: links + structure, no capture)"
                ))
            );
        }
        std::thread::scope(|s| {
            for wk in workers {
                let ctx = &ctx;
                s.spawn(move || worker_loop(wk, ctx, shared));
            }
        });
        // Consume the discovery results (draining CLEARS them so they never leak into `pages`).
        let discovered: Vec<(String, String)> = {
            let mut res = shared.results.lock().unwrap();
            res.drain(..)
                .filter_map(|(_, v)| {
                    let route = v.get("route")?.as_str()?.to_string();
                    let skel = v
                        .get("layoutSkeleton")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some((route, skel))
                })
                .collect()
        };
        let (sampled_routes, type_count, covered, route_budget) =
            sample_routes(&discovered, seeds, crawl_cap, viewports.len());
        route_list = sampled_routes;
        shared.failed.lock().unwrap().clear(); // let the deep pass retry anything that flaked here
        note!(
            progress,
            "  discover: {} page(s) probed → {type_count} page type(s) → auditing {} route(s) (\u{2264}{SAMPLE_PER_STRUCTURE} sample(s)/type)",
            discovered.len(),
            route_list.len()
        );
        if covered < type_count {
            note!(
                progress,
                "  discover: {} page type(s) didn't fit the budget of {route_budget} route(s) (server caps one audit at {MAX_AUDIT_PAGES} captures) — raise --crawl to cover them",
                type_count - covered
            );
        }
    }
    route_list
}

/// The per-viewport capture passes (I/O shell): for each viewport, resize every worker's window,
/// queue the route set, run the worker pool to capture pages, and collect them in queue order.
/// Prunes routes that produced nothing on the first pass so later viewports don't re-pay their
/// timeouts. Appends captures to `pages`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn capture_viewports(
    workers: &[AuditWorker],
    shared: &PassShared,
    args: &AuditArgs,
    collector: &str,
    viewports: &[(String, u32, u32)],
    route_list: &mut Vec<String>,
    crawl_cap: usize,
    pages: &mut Vec<Value>,
    progress: &(dyn Progress + Sync),
) {
    for (vi, (name, w, h)) in viewports.iter().enumerate() {
        // Switch viewport without relaunching Chrome — a real window resize (so @media width
        // queries fire AND screenshots keep working, unlike a device-metrics override).
        for wk in workers {
            let _ =
                wk.slot
                    .lock()
                    .unwrap()
                    .tab
                    .set_bounds(headless_chrome::types::Bounds::Normal {
                        left: None,
                        top: None,
                        width: Some(*w as f64),
                        height: Some(*h as f64),
                    });
        }
        std::thread::sleep(std::time::Duration::from_millis(150)); // let the resize settle
        {
            let st = crate::style::Stream::Err;
            note!(
                progress,
                "\n{}  {}",
                st.header(&format!("▸ {name}")),
                st.dim(&format!("{w}x{h} — {} route(s)", route_list.len()))
            );
        }
        {
            let mut q = shared.queue.lock().unwrap();
            q.pending = route_list.iter().cloned().enumerate().collect();
            q.seen = route_list.clone();
            q.next_ord = route_list.len();
            q.inflight = 0;
        }
        let ctx = PassCtx {
            args,
            collector,
            name,
            w: *w,
            h: *h,
            discover: false, // routes were discovered + sampled in the preliminary phase above
            discover_only: false,
            crawl_cap,
            per_template_cap: SAMPLE_PER_STRUCTURE * 2,
            sample_per_structure: SAMPLE_PER_STRUCTURE,
            progress,
        };
        std::thread::scope(|s| {
            for wk in workers {
                let ctx = &ctx;
                s.spawn(move || worker_loop(wk, ctx, shared));
            }
        });
        // Deterministic output: report pages in queue order, not completion order.
        {
            let mut res = shared.results.lock().unwrap();
            res.sort_by_key(|(ord, _)| *ord);
            pages.extend(res.drain(..).map(|(_, p)| p));
        }
        if vi == 0 {
            // Don't re-pay timeouts/challenges on later viewports for routes that gave nothing.
            let failed = shared.failed.lock().unwrap();
            route_list.retain(|r| !failed.contains(r));
        }
    }
}

/// The signed-out gating pass (I/O shell). Re-visit the public home + each account-view route in a
/// FRESH credential-less browser and record where a logged-out visitor lands, plus whether a Sign-in
/// affordance is discoverable from the home. No-op (empty) when the audit held no session, or past
/// the deadline. Returns `(anon_checks, login_discoverable)`.
pub(crate) fn run_signed_out_gating(
    args: &AuditArgs,
    anon_routes: &[String],
    was_authed: bool,
    deadline: std::time::Instant,
    progress: &(dyn Progress + Sync),
) -> (Vec<Value>, bool) {
    let mut anon_checks: Vec<Value> = Vec::new();
    let mut login_discoverable = false;
    if was_authed && std::time::Instant::now() < deadline {
        // Probe the PUBLIC HOME logged-out (for the Sign in affordance) plus every account-view route
        // (to see where a logged-out visitor gets bounced — that's the login URL).
        let probe_routes: Vec<String> = {
            let mut v = vec!["/".to_string()];
            for r in anon_routes {
                if !v.contains(r) {
                    v.push(r.clone());
                }
            }
            v
        };
        {
            let st = crate::style::Stream::Err;
            note!(
                progress,
                "\n{}  {}",
                st.header("▸ signed-out re-check"),
                st.dim(&format!("{} route(s)", probe_routes.len()))
            );
        }
        // The probes are independent, and the slow ones (a page that DOESN'T redirect — the actual
        // finding — polls the full 2.4s), so fan them out across a small pool, each worker reusing
        // ONE fresh (credential-less) browser across the routes it pulls, so it's still just `conc`
        // browser launches, not one per route.
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
        let conc = probe_routes.len().clamp(1, 3);
        let next = AtomicUsize::new(0);
        let discoverable = AtomicBool::new(false);
        let checks: Mutex<Vec<Value>> = Mutex::new(Vec::new());
        std::thread::scope(|sc| {
            for _ in 0..conc {
                sc.spawn(|| {
                    let Ok(opts) = LaunchOptions::default_builder()
                        .headless(true)
                        .args(base_chrome_flags())
                        .window_size(Some((1280, 900)))
                        .build()
                    else {
                        return;
                    };
                    let Ok(browser) = Browser::new(opts) else {
                        return;
                    };
                    let Ok(tab) = browser.new_tab() else { return };
                    tab.set_default_timeout(std::time::Duration::from_secs(NAV_TIMEOUT_SECS));
                    while let Some(route) = probe_routes.get(next.fetch_add(1, Relaxed)) {
                        let url = format!("{}{}", args.base.trim_end_matches('/'), route);
                        let _ = tab.navigate_to(&url);
                        let _ = tab.wait_until_navigated();
                        // A client-side auth guard redirects on ITS schedule (a fetch has to 401
                        // first) — poll up to 2.4s and exit early once the visitor was sent elsewhere
                        // or sign-in content appeared. One timed sample raced the redirect and flagged
                        // properly-gated pages.
                        let mut probe = json!({});
                        for _ in 0..12 {
                            std::thread::sleep(std::time::Duration::from_millis(200));
                            probe = tab
                                .evaluate(ANON_PROBE_JS, false)
                                .ok()
                                .and_then(|r| r.value)
                                .and_then(|v| {
                                    v.as_str()
                                        .and_then(|s| serde_json::from_str::<Value>(s).ok())
                                })
                                .unwrap_or_else(|| json!({}));
                            let moved = probe["path"].as_str().is_some_and(|p| p != route.as_str());
                            if moved || probe["signin"].as_bool() == Some(true) {
                                break;
                            }
                        }
                        let final_path = probe["path"].as_str().unwrap_or(route).to_string();
                        note!(progress, "  signed-out {route} → {final_path}");
                        // Discoverability is judged from the PUBLIC home: a returning user looks for
                        // "Sign in" there, not on a page they got bounced off.
                        if route == "/" && probe["signinAffordance"].as_bool() == Some(true) {
                            discoverable.store(true, Relaxed);
                        }
                        checks.lock().unwrap().push(json!({
                            "route": route,
                            "final_path": final_path,
                            "text_len": probe["textLen"].as_f64().unwrap_or(0.0),
                            "signin": probe["signin"].as_bool().unwrap_or(false),
                            "login_href": probe["loginHref"].as_str().unwrap_or(""),
                        }));
                    }
                });
            }
        });
        anon_checks = checks.into_inner().unwrap();
        login_discoverable = discoverable.load(Relaxed);
    }
    (anon_checks, login_discoverable)
}

/// The background live-partial HTTP poster (I/O shell). Strictly gated on an actual hosted job id —
/// returns `None` unless `partial_state` exists AND `partial_job` is set (an `external_partial` with
/// no job gets the shared progress STATE but never talks to the server; the async caller polls the
/// Arc itself). Streams progress to `/v1/jobs/{id}/partial` until `partial_stop` is set. The returned
/// handle is joined by the orchestrator after the final flush.
pub(crate) fn spawn_partial_poster(
    partial_state: Option<&std::sync::Arc<crate::worker::PartialState>>,
    partial_job: Option<&str>,
    partial_stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    server: &str,
    token: &str,
) -> Option<std::thread::JoinHandle<()>> {
    partial_state.filter(|_| partial_job.is_some()).map(|ps| {
        use std::sync::atomic::Ordering::Relaxed;
        let ps = ps.clone();
        let stop = partial_stop.clone();
        let server = server.to_string();
        let token = token.to_string();
        let jid = partial_job.unwrap_or_default().to_string();
        std::thread::spawn(move || {
            let http = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .unwrap_or_default();
            loop {
                // Throttle: ≥2s between posts, but wake in 100ms slices to exit promptly on stop.
                for _ in 0..20 {
                    if stop.load(Relaxed) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                let stopping = stop.load(Relaxed);
                // Post when a new page landed OR the phase/walk counters moved, plus one final flush
                // on stop. Runs for the WHOLE audit (crawl → walks → server), not just the crawl
                // window, so the web banner can show phase + walk progress through the ~80s of AI
                // review between the last crawl tick and the finished report.
                if ps.dirty.swap(false, Relaxed) || stopping {
                    let pages = ps.pages.lock().unwrap().clone();
                    if !pages.is_empty() {
                        let total = ps.total.load(Relaxed).max(pages.len());
                        let phase = ps.phase.lock().unwrap().clone();
                        let walks_done = ps.walks_done.load(Relaxed);
                        let walks_total = ps.walks_total.load(Relaxed);
                        let _ = http
                            .post(format!("{server}/v1/jobs/{jid}/partial"))
                            .bearer_auth(&token)
                            .json(&json!({
                                "partial": true, "pages_done": pages.len(), "pages_total": total, "pages": pages,
                                "phase": phase, "walks_done": walks_done, "walks_total": walks_total,
                                "viewports": ps.viewports.load(Relaxed),
                            }))
                            .send();
                    }
                }
                if stopping {
                    break;
                }
            }
        })
    })
}

/// The pre-flight guardrail over an already-fetched `/v1/me`. `fetch_me` itself is I/O (covered by
/// the dogfood/e2e); `prevalidate_org` is pure over the response, so its fail-open/fail-fast
/// boundary is pinned here.
#[cfg(test)]
mod pre_flight_tests {
    use super::*;

    fn me(orgs: Value) -> Value {
        json!({ "authenticated": true, "orgs": orgs })
    }

    #[test]
    fn a_signed_out_me_fails_open() {
        // Not our error to raise — the post-audit POST gives the real auth message, and raising
        // here would replace it with a confusing "org not found".
        assert!(prevalidate_org(&json!({ "authenticated": false }), "acme", None).is_ok());
        assert!(prevalidate_org(&json!({}), "acme", None).is_ok());
    }

    #[test]
    fn an_org_the_account_isnt_in_fails_fast_and_lists_the_real_ones() {
        let me = me(json!([{ "name": "acme", "role": "member", "sites": [] }]));
        let err = prevalidate_org(&me, "typo-corp", None).expect_err("unknown org must bail");
        let msg = err.to_string();
        assert!(msg.contains("typo-corp"), "{msg}");
        assert!(msg.contains("acme"), "names what you COULD use: {msg}");
    }

    #[test]
    fn a_missing_site_only_bails_when_this_account_couldnt_add_it() {
        let member = me(json!([{ "name": "acme", "role": "member", "kind": "team",
                                 "sites": [{ "host": "acme.example" }] }]));
        assert!(prevalidate_org(&member, "ACME", Some("acme.example")).is_ok());
        assert!(prevalidate_org(&member, "acme", Some("other.example")).is_err());
        // An admin (or a personal org) can create the site mid-audit, so it's not an error.
        let admin = me(json!([{ "name": "acme", "role": "admin", "kind": "team", "sites": [] }]));
        assert!(prevalidate_org(&admin, "acme", Some("new.example")).is_ok());
        let personal =
            me(json!([{ "name": "me", "role": "member", "kind": "personal", "sites": [] }]));
        assert!(prevalidate_org(&personal, "me", Some("new.example")).is_ok());
    }
}
