//! The audit orchestration: viewport passes over the worker pool, in-pass crawl,
//! launch probes, tests, and the final POST to the server.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::sync::Mutex;

use crate::progress::{note, Progress};
use crate::project::is_local_target;
use crate::worker::{spawn_worker, AuditWorker, PassQueue, PassShared};
use crate::{AuditArgs, Cli};

mod probes;
mod provenance;
mod request;
// `pub(crate)` for `fetch_me`: the MCP server asks /v1/me for the account's real orgs and sites when
// it has to tell an agent what to put in a missing uxlint.toml (`mcp::project_setup_instructions`).
pub(crate) mod setup;
mod test_plan;
use test_plan::*;
// `uxlint test list`/`walk` resolve declared tests through this same merge — re-export it.
use probes::{
    probe_back_button, probe_not_found_and_favicon, probe_open_redirect, probe_styleguide,
};
use provenance::AuditProvenance;
use request::{build_audit_request, write_dry_run, AuditRequestInputs};
use setup::*;
pub(crate) use test_plan::merged_tests;

// The page-capture script is `crate::redact::collector_js()` — baked into the binary (not fetched
// from the server), with the shared secret-redaction snippet spliced in, so this repo is the
// complete, auditable source of what an audit captures and redacts.

/// Build the audit args for one auth STATE of a multi-state crawl: the base run settings with the
/// credentials REPLACED by that state's — a session persona's headers/storage, a form persona's login,
/// or nothing for `anonymous`. A state defines its OWN session, so it overrides rather than extends.
fn args_for_state(base: &AuditArgs, state: &str) -> AuditArgs {
    let cred = crate::project::credentials_for(state);
    let mut a = base.clone();
    a.headers = cred.headers;
    a.storage = cred.storage;
    match cred.login {
        Some((url, user, pass)) => {
            a.login_url = Some(url);
            a.username = Some(user);
            a.password = Some(pass);
        }
        None => a.login_url = None, // anonymous (or a session persona) — no form login to submit
    }
    a
}

pub(crate) fn run_audit(
    cli: &Cli,
    args: &AuditArgs,
    progress: &(dyn Progress + Sync),
) -> Result<Value> {
    run_audit_ext(cli, args, progress, None)
}

/// Same as `run_audit`, plus an optional externally-owned progress tracker: when given, the
/// crawl/walks/server phase transitions and counts are recorded onto it AS WELL AS (or instead of, if
/// no hosted job) the internally-created one — so a caller like the MCP `audit_url` tool can poll it
/// from an async task running alongside the blocking audit, for real-time MCP progress notifications,
/// with zero coupling to the hosted-job HTTP poster (that stays strictly gated on `UXLINT_JOB_ID`).
pub(crate) fn run_audit_ext(
    cli: &Cli,
    args: &AuditArgs,
    progress: &(dyn Progress + Sync),
    external_partial: Option<std::sync::Arc<crate::worker::PartialState>>,
) -> Result<Value> {
    // Root span for the whole audit — parented on the hosted worker's trace when it handed us a
    // TRACEPARENT, else a fresh root. Held to the end of the function so every phase span below nests
    // under it; a no-op unless OTEL_EXPORTER_OTLP_ENDPOINT is set. This is what turns the crawl from an
    // opaque `audit_worker.job` span into a readable breakdown.
    let _audit_span = crate::otel::audit_root();
    // Age-gated sweep of orphaned Chrome temp profiles, once, up front. A prior audit that
    // was SIGKILLed (uncatchable) can leave a /tmp/rust-headless-chrome-profile* dir behind that the
    // OS never reclaims on a tmpfs; anything untouched for 30min is certainly garbage. Fresh dirs
    // (a concurrent live audit) survive the age gate.
    crate::reaper::sweep_stale_chrome_profiles(std::time::Duration::from_secs(30 * 60));
    // Resolve the audit base BEFORE the target is validated: an explicit `--base` wins, else fall back
    // to `base` in uxlint.toml (written by `uxlint init`), else it's a clear up-front error. Keeping
    // one owned copy here; `inject_credentials` below re-clones anyway. This is what lets a configured
    // project run a bare `uxlint audit` and hit its stored base instead of retyping the URL.
    let resolved_base;
    let args = if args.base.trim().is_empty() {
        let base = crate::project::project_config()
            .and_then(|p| p.base)
            .filter(|b| !b.trim().is_empty())
            .context(
                "no base URL to audit — pass `--base <url>` or set `base` in uxlint.toml (run `uxlint init`)",
            )?;
        resolved_base = AuditArgs {
            base,
            ..args.clone()
        };
        &resolved_base
    } else {
        args
    };
    // Resolve the target: validate --base, pin the site/org, apply excludes, compute the seed
    // routes + crawl budget, and preflight browser + org (bails before any browser work if wrong).
    let TargetConfig {
        project,
        site,
        org,
        excludes,
        seeds,
        crawl_cap,
        run_goals,
    } = resolve_target(cli, args, progress)?;
    // Tell the server this run is starting, so the web shows it in progress exactly like a hosted
    // audit. A CLI/MCP audit used to be invisible for its whole duration — you'd kick one off from an
    // agent, open the dashboard, and see nothing at all until the finished report appeared minutes
    // later, which is indistinguishable from it never having started. Announce-only: it queues no
    // work and meters nothing (the report POST meters, as always).
    let mut local_run = LocalRun::announce(cli, args, site.as_deref());
    // Backfill credentials (hosted-door env vars, then uxlint.toml [credentials]) onto a clone.
    let args = inject_credentials(args, progress);
    let args = &args;
    // The page-capture code is BAKED INTO THIS BINARY (not fetched from the server), so the CLI
    // ships — and this repo fully vouches for — the exact JS that runs in your pages and decides
    // what an audit uploads. No runtime code injection from the server; `uxlint --version` pins the
    // collector too. The shared secret-redaction snippet is spliced in here (one source of truth
    // across every capture channel). (Trust audit remediation.)
    let collector: &str = crate::redact::collector_js();
    // Generous-timeout client for the later report POST / partial posts (the judge + vision passes
    // and summary synthesis are slow; the default client gives up too early on the dogfood).
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .unwrap_or_default();

    let viewports = parse_viewports(&args.viewports);

    let mut pages = Vec::new();
    // Worker pool: each worker is a full browser with its own window, so viewport sizing
    // (a real window resize) and screenshots behave exactly like the serial path. Pool
    // size 1 is the serial path; single-seed audits never over-launch.
    let local = is_local_target(&args.base);
    // Scale the pool to the machine: a browser is mostly waiting on the network and the
    // page, so we can run roughly one per core. Local dev servers take the full fleet;
    // public hosts stay gentle (politeness + their rate limits). The cap only matters up
    // to the route count — no point launching more browsers than there are pages.
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    let k = pool_size(args.parallel, cores, local, crawl_cap);
    // Record the binary + flags Chrome is about to launch with (once), so a deployed run's log proves
    // what's in effect — e.g. --no-sandbox — when a browser won't start. No-op noise locally (RUST_LOG
    // off). See worker::log_chrome_setup.
    crate::worker::log_chrome_setup();
    if k > 1 {
        note!(
            progress,
            "{}",
            crate::style::Stream::Err.dim(&format!(
                "  parallel: {k} worker browsers{} (override with --parallel N)",
                if local && args.parallel.is_none() {
                    " — local target, full throttle"
                } else {
                    ""
                }
            ))
        );
    }
    // Launch the pool concurrently — each spawn is ~2.5s (Chrome boot + auth setup), and
    // paying that serially would eat most of the parallelism win on short audits.
    // A spawn can flake under the simultaneous-boot storm (a missed target-created
    // event) — degrade to the workers that DID come up instead of failing the audit;
    // only zero survivors is fatal.
    let workers: Vec<AuditWorker> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..k).map(|_| s.spawn(|| spawn_worker(args))).collect();
        handles
            .into_iter()
            .filter_map(|h| match h.join().expect("worker spawn thread panicked") {
                Ok(w) => Some(w),
                Err(e) => {
                    note!(
                        progress,
                        "  a worker browser failed to start ({e}) — continuing with fewer"
                    );
                    None
                }
            })
            .collect()
    });
    if workers.is_empty() {
        // The preflight above already confirmed a Chrome/Chromium binary IS discoverable, so every
        // spawn failing here is a different problem (permissions, missing shared libs, resource
        // exhaustion) — not "not installed". Still point at the same escapes: a different binary
        // via CHROME, or skip the local browser entirely with a hosted audit.
        anyhow::bail!(
            "found a Chrome/Chromium binary, but every worker browser still failed to start.\n\
             \n\
             Re-run with RUST_LOG=headless_chrome=debug for the underlying error, try a different\n\
             binary with CHROME=/path/to/chrome, or skip the local browser entirely — hosted\n\
             audits from the dashboard run server-side and need no local browser."
        );
    }
    // Post-pass probes reuse the first worker's CURRENT tab (it may have been replaced
    // mid-audit if a page wedged its renderer) — resolve it lazily, after the passes.

    // Overall browser-phase timeout: the cap on crawl + tests. Resolution, one knob:
    // the `--timeout` flag wins; else uxlint.toml `timeout`; else the 5-minute default. Floored at 1s
    // (a 0 would be a degenerate instant-timeout) — but an explicit tiny value like `--timeout 5` is
    // honoured, so testing the partial-report path is a one-liner. The hosted worker passes
    // `--timeout 60` for the fixed 1-minute web-triggered cap. Whatever the value, the FINALIZE step
    // (the server POST below) runs unconditionally past it — the deadline only gates NEW browser
    // work, so a timed-out audit still produces a (flagged) report.
    let timeout_secs = resolve_timeout(args.timeout, crate::project::project_timeout());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let past_deadline = || std::time::Instant::now() >= deadline;
    // Phase timers: crawl/capture (Chrome) vs tests (LLM) vs server (judge) vs previews, so we
    // can answer "where's the bottleneck?". (`crawl_ms`/`goals_ms` are computed by `run_tests`.)
    let t_crawl = std::time::Instant::now();
    // Live-partial streaming: the background HTTP poster (below) streams progress to
    // /v1/jobs/{id}/partial ONLY under a hosted job (the audit-worker sets UXLINT_JOB_ID) — strictly
    // no-op for local/CLI/MCP runs (env unset). The progress STATE itself (`partial_state`) is
    // broader: an `external_partial` handle (MCP's audit_url) gets the same live crawl/walks/phase
    // tracking without any job id or HTTP involved — the caller polls the Arc directly.
    let partial_job = std::env::var("UXLINT_JOB_ID")
        .ok()
        .filter(|s| !s.is_empty());
    let partial_state: Option<std::sync::Arc<crate::worker::PartialState>> =
        external_partial.clone().or_else(|| {
            partial_job
                .as_ref()
                .map(|_| std::sync::Arc::new(crate::worker::PartialState::default()))
        });

    let shared = PassShared {
        deadline,
        timed_out: std::sync::atomic::AtomicBool::new(false),
        partial: partial_state.clone(),
        queue: Mutex::new(PassQueue::default()),
        coverage: Mutex::new(std::collections::HashMap::new()),
        results: Mutex::new(Vec::new()),
        anon: Mutex::new(Vec::new()),
        bot_blocked: Mutex::new(Vec::new()),
        failed: Mutex::new(Vec::new()),
        throttled: std::sync::atomic::AtomicBool::new(false),
        serial: Mutex::new(()),
        excludes,
        t_nav: std::sync::atomic::AtomicU64::new(0),
        t_settle: std::sync::atomic::AtomicU64::new(0),
        t_capture: std::sync::atomic::AtomicU64::new(0),
        t_states: std::sync::atomic::AtomicU64::new(0),
        t_hover: std::sync::atomic::AtomicU64::new(0),
        t_forms: std::sync::atomic::AtomicU64::new(0),
        t_spinner: std::sync::atomic::AtomicU64::new(0),
        t_resilience: std::sync::atomic::AtomicU64::new(0),
        route_active: std::sync::atomic::AtomicU64::new(0),
        route_peak: std::sync::atomic::AtomicU64::new(0),
        states_active: std::sync::atomic::AtomicU64::new(0),
        states_peak: std::sync::atomic::AtomicU64::new(0),
        context_probed: std::sync::atomic::AtomicBool::new(false),
        crawl_done: std::sync::atomic::AtomicUsize::new(0),
        crawl_total: std::sync::atomic::AtomicUsize::new(0),
    };
    if let Some(ps) = &partial_state {
        ps.set_phase("crawl");
    }

    let mut route_list = discover_and_sample(
        &workers, &shared, args, collector, &viewports, &seeds, crawl_cap, progress,
    );

    // Now the route set is known, tell the crawl-progress counter (CLI tick + web banner's "N of M
    // pages checked" + MCP's progress-notification poller) how many captures to expect. This is
    // unconditional (not tied to whether an HTTP poster runs below) — an `external_partial` with no
    // hosted job (MCP's audit_url) still needs its `total` set for the async caller's poll loop.
    let route_total = route_list.len() * viewports.len().max(1);
    shared
        .crawl_total
        .store(route_total, std::sync::atomic::Ordering::Relaxed);
    if let Some(ps) = &partial_state {
        ps.total
            .store(route_total, std::sync::atomic::Ordering::Relaxed);
        ps.viewports
            .store(viewports.len().max(1), std::sync::atomic::Ordering::Relaxed);
    }
    let partial_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let partial_poster = spawn_partial_poster(
        partial_state.as_ref(),
        partial_job.as_deref(),
        &partial_stop,
        &cli.server,
        cli.api_key.as_deref().unwrap_or(""),
    );

    {
        let _s = crate::otel::phase("capture");
        let states = crate::project::audit_states();
        if states.len() > 1 {
            // AUTH-STATE crawl: capture the same route set under each declared state (anonymous +
            // persona(s)) so a route that renders differently signed-in vs out is audited BOTH ways.
            // Between states we re-session the workers' tabs (setup_tab — the same hook tab-recovery
            // uses) and reset the per-pass accumulators; each capture is tagged so the server keeps the
            // states as distinct pages. Cost is linear in state count — opt in via `audit_states`.
            let route_snapshot = route_list.clone();
            for (si, state) in states.iter().enumerate() {
                let state_args = args_for_state(args, state);
                for wk in &workers {
                    if let Ok(slot) = crate::worker::setup_tab(&wk.browser, &state_args) {
                        *wk.slot.lock().unwrap() = slot;
                    }
                }
                if si > 0 {
                    shared.failed.lock().unwrap().clear();
                    shared.anon.lock().unwrap().clear();
                    shared.bot_blocked.lock().unwrap().clear();
                    route_list = route_snapshot.clone();
                }
                note!(
                    progress,
                    "\n  {} {}",
                    crate::style::Stream::Err.header("▸ state"),
                    crate::style::Stream::Err.dim(state)
                );
                let start = pages.len();
                capture_viewports(
                    &workers,
                    &shared,
                    &state_args,
                    collector,
                    &viewports,
                    &mut route_list,
                    crawl_cap,
                    &mut pages,
                    progress,
                );
                for p in pages[start..].iter_mut() {
                    p["state"] = serde_json::json!(state);
                }
            }
        } else {
            // Single state (the default): unchanged — no state tag, so the report is byte-identical.
            capture_viewports(
                &workers,
                &shared,
                args,
                collector,
                &viewports,
                &mut route_list,
                crawl_cap,
                &mut pages,
                progress,
            );
        }
    }
    // Crawl done, but the poster keeps running — tests and the server's lint+judge pass
    // are still ahead, and the web banner wants phase progress through those too. It's stopped and
    // joined once, right before this function returns.
    let anon_routes: Vec<String> = shared.anon.lock().unwrap().clone();
    let bot_blocked_routes: Vec<String> = shared.bot_blocked.lock().unwrap().clone();
    if !bot_blocked_routes.is_empty() {
        note!(progress,
            "\n  ⚠ bot protection intercepted {} route(s): {}\n    uxlint identifies itself as \"uxlint/0.1 (+https://uxlint.net)\" and does not evade bot\n    detection. Allowlist that user agent (or your audit source IP) in your WAF/CDN, or\n    audit a staging host.",
            bot_blocked_routes.len(),
            bot_blocked_routes.join(", ")
        );
    }

    // ── Launch probes: the 404 page + favicon (once per audit) ─────────────────────
    // A user hitting a dead URL should land on a page that offers a way back — not a bare
    // framework default. And the tab icon is the site's face in tabs/bookmarks.
    let tab = workers[0].slot.lock().unwrap().tab.clone();
    if past_deadline() {
        shared
            .timed_out
            .store(true, std::sync::atomic::Ordering::Relaxed);
        note!(progress, "  TIMEOUT — skipping launch probes, signed-out re-checks and tests; finalizing what we captured");
    }
    let (nf_probe, favicon_status) = {
        let _s = crate::otel::phase("probe.not_found");
        probe_not_found_and_favicon(&tab, &args.base, deadline, progress)
    };
    let back_probe = {
        let _s = crate::otel::phase("probe.back_button");
        probe_back_button(&tab, &args.base, &route_list, deadline, progress)
    };
    let open_redirect = {
        let _s = crate::otel::phase("probe.open_redirect");
        probe_open_redirect(&tab, &args.base, &route_list, deadline, progress)
    };
    // Styleguide existence probe: render the conventional /styleguide (overridable via uxlint.toml
    // `styleguide`; the "off" sentinel opts out) so styleguide-missing doesn't nag a site that ships an
    // UNLINKED design-system page — one the crawl can never discover.
    let styleguide_probe = {
        let _s = crate::otel::phase("probe.styleguide");
        let raw = project
            .as_ref()
            .and_then(|p| p.styleguide.as_deref())
            .unwrap_or("/styleguide");
        let low = raw.trim().to_ascii_lowercase();
        if matches!(low.as_str(), "off" | "none" | "false" | "") {
            json!({ "present": true }) // opted out — report present so the lint stays quiet
        } else {
            probe_styleguide(&tab, &args.base, raw.trim(), deadline, progress)
        }
    };

    // Signed-out gating re-check: routes that showed account affordances while signed in should
    // redirect a logged-out visitor, not strand them. Only meaningful when we WERE signed in.
    let was_authed = !args.storage.is_empty() || !args.headers.is_empty();
    let (anon_checks, login_discoverable) =
        run_signed_out_gating(args, &anon_routes, was_authed, deadline, progress);

    let TestRunOutcome {
        test_outcomes,
        walk_pages,
        walks_planned,
        crawl_ms,
        goals_ms,
    } = {
        let _s = crate::otel::phase("tests");
        run_tests(TestRunInputs {
            cli,
            args,
            progress,
            site: site.as_deref(),
            run_goals,
            pages: &pages,
            anon_checks: &anon_checks,
            anon_routes: &anon_routes,
            was_authed,
            partial_state: partial_state.as_ref(),
            shared: &shared,
            workers: &workers,
            deadline,
            t_crawl,
        })
    };
    // The change (PR/commit) this audit covers. `--change-url` wins; else it's sniffed from
    // GitHub Actions env. `--no-provenance` suppresses all provenance (sha/branch/runner/change_url).
    let provenance = AuditProvenance::collect(args.change_url.as_deref(), args.no_provenance);
    // Did the browser-phase deadline actually CUT work? (a viewport pass dropped routes, or probes/
    // walks were skipped — see PassShared::timed_out.) If so the report is HONESTLY incomplete: send
    // the flag + what was cut (planned vs. captured pages, planned vs. finished walks) in the POST so
    // the server stores it and the web report can banner it. `walks_done` counts walks that produced
    // an outcome. A clean audit sends `timed_out: false` and no detail.
    let timed_out = shared.timed_out.load(std::sync::atomic::Ordering::Relaxed);
    let timeout_detail = compute_timeout_detail(
        timed_out,
        timeout_secs,
        route_total,
        pages.len(),
        walks_planned,
        test_outcomes.len(),
    );
    // Fold the tests' novel captures into the pages to be linted. Merged AFTER the timeout
    // detail above so that stays a crawl-vs-planned measure.
    let (added, over_cap) = merge_walk_pages(&mut pages, walk_pages, WALK_PAGE_CAP);
    if added > 0 {
        note!(
            progress,
            "  {}",
            crate::style::Stream::Err.dim(&format!(
                "tests surfaced {added} page state(s) the crawl didn't reach — linting them too{}",
                if over_cap > 0 {
                    format!(" ({over_cap} more over the cap, skipped)")
                } else {
                    String::new()
                }
            ))
        );
    }
    // `exclude` is authoritative for LINTING, not just crawl discovery: a route in the project's
    // `exclude` list never contributes findings however it was reached — a NAMED seed, a crawled
    // link, or a goal walk that navigated through it. (The walk's own reached/lost outcome is
    // unaffected; only its captured page is dropped from the lint set.) This keeps meta pages — the
    // /example demo, the report viewers — out of the report even when a run names one explicitly or a
    // test walks to it, which the discovery-time filter (worker.rs) can't catch.
    let excluded_n = drop_excluded_pages(&mut pages, &shared.excludes);
    if excluded_n > 0 {
        note!(
            progress,
            "  {}",
            crate::style::Stream::Err.dim(&format!(
                "excluded {excluded_n} page(s) from linting (uxlint.toml `exclude`)"
            ))
        );
    }
    let theme = project.as_ref().and_then(|p| p.theme.clone());
    let site_type = args
        .site_type
        .clone()
        .or_else(|| project.as_ref().and_then(|p| p.site_type.clone()));
    // Desktop-primary routes (uxlint.toml `desktop_only`) — sent so the server can demote their
    // mobile findings to `info`. Config-only (no CLI flag): a project declares its own tiering.
    let desktop_only = project
        .as_ref()
        .map(|p| p.desktop_only.clone())
        .unwrap_or_default();
    // Fold duplicate auth walls (many gated URLs anonymously render the SAME login) into ONE
    // representative page — so they're counted + linted once, not N times. Runs AFTER walk pages merge
    // and BEFORE the payload build, since the server lints exactly what we post. The folded routes ride
    // along on the representative (auth_blocked_also) so the report still lists them all.
    collapse_auth_walls(&mut pages);
    // THE single place the upload payload is assembled — see `build_audit_request` (pure).
    let payload = build_audit_request(&AuditRequestInputs {
        base_url: &args.base,
        org: org.as_deref(),
        site: site.as_deref(),
        pages: &pages,
        tests: &test_outcomes,
        anon_checks: &anon_checks,
        login_discoverable,
        no_judge: args.no_judge,
        nf_probe: &nf_probe,
        favicon_status,
        back_probe: &back_probe,
        open_redirect: &open_redirect,
        styleguide: &styleguide_probe,
        bot_blocked_routes: &bot_blocked_routes,
        labels: &args.labels,
        timed_out,
        timeout_detail: timeout_detail.as_ref(),
        provenance: &provenance,
        theme: theme.as_ref(),
        site_type: site_type.as_deref(),
        desktop_only: &desktop_only,
    });
    // --dry-run: this is the whole point of the flag — write the EXACT payload we would POST to disk
    // (with screenshots split out as viewable JPEGs) and stop, without sending anything to the
    // server. Assembled from the same `payload` value, so what you inspect is what would ship.
    if let Some(dir) = &args.dry_run {
        return write_dry_run(&payload, std::path::Path::new(dir), progress);
    }
    // Name the progress row this run announced, so the report closes it server-side the moment it
    // lands (rather than the row waiting out the staleness window). Stamped here rather than threaded
    // through `AuditRequestInputs`: it isn't part of what was captured, it's who to tell we're done.
    let mut payload = payload;
    if let Some(run) = &local_run {
        payload["job_id"] = json!(run.job_id());
    }
    let out = send_and_finalize(FinalizeInputs {
        cli,
        args,
        progress,
        http: &http,
        payload,
        pages: &pages,
        partial_state: partial_state.as_ref(),
        partial_stop: &partial_stop,
        partial_poster,
        timed_out,
        timeout_detail: timeout_detail.as_ref(),
        crawl_ms,
        goals_ms,
        t_crawl,
    });
    // A posted report closed the job server-side; anything else leaves the guard to cancel it on the
    // way out, so a failed audit doesn't leave a spinner running in the user's browser.
    if out.is_ok() {
        if let Some(run) = &mut local_run {
            run.finish();
        }
    }
    out
}

/// The `audit_jobs` row that makes THIS run visible in the web while it happens (`POST
/// /v1/audit-jobs/local`). Best-effort throughout: an audit must never fail because its progress
/// row couldn't be recorded, so every call here swallows its error and the audit carries on
/// unannounced.
///
/// It closes itself. The report POST carries `job_id` and the server marks the job done — that's the
/// happy path, and `finish()` records it so this guard stays quiet. Anything else (a failed crawl, a
/// bad target, an unwind on Ctrl-C) drops the guard, which cancels the row: a failed audit clears its
/// own spinner instead of leaving one for the server's staleness window to reap half an hour later.
/// A SIGKILL still leaves the row behind, which is exactly what that window is for.
struct LocalRun<'a> {
    cli: &'a Cli,
    job_id: String,
    finished: bool,
}

impl<'a> LocalRun<'a> {
    /// `None` when there is nothing to announce: no API key (nothing to authenticate with), a
    /// `--dry-run` (which posts nothing at all, by definition), or a HOSTED run — the audit-worker
    /// sets `UXLINT_JOB_ID`, and that job is already on the dashboard. Announcing there would put the
    /// same audit in the list twice.
    fn announce(cli: &'a Cli, args: &AuditArgs, site: Option<&str>) -> Option<Self> {
        let key = cli.api_key.as_deref().filter(|k| !k.trim().is_empty())?;
        if args.dry_run.is_some() || std::env::var("UXLINT_JOB_ID").is_ok_and(|v| !v.is_empty()) {
            return None;
        }
        // Short timeout: this is a progress nicety in front of a multi-minute audit — it must never
        // be the thing that makes one wait.
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .ok()?;
        let body = json!({ "base_url": args.base, "site": site });
        let job_id = http
            .post(format!("{}/v1/audit-jobs/local", cli.server))
            .bearer_auth(key)
            .json(&body)
            .send()
            .ok()
            .filter(|r| r.status().is_success())
            .and_then(|r| r.json::<Value>().ok())
            .and_then(|v| v["job_id"].as_str().map(str::to_string))
            .filter(|id| !id.is_empty())?;
        Some(Self {
            cli,
            job_id,
            finished: false,
        })
    }

    /// The id to put on the report payload — the server closes the job when that report lands.
    fn job_id(&self) -> &str {
        &self.job_id
    }

    /// The report was posted: the server has already closed this job, so Drop must not cancel it.
    fn finish(&mut self) {
        self.finished = true;
    }
}

impl Drop for LocalRun<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let Some(key) = self.cli.api_key.as_deref() else {
            return;
        };
        let Ok(http) = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        else {
            return;
        };
        // Cancel, not fail: from the server's side an audit that stopped on the user's machine is
        // indistinguishable from one the user aborted, and `cancel_audit_job` is the endpoint that
        // already means "this job is over, nobody finished it".
        let _ = http
            .post(format!(
                "{}/v1/audit-jobs/{}/cancel",
                self.cli.server, self.job_id
            ))
            .bearer_auth(key)
            .send();
    }
}

/// Inputs to the POST + finalize phase (some borrowed, some owned — it consumes the payload and the
/// poster handle it joins).
struct FinalizeInputs<'a> {
    cli: &'a Cli,
    args: &'a AuditArgs,
    progress: &'a (dyn Progress + Sync),
    http: &'a reqwest::blocking::Client,
    payload: Value,
    pages: &'a [Value],
    partial_state: Option<&'a std::sync::Arc<crate::worker::PartialState>>,
    partial_stop: &'a std::sync::atomic::AtomicBool,
    partial_poster: Option<std::thread::JoinHandle<()>>,
    timed_out: bool,
    timeout_detail: Option<&'a Value>,
    crawl_ms: u128,
    goals_ms: u128,
    t_crawl: std::time::Instant,
}

/// POST the payload to `/v1/audit` and finalize (I/O shell): surface the paywall/error branches,
/// stamp the timeout flag, run fix previews, fold in the client-side phase timings, apply
/// suppressions (+ feed them back), annotate local source, then stop + join the partial poster.
/// Returns the finished report.
fn send_and_finalize(input: FinalizeInputs) -> Result<Value> {
    let FinalizeInputs {
        cli,
        args,
        progress,
        http,
        payload,
        pages,
        partial_state,
        partial_stop,
        partial_poster,
        timed_out,
        timeout_detail,
        mut crawl_ms,
        goals_ms,
        t_crawl,
    } = input;
    let mut req = http.post(format!("{}/v1/audit", cli.server)).json(&payload);
    if let Some(key) = &cli.api_key {
        req = req.bearer_auth(key);
    }
    // Phase: "server" — the deterministic lint pass + (unless --no-judge) the AI judge pass now run
    // server-side, in ONE blocking call the CLI can't see inside. That's why the CLI can't show a live
    // done/left count for lint/judge specifically (unlike crawl/walks): from here it just waits. The
    // hosted partial keeps posting this phase (and its own last page/walk counts) throughout the wait,
    // so the web banner reads "AI review still running" rather than going stale.
    if let Some(ps) = partial_state {
        ps.set_phase("server");
    }
    {
        let st = crate::style::Stream::Err;
        note!(
            progress,
            "\n{}  {}",
            st.header("▸ server"),
            st.dim(&format!(
                "posting {} page capture(s){} — running lint + judge …",
                pages.len(),
                if args.no_judge {
                    " (judge tier skipped)"
                } else {
                    ""
                }
            ))
        );
    }
    let t_post = std::time::Instant::now();
    // The server's lint + judge pass runs INSIDE this request, so the `post` span's duration is the
    // deterministic-lint + LLM-judge time (the report echoes a judge_ms/judge_calls breakdown too).
    let resp = {
        let _s = crate::otel::phase("post");
        // Put this span's traceparent on the request so the server continues the trace — its judge
        // spans nest under `post` instead of forming a disconnected root. Injected inside the span
        // scope so `traceparent()` reads THIS span. No-op header omitted when tracing is off.
        let req = match crate::otel::traceparent() {
            Some(tp) => req.header("traceparent", tp),
            None => req,
        };
        req.send()
    }?;
    if resp.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
        let v: Value = resp.json().unwrap_or_default();
        note!(
            progress,
            "Free-plan quota reached. Upgrade for unlimited audits + the judge tier:"
        );
        note!(
            progress,
            "  curl -X POST {} -H \"Authorization: Bearer $UXLINT_API_KEY\"",
            v["checkout"].as_str().unwrap_or("(checkout)")
        );
        anyhow::bail!("quota exhausted");
    }
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        // A structured rejection (e.g. a uxlint.toml misconfig) carries an `error` + `fix` — surface
        // those plainly instead of dumping the raw JSON.
        if let Ok(v) = serde_json::from_str::<Value>(&body) {
            if let Some(err) = v["error"].as_str() {
                match v["fix"].as_str() {
                    Some(fix) => anyhow::bail!("{err}\n  → {fix}"),
                    None => anyhow::bail!("{err}"),
                }
            }
        }
        anyhow::bail!("server rejected audit: {status} — {body}");
    }
    let mut report: Value = resp.json()?;
    // Stamp the timeout flag on the report we hand back (the server also stores it from the POST for
    // the web view; this guarantees the CLI print and the MCP result see it without depending on the
    // server echoing the field). Only when it actually fired — never clobber a clean report.
    if timed_out {
        report["timed_out"] = json!(true);
        if let Some(detail) = timeout_detail {
            report["timeout_detail"] = detail.clone();
        }
    }
    let post_ms = t_post.elapsed().as_millis();
    if crawl_ms == 0 {
        crawl_ms = t_crawl.elapsed().as_millis().saturating_sub(post_ms); // goals were skipped
    }
    let blocked = auth_blocked_routes(pages);
    if !blocked.is_empty() {
        report["auth_blocked_routes"] = json!(blocked);
    }
    // Fix previews (on by default): re-open each finding's element, outline it in a captured
    // screenshot, and for fixable ones apply the fix and capture the "after" too. This is what
    // gives the report its screenshots. It works off any finding's rect and does NOT depend on the
    // judge — so `--no-judge` (which only disables the LLM lints) does not skip it. Turn previews
    // off explicitly with `--no-previews`, or `UXLINT_NO_PREVIEWS` for a whole harness run (the e2e
    // sets it: many fixture audits, and it asserts findings, not pictures).
    if let Some(ps) = partial_state {
        ps.set_phase("previews");
    }
    let t_prev = std::time::Instant::now();
    let skip_previews = args.no_previews || std::env::var_os("UXLINT_NO_PREVIEWS").is_some();
    if !skip_previews {
        {
            let st = crate::style::Stream::Err;
            note!(
                progress,
                "\n{}  {}",
                st.header("▸ previews"),
                st.dim("re-opening each finding for before/after crops …")
            );
        }
        let previews = {
            let _s = crate::otel::phase("previews");
            crate::fix_preview::run(cli, args, &report)
        };
        match previews {
            Ok(0) => note!(
                progress,
                "{}",
                crate::style::Stream::Err.dim("  no previewable fixes on this audit")
            ),
            Ok(n) => note!(
                progress,
                "{}",
                crate::style::Stream::Err.dim(&format!(
                    "  {n} before/after preview(s) added to the report"
                ))
            ),
            Err(e) => note!(
                progress,
                "{}",
                crate::style::Stream::Err.yellow(&format!("  fix previews skipped: {e}"))
            ),
        }
    }
    let prev_ms = t_prev.elapsed().as_millis();
    // Where did the time go? Crawl/capture + previews are Chrome; tests + the server's judge
    // time are the LLM. (The server post's non-judge share is deterministic lints — usually tiny.)
    let judge_ms = report["timing"]["judge_ms"].as_u64().unwrap_or(0) as u128;
    let judge_calls = report["timing"]["judge_calls"].as_u64().unwrap_or(0);
    // Fold the CLIENT-side phase breakdown into the same `timing` object the server's judge_ms/
    // judge_calls already ride (the MCP fallback: a local `audit_url` result carries phase timings
    // even though there's no live progress channel across a single blocking JSON-RPC call).
    if let Some(obj) = report["timing"].as_object_mut() {
        obj.insert("crawl_ms".into(), json!(crawl_ms));
        obj.insert("goals_ms".into(), json!(goals_ms));
        obj.insert("post_ms".into(), json!(post_ms));
        obj.insert("prev_ms".into(), json!(prev_ms));
    } else {
        report["timing"] = json!({
            "crawl_ms": crawl_ms, "goals_ms": goals_ms, "post_ms": post_ms, "prev_ms": prev_ms,
            "judge_ms": judge_ms, "judge_calls": judge_calls,
        });
    }
    let s = |ms: u128| format!("{:.1}s", ms as f64 / 1000.0);
    let llm = goals_ms + judge_ms;
    let browser = crawl_ms + prev_ms + post_ms.saturating_sub(judge_ms);
    note!(
        progress,
        "\n{}",
        crate::style::Stream::Err.dim(&format!(
            "  timing: crawl/capture {} · tests {} · server {} (judge {} / {} calls) · previews {}",
            s(crawl_ms),
            s(goals_ms),
            s(post_ms),
            s(judge_ms),
            judge_calls,
            s(prev_ms)
        ))
    );
    note!(
        progress,
        "{}",
        crate::style::Stream::Err.dim(&format!(
            "  ≈ LLM {} vs browser {} — bottleneck: {}",
            s(llm),
            s(browser),
            if llm >= browser {
                "the LLM/judge"
            } else {
                "Chrome crawl/capture"
            }
        ))
    );
    // Drop findings the project has reviewed and suppressed (uxlint.toml [[suppress]]) before
    // anything else looks at them.
    let suppressed =
        crate::project::apply_suppressions(&mut report, &crate::project::suppressions());
    // A suppression is an implicit "reject" — feed it back so we learn which rules users don't
    // trust. Best-effort and stable-keyed (no report_id) so re-audits update, never pile up; a
    // failed post never fails the audit.
    if let Some(key) = &cli.api_key {
        for rule in &suppressed {
            let _ = http
                .post(format!("{}/v1/feedback", cli.server))
                .bearer_auth(key)
                .json(&json!({"rule": rule, "verdict": "reject", "source": "suppress", "reason": "suppressed in uxlint.toml"}))
                .send();
        }
    }
    // Local audits: map findings back to source (file:line) by grepping the project we're in, so
    // an agent can jump straight to the fix. Client-side only — the server never sees the code.
    if is_local_target(&args.base) {
        crate::source_map::annotate(&mut report, std::path::Path::new("."));
        // DRY advisory: card/panel utility clusters retyped across the source are a component waiting
        // to be extracted (see web Panel.svelte). Source-based — the rendered DOM can't tell an
        // inlined panel from a <Panel>, so this is the only sound place to catch it. Local + printed
        // only; never posted to the server.
        let dry = crate::source_map::dry_advisory(std::path::Path::new("."));
        if !dry.is_empty() {
            let total: usize = dry.iter().map(|d| d.count).sum();
            note!(progress, "\n{}", crate::style::Stream::Err.dim(&format!("  DRY: {total} inlined card/panel(s) across {} repeated cluster(s) — candidates for a shared component:", dry.len())));
            for d in dry.iter().take(5) {
                note!(
                    progress,
                    "{}",
                    crate::style::Stream::Err.dim(&format!(
                        "    ×{} in {} file(s): \"{}\"",
                        d.count, d.files, d.cluster
                    ))
                );
            }
            // Carry the advisory in the report so it reaches an agent driving the audit over MCP (the
            // printed note above only lands in a human's terminal). Client-side field, added AFTER the
            // server POST — the source (and this signal) never leaves the machine.
            report["source_dry"] = json!(dry
                .iter()
                .map(|d| json!({ "cluster": d.cluster, "count": d.count, "files": d.files, "source": d.source }))
                .collect::<Vec<_>>());
        }
    }
    // Stop the partial poster and let it flush one last time — the finished report (about to be
    // returned/saved) supersedes any partial from here. Runs even on the local/no-job path (the
    // stop flag and join are no-ops there — `partial_poster` is `None`).
    if let Some(ps) = partial_state {
        ps.set_phase("done");
    }
    partial_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Some(h) = partial_poster {
        let _ = h.join();
    }
    Ok(report)
}

/// How many test-run-captured page states may be added to a report. Walks reach a bounded set of
/// novel states; the cap stops a pathological run from ballooning the report + judge cost.
const WALK_PAGE_CAP: usize = 12;

/// Merge the tests' captured page states into `pages`. Keyed by (route, viewport, empty-state):
/// a walk page is kept when that COMBINATION is new — so both a NOVEL route (the interaction-reached
/// pages the link-crawl never sees) AND a novel STATE of an already-crawled route (a walk's EMPTY
/// /sites next to the crawl's populated one) survive, while an exact-duplicate state is dropped. When
/// a walk's empty capture lands on the same (route, viewport) as the crawl, the SERVER folds them and
/// dedupes the findings — so an empty-state finding is added, shared failures aren't doubled. Appends
/// up to `cap`; returns `(added, over_cap)` so the caller reports both what was linted and dropped
/// (never a silent truncation). Pure so the dedup/cap contract is unit-tested without a browser.
/// Drop pages whose route is in the project's `exclude` list from the LINT set — however they were
/// reached (a named seed, a crawled link, or a goal walk that navigated through it). Returns how many
/// were dropped. This makes `exclude` authoritative for LINTING, not just crawl discovery, so meta
/// pages (the /example demo, report viewers) never contribute findings even when a run names one or a
/// test walks to it.
fn drop_excluded_pages(pages: &mut Vec<Value>, excludes: &[String]) -> usize {
    let before = pages.len();
    pages.retain(|p| !crate::project::route_excluded(p["route"].as_str().unwrap_or(""), excludes));
    before - pages.len()
}

fn merge_walk_pages(pages: &mut Vec<Value>, walk_pages: Vec<Value>, cap: usize) -> (usize, usize) {
    let key = |p: &Value| {
        (
            p["route"].as_str().unwrap_or_default().to_string(),
            p["viewport"].as_str().unwrap_or_default().to_string(),
            p["snapshot"]["emptyState"].as_bool().unwrap_or(false),
        )
    };
    let mut seen: std::collections::HashSet<(String, String, bool)> =
        pages.iter().map(key).collect();
    let (mut added, mut over_cap) = (0usize, 0usize);
    for wp in walk_pages {
        if !seen.insert(key(&wp)) {
            continue; // same route+viewport AND same data state — already captured, don't re-lint
        }
        if added >= cap {
            over_cap += 1;
            continue;
        }
        pages.push(wp);
        added += 1;
    }
    (added, over_cap)
}

#[cfg(test)]
mod walk_page_merge_tests {
    use super::*;
    use serde_json::json;

    fn page(route: &str, vp: &str) -> Value {
        json!({ "route": route, "viewport": vp, "snapshot": {} })
    }

    #[test]
    fn drop_excluded_pages_removes_only_excluded_routes() {
        // Even a page that reached the lint set as a named seed or a goal walk is dropped if its route
        // is excluded — /example (prefix) and the report viewer (glob) go; /pricing and /docs stay.
        let mut pages = vec![
            page("/pricing", "desktop"),
            page("/example", "desktop"),
            page("/example/before", "mobile"),
            page("/sites/5/r/abc", "desktop"),
            page("/docs", "mobile"),
        ];
        let dropped = drop_excluded_pages(&mut pages, &["/example".into(), "/sites/*/r/*".into()]);
        assert_eq!(dropped, 3);
        let routes: Vec<&str> = pages.iter().map(|p| p["route"].as_str().unwrap()).collect();
        assert_eq!(routes, vec!["/pricing", "/docs"]);
    }
    // A page whose snapshot carries an explicit emptyState.
    fn page_empty(route: &str, vp: &str, empty: bool) -> Value {
        json!({ "route": route, "viewport": vp, "snapshot": { "emptyState": empty } })
    }

    #[test]
    fn novel_routes_merge_dupes_and_cap_drop() {
        // Crawl already has /a (desktop) and /b (desktop).
        let mut pages = vec![page("/a", "desktop"), page("/b", "desktop")];
        let walk = vec![
            page("/a", "desktop"), // dup vs crawl → skip
            page("/c", "desktop"), // novel → add
            page("/a", "mobile"),  // novel (different viewport) → add
            page("/c", "desktop"), // dup vs the just-added walk page → skip
        ];
        let (added, over_cap) = merge_walk_pages(&mut pages, walk, 12);
        assert_eq!((added, over_cap), (2, 0));
        assert_eq!(pages.len(), 4);
    }

    #[test]
    fn empty_state_of_a_crawled_route_is_kept() {
        // The crawl captured /sites POPULATED; a walk reaches /sites EMPTY. Same route+viewport but a
        // different data state → keep it (the server folds the two and dedupes findings).
        let mut pages = vec![page_empty("/sites", "desktop", false)];
        let walk = vec![
            page_empty("/sites", "desktop", true), // empty state → novel → add
            page_empty("/sites", "desktop", false), // same populated state again → skip
        ];
        let (added, over_cap) = merge_walk_pages(&mut pages, walk, 12);
        assert_eq!((added, over_cap), (1, 0));
        assert_eq!(pages.len(), 2);
    }

    #[test]
    fn cap_bounds_additions_and_reports_the_overflow() {
        let mut pages = vec![page("/", "desktop")];
        let walk: Vec<Value> = (0..5).map(|i| page(&format!("/n{i}"), "desktop")).collect();
        let (added, over_cap) = merge_walk_pages(&mut pages, walk, 3);
        assert_eq!((added, over_cap), (3, 2));
        assert_eq!(pages.len(), 4);
    }

    #[test]
    fn no_walk_pages_is_a_noop() {
        let mut pages = vec![page("/", "desktop")];
        assert_eq!(merge_walk_pages(&mut pages, Vec::new(), 12), (0, 0));
        assert_eq!(pages.len(), 1);
    }
}

#[cfg(test)]
mod goal_walk_gate_tests {
    use super::*;

    #[test]
    fn tests_in_scope_needs_a_full_site_audit() {
        // A crawl (crawl_cap > seeds) or more than one seed route is "full site" — goals in scope.
        assert!(
            tests_in_scope(false, 1, 12),
            "crawl widens beyond the single seed — in scope"
        );
        assert!(
            tests_in_scope(false, 3, 3),
            "several explicit seed routes — in scope"
        );
        // A single-route, no-crawl audit (targeted check / verify) is out of scope even with goals
        // declared — walking the whole site's goals when auditing one page is the mismatch.
        assert!(
            !tests_in_scope(false, 1, 1),
            "single route, no crawl — targeted, out of scope"
        );
    }

    #[test]
    fn tests_in_scope_no_goals_forces_off_regardless() {
        // --no-goals (and its --no-wayfind alias) is the hard off switch, even on a full-site audit.
        assert!(!tests_in_scope(true, 5, 12));
    }

    #[test]
    fn plan_allows_tests_only_for_non_free_plans() {
        assert!(!plan_allows_tests("free"));
        assert!(
            !plan_allows_tests("FREE"),
            "case-insensitive — /v1/me could plausibly vary"
        );
        for plan in ["pro", "team", "enterprise", "admin"] {
            assert!(
                plan_allows_tests(plan),
                "{plan} should be allowed to walk goals"
            );
        }
    }

    #[test]
    fn paywall_warning_names_the_count_and_the_upgrade_path() {
        let one = test_paywall_warning(1, "https://uxlint.net");
        assert!(
            one.contains("1 declared test") && !one.contains("goals"),
            "singular: {one}"
        );
        let five = test_paywall_warning(5, "https://uxlint.net/");
        assert!(five.contains("5 declared tests"), "plural + count: {five}");
        assert!(
            five.contains("https://uxlint.net/pricing"),
            "upgrade pointer (no double slash): {five}"
        );
        assert!(
            five.to_lowercase().contains("paid plan") || five.to_lowercase().contains("pro"),
            "names why: {five}"
        );
    }

    #[test]
    fn test_tasks_has_no_subset_cap() {
        // Paid plans walk EVERY declared test; there is no client-side subset cap. 5 declared tests
        // (single desktop viewport each) must yield 5 tasks, not 3.
        let goals: Vec<Value> = (0..5)
            .map(|i| json!({"test": format!("goal {i}"), "expect": "x", "importance": "important", "persona": "", "viewport": ""}))
            .collect();
        let tasks = test_tasks(&goals);
        assert_eq!(
            tasks.len(),
            5,
            "every declared test gets a walk task, no cap"
        );
    }

    #[test]
    fn test_tasks_fans_out_both_viewports() {
        let goals = vec![
            json!({"test": "g", "expect": "x", "importance": "important", "persona": "", "viewport": "both"}),
        ];
        let tasks = test_tasks(&goals);
        assert_eq!(
            tasks.len(),
            2,
            "\"both\" viewport fans one goal into desktop + mobile tasks"
        );
    }

    #[test]
    fn test_tasks_skips_incomplete_declarations() {
        // A goal missing `expect` (or `goal` itself) can't be walked — dropped rather than crashing.
        let goals = vec![
            json!({"test": "", "expect": "x"}),
            json!({"test": "g", "expect": ""}),
        ];
        assert!(test_tasks(&goals).is_empty());
    }

    #[test]
    fn dedup_tests_local_wins_a_name_collision() {
        // uxlint.toml (local, checked-in) takes precedence over a server-declared test with the
        // SAME goal text — the local one's expect/importance is what survives.
        let local =
            vec![json!({"test": "sign in", "expect": "dashboard", "importance": "critical"})];
        let server = vec![
            json!({"test": "sign in", "expect": "login", "importance": "minor"}),
            json!({"test": "invite a teammate", "expect": "invite", "importance": "important"}),
        ];
        let merged = dedup_tests(local, server);
        assert_eq!(
            merged.len(),
            2,
            "the colliding server goal is dropped, the distinct one kept"
        );
        assert_eq!(
            merged[0]["expect"], "dashboard",
            "local goal's fields win on a name collision"
        );
        assert_eq!(merged[1]["test"], "invite a teammate");
    }

    #[test]
    fn dedup_tests_is_order_stable_local_first() {
        // Server goals not already declared locally are appended AFTER the local set, in the
        // server's own order — so a project's checked-in goals always list first.
        let local = vec![json!({"test": "a"}), json!({"test": "b"})];
        let server = vec![
            json!({"test": "c"}),
            json!({"test": "a"}),
            json!({"test": "d"}),
        ];
        let merged = dedup_tests(local, server);
        let names: Vec<&str> = merged.iter().map(|g| g["test"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn test_cache_unreadable_when_goals_empty() {
        // Nothing declared, or the paywall check just cleared `goals` for a free plan —
        // either way the cache must NOT be consulted, or a downgraded org would see a stale
        // (possibly pre-downgrade) walk outcome that was never re-earned on this run.
        assert!(
            !test_cache_readable(0),
            "empty goals must never read the cache"
        );
        assert!(
            test_cache_readable(3),
            "a real declared-goal set may read the cache"
        );
    }

    #[test]
    fn no_tests_flag_parses() {
        use clap::Parser;
        let with = crate::AuditArgs::try_parse_from(["audit", "--base", "http://x", "--no-tests"])
            .expect("--no-tests must parse");
        assert!(with.no_tests);
        let without = crate::AuditArgs::try_parse_from(["audit", "--base", "http://x"])
            .expect("bare audit must parse");
        assert!(!without.no_tests);
    }

    #[test]
    fn timeout_knob_parses_flag_and_deadline_alias() {
        use clap::Parser;
        // The one knob: `--timeout` sets the browser-phase cap in seconds…
        let by_flag =
            crate::AuditArgs::try_parse_from(["audit", "--base", "http://x", "--timeout", "45"])
                .expect("--timeout must parse");
        assert_eq!(by_flag.timeout, Some(45));
        // …with `--deadline` as a working, hidden back-compat alias for the same field…
        let by_alias =
            crate::AuditArgs::try_parse_from(["audit", "--base", "http://x", "--deadline", "90"])
                .expect("--deadline must still parse as an alias");
        assert_eq!(by_alias.timeout, Some(90));
        // …and, unset, it stays None so the resolver can fall through to uxlint.toml then the default.
        let bare = crate::AuditArgs::try_parse_from(["audit", "--base", "http://x"])
            .expect("bare audit must parse");
        assert_eq!(bare.timeout, None);
    }

    #[test]
    fn deadline_alias_is_hidden_from_help() {
        use clap::CommandFactory;
        let help = crate::AuditArgs::command().render_long_help().to_string();
        assert!(
            help.contains("--timeout"),
            "the documented knob name must appear in help:\n{help}"
        );
        assert!(
            !help.contains("--deadline"),
            "the back-compat alias must stay hidden from help:\n{help}"
        );
    }

    #[test]
    fn no_tests_flag_is_in_help() {
        use clap::CommandFactory;
        let help = crate::AuditArgs::command().render_long_help().to_string();
        assert!(
            help.contains("--no-tests"),
            "the documented flag name must appear in help:\n{help}"
        );
    }

    #[test]
    fn change_url_flag_parses() {
        use clap::Parser;
        let with_flag = crate::AuditArgs::try_parse_from([
            "audit",
            "--base",
            "http://x",
            "--change-url",
            "https://github.com/acme/site/pull/42",
        ])
        .expect("--change-url must parse");
        assert_eq!(
            with_flag.change_url.as_deref(),
            Some("https://github.com/acme/site/pull/42")
        );
        let bare = crate::AuditArgs::try_parse_from(["audit", "--base", "http://x"])
            .expect("bare audit must parse");
        assert_eq!(bare.change_url, None);
    }
}

#[cfg(test)]
mod collector_tests {
    /// Regression guard for the large-page truncation bug: the collector capped every element's
    /// text at 120 chars, which cut hero descriptions mid-sentence and made value-prop misfire on
    /// pages whose value prop was concrete but long. Keep the cap generous.
    #[test]
    fn element_text_cap_survives_a_hero_paragraph() {
        let cap: usize = crate::redact::collector_js()
            .split("text: text.slice(0, ")
            .nth(1)
            .and_then(|s| s.split([',', ')']).next())
            .and_then(|s| s.trim().parse().ok())
            .expect("collector element-text cap not found — did `text: text.slice(0, N)` change?");
        assert!(
            cap >= 400,
            "element-text cap {cap} is too small — hero copy gets truncated (the 120 bug)"
        );
    }

    /// `scrollOffsets.targets` and `anchorIds` must come from ONE `[id]` enumeration. A second
    /// `querySelectorAll('[id]')` is how they'd silently drift — differently capped or filtered — and
    /// then "is this element a fragment target?" would have two answers, one per consumer.
    #[test]
    fn fragment_targets_and_anchor_ids_share_one_id_list() {
        let js = crate::redact::collector_js();
        assert_eq!(
            js.matches("querySelectorAll('[id]')").count(),
            1,
            "the page's ids must be enumerated exactly once (`idEls`); a second scan can diverge"
        );
        assert!(
            js.contains("anchorIds = idEls.map(") && js.contains("idEls.filter("),
            "anchorIds and the scroll-offset targets must both be derived from `idEls`"
        );
    }

    /// `scroll-padding-top` is not resolved to used pixels by CSSOM: `getComputedStyle` hands back
    /// the computed value, so a percentage arrives as "10%" and an undeclared one as "auto". Both
    /// must become px here — a bare `parseFloat` would report 10 for a 76px offset, NaN for auto.
    #[test]
    fn scroll_padding_top_is_reported_in_pixels() {
        let js = crate::redact::collector_js();
        assert!(
            js.contains("scrollPaddingTop"),
            "the scroll container's scroll-padding-top is the primary offset declaration"
        );
        assert!(
            js.contains("raw.endsWith('%')"),
            "a percentage scroll-padding-top must be resolved against the scrollport, not sent raw"
        );
    }
}

#[cfg(test)]
mod request_tests {
    use super::*;

    fn sample_inputs<'a>(prov: &'a AuditProvenance) -> AuditRequestInputs<'a> {
        AuditRequestInputs {
            base_url: "https://example.com",
            org: Some("acme"),
            site: Some("example.com"),
            pages: &[],
            tests: &[],
            anon_checks: &[],
            login_discoverable: false,
            no_judge: false,
            nf_probe: &Value::Null,
            favicon_status: Some(200),
            back_probe: &Value::Null,
            open_redirect: &Value::Null,
            styleguide: &Value::Null,
            bot_blocked_routes: &[],
            labels: &[],
            timed_out: false,
            timeout_detail: None,
            provenance: prov,
            theme: None,
            site_type: Some("saas"),
            desktop_only: &[],
        }
    }

    #[test]
    fn build_audit_request_carries_the_expected_fields() {
        let prov = AuditProvenance {
            git_sha: Some("deadbeef".into()),
            git_branch: Some("main".into()),
            runner: "ci-box".into(),
            change_url: Some("https://github.com/acme/site/pull/7".into()),
        };
        let body = build_audit_request(&sample_inputs(&prov));
        // Spot-check the load-bearing fields a reviewer cares about are present and correct.
        assert_eq!(body["base_url"], "https://example.com");
        assert_eq!(body["org"], "acme");
        assert_eq!(body["site"], "example.com");
        assert_eq!(body["site_type"], "saas");
        assert_eq!(body["git_sha"], "deadbeef");
        assert_eq!(body["git_branch"], "main");
        assert_eq!(body["runner"], "ci-box");
        assert_eq!(body["change_url"], "https://github.com/acme/site/pull/7");
        // Fields must EXIST even when empty, so the server sees a stable shape.
        assert!(body.get("pages").is_some());
        assert!(body.get("timed_out").is_some());
        // The styleguide existence probe rides under its stable key (drives styleguide-missing).
        assert!(body.get("styleguide").is_some());
    }

    #[test]
    fn desktop_only_globs_ride_in_the_request_body() {
        // The declared desktop-primary routes must reach the server (which demotes their mobile
        // findings). Assert the glob rides verbatim under the stable `desktop_only` key.
        let prov = AuditProvenance {
            git_sha: None,
            git_branch: None,
            runner: "t".into(),
            change_url: None,
        };
        let pats = vec!["/dashboard/scenarios/*/pages/*".to_string()];
        let mut inputs = sample_inputs(&prov);
        inputs.desktop_only = &pats;
        let body = build_audit_request(&inputs);
        assert_eq!(body["desktop_only"][0], "/dashboard/scenarios/*/pages/*");
        // And it's always present (empty when unset) so the server sees a stable shape.
        assert!(build_audit_request(&sample_inputs(&prov))
            .get("desktop_only")
            .is_some());
    }

    #[test]
    fn no_provenance_blanks_every_provenance_field() {
        // `--no-provenance` (suppress=true) must strip sha/branch/runner/change_url from the payload
        // — a branch name or hostname can itself be sensitive.
        let prov = AuditProvenance::collect(Some("https://github.com/acme/site/pull/7"), true);
        let body = build_audit_request(&sample_inputs(&prov));
        assert!(body["git_sha"].is_null(), "sha suppressed");
        assert!(body["git_branch"].is_null(), "branch suppressed");
        assert_eq!(body["runner"], "", "runner blanked");
        assert!(body["change_url"].is_null(), "change_url suppressed");
    }

    #[test]
    fn change_url_flag_wins_over_the_env_sniff() {
        // With --change-url given, provenance uses it verbatim regardless of any GITHUB_* env.
        let prov = AuditProvenance::collect(Some("https://example.com/my/pr"), false);
        assert_eq!(
            prov.change_url.as_deref(),
            Some("https://example.com/my/pr")
        );
    }

    #[test]
    fn payload_never_contains_a_credential() {
        // The payload borrows only captured/aggregate data — no header, storage, or login value can
        // reach it. Assert none of a set of sentinel secrets appears anywhere in the serialized body.
        let prov = AuditProvenance::default();
        let body = build_audit_request(&sample_inputs(&prov));
        let text = serde_json::to_string(&body).unwrap();
        for sentinel in ["Authorization", "Bearer", "password", "sk_live", "Cookie"] {
            assert!(
                !text.contains(sentinel),
                "payload unexpectedly contains {sentinel:?}: {text}"
            );
        }
    }

    #[test]
    fn require_http_base_rejects_non_http_schemes() {
        for bad in [
            "file:///etc/passwd",
            "data:text/html,<h1>x</h1>",
            "javascript:alert(1)",
            "ftp://host/x",
            "chrome://settings",
        ] {
            assert!(
                require_http_base(bad).is_err(),
                "{bad:?} must be rejected as a --base"
            );
        }
        for ok in ["http://localhost:5173", "https://example.com/app"] {
            assert!(require_http_base(ok).is_ok(), "{ok:?} must be accepted");
        }
        // A bare host has no scheme → parse fails → left for navigation to prepend http://.
        assert!(require_http_base("example.com").is_ok());
    }

    #[test]
    fn write_dry_run_splits_screenshots_and_writes_request_json() {
        use base64::Engine as _;
        // A minimal payload with one page carrying a (tiny fake) base64 screenshot.
        let shot =
            base64::engine::general_purpose::STANDARD.encode(b"\xff\xd8\xff-not-a-real-jpeg");
        let payload = json!({
            "base_url": "https://example.com",
            "pages": [{ "route": "/pricing", "viewport": "desktop", "screenshot": shot }],
        });
        let dir = std::env::temp_dir().join(format!("uxlint-dryrun-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let marker =
            write_dry_run(&payload, &dir, &crate::progress::Silent).expect("dry run writes");
        assert_eq!(marker["dry_run"], true);
        assert_eq!(marker["screenshots"], 1);
        // request.json exists, and the giant base64 blob was replaced by a pointer (not the raw b64).
        let req = std::fs::read_to_string(dir.join("request.json")).expect("request.json written");
        assert!(
            req.contains("screenshot → "),
            "screenshot replaced with a file pointer: {req}"
        );
        assert!(
            !req.contains(&shot),
            "raw base64 blob must not remain in request.json"
        );
        // The JPEG was written out for a reviewer to open.
        let jpgs: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "jpg"))
            .collect();
        assert_eq!(jpgs.len(), 1, "one screenshot JPEG written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn base_path_hint_only_fires_on_a_path_and_preserves_the_port() {
        // A bare origin: no nudge.
        assert!(base_path_hint("https://example.com").is_none());
        assert!(base_path_hint("http://localhost:5173/").is_none());
        // A path on the base: nudge, and the suggested --base keeps scheme + host + port.
        let hint =
            base_path_hint("http://localhost:5173/r/abc123").expect("a path must produce a hint");
        assert!(
            hint.contains("--base http://localhost:5173"),
            "keeps origin+port: {hint}"
        );
        assert!(
            hint.contains("--routes /r/abc123"),
            "suggests the path as a route: {hint}"
        );
    }
}

/// Unit coverage for the audit's pure decision cores. These are the tests that catch a behaviour
/// change in a future refactor; the dogfood/e2e covers the thin I/O shells that call them.
#[cfg(test)]
mod decision_tests {
    use super::*;

    fn args() -> AuditArgs {
        use clap::Parser;
        AuditArgs::try_parse_from(["audit", "--base", "http://x"]).expect("defaults parse")
    }

    #[test]
    fn effective_routes_prefers_toml_only_for_the_bare_default() {
        // Bare `--routes /` yields to the project's declared routes…
        assert_eq!(effective_routes("/", Some("/a,/b")), "/a,/b");
        // …but an explicit --routes always wins, even over declared routes…
        assert_eq!(effective_routes("/pricing", Some("/a,/b")), "/pricing");
        // …and with no declared routes, the CLI value stands (including the bare default).
        assert_eq!(effective_routes("/", None), "/");
        assert_eq!(effective_routes("/x", None), "/x");
    }

    #[test]
    fn resolve_site_precedence_flag_then_toml_then_public_host() {
        // --site wins.
        assert_eq!(
            resolve_site(
                Some("flag.example"),
                Some("toml.example"),
                "https://base.example"
            ),
            Some("flag.example".into())
        );
        // Else uxlint.toml site.
        assert_eq!(
            resolve_site(None, Some("toml.example"), "https://base.example"),
            Some("toml.example".into())
        );
        // Else the base host, for a real public host.
        assert_eq!(
            resolve_site(None, None, "https://base.example"),
            Some("base.example".into())
        );
        // A local host with no declared site is None (a hard error at the call site).
        assert_eq!(resolve_site(None, None, "http://localhost:5173"), None);
    }

    #[test]
    fn resolve_org_precedence_flag_then_toml() {
        assert_eq!(resolve_org(Some("a"), Some("b")), Some("a".into()));
        assert_eq!(resolve_org(None, Some("b")), Some("b".into()));
        assert_eq!(resolve_org(None, None), None);
    }

    #[test]
    fn compute_seeds_normalises_and_drops_excluded() {
        // Trailing slashes normalised, query stripped; an excluded prefix is filtered out.
        let seeds = compute_seeds("/, /pricing/, /admin?x=1", &["/admin".to_string()]);
        assert_eq!(seeds, vec!["/".to_string(), "/pricing".to_string()]);
        // A glob exclude also filters.
        let seeds = compute_seeds("/a,/b/c", &["/b/*".to_string()]);
        assert_eq!(seeds, vec!["/a".to_string()]);
    }

    #[test]
    fn resolve_crawl_cap_is_the_max_of_flag_toml_and_seed_count() {
        assert_eq!(resolve_crawl_cap(12, 0, 3), 12); // flag wins
        assert_eq!(resolve_crawl_cap(2, 30, 3), 30); // toml wins
        assert_eq!(resolve_crawl_cap(2, 1, 5), 5); // never fewer than the seeds asked for
    }

    #[test]
    fn parse_viewports_parses_valid_and_drops_malformed() {
        let vps = parse_viewports("desktop:1440x900,mobile:390x844");
        assert_eq!(
            vps,
            vec![
                ("desktop".to_string(), 1440, 900),
                ("mobile".to_string(), 390, 844)
            ]
        );
        // Malformed entries are silently dropped (no ':' / no 'x' / unparsable number).
        let vps = parse_viewports("bad,desktop:1440x900,also:bad,x:1xy");
        assert_eq!(vps, vec![("desktop".to_string(), 1440, 900)]);
    }

    #[test]
    fn pool_size_clamps_to_hardware_and_crawl_budget() {
        // Local target, plenty of routes: default is hw_cap = cores-2 clamped [4,24].
        assert_eq!(pool_size(None, 10, true, 100), 8);
        assert_eq!(pool_size(None, 64, true, 100), 24); // hw_cap ceiling
        assert_eq!(pool_size(None, 3, true, 100), 4); // hw_cap floor
                                                      // Public host default is 4.
        assert_eq!(pool_size(None, 16, false, 100), 4);
        // --parallel overrides but is still clamped to [1, hw_cap] and to the crawl budget.
        assert_eq!(pool_size(Some(100), 10, true, 100), 8); // clamped to hw_cap
        assert_eq!(pool_size(Some(6), 16, false, 100), 6); // honoured within range
        assert_eq!(pool_size(Some(6), 16, false, 2), 2); // never more browsers than pages
        assert_eq!(pool_size(Some(0), 16, true, 100), 1); // never zero
    }

    #[test]
    fn resolve_timeout_precedence_flag_then_toml_then_default() {
        assert_eq!(resolve_timeout(Some(45), Some(420)), 45); // flag wins
        assert_eq!(resolve_timeout(None, Some(420)), 420); // toml
        assert_eq!(resolve_timeout(None, None), 300); // default
        assert_eq!(resolve_timeout(Some(0), None), 1); // floored at 1
    }

    #[test]
    fn merge_credentials_precedence_cli_over_env_over_toml() {
        // A CLI login already present is never overwritten by env or toml.
        let mut a = args();
        a.login_url = Some("/cli-login".into());
        a.username = Some("cli-user".into());
        a.password = Some("cli-pass".into());
        let (merged, _) = merge_credentials(
            a,
            None,
            None,
            Some("/env-login\nenv-user\nenv-pass"),
            crate::project::ProjectCredentials {
                headers: vec![],
                storage: vec![],
                login: Some(("/toml-login".into(), "toml-user".into(), "toml-pass".into())),
            },
        );
        assert_eq!(merged.login_url.as_deref(), Some("/cli-login"));
        assert_eq!(merged.username.as_deref(), Some("cli-user"));

        // No CLI login: env wins over toml.
        let (merged, applied) = merge_credentials(
            args(),
            Some("H1: a\nH2: b"),
            None,
            Some("/env-login\nenv-user\nenv-pass"),
            crate::project::ProjectCredentials {
                headers: vec!["H3: c".into()],
                storage: vec![],
                login: Some(("/toml-login".into(), "toml-user".into(), "toml-pass".into())),
            },
        );
        assert_eq!(merged.login_url.as_deref(), Some("/env-login"));
        assert_eq!(merged.username.as_deref(), Some("env-user"));
        // env headers precede the toml header, and `applied` reflects a toml credential was present.
        assert_eq!(merged.headers, vec!["H1: a", "H2: b", "H3: c"]);
        assert!(applied);

        // No CLI, no env: toml login backfills.
        let (merged, _) = merge_credentials(
            args(),
            None,
            None,
            None,
            crate::project::ProjectCredentials {
                headers: vec![],
                storage: vec![],
                login: Some(("/toml-login".into(), "toml-user".into(), "toml-pass".into())),
            },
        );
        assert_eq!(merged.login_url.as_deref(), Some("/toml-login"));
    }

    #[test]
    fn compute_timeout_detail_none_when_clean_counts_when_cut() {
        assert!(compute_timeout_detail(false, 60, 10, 10, 3, 3).is_none());
        let d = compute_timeout_detail(true, 60, 10, 7, 3, 2).expect("detail on a timed-out run");
        assert_eq!(d["cap_secs"], 60);
        assert_eq!(d["pages_planned"], 10);
        assert_eq!(d["pages_captured"], 7);
        assert_eq!(d["walks_planned"], 3);
        assert_eq!(d["walks_done"], 2);
    }

    #[test]
    fn auth_blocked_routes_dedups_and_sorts() {
        let pages = vec![
            json!({"route": "/b", "auth_blocked": true}),
            json!({"route": "/a", "auth_blocked": true}),
            json!({"route": "/a", "auth_blocked": true}), // dup
            json!({"route": "/c", "auth_blocked": false}), // not blocked
            json!({"route": "/d"}),                       // no flag
        ];
        assert_eq!(
            auth_blocked_routes(&pages),
            vec!["/a".to_string(), "/b".to_string()]
        );
    }

    #[test]
    fn collapse_auth_walls_folds_duplicates_but_reports_every_route() {
        // Three gated routes × 2 viewports = 6 auth walls; /pricing is a real (unblocked) page.
        let mut pages = vec![
            json!({"route": "/dashboard", "viewport": "desktop", "auth_blocked": true}),
            json!({"route": "/dashboard", "viewport": "mobile", "auth_blocked": true}),
            json!({"route": "/settings", "viewport": "desktop", "auth_blocked": true}),
            json!({"route": "/settings", "viewport": "mobile", "auth_blocked": true}),
            json!({"route": "/sites", "viewport": "desktop", "auth_blocked": true}),
            json!({"route": "/sites", "viewport": "mobile", "auth_blocked": true}),
            json!({"route": "/pricing", "viewport": "desktop", "auth_blocked": false}),
        ];
        collapse_auth_walls(&mut pages);
        // The representative (/dashboard, first in crawl order) survives at BOTH viewports; the other
        // walls are dropped; the real page is untouched → the count reflects 2 pages, not 4.
        let kept: Vec<(&str, &str)> = pages
            .iter()
            .map(|p| {
                (
                    p["route"].as_str().unwrap(),
                    p["viewport"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            kept,
            vec![
                ("/dashboard", "desktop"),
                ("/dashboard", "mobile"),
                ("/pricing", "desktop"),
            ]
        );
        // …yet EVERY gated URL is still reported (folded routes ride on the representative).
        assert_eq!(
            auth_blocked_routes(&pages),
            vec![
                "/dashboard".to_string(),
                "/settings".to_string(),
                "/sites".to_string()
            ]
        );
    }

    #[test]
    fn collapse_auth_walls_is_a_noop_for_a_single_wall() {
        // One gated route (across 2 viewports) is already a single wall — leave it, stamp nothing.
        let mut pages = vec![
            json!({"route": "/dashboard", "viewport": "desktop", "auth_blocked": true}),
            json!({"route": "/dashboard", "viewport": "mobile", "auth_blocked": true}),
            json!({"route": "/", "viewport": "desktop", "auth_blocked": false}),
        ];
        collapse_auth_walls(&mut pages);
        assert_eq!(pages.len(), 3);
        assert!(pages.iter().all(|p| p["auth_blocked_also"].is_null()));
    }

    #[test]
    fn site_map_dedups_desktop_routes_titles_and_caps_at_30() {
        let mut pages = vec![
            json!({"route": "/", "viewport": "desktop", "snapshot": {"docTitle": " Home "}}),
            json!({"route": "/", "viewport": "desktop", "snapshot": {"docTitle": "dup"}}), // dup route
            json!({"route": "/x", "viewport": "mobile", "snapshot": {"docTitle": "Mobile"}}), // not desktop
        ];
        for i in 0..40 {
            pages.push(json!({"route": format!("/p{i}"), "viewport": "desktop", "snapshot": {"docTitle": "t"}}));
        }
        let sm = site_map(&pages);
        assert_eq!(sm.len(), 30, "capped at 30");
        assert_eq!(
            sm[0],
            ("/".to_string(), "Home".to_string()),
            "title trimmed, first route kept"
        );
        assert!(
            !sm.iter().any(|(r, _)| r == "/x"),
            "mobile-only route excluded"
        );
    }

    #[test]
    fn login_route_prefers_the_signin_link_then_bounce_then_crawled() {
        // Primary: the login_href a logged-out visitor sees.
        let anon =
            vec![json!({"login_href": "/accounts/sign-in", "signin": false, "final_path": "/"})];
        assert_eq!(
            login_route(&anon, &[], &[]),
            Some("/accounts/sign-in".to_string())
        );
        // Else: where a logged-out visitor got bounced (a signin final_path).
        let anon = vec![json!({"login_href": "", "signin": true, "final_path": "/login"})];
        assert_eq!(login_route(&anon, &[], &[]), Some("/login".to_string()));
        // Else: a crawled login-ish route.
        let pages = vec![json!({"route": "/signin", "viewport": "desktop"})];
        assert_eq!(login_route(&[], &pages, &[]), Some("/signin".to_string()));
        // Else: the shallowest signed-in route (not "/").
        let anon_routes = vec![
            "/app/deep/page".to_string(),
            "/app".to_string(),
            "/".to_string(),
        ];
        assert_eq!(
            login_route(&[], &[], &anon_routes),
            Some("/app".to_string())
        );
    }

    #[test]
    fn sample_routes_puts_seeds_first_and_respects_the_budget() {
        // Two page types (templated); one seed. Budget large enough to cover both types.
        let discovered = vec![
            ("/posts/1".to_string(), "skelA".to_string()),
            ("/posts/2".to_string(), "skelA".to_string()),
            ("/users/1".to_string(), "skelB".to_string()),
        ];
        let seeds = vec!["/".to_string()];
        let (routes, type_count, covered, _budget) = sample_routes(&discovered, &seeds, 12, 1);
        assert_eq!(routes[0], "/", "seeds always lead");
        assert!(type_count >= 2, "distinct page types found: {type_count}");
        assert!(covered >= 1);
        // A tiny budget (seed only) yields just the seeds.
        let (routes, _, _, _) = sample_routes(&discovered, &seeds, 1, 1);
        assert_eq!(routes, vec!["/".to_string()]);
    }
}
