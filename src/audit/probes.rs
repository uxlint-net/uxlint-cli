//! Once-per-audit launch probes over the shared first-worker tab: the 404 page + favicon,
//! the Back button, and open-redirect params. Each returns its report fragment and is a
//! no-op past the browser-phase deadline.

use crate::progress::{note, Progress};
use crate::project::norm_route;
use serde_json::{json, Value};

/// Signed-out probe: after visiting an account-view route with NO credentials, where did we
/// land, is there content, and is a sign-in path offered? Drives the private-page-gating lint.
pub(crate) const ANON_PROBE_JS: &str = r##"(() => {
  const path = location.pathname;
  const txt = ((document.body && document.body.innerText) || '').replace(/\s+/g, ' ').trim();
  // A visible way to sign in FROM this page — a login link, or a link/button labelled sign in / log
  // in. This is how a real returning user finds login; its href is the most direct login signal.
  const aff = document.querySelector('a[href*="login" i], a[href*="signin" i], a[href*="sign-in" i]')
    || [...document.querySelectorAll('a[href], button, [role="button"]')]
        .find(el => /\b(sign ?in|log ?in)\b/i.test(el.textContent || ''));
  const loginHref = aff && aff.getAttribute ? (aff.getAttribute('href') || '') : '';
  const signinAffordance = !!aff;
  // Whether this page ITSELF is a sign-in page — used to spot where a protected route bounced to.
  const signin = /\b(sign in|log ?in|not signed in|get an api key|create.{0,12}account)\b/i
      .test(document.title + ' ' + txt.slice(0, 1500))
    || signinAffordance
    || !!document.querySelector('input[type="password"], form[action*="login" i]');
  return JSON.stringify({ path, textLen: txt.length, signin, signinAffordance, loginHref });
})()"##;

// Each probe runs once per audit over the shared first-worker tab, returns its report fragment,
// and is a no-op (null/empty) past the browser-phase `deadline`.

/// The 404 page + favicon probe: a dead URL should land on a page that offers a way back, and the
/// tab icon is the site's face in tabs/bookmarks. Returns `(nf_probe, favicon_status)`.
pub(crate) fn probe_not_found_and_favicon(
    tab: &headless_chrome::Tab,
    base: &str,
    deadline: std::time::Instant,
    progress: &(dyn Progress + Sync),
) -> (Value, Option<i64>) {
    if std::time::Instant::now() >= deadline {
        return (json!(null), None);
    }
    let mut nf = json!(null);
    let mut fav: Option<i64> = None;
    let probe_url = format!(
        "{}/uxlint-nf-probe-{}",
        base.trim_end_matches('/'),
        std::process::id()
    );
    if tab
        .navigate_to(&probe_url)
        .and_then(|t| t.wait_until_navigated().map(|_| ()))
        .is_ok()
    {
        std::thread::sleep(std::time::Duration::from_millis(500));
        nf = tab
            .evaluate(
                r##"(() => {
  const nav = performance.getEntriesByType('navigation')[0];
  const txt = ((document.body && document.body.innerText) || '').replace(/\s+/g, ' ').trim();
  const home = !!document.querySelector('nav a, header a, a[href="/"]');
  return JSON.stringify({ status: nav && nav.responseStatus ? nav.responseStatus : 0,
    textLen: txt.length, home });
})()"##,
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
            })
            .unwrap_or(json!(null));
        // Same-origin favicon probe (await the fetch promise).
        fav = tab
            .evaluate(
                "fetch('/favicon.ico').then(r => r.status).catch(() => 0)",
                true,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_i64());
        note!(
            progress,
            "{}",
            crate::style::Stream::Err.dim(&format!(
                "  probes: 404-page home-link={} favicon={}",
                nf["home"]
                    .as_bool()
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "?".into()),
                fav.map(|s| s.to_string()).unwrap_or_else(|| "?".into())
            ))
        );
    }
    (nf, fav)
}

/// Styleguide existence probe: a design-system page is often UNLINKED (reachable by URL only, to keep
/// it out of the crawl and out of every report), so the crawl can't find it — yet its ABSENCE is what
/// `styleguide-missing` nags about. Render the conventional path (default `/styleguide`, overridable
/// via uxlint.toml `styleguide`) and report whether a REAL page lives there, so a site that ships one
/// isn't nagged. An SPA serves a 200 shell at any path, so CONTENT — not HTTP status — is the tell.
/// Returns `{ path, present }`; `null` (skipped/failed) leaves the crawl-based check in charge.
pub(crate) fn probe_styleguide(
    tab: &headless_chrome::Tab,
    base: &str,
    path: &str,
    deadline: std::time::Instant,
    progress: &(dyn Progress + Sync),
) -> Value {
    if std::time::Instant::now() >= deadline {
        return json!(null);
    }
    let url = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    if tab
        .navigate_to(&url)
        .and_then(|t| t.wait_until_navigated().map(|_| ()))
        .is_err()
    {
        return json!(null);
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    let probed = tab
        .evaluate(
            r##"(() => {
  const txt = ((document.body && document.body.innerText) || '').replace(/\s+/g, ' ').trim();
  const hay = (document.title + ' ' + txt.slice(0, 400)).toLowerCase();
  // A not-found / error view — an SPA renders one at any dead path (same 200 as a real route), so
  // content, not HTTP status, is the tell.
  const notFound = /\b(404|not found|page not found|does ?n'?t exist|no such page)\b/.test(hay);
  return JSON.stringify({ textLen: txt.length, notFound });
})()"##,
            false,
        )
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| {
            v.as_str()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
        })
        .unwrap_or(json!(null));
    // Present = a substantial page that isn't the not-found view. A real styleguide renders many
    // components (long text); a 404 view is short and/or says so.
    let present = probed["textLen"].as_f64().unwrap_or(0.0) >= 300.0
        && !probed["notFound"].as_bool().unwrap_or(false);
    note!(
        progress,
        "{}",
        crate::style::Stream::Err.dim(&format!("  probes: styleguide {path} present={present}"))
    );
    json!({ "path": path, "present": present })
}

/// Back-button probe: visit the first route, follow its first same-site link, press Back — a user
/// must land where they came from, with content. SPAs that hijack history break this constantly.
pub(crate) fn probe_back_button(
    tab: &headless_chrome::Tab,
    base: &str,
    route_list: &[String],
    deadline: std::time::Instant,
    progress: &(dyn Progress + Sync),
) -> Value {
    let mut result = json!(null);
    if route_list.is_empty() || std::time::Instant::now() >= deadline {
        return result;
    }
    let start = route_list[0].clone();
    let start_url = format!("{}{}", base.trim_end_matches('/'), start);
    if tab
        .navigate_to(&start_url)
        .and_then(|t| t.wait_until_navigated().map(|_| ()))
        .is_ok()
    {
        // Wait for the URL to STABILIZE (two identical readings) — client-side redirects are part of
        // loading. If the route redirected at all, skip the probe: an auth bounce is not a clean test
        // bed for Back, and Back landing on the redirect target is correct, not broken.
        let mut settled = start.clone();
        let mut prev = String::new();
        for _ in 0..10 {
            std::thread::sleep(std::time::Duration::from_millis(300));
            let now = tab
                .evaluate("location.pathname", false)
                .ok()
                .and_then(|r| r.value)
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default();
            if !now.is_empty() && now == prev {
                settled = now;
                break;
            }
            prev = now;
        }
        let redirected = norm_route(&settled) != norm_route(&start);
        let start = settled;
        // The first same-site link that leads somewhere else.
        let next = tab
            .evaluate(
                r#"(() => { const a = Array.from(document.querySelectorAll('a[href^="/"]')).find(a => { const h = a.getAttribute('href').split(/[?#]/)[0]; return h && h !== location.pathname; }); return a ? a.getAttribute('href') : ''; })()"#,
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        if !next.is_empty() && !redirected {
            let next_url = format!("{}{}", base.trim_end_matches('/'), next);
            if tab
                .navigate_to(&next_url)
                .and_then(|t| t.wait_until_navigated().map(|_| ()))
                .is_ok()
            {
                std::thread::sleep(std::time::Duration::from_millis(600));
                let _ = tab.evaluate("history.back()", false);
                // Poll instead of one timed sample: SPA routers restore state on their own schedule,
                // and a single early snapshot reads a healthy Back as broken (flaky = worse than no
                // lint). Early exit when the start route (with content) is back.
                let start_norm = norm_route(&start);
                let mut landed = String::new();
                let mut text_len = 0.0;
                for _ in 0..12 {
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    let after = tab
                        .evaluate(
                            r#"JSON.stringify({ path: location.pathname, textLen: ((document.body && document.body.innerText) || '').trim().length })"#,
                            false,
                        )
                        .ok()
                        .and_then(|r| r.value)
                        .and_then(|v| v.as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()))
                        .unwrap_or(json!({}));
                    landed = after["path"].as_str().unwrap_or("").to_string();
                    text_len = after["textLen"].as_f64().unwrap_or(0.0);
                    if norm_route(&landed) == start_norm && text_len >= 40.0 {
                        break;
                    }
                }
                let broken = norm_route(&landed) != start_norm || text_len < 40.0;
                if broken {
                    note!(progress, "  probes: back-button BROKEN ({start} → {next} → back landed {landed}, {text_len:.0} chars)");
                }
                result = json!({ "from": start, "via": next, "landed": landed, "text_len": text_len, "broken": broken });
            }
        }
    }
    result
}

/// Open-redirect probe: auth pages take a post-login redirect param (next/redirect/…). Used
/// unsanitised, `?next=//evil` lands the user off-site — a phishing vector. Probe with a `.invalid`
/// host (never resolves — nothing leaves the machine) and flag if the crafted value ends up pointing
/// off-origin: a load-time redirect, or reflected into a link/form/meta target.
pub(crate) fn probe_open_redirect(
    tab: &headless_chrome::Tab,
    base: &str,
    route_list: &[String],
    deadline: std::time::Instant,
    progress: &(dyn Progress + Sync),
) -> Value {
    if std::time::Instant::now() >= deadline {
        return json!([]);
    }
    const EVIL: &str = "uxlint-redirect-probe.invalid";
    let auth_routes: Vec<String> = route_list
        .iter()
        .filter(|r| {
            let l = r.to_lowercase();
            l.contains("login")
                || l.contains("signin")
                || l.contains("sign-in")
                || l.contains("/auth")
        })
        .cloned()
        .collect();
    let candidates: Vec<String> = if auth_routes.is_empty() {
        route_list.iter().take(1).cloned().collect()
    } else {
        auth_routes.into_iter().take(2).collect()
    };
    let sink_js = format!(
        r##"(() => {{
  const EVIL = {EVIL:?};
  if (location.hostname === EVIL) return 'redirect';
  const abs = (u) => {{ try {{ return new URL(u, location.href).hostname; }} catch (_) {{ return ''; }} }};
  for (const a of document.querySelectorAll('a[href]')) if (abs(a.getAttribute('href')) === EVIL) return 'link';
  for (const f of document.querySelectorAll('form[action]')) if (abs(f.getAttribute('action')) === EVIL) return 'form';
  const m = document.querySelector('meta[http-equiv="refresh" i]');
  if (m && abs((m.getAttribute('content') || '').replace(/^[^;]*;\s*url=/i, '')) === EVIL) return 'meta';
  return '';
}})()"##
    );
    // Navigate to one probe URL and return the sink verdict ("" = clean; else redirect/link/form/meta).
    let check = |probe_url: &str| -> String {
        if tab
            .navigate_to(probe_url)
            .and_then(|t| t.wait_until_navigated().map(|_| ()))
            .is_err()
        {
            return String::new();
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
        tab.evaluate(&sink_js, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    };
    const PARAMS: [&str; 7] = [
        "next",
        "redirect",
        "redirect_uri",
        "return",
        "returnTo",
        "callback",
        "url",
    ];
    let mut hits: Vec<Value> = Vec::new();
    'outer: for route in &candidates {
        if std::time::Instant::now() >= deadline {
            break;
        }
        let base_route = format!("{}{}", base.trim_end_matches('/'), route);
        // Fast path: probe ALL params in ONE navigation. A page ignores query params it doesn't use,
        // so if the union — every param pointed at EVIL at once — produces no redirect/link/form/meta
        // to EVIL, then no single param does either. The clean case (the overwhelming majority of
        // routes) therefore costs ONE navigation instead of seven — the difference between a ~2s and a
        // ~14s per-audit probe. A real hit falls through to the per-param replay below to ATTRIBUTE
        // it, so the finding is identical; only clean routes shed the six extra navigations.
        let combined = format!(
            "{base_route}?{}",
            PARAMS
                .iter()
                .map(|p| format!("{p}=//{EVIL}/x"))
                .collect::<Vec<_>>()
                .join("&")
        );
        if check(&combined).is_empty() {
            continue 'outer; // no param triggers a redirect to EVIL — clean, one nav
        }
        // The union tripped — replay each param alone to name the vulnerable one.
        for param in PARAMS {
            if std::time::Instant::now() >= deadline {
                break 'outer;
            }
            let sink = check(&format!("{base_route}?{param}=//{EVIL}/x"));
            if !sink.is_empty() {
                hits.push(json!({ "route": route, "param": param, "sink": sink }));
                continue 'outer; // one hit per route is enough
            }
        }
    }
    if !hits.is_empty() {
        note!(
            progress,
            "  probes: open-redirect on {} route(s)",
            hits.len()
        );
    }
    json!(hits)
}
