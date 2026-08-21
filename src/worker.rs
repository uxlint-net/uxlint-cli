//! The browser worker pool: one headless Chrome per worker, replaceable tabs,
//! the per-route load→settle→collect pipeline, and wedge recovery.

use crate::progress::note;
use anyhow::{Context, Result};
use headless_chrome::protocol::cdp::types::Event;
use headless_chrome::{Browser, LaunchOptions};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::passes::{
    destructive_pass, discovery_pass, feedback_pass, forms_pass, probe_error_state,
    resilience_pass, states_pass,
};
use crate::project::{
    norm_route, route_excluded, route_template, skip_route, structure_fingerprint,
};
use crate::AuditArgs;

/// Geometry-based semantic layout skeleton (see the file header) — injected after capture, posted as
/// snapshot.layoutSkeleton for the server's archetype lint.
pub(crate) const LAYOUT_SKELETON_JS: &str = include_str!("layout_skeleton.js");

/// Detect an auth wall after navigation: login redirect, 401/403, or a password gate.
pub(crate) const AUTH_DETECT_JS: &str = r##"(() => {
  const nav = performance.getEntriesByType('navigation')[0];
  // A password field alone isn't a wall (API-key / credential-store / change-password inputs use
  // type=password too, and their pages talk about "login"). The tell of an actual LOGIN form is a
  // password field in a form whose SUBMIT says sign in — a settings/credentials form submits with
  // "Save"/"Add". So require that, not just a password field + sign-in language on the page.
  const signin = /\b(sign in|log ?in|authenticate|create.{0,12}account)\b/i
    .test(document.title + ' ' + (document.body ? document.body.innerText.slice(0, 1500) : ''));
  const pw = [...document.querySelectorAll('input[type="password"]')].some((inp) => {
    const form = inp.closest('form') || document.body;
    return [...form.querySelectorAll('button, input[type="submit"], [role="button"]')].some((b) =>
      /\b(sign ?in|log ?in|continue|authenticate)\b/i.test((b.textContent || '') + ' ' + (b.value || ''))
    );
  });
  // Signed-in chrome: if the page offers a sign-out, the visitor is authenticated — not walled.
  const signout = [...document.querySelectorAll('a[href],button,[role="button"],[role="menuitem"]')].some((el) =>
    /\b(sign ?out|log ?out|logout)\b/i.test((el.textContent || '') + ' ' + (el.getAttribute('aria-label') || '') + ' ' + (el.getAttribute('href') || ''))
  );
  return JSON.stringify({
    path: location.pathname,
    status: nav && nav.responseStatus ? nav.responseStatus : 0,
    pw,
    signin,
    signout
  });
})()"##;

pub(crate) fn detect_auth_block(tab: &headless_chrome::Tab, requested_route: &str) -> bool {
    let Some(v) = tab
        .evaluate(AUTH_DETECT_JS, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| {
            v.as_str()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
        })
    else {
        return false;
    };
    // A visible sign-out means the visitor is authenticated — never an auth wall, whatever password
    // fields or "login" copy the page carries (e.g. a credentials/security settings page).
    if v["signout"].as_bool().unwrap_or(false) {
        return false;
    }
    let path = v["path"].as_str().unwrap_or("");
    let status = v["status"].as_u64().unwrap_or(0);
    let pw = v["pw"].as_bool().unwrap_or(false) && v["signin"].as_bool().unwrap_or(false);
    let loginish = |p: &str| {
        let p = p.to_lowercase();
        p.contains("login")
            || p.contains("signin")
            || p.contains("sign-in")
            || p.contains("/auth")
            || p.contains("/sso")
    };
    let requested = requested_route.to_lowercase();
    // Redirected to a login screen we didn't ask for, hard auth status, or a password gate.
    (loginish(path) && !loginish(&requested))
        || status == 401
        || status == 403
        || (pw && !loginish(&requested))
}

/// How long to wait before re-capturing a page that rendered nothing. Long enough for a framework's
/// auth check to return and its redirect to run; short enough that a genuinely blank page costs
/// almost nothing (it is one retry, not a poll).
pub(crate) const RECAPTURE_DELAY: std::time::Duration = std::time::Duration::from_millis(1500);

/// Did the collector come back with a page that hasn't drawn yet?
///
/// A real page always has elements — even a 404 has a heading. Zero means we photographed a single-
/// page app mid-boot, which is worse than useless: the lints see an empty document and report a page
/// as audited when nothing was there.
pub(crate) fn capture_looks_unrendered(snap: &Value) -> bool {
    let count = snap["count"]
        .as_u64()
        .unwrap_or_else(|| snap["elements"].as_array().map_or(0, |a| a.len() as u64));
    count == 0
}

/// Cap on how long any single navigation may block before it's skipped — a hung route
/// (SSE, never-settling fetch, redirect loop) must not stall the whole audit.
pub(crate) const NAV_TIMEOUT_SECS: u64 = 25;

/// Adaptive post-navigation settle: resolves once the page's layout and CLS have been stable
/// for two consecutive animation frames (min 150ms so buffered layout-shifts land), with a
/// 600ms cap and a 700ms setTimeout backstop in case rAF stalls.
pub(crate) const SETTLE_JS: &str = r#"new Promise(res => {
  const t0 = performance.now(); let last = '', stable = 0;
  setTimeout(() => res(-1), 700);
  (function tick(){
    const b = document.body;
    const f = (b ? Math.round(b.getBoundingClientRect().height) : 0) + ':' +
              document.getElementsByTagName('*').length + ':' + (window.__cls || 0);
    const dt = performance.now() - t0;
    if (f === last) stable++; else stable = 0;
    last = f;
    if ((stable >= 2 && dt >= 150) || dt >= 600) return res(Math.round(dt));
    requestAnimationFrame(tick);
  })();
})"#;

/// Make headless Chrome report a hover-capable fine pointer (matches Playwright's behaviour).
pub(crate) const BLINK_POINTER: &str =
    "--blink-settings=primaryHoverType=2,availableHoverTypes=2,primaryPointerType=4,availablePointerTypes=4";

/// The Chrome flags EVERY launch shares: the hover-pointer fix plus per-run isolation/hardening.
/// `--disable-dev-shm-usage` keeps Chrome off the tiny container `/dev/shm` (which fills and crashes
/// renderers under a hosted worker); the rest strip first-run/extension/sync/background-networking
/// noise so each launch is a clean, self-contained browser — belt-and-braces to the worker's per-job
/// fresh-profile isolation (it honours TMPDIR, so the profile already lands in the job's throwaway
/// dir). Callers append site-specific flags (e.g. `--hide-scrollbars`) onto this base.
pub(crate) fn base_chrome_flags() -> Vec<&'static std::ffi::OsStr> {
    let mut flags: Vec<&'static str> = vec![
        BLINK_POINTER,
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-extensions",
    ];
    // In a locked-down container (unprivileged, restricted user-namespaces / no setuid sandbox — the
    // SAME capability restriction that stops the worker's egress firewall loading) Chrome's own sandbox
    // can't initialize: it crashes on boot before opening its DevTools port, so headless_chrome times
    // out waiting to connect and every worker browser "fails to start". The hosted worker sets
    // UXLINT_CHROME_NO_SANDBOX=1 to drop the sandbox there — safe because the CONTAINER is the boundary
    // (the worker's ssrf-preflight proves metadata/RFC1918 are unreachable). NEVER default-on: a local
    // `uxlint audit` keeps Chrome's sandbox around untrusted pages.
    if std::env::var("UXLINT_CHROME_NO_SANDBOX").is_ok_and(|v| v == "1" || v == "true") {
        flags.push("--no-sandbox");
        flags.push("--disable-setuid-sandbox");
    }
    flags.into_iter().map(std::ffi::OsStr::new).collect()
}

/// Is a Chrome/Chromium binary discoverable? Delegates to headless_chrome's OWN lookup
/// (`browser::default_executable`) — the exact search (`CHROME` env, then `which` over the
/// usual binary names, then, per-OS, fixed install paths / the Windows registry) that
/// `Browser::new` performs internally whenever a `LaunchOptions` doesn't set `.path(...)`,
/// which is true at every launch site in this crate. Reusing it (instead of re-implementing
/// the search here) means this can never say "missing" in a case where a real launch would
/// in fact succeed — the preflight and the launcher always agree.
pub(crate) fn browser_discoverable() -> bool {
    headless_chrome::browser::default_executable().is_ok()
}

/// Log the resolved Chrome binary + the exact flags every launch shares — ONCE, at audit start — so a
/// deployed run's log shows precisely what Chrome is invoked with (crucially: whether `--no-sandbox` is
/// in effect). `info` level: visible under the worker's baseline, silent for a quiet local run
/// (RUST_LOG=off). Diagnosing "the browser won't start" needs this — otherwise the flags are invisible.
pub(crate) fn log_chrome_setup() {
    let bin = headless_chrome::browser::default_executable()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "(none discoverable)".into());
    let flags: Vec<String> = base_chrome_flags()
        .iter()
        .map(|f| f.to_string_lossy().into_owned())
        .collect();
    log::info!("chrome: binary={bin} flags=[{}]", flags.join(" "));
}

/// One actionable message for "no Chrome/Chromium found", shared by every launch site so we
/// print ONE message, not four bespoke variants. Covers: per-OS install hints, the `CHROME`
/// env override (same variable `default_executable` itself checks first), and the escape
/// hatch — a hosted audit from the dashboard runs the browser server-side and needs none of
/// this locally.
pub(crate) fn missing_browser_message() -> String {
    "no Chrome/Chromium found to launch an audit with.\n\
     \n\
     Install one:\n\
     \u{20}   Debian/Ubuntu:  sudo apt install chromium\n\
     \u{20}   Fedora:         sudo dnf install chromium\n\
     \u{20}   macOS:          brew install --cask google-chrome\n\
     \u{20}   Windows:        winget install -e --id Google.Chrome\n\
     \n\
     Already have one somewhere uxlint won't find on its own (a custom install location,\n\
     a non-default binary name)? Point straight at it:\n\
     \u{20}   CHROME=/path/to/chrome uxlint audit ...\n\
     \n\
     Don't want to install a browser locally at all? Run the audit hosted from the\n\
     dashboard instead — hosted audits execute server-side and need no local browser."
        .to_string()
}

/// Conservative bot-challenge detector. uxlint identifies itself honestly and NEVER evades
/// bot protection — this only recognizes interstitials so we can tell the owner to
/// allowlist the audit UA instead of feeding a CAPTCHA page to the lints.
pub(crate) const BOT_CHALLENGE_JS: &str = r#"(() => {
  const txt = ((document.title || '') + ' ' +
    (document.body ? document.body.innerText.slice(0, 1500) : '')).toLowerCase();
  const marks = ['just a moment', 'checking your browser', 'verify you are human',
    'confirm you are human', 'enable javascript and cookies to continue',
    'ddos protection by', 'attention required! | cloudflare', 'ddos-guard'];
  // Known challenge scaffolding only — a legit login form with a captcha is NOT a wall.
  const el = !!document.querySelector('#challenge-form, #challenge-running, #challenge-stage');
  const short = document.body ? document.body.innerText.length < 2000 : true;
  return (el || marks.some(m => txt.includes(m))) && short;
})()"#;

/// One audit worker: a full browser with its own window, so viewport sizing (window
/// resize) and screenshots behave exactly like the serial path. Pool size 1 == serial.
pub(crate) struct AuditWorker {
    pub(crate) browser: Browser,
    /// Replaceable: an interaction pass can wedge a renderer so hard the tab never
    /// completes another navigation — recovery swaps in a fresh tab (same browser).
    pub(crate) slot: Mutex<TabSlot>,
    /// Tells the keepalive thread to stop — it holds a Browser CLONE, and without this
    /// the clone keeps BrowserInner (and the Chrome process) alive forever after the
    /// audit ends. That leak once piled up hundreds of headless Chromes.
    hb_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    hb_thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for AuditWorker {
    fn drop(&mut self) {
        if let Some(pid) = self.browser.get_process_id() {
            crate::reaper::unregister(pid);
        }
        self.hb_stop
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Join so the thread's Browser clone is RELEASED before we return — a plain
        // flag races process exit (threads die mid-sleep, the clone never drops, and
        // Chrome's kill-on-drop never runs → orphaned headless Chromes).
        if let Some(t) = self.hb_thread.take() {
            let _ = t.join();
        }
    }
}

#[derive(Clone)]
pub(crate) struct TabSlot {
    pub(crate) tab: Arc<headless_chrome::Tab>,
    pub(crate) logbuf: Arc<Mutex<Vec<Value>>>,
    /// Native alert()/confirm()/prompt() dialogs the page fired (recorded, then dismissed).
    pub(crate) native_dialogs: Arc<Mutex<Vec<Value>>>,
}

/// Sign in through the login FORM in a real browser exactly as an audit does, then check we ended
/// up authenticated. This is the only TRUTHFUL check for a login-form site: an HTTP form POST can't
/// verify a JS-driven login (our own `/login` submits a `fetch`, not a form action), so it would
/// report "no session cookie" on credentials that are actually fine. `uxlint init` uses this to
/// confirm what you typed before writing it down.
///
/// Best-effort and never fatal: `Err`/`Ok(false)` means "couldn't confirm here", and the first
/// audit stays the final word. Returns `Ok(true)` only when, after the login, the base URL is NOT
/// behind an auth wall (`detect_auth_block`) — i.e. the form actually signed us in.
pub(crate) fn verify_login(base: &str, login_url: &str, user: &str, pass: &str) -> Result<bool> {
    let browser = Browser::new(
        LaunchOptions::default_builder()
            .headless(true)
            .args(base_chrome_flags())
            .idle_browser_timeout(std::time::Duration::from_secs(30))
            .build()?,
    )
    .with_context(missing_browser_message)?;
    if let Some(pid) = browser.get_process_id() {
        crate::reaper::register(pid);
    }
    let tab = browser.new_tab()?;
    tab.set_default_timeout(std::time::Duration::from_secs(NAV_TIMEOUT_SECS));

    // Same steps, same waits as the crawl's login (auth path 3), so a pass here predicts a pass there.
    let login = if login_url.starts_with("http") {
        login_url.to_string()
    } else {
        format!("{}{}", base.trim_end_matches('/'), login_url)
    };
    tab.navigate_to(&login)?;
    tab.wait_until_navigated()?;
    std::thread::sleep(std::time::Duration::from_millis(300));
    crate::test_run::wait_for_login_form(&tab); // SPA form renders after a fetch
    let fill = crate::test_run::FILL_JS
        .replace(
            "__EMAIL__",
            &serde_json::to_string(user).unwrap_or_else(|_| "\"\"".into()),
        )
        .replace(
            "__PW__",
            &serde_json::to_string(pass).unwrap_or_else(|_| "\"\"".into()),
        );
    let _ = tab.evaluate(&fill, false);
    std::thread::sleep(std::time::Duration::from_millis(450));
    let _ = tab.evaluate(crate::test_run::SUBMIT_JS, false);
    std::thread::sleep(std::time::Duration::from_millis(1600));

    // The verdict must be POSITIVE proof of a session, not merely "no wall": the base's root is
    // often a PUBLIC page (a marketing homepage) that is never walled, so "not walled" would pass
    // for any password, right or wrong. The honest signal is a sign-out control — the same one the
    // crawler trusts as "authenticated". A good login redirects to an app page whose chrome carries
    // it; a bad login leaves you on the login screen with none.
    let has_signout = |tab: &headless_chrome::Tab| -> bool {
        tab.evaluate(AUTH_DETECT_JS, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
            })
            .and_then(|v| v["signout"].as_bool())
            .unwrap_or(false)
    };
    // Where the login landed us (a successful sign-in has redirected to an app page by now).
    if has_signout(&tab) {
        return Ok(true);
    }
    // Fallback for apps that don't redirect after login: load the base and look once more.
    tab.navigate_to(base.trim_end_matches('/'))?;
    tab.wait_until_navigated()?;
    std::thread::sleep(std::time::Duration::from_millis(400));
    Ok(has_signout(&tab))
}

pub(crate) fn spawn_worker(args: &AuditArgs) -> Result<AuditWorker> {
    let browser = Browser::new(
        LaunchOptions::default_builder()
            .headless(true)
            // Headless defaults to hover:none, which turns off every @media (hover)-gated
            // style (all of Tailwind's hover: variants). Report a real mouse instead.
            //
            // --hide-scrollbars: without it, a page tall enough to scroll renders a classic
            // (space-reserving) scrollbar that shrinks the layout viewport by its width
            // (~15px) versus the nominal window width — so getBoundingClientRect() (collector.js)
            // records element rects a coordinate space narrower than the viewport we later
            // draw annotations against. fix_preview.rs's fresh re-render already hides
            // scrollbars for its crop; MUST match here too, or a right-anchored/centered
            // element measured in this (scrollbar-visible) pass renders wider — and thus
            // shifted right — in that (scrollbar-hidden) pass, leaving the baked
            // annotation box sitting left of the element it's meant to frame.
            .args({
                let mut f = base_chrome_flags();
                f.push(std::ffi::OsStr::new("--hide-scrollbars"));
                f
            })
            .window_size(Some((1440, 1000)))
            // Bounds each method call's response wait AND the transport's silence
            // watchdog (the keepalive below feeds the latter on healthy connections,
            // so it only fires on a genuinely dead browser).
            .idle_browser_timeout(std::time::Duration::from_secs(30))
            .build()?,
    )
    .with_context(missing_browser_message)?;
    // Track this Chrome PID so a fatal signal (timeout/SIGTERM, Ctrl-C) reaps it even
    // though Drop won't run on a signalled exit.
    if let Some(pid) = browser.get_process_id() {
        crate::reaper::register(pid);
    }
    // Keepalive: the crate's transport loop dies after idle_browser_timeout with NO
    // incoming messages — and a long interaction pass or a page that never fires its
    // load event is mostly silence. That killed whole workers mid-audit (every route
    // after the quiet spell "timed out"). A trivial version ping guarantees traffic
    // while Chrome is actually alive, so the watchdog only fires on a dead browser.
    // The thread exits on the worker's stop flag (or a dead ping) and polls it every
    // 250ms so the Browser clone it holds is released promptly at audit end.
    let hb_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hb_thread = {
        let hb = browser.clone();
        let stop = hb_stop.clone();
        std::thread::spawn(move || {
            let mut last_ping = std::time::Instant::now();
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                if last_ping.elapsed() >= std::time::Duration::from_secs(10) {
                    if hb.get_version().is_err() {
                        break;
                    }
                    last_ping = std::time::Instant::now();
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        })
    };
    let slot = setup_tab(&browser, args)?;
    Ok(AuditWorker {
        browser,
        slot: Mutex::new(slot),
        hb_stop,
        hb_thread: Some(hb_thread),
    })
}

/// Create + fully configure a tab on this browser: timeouts, clipboard permission, honest
/// UA, auth headers/storage, runtime-signal listener. Used at spawn AND to replace a
/// wedged tab mid-audit (see nav_with_recovery).
/// Injected BEFORE any page script (CDP `addScriptToEvaluateOnNewDocument`) so it can intercept
/// `attachShadow` and record every shadow root it creates — including CLOSED ones, which are
/// otherwise unreachable from JS — into a registry the pre-screenshot mask then redacts. Transparent
/// to the page: it calls the real `attachShadow` and returns the same root, so a closed root stays
/// closed for the site's own code; we just keep a reference so nothing inside it leaks into a shot.
const SHADOW_REGISTRY_JS: &str = r#"(() => { try {
  const proto = Element.prototype, orig = proto.attachShadow;
  if (!orig || orig.__uxpatched) return;
  const patched = function(init) {
    const root = orig.call(this, init);
    try { (window.__uxShadowRoots = window.__uxShadowRoots || []).push(root); } catch (_) {}
    return root;
  };
  patched.__uxpatched = true;
  proto.attachShadow = patched;
} catch (_) {} })();"#;

// Author opt-out: any element carrying the `uxlint-hide` class is removed from the audit — a site
// tags dev-only or noise chrome (an env banner, a "DEV" marker, a debug toolbar) with it and that
// chrome vanishes from screenshots AND from the captured element set, so it never seeds findings.
// Injected as an init script (before the page's own scripts, on every document) so the elements are
// display:none from first paint — never flashing into a screenshot and zero-sized to the collector.
// Inert on the real site: the class does nothing unless THIS stylesheet is present, which only the
// audit injects. `!important` + late-appended <style> so it beats the site's own rules.
const UXLINT_HIDE_JS: &str = r#"(() => { try {
  const inject = () => {
    if (document.getElementById('__uxlint_hide')) return;
    const s = document.createElement('style');
    s.id = '__uxlint_hide';
    s.textContent = '.uxlint-hide{display:none !important;}';
    (document.head || document.documentElement).appendChild(s);
  };
  if (document.head || document.documentElement) inject();
  else document.addEventListener('readystatechange', inject, { once: true });
} catch (_) {} })();"#;

/// Register the `.uxlint-hide` opt-out on a freshly-created tab, BEFORE it navigates, so author-
/// tagged chrome is display:none from first paint in every capture path — the crawl, goal walks,
/// and fix previews alike (each opens its own tab).
pub(crate) fn hide_opted_out_chrome(tab: &headless_chrome::Tab) {
    use headless_chrome::protocol::cdp::Page::AddScriptToEvaluateOnNewDocument;
    let _ = tab.call_method(AddScriptToEvaluateOnNewDocument {
        source: UXLINT_HIDE_JS.to_string(),
        world_name: None,
        include_command_line_api: None,
        run_immediately: Some(true),
    });
}

pub(crate) fn setup_tab(browser: &Browser, args: &AuditArgs) -> Result<TabSlot> {
    let tab = browser.new_tab()?;
    // Never block forever on a route that won't finish loading.
    tab.set_default_timeout(std::time::Duration::from_secs(NAV_TIMEOUT_SECS));
    // Intercept attachShadow before any page script runs, so the pre-screenshot mask can reach
    // CLOSED shadow roots too (see SHADOW_REGISTRY_JS). Best-effort: ignored if the browser is old.
    {
        use headless_chrome::protocol::cdp::Page::AddScriptToEvaluateOnNewDocument;
        let _ = tab.call_method(AddScriptToEvaluateOnNewDocument {
            source: SHADOW_REGISTRY_JS.to_string(),
            world_name: None,
            include_command_line_api: None,
            run_immediately: Some(true),
        });
    }
    // Hide author-opted-out chrome (`.uxlint-hide`) before the page paints — see UXLINT_HIDE_JS.
    hide_opted_out_chrome(&tab);
    // The discovery pass clicks safe buttons, which include copy-to-clipboard ones —
    // grant clipboard write so the page behaves as it would for a real user (writeText
    // resolves, the "Copied" state renders) instead of stalling on a permission request.
    {
        use headless_chrome::protocol::cdp::Browser::{GrantPermissions, PermissionType};
        let _ = tab.call_method(GrantPermissions {
            permissions: vec![
                PermissionType::ClipboardReadWrite,
                PermissionType::ClipboardSanitizedWrite,
            ],
            origin: None,
            browser_context_id: None,
        });
    }
    // Turn the Network domain on for EVERY tab, unconditionally.
    //
    // This is not bookkeeping — it is what makes the adversity passes real. `Network.
    // emulateNetworkConditions` (offline, and the latency injection behind --slow-network) is a
    // Network-domain command, and with the domain disabled Chrome accepts it and does NOTHING: no
    // error, no warning, just a page that stays online. The probe then navigates on a live
    // connection and faithfully reports what a HEALTHY page looks like — `offline_has_content:
    // true`, no offline message — which is precisely the shape of "this app handles offline fine".
    // So `offline-unhandled` could not fire on any site, and `slow-network-no-feedback` measured a
    // fast request.
    //
    // It used to be enabled only inside the `--header "Cookie: …"` branch below (setCookie needs
    // it), so the ONE configuration where the offline probe worked was a credentialed audit — which
    // is how it survived: `just dogfood` passes a session cookie, so our own runs were the only ones
    // taking the working path. Enabling it here, beside the other tab-wide setup, decouples "we can
    // emulate the network" from "this audit happens to carry cookies".
    {
        use headless_chrome::protocol::cdp::Network;
        let _ = tab.call_method(Network::Enable {
            max_total_buffer_size: None,
            max_resource_buffer_size: None,
            max_post_data_size: None,
            enable_durable_messages: None,
            report_direct_socket_traffic: None,
        });
    }
    // Identify honestly: site owners allowlist this UA instead of us playing fingerprint
    // games. Appended to the real UA, not replacing it — no disguise either way.
    if let Ok(r) = tab.evaluate("navigator.userAgent", false) {
        if let Some(ua) = r.value.as_ref().and_then(|v| v.as_str()) {
            let _ = tab.set_user_agent(
                &format!("{ua} uxlint/0.1 (+https://uxlint.net)"),
                None,
                None,
            );
        }
    }
    // Auth path 1: extra headers.
    //
    // SECURITY: extra HTTP headers set via CDP ride EVERY request the page makes,
    // including cross-origin subresources (a third-party image/script/font the page
    // embeds). Sending an auth credential there would leak it off-site. So a `Cookie`
    // header — the common case — is instead installed as an ORIGIN-SCOPED cookie via
    // Network.setCookie: Chrome then only attaches it to requests to the target domain.
    // Other headers (e.g. Authorization) have no cookie equivalent and stay blanket —
    // we warn, since only same-origin subresources are typical but off-origin is possible.
    if !args.headers.is_empty() {
        let base_domain = args
            .base
            .split("://")
            .nth(1)
            .and_then(|s| s.split(['/', ':', '?']).next())
            .unwrap_or("")
            .to_string();
        let mut blanket: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        let mut cookie_pairs: Vec<(String, String)> = Vec::new();
        for hd in &args.headers {
            let Some((k, v)) = hd.split_once(':') else {
                continue;
            };
            let (k, v) = (k.trim(), v.trim());
            if k.eq_ignore_ascii_case("cookie") {
                // "a=1; b=2" → individual origin-scoped cookies
                for pair in v.split(';') {
                    if let Some((ck, cv)) = pair.split_once('=') {
                        cookie_pairs.push((ck.trim().to_string(), cv.trim().to_string()));
                    }
                }
            } else {
                blanket.insert(k, v);
            }
        }
        if !cookie_pairs.is_empty() && !base_domain.is_empty() {
            // The domain is already on (setup above) — setCookie needs it, and so does every
            // adversity probe, which is why that enable no longer lives here.
            use headless_chrome::protocol::cdp::Network;
            for (name, value) in cookie_pairs {
                let _ = tab.call_method(Network::SetCookie {
                    name,
                    value,
                    url: None,
                    domain: Some(base_domain.clone()),
                    path: Some("/".into()),
                    secure: None,
                    http_only: None,
                    same_site: None,
                    expires: None,
                    priority: None,
                    same_party: None,
                    source_scheme: None,
                    source_port: None,
                    partition_key: None,
                });
            }
        }
        if !blanket.is_empty() {
            eprintln!(
                "  ⚠ {} non-cookie auth header(s) are sent to EVERY origin the page loads \
                 (including third-party subresources) — prefer a Cookie header or --storage for \
                 credentials that must stay on {base_domain}",
                blanket.len()
            );
            tab.set_extra_http_headers(blanket)?;
        }
    }
    // Auth path 2: localStorage tokens — needs a same-origin page first. Set once.
    if !args.storage.is_empty() {
        tab.navigate_to(&args.base)?;
        tab.wait_until_navigated()?;
        for kv in &args.storage {
            if let Some((k, v)) = kv.split_once('=') {
                tab.evaluate(&format!("localStorage.setItem({:?}, {:?})", k, v), false)?;
            }
        }
    }
    // Auth path 3: username/password FORM login — sign in ONCE here so the whole crawl runs
    // authenticated (the session cookie the login sets persists across the audit). Reuses the
    // heuristic login-form fill; best-effort (fields vary), a settle sleep covers an SPA login's
    // fetch + client-side redirect. Runs after headers/storage so those can help reach the form.
    if let (Some(url), Some(user), Some(pass)) = (&args.login_url, &args.username, &args.password) {
        let login_url = if url.starts_with("http") {
            url.clone()
        } else {
            format!("{}{}", args.base.trim_end_matches('/'), url)
        };
        if tab
            .navigate_to(&login_url)
            .and_then(|t| t.wait_until_navigated().map(|_| ()))
            .is_ok()
        {
            std::thread::sleep(std::time::Duration::from_millis(700));
            let fill = crate::test_run::FILL_JS
                .replace(
                    "__EMAIL__",
                    &serde_json::to_string(user).unwrap_or_else(|_| "\"\"".into()),
                )
                .replace(
                    "__PW__",
                    &serde_json::to_string(pass).unwrap_or_else(|_| "\"\"".into()),
                );
            let _ = tab.evaluate(&fill, false);
            std::thread::sleep(std::time::Duration::from_millis(450)); // let the framework enable submit
            let _ = tab.evaluate(crate::test_run::SUBMIT_JS, false);
            std::thread::sleep(std::time::Duration::from_millis(1600)); // round-trip + post-auth redirect
        }
    }
    // Runtime signals: the browser's OWN error stream — failed/blocked requests, CORS
    // rejections, console errors. Listener attached once; buffer cleared per route.
    let logbuf: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let _ = tab.enable_log();
    {
        let buf = logbuf.clone();
        let _ = tab.add_event_listener(Arc::new(move |e: &Event| {
            if let Event::LogEntryAdded(ev) = e {
                let le = &ev.params.entry;
                let level = format!("{:?}", le.level).to_lowercase();
                if level == "error" || level == "warning" {
                    if let Ok(mut v) = buf.lock() {
                        if v.len() < 100 {
                            // Console output is a top spot for real apps to spill tokens/PII (logged
                            // bearer tokens, request URLs with secrets in the query string, emailed
                            // error strings). Build the entry, then redact the message and
                            // strip+redact the URL's query BEFORE it enters the payload — same
                            // patterns as every other channel (`sanitize_console_entry`).
                            let mut entry = json!({
                                "source": format!("{:?}", le.source).to_lowercase(),
                                "level": level,
                                "text": le.text.chars().take(300).collect::<String>(),
                                "url": le.url,
                            });
                            crate::redact::sanitize_console_entry(&mut entry);
                            v.push(entry);
                        }
                    }
                }
            }
        }));
    }
    // Auto-dismiss native JS dialogs (alert/confirm/prompt). Without this a confirm() — e.g. a
    // "Rotate key?" / "Revoke?" button — FREEZES the renderer, and every later CDP call then times
    // out (~8s each), which turned a single page into a 4½-minute hang. Dismiss = Cancel, so the
    // destructive action is skipped and the page unblocks at once. A Weak ref avoids a tab↔listener
    // reference cycle that would keep the browser alive (and leaking) forever.
    let native_dialogs: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let weak = Arc::downgrade(&tab);
        let nd = native_dialogs.clone();
        let _ = tab.add_event_listener(Arc::new(move |e: &Event| {
            if let Event::PageJavascriptDialogOpening(ev) = e {
                let kind = format!("{:?}", ev.params.Type).to_lowercase();
                if let Some(entry) = native_dialog_entry(&kind, &ev.params.message) {
                    if let Ok(mut v) = nd.lock() {
                        if v.len() < 20 {
                            v.push(entry);
                        }
                    }
                }
                if let Some(tab) = weak.upgrade() {
                    let _ = tab.get_dialog().dismiss();
                }
            }
        }));
    }
    Ok(TabSlot {
        tab,
        logbuf,
        native_dialogs,
    })
}

/// Work queue for one viewport pass. `seen` doubles as the discovered-route record.
#[derive(Default)]
pub(crate) struct PassQueue {
    pub(crate) pending: std::collections::VecDeque<(usize, String)>,
    pub(crate) seen: Vec<String>,
    pub(crate) next_ord: usize,
    pub(crate) inflight: usize,
    /// How many routes of each ROUTE TEMPLATE (`route_template`) we've queued. Discovery audits at
    /// most `TEMPLATE_CAP` instances per template so a site with 500 report pages doesn't get every
    /// `/sites/{id}/r/{id}` audited — we lint the page TYPE, not each row of data.
    pub(crate) templates: std::collections::HashMap<String, usize>,
    /// Discovered routes skipped purely because their template was already covered (for the log).
    pub(crate) tmpl_skipped: usize,
}

/// State shared by all workers during the viewport passes.
/// Live-partial streaming state: the hosted crawl records each captured page here as it lands,
/// so a background poster in `run_audit` can stream the findings-so-far to the server. Created ONLY
/// when the audit runs under a hosted job (`UXLINT_JOB_ID`, set by the audit-worker); local/CLI runs
/// never build one, so the recording below is a strict no-op for them.
#[derive(Default)]
pub(crate) struct PartialState {
    /// Captured page snapshots so far, screenshots stripped (the deterministic lints don't need them,
    /// and it keeps the streamed payload small). The poster clones this out under the lock.
    pub(crate) pages: Mutex<Vec<Value>>,
    /// route×viewport captures expected, set once the route set is known — the "N of M pages" total.
    pub(crate) total: std::sync::atomic::AtomicUsize,
    /// A new page landed since the last post — lets the poster skip idle wakeups.
    pub(crate) dirty: std::sync::atomic::AtomicBool,
    /// Phase-aware progress: "crawl" | "walks" | "server" | "previews". Empty before the crawl
    /// starts. Drives both the hosted partial payload's `phase` field (web banner) and the MCP
    /// `audit_url` progress notification's message.
    pub(crate) phase: Mutex<String>,
    /// Tests completed / declared for THIS audit (0/0 outside the walks phase).
    pub(crate) walks_done: std::sync::atomic::AtomicUsize,
    pub(crate) walks_total: std::sync::atomic::AtomicUsize,
    /// How many viewports each route is captured at (desktop + mobile = 2). Lets the UI express the
    /// "N of M pages" total — which counts route×viewport CAPTURES — honestly as "pages · viewports"
    /// instead of implying M distinct pages. Set once, alongside `total`.
    pub(crate) viewports: std::sync::atomic::AtomicUsize,
}
impl PartialState {
    /// Record a freshly-captured page (screenshot dropped) for the next partial post.
    pub(crate) fn note_page(&self, page: &Value) {
        let mut p = page.clone();
        if let Some(o) = p.as_object_mut() {
            o.remove("screenshot");
        }
        self.pages.lock().unwrap().push(p);
        self.dirty.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    /// Enter a new named phase (see `phase` above) — marks the state dirty so the poster flushes it
    /// promptly instead of waiting for the next page/walk event.
    pub(crate) fn set_phase(&self, phase: &str) {
        *self.phase.lock().unwrap() = phase.to_string();
        self.dirty.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    /// How many tests this audit will attempt — set once, right before the walks phase starts.
    pub(crate) fn set_walks_total(&self, n: usize) {
        self.walks_total
            .store(n, std::sync::atomic::Ordering::Relaxed);
        self.dirty.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    /// One more test run finished (reached the goal, lost, or couldn't run) — walks run concurrently,
    /// so this is a plain completion counter, not tied to any particular walk's start order.
    pub(crate) fn note_walk_done(&self) {
        self.walks_done
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.dirty.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    /// A cheap read-only snapshot for a poller (the hosted HTTP poster, or MCP's progress-notification
    /// loop) — (pages_done, pages_total, walks_done, walks_total, phase).
    pub(crate) fn snapshot(&self) -> (usize, usize, usize, usize, String) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.pages.lock().unwrap().len(),
            self.total.load(Relaxed),
            self.walks_done.load(Relaxed),
            self.walks_total.load(Relaxed),
            self.phase.lock().unwrap().clone(),
        )
    }
}

pub(crate) struct PassShared {
    /// No NEW work starts past this instant — the audit posts what it has.
    pub(crate) deadline: std::time::Instant,
    /// Set the moment the deadline actually CUTS work (a viewport pass dropping unvisited routes, or
    /// a probe/walk skipped in `run_audit`) — the honest signal that the report is incomplete because
    /// time ran out, distinct from routes that merely failed. Drives the report's `timed_out` flag.
    pub(crate) timed_out: std::sync::atomic::AtomicBool,
    /// Hosted-run live-partial recorder. `None` for local runs — then the crawl records nothing.
    pub(crate) partial: Option<Arc<PartialState>>,
    pub(crate) queue: Mutex<PassQueue>,
    /// Per route-template discovery coverage: (instances probed, distinct structure fingerprints
    /// seen). Discovery uses this to STOP walking a template once its structure is covered — so a
    /// uniform 500-row list stops after a handful of probes instead of being re-probed to the cap.
    pub(crate) coverage:
        Mutex<std::collections::HashMap<String, (usize, std::collections::HashSet<u64>)>>,
    pub(crate) results: Mutex<Vec<(usize, Value)>>,
    pub(crate) anon: Mutex<Vec<String>>,
    pub(crate) bot_blocked: Mutex<Vec<String>>,
    /// Routes that produced no capture on the first pass (nav failure, rate-limited,
    /// challenged) — later viewport passes skip them instead of re-paying the timeout.
    pub(crate) failed: Mutex<Vec<String>>,
    /// Set on the first 429/503 — every later navigation then serializes through `serial`.
    pub(crate) throttled: std::sync::atomic::AtomicBool,
    pub(crate) serial: Mutex<()>,
    /// Route patterns from uxlint.toml `exclude` — discovered links matching these are never queued.
    pub(crate) excludes: Vec<String>,
    /// Phase timers (ms), summed across every route×viewport — the crawl-cost breakdown.
    pub(crate) t_nav: std::sync::atomic::AtomicU64,
    pub(crate) t_settle: std::sync::atomic::AtomicU64,
    pub(crate) t_capture: std::sync::atomic::AtomicU64,
    pub(crate) t_states: std::sync::atomic::AtomicU64,
    pub(crate) t_hover: std::sync::atomic::AtomicU64,
    pub(crate) t_forms: std::sync::atomic::AtomicU64,
    pub(crate) t_spinner: std::sync::atomic::AtomicU64,
    pub(crate) t_resilience: std::sync::atomic::AtomicU64,
    /// Concurrency probe: workers currently inside audit_route, and the peak seen. If the peak is
    /// ~1 while there are many workers, the interaction work isn't parallelising.
    pub(crate) route_active: std::sync::atomic::AtomicU64,
    pub(crate) route_peak: std::sync::atomic::AtomicU64,
    pub(crate) states_active: std::sync::atomic::AtomicU64,
    pub(crate) states_peak: std::sync::atomic::AtomicU64,
    /// The global context switcher (org/workspace select in the app shell) repeats on every route —
    /// probe it ONCE per audit, on the first desktop page that has one.
    pub(crate) context_probed: std::sync::atomic::AtomicBool,
    /// Crawl done-vs-total: real (non-discovery) captures landed so far, and the route×viewport
    /// total once the route set is known — drives the CLI's live "crawl: N/M pages" progress line.
    /// Tracked unconditionally (unlike `partial`, which only exists under a hosted job), so a plain
    /// local/interactive run gets the same live tick on stderr.
    pub(crate) crawl_done: std::sync::atomic::AtomicUsize,
    pub(crate) crawl_total: std::sync::atomic::AtomicUsize,
}

/// Decide whether a native dialog is worth recording for the native-dialog lint. alert/confirm/
/// prompt are UI that should be a styled in-page dialog; `beforeunload` is a legitimate unsaved-
/// changes guard (browser-owned, not restylable) and is never flagged. Message is truncated.
pub(crate) fn native_dialog_entry(kind: &str, message: &str) -> Option<Value> {
    if !matches!(kind, "alert" | "confirm" | "prompt") {
        return None;
    }
    // A prompt() default value or an alert() embedding user data would otherwise ship verbatim —
    // redact through the shared patterns before truncating, same policy as every other channel.
    let message: String = message.chars().take(200).collect();
    Some(json!({ "type": kind, "message": crate::redact::redact_dialog_message(&message) }))
}

/// Add `t` (a phase duration) to a shared ms counter.
fn add_ms(counter: &std::sync::atomic::AtomicU64, t: std::time::Instant) {
    counter.fetch_add(
        t.elapsed().as_millis() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// RAII concurrency counter: bumps `active` (and `peak`) on construction, drops it on scope exit
/// (covers every early return).
struct Concurrency<'a>(&'a std::sync::atomic::AtomicU64);
impl<'a> Concurrency<'a> {
    fn enter(
        active: &'a std::sync::atomic::AtomicU64,
        peak: &std::sync::atomic::AtomicU64,
    ) -> Self {
        use std::sync::atomic::Ordering::Relaxed;
        let n = active.fetch_add(1, Relaxed) + 1;
        peak.fetch_max(n, Relaxed);
        Concurrency(active)
    }
}
impl Drop for Concurrency<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Per-pass parameters shared by every worker.
pub(crate) struct PassCtx<'a> {
    pub(crate) args: &'a AuditArgs,
    pub(crate) collector: &'a str,
    pub(crate) name: &'a str,
    pub(crate) w: u32,
    pub(crate) h: u32,
    pub(crate) discover: bool,
    /// Preliminary discovery: navigate + extract links + grab the layout skeleton for sampling, but
    /// SKIP the expensive capture/state/screenshot work. The driver then samples structurally-
    /// distinct pages from what discovery found and deep-audits only those.
    pub(crate) discover_only: bool,
    pub(crate) crawl_cap: usize,
    /// Max instances of one route TEMPLATE to enqueue while discovering — bounds how far we walk a
    /// big list (we only need enough instances to sample its structural variety).
    pub(crate) per_template_cap: usize,
    /// How many instances of one structure we ultimately audit — discovery treats a template as
    /// COVERED (and stops walking it) once it's probed this many and they've all shown one structure.
    pub(crate) sample_per_structure: usize,
    /// Where per-route crawl progress goes (stderr on the CLI, silent under MCP). Shared across
    /// the scoped crawl workers, so it must be Sync.
    pub(crate) progress: &'a (dyn crate::progress::Progress + Sync + 'a),
}

/// Pull routes off the shared queue until it drains. Discovery keeps the queue alive, so
/// "empty + nothing in flight" is the only termination condition on the discovery pass.
pub(crate) fn worker_loop(wk: &AuditWorker, ctx: &PassCtx, shared: &PassShared) {
    loop {
        let job = {
            let mut q = shared.queue.lock().unwrap();
            if let Some(j) = q.pending.pop_front() {
                q.inflight += 1;
                Some(j)
            } else if q.inflight == 0 {
                break;
            } else {
                None // a peer may still discover more routes
            }
        };
        if std::time::Instant::now() >= shared.deadline {
            let n = shared.queue.lock().unwrap().pending.len();
            if n > 0 {
                shared
                    .timed_out
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                note!(ctx.progress, "  TIMEOUT reached — dropping {n} unvisited route(s); finalizing what we captured (raise --timeout to cover slower targets)");
                shared.queue.lock().unwrap().pending.clear();
            }
            // fall through: with pending drained, the loop drains inflight and exits
        }
        match job {
            Some((ord, route)) => {
                match audit_route(wk, ctx, shared, &route) {
                    Ok(Some(page)) => {
                        // Hosted runs stream the findings-so-far: record each real capture as it
                        // lands. Discovery's link-only captures are drained without becoming
                        // findings, so they're excluded (`discover_only`).
                        if !ctx.discover_only {
                            if let Some(ps) = &shared.partial {
                                ps.note_page(&page);
                            }
                            // Live "crawl: N/M pages" tick — unconditional, so a local
                            // interactive run gets it on stderr even with no hosted job behind it.
                            use std::sync::atomic::Ordering::Relaxed;
                            let done = shared.crawl_done.fetch_add(1, Relaxed) + 1;
                            let total = shared.crawl_total.load(Relaxed);
                            if total > 0 {
                                let route = page["route"].as_str().unwrap_or(&route);
                                note!(
                                    ctx.progress,
                                    "{}",
                                    crate::style::Stream::Err.dim(&format!(
                                        "  crawl: {done}/{total} — {} ({})",
                                        route, ctx.name
                                    ))
                                );
                            }
                        }
                        shared.results.lock().unwrap().push((ord, page));
                    }
                    Ok(None) => shared.failed.lock().unwrap().push(route.clone()),
                    Err(e) => {
                        note!(
                            ctx.progress,
                            "  {} {route} … skipped (error: {e})",
                            ctx.name
                        );
                        shared.failed.lock().unwrap().push(route.clone());
                    }
                }
                shared.queue.lock().unwrap().inflight -= 1;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    }
}

// The pre-screenshot DOM secret mask lives in `crate::redact::mask_secrets_js`, the
// single-source-of-truth redaction module, so the screenshot channel shares one pattern set with
// the collector, the test-run harvest, and the console/dialog redactors.

/// BFS link discovery: scrape same-origin links off the current page and enqueue the ones we
/// haven't seen — bounded by the total crawl cap AND a per-template cap (so a 500-item list only
/// contributes `per_template_cap` instances, enough to sample its structural variety). Resolve
/// each href IN-PAGE against the document URL so relative links and same-origin absolute URLs both
/// count, keeping only the pathname.
fn discover_links(tab: &Arc<headless_chrome::Tab>, shared: &PassShared, ctx: &PassCtx) {
    if shared.queue.lock().unwrap().seen.len() >= ctx.crawl_cap {
        return;
    }
    let hrefs: Vec<String> = tab
        .evaluate(
            r#"JSON.stringify(Array.from(document.querySelectorAll('a[href]')).map(a => { try { const u = new URL(a.href); return u.origin === location.origin ? u.pathname : null; } catch (e) { return null; } }).filter(Boolean))"#,
            false,
        )
        .ok()
        .and_then(|v| v.value)
        .and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
        .unwrap_or_default();
    let mut q = shared.queue.lock().unwrap();
    for h in hrefs {
        if q.seen.len() >= ctx.crawl_cap {
            break;
        }
        if !h.starts_with('/') || h.starts_with("//") {
            continue;
        }
        let n = norm_route(&h);
        if n.is_empty()
            || skip_route(&n)
            || route_excluded(&n, &shared.excludes)
            || q.seen.contains(&n)
        {
            continue;
        }
        // Stop walking a page TYPE once it's COVERED: either we've hit the hard per-template cap,
        // or we've probed enough instances and they've all shown the same structure (a uniform
        // list — no point loading more of it). Templates that keep revealing NEW structures keep
        // being walked up to the cap.
        let tmpl = route_template(&n);
        let queued = q.templates.get(&tmpl).copied().unwrap_or(0);
        let covered = {
            let cov = shared.coverage.lock().unwrap();
            cov.get(&tmpl)
                .is_some_and(|(probed, fps)| *probed >= ctx.sample_per_structure && fps.len() <= 1)
        };
        if queued >= ctx.per_template_cap || covered {
            q.tmpl_skipped += 1;
            continue;
        }
        *q.templates.entry(tmpl).or_insert(0) += 1;
        q.seen.push(n.clone());
        let ord = q.next_ord;
        q.next_ord += 1;
        q.pending.push_back((ord, n));
    }
}

/// The host of a URL string, lowercased — scheme, userinfo, port and path stripped. Pure, and
/// dependency-free (the CLI doesn't pull in the `url` crate), so it's deliberately lenient: anything
/// it can't parse yields `None` and callers fail OPEN.
fn host_of(u: &str) -> Option<String> {
    // Require an authority (`scheme://…`); a scheme-only URL like `about:blank` or `data:…` has no
    // host, so it yields None and callers fail open rather than treating `about` as a host.
    let after_scheme = u.split_once("://")?.1;
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or(authority); // drop userinfo
    let host = hostport
        .split(':')
        .next()
        .unwrap_or(hostport)
        .trim()
        .to_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Do two URLs belong to the same SITE? Used to drop a page that redirected off the audited origin —
/// an OAuth handoff to accounts.google.com is a third party's page, not the site's. Compares the
/// registrable domain by the last two labels: a good-enough heuristic that needs no public-suffix
/// list. It only ever UNDER-drops (multi-part suffixes like `.co.uk` read as same-site), which is the
/// safe direction. An IP or a dot-less host (`localhost`) must match exactly, so local dev is never
/// mis-dropped. Unparseable on either side → `true` (fail open: better to over-audit than lose a real
/// page to a parser edge case).
fn same_site(base: &str, landed: &str) -> bool {
    fn reg_domain(u: &str) -> Option<String> {
        let host = host_of(u)?;
        if host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') {
            return Some(host); // IP or bare host — exact match only
        }
        let labels: Vec<&str> = host.split('.').collect();
        Some(labels[labels.len() - 2..].join("."))
    }
    match (reg_domain(base), reg_domain(landed)) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

pub(crate) fn audit_route(
    wk: &AuditWorker,
    ctx: &PassCtx,
    shared: &PassShared,
    route: &str,
) -> Result<Option<Value>> {
    use std::sync::atomic::Ordering;
    let _route_conc = Concurrency::enter(&shared.route_active, &shared.route_peak);
    let url = format!("{}{}", ctx.args.base.trim_end_matches('/'), route);
    let t0 = std::time::Instant::now();
    // Once the site has pushed back, only one page load happens at a time.
    let _serial_guard = if shared.throttled.load(Ordering::SeqCst) {
        Some(shared.serial.lock().unwrap())
    } else {
        None
    };
    let TabSlot {
        tab,
        logbuf,
        native_dialogs,
    } = wk.slot.lock().unwrap().clone();
    if let Ok(mut v) = logbuf.lock() {
        v.clear(); // per-route capture
    }
    if let Ok(mut v) = native_dialogs.lock() {
        v.clear();
    }
    // A hung route times out (NAV_TIMEOUT_SECS) and is skipped, not left to stall.
    // Some pages wedge their renderer during the interaction passes (observed: a page
    // never fires another navigation event after states+forms ran on it) — the tab is
    // expendable, so recovery is a fresh tab on the same browser and ONE retry.
    let (tab, logbuf) = match tab
        .navigate_to(&url)
        .and_then(|t| t.wait_until_navigated().map(|_| ()))
    {
        Ok(()) => (tab, logbuf),
        Err(first_err) => {
            let revived = setup_tab(&wk.browser, ctx.args).and_then(|fresh| {
                fresh
                    .tab
                    .navigate_to(&url)
                    .and_then(|t| t.wait_until_navigated().map(|_| ()))?;
                Ok(fresh)
            });
            match revived {
                Ok(fresh) => {
                    note!(ctx.progress, "  {} {route} … renderer wedged after {:.1}s — replaced the tab and recovered", ctx.name, t0.elapsed().as_secs_f64());
                    *wk.slot.lock().unwrap() = fresh.clone();
                    (fresh.tab, fresh.logbuf)
                }
                Err(rev_err) => {
                    note!(ctx.progress, "  {} {route} … skipped after {:.1}s (nav timeout/error: {first_err}; revive failed: {rev_err})", ctx.name, t0.elapsed().as_secs_f64());
                    return Ok(None);
                }
            }
        }
    };
    let tab = &tab;
    let logbuf = &logbuf;
    let nav_status = || {
        tab.evaluate(
            "(performance.getEntriesByType('navigation')[0]||{}).responseStatus||0",
            false,
        )
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
    };
    // Politeness: 429/503 means back off — collapse the pool to serial for the rest of the
    // audit and retry this route once after a pause. Speed never wins over a struggling site.
    let mut status = nav_status();
    if status == 429 || status == 503 {
        if !shared.throttled.swap(true, Ordering::SeqCst) {
            note!(
                ctx.progress,
                "  rate limiting detected (HTTP {status}) — dropping to one page at a time"
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
        if tab
            .navigate_to(&url)
            .and_then(|t| t.wait_until_navigated().map(|_| ()))
            .is_err()
        {
            return Ok(None);
        }
        status = nav_status();
        if status == 429 || status == 503 {
            note!(
                ctx.progress,
                "  {} {route} … skipped (still HTTP {status} after backoff)",
                ctx.name
            );
            return Ok(None);
        }
    }
    // Bot walls get reported, not audited — a CAPTCHA interstitial isn't the site's UX.
    let challenged = tab
        .evaluate(BOT_CHALLENGE_JS, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if challenged {
        note!(
            ctx.progress,
            "  {} {route} … BOT CHALLENGE — skipped (allowlist the uxlint user agent in your WAF)",
            ctx.name
        );
        let mut bb = shared.bot_blocked.lock().unwrap();
        if !bb.iter().any(|r| r == route) {
            bb.push(route.to_string());
        }
        return Ok(None);
    }
    // Left the site? Navigating this route may have REDIRECTED us off the audited origin — the
    // classic case is an auth handoff to an identity provider (a "Sign in" that lands on
    // accounts.google.com / a Firebase `__/auth/handler`). The page we'd capture there is a THIRD
    // PARTY's, not the site's: its fonts, colours, CSS and outbound links are theirs, so every lint on
    // it is noise (theme-consistency vs the provider's brand, css-specificity on their classes,
    // dead-external-link on their support URLs, breadcrumbs for their path). Skip it — and, returning
    // before link discovery, never crawl deeper INTO the third-party site either.
    let landed = tab
        .evaluate("location.href", false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_str().map(String::from));
    if let Some(landed) = landed {
        if !same_site(&ctx.args.base, &landed) {
            note!(
                ctx.progress,
                "  {} {route} … left the site (→ {landed}) — not auditing a third-party page",
                ctx.name
            );
            return Ok(None);
        }
    }
    // Not a PAGE? The crawler follows every same-origin link, but a link can point at a NON-HTML
    // response — a PDF (a print sheet), a JSON/API endpoint, a .txt/.csv export, an image. Chrome
    // renders each in a built-in viewer, and "auditing" that is pure noise: no <main>/<html lang>, the
    // PDF viewer's Times New Roman, "no header nav". A real page is served as HTML; anything else is a
    // file the browser opened, whose UX is "a download", not a design we lint. Skip it — and, returning
    // before link discovery, don't crawl deeper through it either. This is why no `exclude = ["/api/*"]`
    // should be needed: the mime type is the ground truth, not the path. `document.contentType` is the
    // mime the browser resolved the response to; empty (rare) is treated as a page, so we never drop a
    // real one.
    let content_type = tab
        .evaluate("document.contentType || ''", false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
        .unwrap_or_default();
    // HTML is `text/html` / `application/xhtml+xml` (both contain "html"). Everything else — pdf, json,
    // plain/csv text, images, xml feeds/sitemaps — is a file, not a page.
    if !content_type.is_empty() && !content_type.contains("html") {
        note!(
            ctx.progress,
            "  {} {route} … skipped (not a page — {content_type})",
            ctx.name
        );
        return Ok(None);
    }
    // Layout-shift observer — buffered:true backfills shifts since navigation, so
    // installing it now still captures the content jumping as JS hydrates.
    let _ = tab.evaluate(
        "window.__cls=0;window.__clsPath=location.pathname;try{new PerformanceObserver((l)=>{for(const e of l.getEntries()){if(!e.hadRecentInput)window.__cls+=e.value;}}).observe({type:'layout-shift',buffered:true});}catch(_){}",
        false,
    );
    add_ms(&shared.t_nav, t0); // start → here ≈ navigation + gate checks
                               // Adaptive settle: proceed once layout + CLS stop changing (two stable rAF frames,
                               // min 150ms so buffered shifts land), capped at 600ms.
    let tp = std::time::Instant::now();
    if tab.evaluate(SETTLE_JS, true).is_err() {
        std::thread::sleep(std::time::Duration::from_millis(600)); // fallback: fixed settle
    }
    add_ms(&shared.t_settle, tp);
    // Preliminary discovery: we only need the page's links (to keep crawling) and its layout
    // skeleton (to fingerprint its structure for sampling). Skip the whole capture/state/screenshot
    // pipeline — the sampled pages get the full treatment in the deep-audit passes that follow.
    if ctx.discover_only {
        let skel = tab
            .evaluate(LAYOUT_SKELETON_JS, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| {
                if let Value::String(s) = v {
                    Some(s)
                } else {
                    None
                }
            })
            .unwrap_or_default();
        // Record this instance's structure against its template so discovery can tell when a page
        // TYPE is covered (converged to one structure) and stop walking more of it.
        {
            let mut cov = shared.coverage.lock().unwrap();
            let e = cov.entry(route_template(route)).or_default();
            e.0 += 1;
            e.1.insert(structure_fingerprint(&skel));
        }
        discover_links(tab, shared, ctx);
        return Ok(Some(
            serde_json::json!({ "route": route, "layoutSkeleton": skel }),
        ));
    }
    let tp = std::time::Instant::now();
    let result = tab.evaluate(ctx.collector, false)?;
    add_ms(&shared.t_capture, tp);
    let Some(Value::String(snap_json)) = result.value else {
        note!(
            ctx.progress,
            "  {} {route} … collector returned nothing — skipped",
            ctx.name
        );
        return Ok(None);
    };
    let mut snapshot: Value = serde_json::from_str(&snap_json)?;
    // An EMPTY capture is never a real page — it's a single-page app photographed before it rendered.
    // The settle budget is ~700ms, and a framework that boots, checks auth over the network and then
    // client-side redirects can blow straight through that: we recorded worldbuilding.dev/dashboard
    // with ZERO elements and auth_blocked=false, i.e. "audited, found nothing" about a page that had
    // not drawn yet and was about to bounce to /login. One retry costs a second and a half on a page
    // that was worthless anyway, and it lets the auth check below see where the app actually went.
    if capture_looks_unrendered(&snapshot) {
        std::thread::sleep(RECAPTURE_DELAY);
        if let Ok(Some(Value::String(again))) = tab.evaluate(ctx.collector, false).map(|r| r.value)
        {
            if let Ok(v2) = serde_json::from_str::<Value>(&again) {
                if !capture_looks_unrendered(&v2) {
                    note!(
                        ctx.progress,
                        "  {} {route} … nothing rendered at first, re-captured after {}ms",
                        ctx.name,
                        RECAPTURE_DELAY.as_millis()
                    );
                    snapshot = v2;
                }
            }
        }
    }
    // Layout skeleton for the archetype lint — a compact geometry-based map of the page's semantic
    // layout. Best-effort: a page that trips the extractor simply gets no skeleton.
    if let Ok(Some(Value::String(skel))) = tab.evaluate(LAYOUT_SKELETON_JS, false).map(|r| r.value)
    {
        snapshot["layoutSkeleton"] = Value::String(skel);
    }
    // In-pass crawl: on the discovery pass, widen the route list from this page's links until the
    // budget is spent (BFS). Bounded per route template so a huge list doesn't get fully walked.
    if ctx.discover {
        discover_links(tab, shared, ctx);
    }
    // Signed-in view? Queue it for a signed-out re-check (desktop only, dedup).
    if ctx.name == "desktop" {
        if let Some(aff) = snapshot["authAffordances"].as_array() {
            if !aff.is_empty() {
                let mut anon = shared.anon.lock().unwrap();
                if !anon.iter().any(|r| r == route) {
                    anon.push(route.to_string());
                }
            }
        }
    }
    let auth_blocked = detect_auth_block(tab, route);
    {
        let st = crate::style::Stream::Err;
        let line = format!(
            "  {} {route} … {} ({} elements, {:.1}s)",
            ctx.name,
            if auth_blocked {
                "AUTH WALL (public view only)"
            } else {
                "ok"
            },
            snapshot["count"],
            t0.elapsed().as_secs_f64()
        );
        // A healthy capture is background noise — dim it so the exceptions are what catch the eye.
        note!(
            ctx.progress,
            "{}",
            if auth_blocked {
                st.yellow(&line)
            } else {
                st.dim(&line)
            }
        );
    }
    // Clean viewport screenshot — the server annotates it with finding overlays and the VLM
    // reads it. JPEG (q82) instead of PNG: a screenshot of a real page is far smaller as JPEG,
    // which shrinks the upload, the NATS payload to the GPU worker, and the report — with no
    // meaningful loss for either a human preview or the vision model.
    //
    // Explicit clip to the pass viewport (ctx.w × ctx.h): a plain from-surface capture returned a
    // SHORTER frame than the set_bounds height (e.g. 757 for a 900 window), which both fed the
    // vision model a cropped composition (it read the page as "fine") and broke the server's
    // overlay math — parse_region assumes the desktop height is exactly 900. Clipping pins the
    // output to the intended dimensions so image and rects agree.
    // A page may DISPLAY a credential (a token in a readonly field, an API key in docs). Mask
    // secrets in the live DOM before the screenshot so they never land in a stored report image.
    let _ = tab.evaluate(crate::redact::mask_secrets_js(), false);
    let tp = std::time::Instant::now();
    let shot = tab
        .capture_screenshot(
            headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Jpeg,
            Some(82),
            Some(headless_chrome::protocol::cdp::Page::Viewport {
                x: 0.0,
                y: 0.0,
                width: ctx.w as f64,
                height: ctx.h as f64,
                scale: 1.0,
            }),
            true,
        )
        .ok();
    add_ms(&shared.t_capture, tp);
    use base64::Engine;
    // Where we actually landed + accumulated CLS — read NOW, before the interaction /
    // resilience passes reload or navigate the page and destroy both signals.
    let final_path = tab
        .evaluate("location.pathname", false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_str().map(String::from));
    let cls = tab
        .evaluate(
            "(location.pathname !== window.__clsPath) ? -1 : (window.__cls || 0)",
            false,
        )
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    // Stuck spinner (desktop): a loading affordance still animating well after the page
    // settled. Only pages showing one at settle pay the 8s recheck — healthy pages skip it.
    const SPINNER_JS: &str = r#"Array.from(document.querySelectorAll('[class*="spinner" i],[class*="loading" i],[role="progressbar"],[aria-busy="true"]')).filter(e => { const r = e.getBoundingClientRect(); return r.width > 8 && r.height > 8 && e.getClientRects().length; }).length"#;
    // Stuck-spinner setup: note any spinner visible at settle NOW; the 8s recheck happens
    // after the interaction passes so their runtime counts toward the observation window
    // instead of a dedicated 8s sleep (which read as a hang).
    let spinner_t0 = std::time::Instant::now();
    let spinner_n0 = if ctx.name == "desktop" && !auth_blocked {
        tab.evaluate(SPINNER_JS, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0)
    } else {
        0.0
    };
    // Interaction states (opt-in, desktop only): hover + Tab every distinct control, plus
    // the read-only form/keyboard probes (forms_pass navigates, so it runs last).
    // These passes are where renderers wedge (clicks can trigger anything), so their
    // internal event-waits get a tight budget, and afterwards the tab must PROVE it can
    // still navigate — cheap when healthy, 3s cap when wedged. A wedged tab is replaced
    // here and now; a hung worker stalling the whole audit is a product dealbreaker.
    let mut renderer_ok = true;
    let tp_states = std::time::Instant::now();
    let interactions = if ctx.args.states && ctx.name == "desktop" {
        let _states_conc = Concurrency::enter(&shared.states_active, &shared.states_peak);
        tab.set_default_timeout(std::time::Duration::from_secs(8));
        let tph = std::time::Instant::now();
        let mut ix = states_pass(tab); // per-control HOVER probing (sample-able)
        add_ms(&shared.t_hover, tph);
        let disc = discovery_pass(tab, &url);
        ix["dialogs"] = disc["dialogs"].clone();
        ix["disclosures"] = disc["disclosures"].clone();
        ix["liveGaps"] = disc["liveGaps"].clone();
        // The shell's context switcher (org/workspace select) repeats on every route — probe it on
        // the first desktop page that actually HAS one, once per audit (a candidate-less page — the
        // marketing homepage, a login screen — must not burn the slot). Server-side dedup keeps a
        // single finding if two pages race past the flag.
        if !shared
            .context_probed
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            let cs = crate::passes::context_switch_pass(tab);
            if cs["contextSwitches"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
            {
                shared
                    .context_probed
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                ix["contextSwitches"] = cs["contextSwitches"].clone();
            }
        }
        let tpf = std::time::Instant::now();
        let forms = forms_pass(tab, &url); // Tab-through: order + trap (sequential, must be complete)
        add_ms(&shared.t_forms, tpf);
        // Destructive + feedback probes LAST inside the interaction block (they mutate the page):
        // the feedback probe FIRST (it clicks a constructive action — Add/Create/Save), then the
        // destructive probe (which deletes through confirm dialogs). uxlint IS a tester — a test run
        // exercises create-and-delete to check the action-feedback and confirm-or-undo contracts.
        // Only reaches these controls on an AUTHED view of the user's own app (an anonymous crawl of
        // a third-party URL hits the login wall first), so it never touches data you don't own.
        {
            ix["feedback"] = feedback_pass(tab, &url);
            let d = destructive_pass(tab, &url);
            ix["destructive"] = d["destructive"].clone();
        }
        note!(ctx.progress,
            "  {} {route} states ({:.0}s): {} hovers, {} focuses, {} dialogs, {} disclosures{}{}{}{}",
            ctx.name,
            tp_states.elapsed().as_secs_f64(),
            ix["hovers"].as_array().map_or(0, |a| a.len()),
            ix["focuses"].as_array().map_or(0, |a| a.len()),
            ix["dialogs"].as_array().map_or(0, |a| a.len()),
            ix["disclosures"].as_array().map_or(0, |a| a.len()),
            if forms["keyboardTrap"].as_bool() == Some(true) { ", KEYBOARD TRAP" } else { "" },
            if forms["passwordPasteBlocked"].as_bool() == Some(true) { ", paste blocked" } else { "" },
            if forms["noInlineValidation"].as_bool() == Some(true) { ", no inline validation" } else { "" },
            if forms["dataLost"].as_bool() == Some(true) { ", form data lost" } else { "" },
        );
        ix["forms"] = forms;
        Some(ix)
    } else {
        None
    };
    add_ms(&shared.t_states, tp_states);
    let tp_spin = std::time::Instant::now();
    // Stuck-spinner verdict: recheck once 8s have passed since settle — time already
    // spent in the interaction passes counts toward the observation window, so this
    // usually sleeps little or nothing. Runs BEFORE the health gate (which navigates
    // the tab away). A wedged tab just fails the evaluate → no finding, no stall.
    let mut stuck_spinner = false;
    if spinner_n0 > 0.0 {
        let elapsed = spinner_t0.elapsed();
        if elapsed < std::time::Duration::from_secs(8) {
            std::thread::sleep(std::time::Duration::from_secs(8) - elapsed);
        }
        let n1 = tab
            .evaluate(SPINNER_JS, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        stuck_spinner = n1 >= spinner_n0;
        if stuck_spinner {
            note!(
                ctx.progress,
                "  {} {route} … spinner still running 8s after settle",
                ctx.name
            );
        }
    }
    // Health gate (states runs only — they're the wedge factories): does this tab still
    // complete a navigation at all? Cheap when healthy, 3s cap when wedged; a wedged tab
    // is replaced here so the next route never pays for it.
    if interactions.is_some() {
        tab.set_default_timeout(std::time::Duration::from_secs(3));
        renderer_ok = tab
            .navigate_to("about:blank")
            .and_then(|t| t.wait_until_navigated().map(|_| ()))
            .is_ok();
        tab.set_default_timeout(std::time::Duration::from_secs(NAV_TIMEOUT_SECS));
        if !renderer_ok {
            note!(
                ctx.progress,
                "  {} {route} … interaction pass wedged the renderer — replacing the tab",
                ctx.name
            );
            if let Ok(fresh) = setup_tab(&wk.browser, ctx.args) {
                *wk.slot.lock().unwrap() = fresh;
            }
        }
    }
    add_ms(&shared.t_spinner, tp_spin); // spinner recheck + renderer health gate

    // Fault injection (opt-in, desktop, non-auth-walled): fail data requests and see how
    // the error UX holds up. Runs LAST — it leaves the page broken. Skipped when the
    // renderer wedged — these passes navigate, and the replacement tab belongs to the
    // NEXT route, not this one's post-mortem.
    let tp_res = std::time::Instant::now();
    let resilience = if (ctx.args.resilience || ctx.args.slow_network)
        && ctx.name == "desktop"
        && !auth_blocked
        && renderer_ok
    {
        let r = resilience_pass(tab, &url, ctx.args.slow_network);
        note!(
            ctx.progress,
            "  {} {route} resilience{}: no-js-len={} anim={} reflow={}px",
            ctx.name,
            if ctx.args.slow_network { "+slow" } else { "" },
            r["no_js_text_len"].as_f64().unwrap_or(0.0),
            r["reduced_motion_running"].as_f64().unwrap_or(0.0),
            r["reflow_overflow_px"].as_f64().unwrap_or(0.0)
        );
        Some(r)
    } else {
        None
    };
    add_ms(&shared.t_resilience, tp_res);
    let fault = if ctx.args.probe_errors && ctx.name == "desktop" && !auth_blocked && renderer_ok {
        let fr = probe_error_state(tab, &url);
        note!(
            ctx.progress,
            "  {} {route} probe-errors: error-affordance={} retry={}",
            ctx.name,
            fr["has_error_affordance"].as_bool().unwrap_or(false),
            fr["has_retry"].as_bool().unwrap_or(false)
        );
        Some(fr)
    } else {
        None
    };
    Ok(Some(json!({
        "route": route,
        "viewport": ctx.name,
        "snapshot": snapshot,
        "screenshot": shot.map(|png| base64::engine::general_purpose::STANDARD.encode(png)),
        "shot_w": ctx.w as f64,
        "shot_h": ctx.h as f64,
        "interactions": interactions,
        "auth_blocked": auth_blocked,
        "console": logbuf.lock().map(|v| v.clone()).unwrap_or_default(),
        "native_dialogs": native_dialogs.lock().map(|v| v.clone()).unwrap_or_default(),
        "fault": fault,
        "resilience": resilience,
        "stuck_spinner": stuck_spinner,
        // Where we actually landed — a client-side redirect (login → reports) means this
        // page's content belongs to another route; cross-page content lints skip it.
        // (Captured BEFORE the interaction/resilience passes, which reload the page.)
        "final_path": final_path,
        "cls": cls
    })))
}

#[cfg(test)]
mod same_site_tests {
    use super::{host_of, same_site};

    #[test]
    fn extracts_the_host() {
        assert_eq!(
            host_of("https://accounts.google.com/v3/signin").as_deref(),
            Some("accounts.google.com")
        );
        assert_eq!(
            host_of("http://127.0.0.1:49800/x?y#z").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            host_of("https://user:pw@Example.COM:8443/a").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_of("about:blank"), None); // scheme-only, no authority → None (callers fail open)
        assert_eq!(host_of("not a url"), None);
    }

    #[test]
    fn an_oauth_redirect_off_the_site_is_not_same_site() {
        // The worldbuilding.dev case: a "Sign in" that lands on Google's identity provider.
        assert!(!same_site(
            "https://worldbuilding.dev",
            "https://accounts.google.com/v3/signin/identifier"
        ));
        assert!(!same_site(
            "https://worldbuilding.dev/",
            "https://support.google.com/accounts"
        ));
    }

    #[test]
    fn same_registrable_domain_including_subdomains_stays() {
        assert!(same_site(
            "https://worldbuilding.dev",
            "https://worldbuilding.dev/docs"
        ));
        // A sign-in on the site's OWN auth subdomain is still the site — must NOT be dropped.
        assert!(same_site(
            "https://worldbuilding.dev",
            "https://app.worldbuilding.dev/login"
        ));
        assert!(same_site(
            "https://auth.worldbuilding.dev/x",
            "https://worldbuilding.dev/y"
        ));
    }

    #[test]
    fn local_dev_hosts_match_exactly_and_never_drop() {
        assert!(same_site(
            "http://127.0.0.1:49800",
            "http://127.0.0.1:49800/docs"
        ));
        assert!(same_site(
            "http://localhost:5173",
            "http://localhost:5173/x"
        ));
        // Distinct local hosts are genuinely different sites.
        assert!(!same_site(
            "http://127.0.0.1:8080",
            "http://192.168.1.9:8080/x"
        ));
    }

    #[test]
    fn unparseable_fails_open() {
        // If we can't get a host on one side, don't drop the page (over-audit beats losing a real one).
        assert!(same_site("https://worldbuilding.dev", "about:blank"));
    }
}

#[cfg(test)]
mod native_dialog_tests {
    use super::native_dialog_entry;

    #[test]
    fn records_confirm_alert_prompt() {
        for k in ["confirm", "alert", "prompt"] {
            let e = native_dialog_entry(k, "Delete this?").expect("should record");
            assert_eq!(e["type"], k);
            assert_eq!(e["message"], "Delete this?");
        }
    }

    #[test]
    fn skips_beforeunload_and_unknown() {
        // beforeunload is a legit browser guard, not a UI to restyle.
        assert!(native_dialog_entry("beforeunload", "You have unsaved changes").is_none());
        assert!(native_dialog_entry("", "x").is_none());
    }

    #[test]
    fn truncates_long_message() {
        let long = "x".repeat(500);
        let e = native_dialog_entry("alert", &long).unwrap();
        assert_eq!(e["message"].as_str().unwrap().chars().count(), 200);
    }
}

#[cfg(test)]
mod missing_browser_message_tests {
    use super::missing_browser_message;

    /// The message is a fail-fast's whole payload — it must actually contain the way out, not
    /// just name the problem. Per-OS install hints, the CHROME env override (the same variable
    /// `default_executable` itself reads first), and the no-local-browser escape hatch all have
    /// to survive edits to the wording.
    #[test]
    fn covers_install_hints_env_override_and_hosted_escape_hatch() {
        let msg = missing_browser_message();
        for hint in [
            "apt install chromium",
            "dnf install chromium",
            "brew install --cask google-chrome",
            "winget install",
        ] {
            assert!(
                msg.contains(hint),
                "missing per-OS install hint: {hint:?}\n---\n{msg}"
            );
        }
        assert!(
            msg.contains("CHROME="),
            "missing the CHROME env override:\n{msg}"
        );
        assert!(
            msg.to_lowercase().contains("hosted")
                && msg.to_lowercase().contains("no local browser"),
            "missing the hosted-audit escape hatch:\n{msg}"
        );
    }
}

/// The phase-aware progress tracker (PartialState) is the one shared piece both the hosted HTTP
/// poster and MCP's audit_url progress-notification loop poll — so it's worth pinning its behavior
/// directly, without spinning up a browser or a server.
#[cfg(test)]
mod partial_state_progress_tests {
    use super::PartialState;
    use serde_json::json;

    #[test]
    fn starts_empty_and_records_a_page() {
        let ps = PartialState::default();
        let (done, total, walks_done, walks_total, phase) = ps.snapshot();
        assert_eq!((done, total, walks_done, walks_total), (0, 0, 0, 0));
        assert_eq!(phase, "", "no phase set yet");

        ps.note_page(
            &json!({"route": "/", "viewport": "desktop", "screenshot": "big-base64-blob"}),
        );
        let (done, ..) = ps.snapshot();
        assert_eq!(done, 1);
        assert!(
            ps.pages.lock().unwrap()[0].get("screenshot").is_none(),
            "screenshot must be stripped before it's ever streamed"
        );
    }

    #[test]
    fn phase_and_walk_counters_move_independently_of_pages() {
        let ps = PartialState::default();
        ps.set_phase("crawl");
        ps.total.store(4, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(ps.snapshot().4, "crawl");

        // Entering the walks phase: total switches to the walk count, done starts at 0.
        ps.set_phase("walks");
        ps.set_walks_total(3);
        let (_, _, walks_done, walks_total, phase) = ps.snapshot();
        assert_eq!((walks_done, walks_total, phase.as_str()), (0, 3, "walks"));

        // Walks complete one at a time, in whatever order concurrent tasks finish — just a counter.
        ps.note_walk_done();
        ps.note_walk_done();
        let (_, _, walks_done, walks_total, _) = ps.snapshot();
        assert_eq!((walks_done, walks_total), (2, 3));

        // Later phases (server/previews/done) don't touch the walk counters — they stay put as the
        // last real values, which is what the web banner and MCP progress reader both rely on.
        ps.set_phase("server");
        let (_, _, walks_done, walks_total, phase) = ps.snapshot();
        assert_eq!((walks_done, walks_total, phase.as_str()), (2, 3, "server"));
    }

    #[test]
    fn any_mutation_marks_the_state_dirty_for_the_poster() {
        let ps = PartialState::default();
        assert!(!ps.dirty.load(std::sync::atomic::Ordering::Relaxed));
        ps.set_phase("walks");
        assert!(
            ps.dirty.swap(false, std::sync::atomic::Ordering::Relaxed),
            "set_phase must mark dirty"
        );
        ps.set_walks_total(5);
        assert!(
            ps.dirty.swap(false, std::sync::atomic::Ordering::Relaxed),
            "set_walks_total must mark dirty"
        );
        ps.note_walk_done();
        assert!(
            ps.dirty.swap(false, std::sync::atomic::Ordering::Relaxed),
            "note_walk_done must mark dirty"
        );
    }
}

#[cfg(test)]
mod capture_retry_tests {
    use super::capture_looks_unrendered;
    use serde_json::json;

    #[test]
    fn a_page_with_no_elements_is_not_a_page() {
        // The shape that produced "audited, no findings" for an app that hadn't drawn yet.
        assert!(capture_looks_unrendered(
            &json!({"count": 0, "elements": []})
        ));
        assert!(capture_looks_unrendered(&json!({"elements": []})));
    }

    #[test]
    fn anything_that_rendered_is_left_alone() {
        // Even one element means the page drew something; re-capturing would just cost time.
        assert!(!capture_looks_unrendered(&json!({"count": 1})));
        assert!(!capture_looks_unrendered(
            &json!({"elements": [{"tag": "h1"}]})
        ));
    }
}
