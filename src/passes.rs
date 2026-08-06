//! Interaction & adversity passes: everything the client DOES to a loaded page
//! beyond snapshotting it — hover/focus states, dialog discovery, form probes,
//! resilience emulation, and fault injection. The server judges; these act.

use serde_json::{json, Value};
use std::sync::Arc;

// ── the audit flow (shared by CLI and MCP) ───────────────────────────────────
/// Resilience: embedded Chrome lets us emulate conditions a real user hits but a happy-path
/// audit never does — JS disabled, reduced-motion preference, a 320px viewport. Each is a
/// deterministic emulation + one observation.
pub(crate) fn resilience_pass(tab: &headless_chrome::Tab, url: &str, slow_network: bool) -> Value {
    use headless_chrome::protocol::cdp::Emulation;
    let mut out = json!({});

    // 1) No JavaScript: does anything render? An SPA with no SSR/no-JS fallback is blank —
    //    invisible to crawlers and broken for anyone whose JS didn't run.
    if tab
        .call_method(Emulation::SetScriptExecutionDisabled { value: true })
        .is_ok()
    {
        let _ = tab.navigate_to(url);
        let _ = tab.wait_until_navigated();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let text_len = tab
            .evaluate("(document.body && document.body.innerText || '').replace(/\\s+/g,' ').trim().length", false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        out["no_js_text_len"] = json!(text_len);
        let _ = tab.call_method(Emulation::SetScriptExecutionDisabled { value: false });
    }

    // 2) prefers-reduced-motion: an accessible site suppresses non-essential animation
    //    (WCAG 2.3.3). getAnimations() still running many = the preference was ignored.
    if tab
        .call_method(Emulation::SetEmulatedMedia {
            media: None,
            features: Some(vec![Emulation::MediaFeature {
                name: "prefers-reduced-motion".into(),
                value: "reduce".into(),
            }]),
        })
        .is_ok()
    {
        let _ = tab.navigate_to(url);
        let _ = tab.wait_until_navigated();
        std::thread::sleep(std::time::Duration::from_millis(800));
        let running = tab
            .evaluate(
                "(document.getAnimations ? document.getAnimations().filter(a => a.playState === 'running' && (a.effect && a.effect.getComputedTiming().iterations > 2 || a.effect === null)).length : 0)",
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        out["reduced_motion_running"] = json!(running);
        let _ = tab.call_method(Emulation::SetEmulatedMedia {
            media: None,
            features: Some(vec![]),
        });
    }

    // 3) Reflow at 320 CSS px (WCAG 1.4.10): content must reflow, not force horizontal
    //    scrolling. Emulate a 320-wide viewport and measure overflow.
    if tab
        .call_method(Emulation::SetDeviceMetricsOverride {
            width: 320,
            height: 800,
            device_scale_factor: 1.0,
            mobile: false,
            scale: None,
            screen_width: None,
            screen_height: None,
            position_x: None,
            position_y: None,
            dont_set_visible_size: None,
            screen_orientation: None,
            viewport: None,
            display_feature: None,
            device_posture: None,
        })
        .is_ok()
    {
        let _ = tab.navigate_to(url);
        let _ = tab.wait_until_navigated();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let overflow = tab
            .evaluate(
                "(() => { const de = document.documentElement, sw = Math.max(de.scrollWidth, document.body ? document.body.scrollWidth : 0); return Math.max(0, sw - de.clientWidth); })()",
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        out["reflow_overflow_px"] = json!(overflow);
        let _ = tab.call_method(Emulation::ClearDeviceMetricsOverride(None));
    }

    // 4) Offline: does the app notice and say so, or silently break? Go offline, reload,
    //    and check for an offline/connection message.
    use headless_chrome::protocol::cdp::Network;
    if tab
        .call_method(Network::EmulateNetworkConditions {
            offline: true,
            latency: 0.0,
            download_throughput: 0.0,
            upload_throughput: 0.0,
            connection_Type: None,
            packet_loss: None,
            packet_queue_length: None,
            packet_reordering: None,
        })
        .is_ok()
    {
        let _ = tab.navigate_to(url);
        let _ = tab.wait_until_navigated();
        std::thread::sleep(std::time::Duration::from_millis(900));
        let offline_msg = tab
            .evaluate(
                r##"(() => { const t=(document.body&&document.body.innerText||'').toLowerCase(); return /offline|no (internet|connection|network)|check your connection|you'?re offline|reconnect|network error/.test(t); })()"##,
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        // Did anything render at all? (a cached shell counts as "handled enough")
        let has_content = tab
            .evaluate(
                "(document.body&&document.body.innerText||'').trim().length > 40",
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        out["offline_message"] = json!(offline_msg);
        out["offline_has_content"] = json!(has_content);
        let _ = tab.call_method(Network::EmulateNetworkConditions {
            offline: false,
            latency: 0.0,
            download_throughput: -1.0,
            upload_throughput: -1.0,
            connection_Type: None,
            packet_loss: None,
            packet_queue_length: None,
            packet_reordering: None,
        });
    }

    // 5) forced-colors (Windows High Contrast / prefers-contrast): icons drawn as CSS
    //    background-images vanish, because the OS overrides backgrounds. <img>/<svg> icons
    //    survive; CSS-sprite icons disappear, leaving unlabelled blank controls.
    if tab
        .call_method(Emulation::SetEmulatedMedia {
            media: None,
            features: Some(vec![Emulation::MediaFeature {
                name: "forced-colors".into(),
                value: "active".into(),
            }]),
        })
        .is_ok()
    {
        let _ = tab.navigate_to(url);
        let _ = tab.wait_until_navigated();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let broken = tab
            .evaluate(
                r##"(() => {
  let n = 0;
  for (const el of document.querySelectorAll('a, button, [role="button"], [class*="icon" i]')) {
    const cs = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    if (r.width < 6 || r.height < 6) continue;
    const bgImg = cs.backgroundImage && cs.backgroundImage !== 'none';
    const noText = !(el.textContent || '').trim();
    const noRealIcon = !el.querySelector('img, svg, use');
    const noLabel = !el.getAttribute('aria-label') && !el.getAttribute('title');
    if (bgImg && noText && noRealIcon && noLabel) n++;
  }
  return n;
})()"##,
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        out["forced_colors_lost_icons"] = json!(broken);
        let _ = tab.call_method(Emulation::SetEmulatedMedia {
            media: None,
            features: Some(vec![]),
        });
    }

    // 6) CPU throttle (a mid-range phone is ~4-6x slower): how long to become interactive?
    if tab
        .call_method(Emulation::SetCPUThrottlingRate { rate: 4.0 })
        .is_ok()
    {
        let _ = tab.navigate_to(url);
        let _ = tab.wait_until_navigated();
        std::thread::sleep(std::time::Duration::from_millis(700));
        let interactive = tab
            .evaluate("(() => { const n = performance.getEntriesByType('navigation')[0]; return n ? Math.round(n.domInteractive) : 0; })()", false)
            .ok().and_then(|r| r.value).and_then(|v| v.as_f64()).unwrap_or(0.0);
        out["cpu4x_interactive_ms"] = json!(interactive);
        let _ = tab.call_method(Emulation::SetCPUThrottlingRate { rate: 1.0 });
    }

    // 7) Timezone: shift far away and see if dates survive — "Invalid Date", NaN, or raw
    //    ISO strings leaking into the UI mean fragile date handling.
    if tab
        .call_method(
            headless_chrome::protocol::cdp::Emulation::SetTimezoneOverride {
                timezone_id: "Pacific/Kiritimati".into(),
            },
        )
        .is_ok()
    {
        let _ = tab.navigate_to(url);
        let _ = tab.wait_until_navigated();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let bad_dates = tab
            .evaluate(
                r##"(() => { const t = document.body ? document.body.innerText : ''; return (t.match(/invalid date|NaN|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/g) || []).length; })()"##,
                false,
            )
            .ok().and_then(|r| r.value).and_then(|v| v.as_f64()).unwrap_or(0.0);
        out["timezone_bad_dates"] = json!(bad_dates);
        let _ = tab.call_method(
            headless_chrome::protocol::cdp::Emulation::SetTimezoneOverride {
                timezone_id: String::new(),
            },
        );
    }

    // 8) Slow network + primary action: does the button give loading feedback, or look dead?
    //    Inject 5s latency (request guaranteed in-flight), click a SAFE primary button, and
    //    check for a spinner / disabled / aria-busy / text change. Runs LAST (it clicks).
    //    Opt-in (--slow-network): the 5s wait adds up across many routes.
    if !slow_network {
        return out;
    }
    let _ = tab.navigate_to(url);
    let _ = tab.wait_until_navigated();
    std::thread::sleep(std::time::Duration::from_millis(500));
    // Pick a safe primary button and snapshot the page's feedback indicators.
    const FIND_PRIMARY: &str = r##"(() => {
  const DANGER = /\b(delete|remove|pay|buy|checkout|purchase|submit|sign ?out|log ?out|publish|upgrade|confirm|deploy|send)\b/i;
  let best = null, bestArea = 0;
  for (const el of document.querySelectorAll('button, [role="button"]')) {
    if (el.disabled || el.closest('[aria-hidden="true"]')) continue;
    const label = (el.getAttribute('aria-label') || el.textContent || '').trim();
    if (!label || DANGER.test(label)) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 24 || r.height < 20 || r.bottom < 0 || r.top > innerHeight) continue;
    const cs = getComputedStyle(el);
    // Prefer a filled/branded button (a real primary action).
    const filled = cs.backgroundColor && cs.backgroundColor !== 'rgba(0, 0, 0, 0)' && cs.backgroundColor !== 'transparent';
    const area = r.width * r.height * (filled ? 2 : 1);
    if (area > bestArea) { bestArea = area; best = el; }
  }
  if (!best) return JSON.stringify({ found: false });
  window.__uxrSlow = best;
  const spinners = () => document.querySelectorAll('[role="progressbar"],[aria-busy="true"],[class*="spinner" i],[class*="loading" i]').length;
  return JSON.stringify({ found: true, label: (best.textContent||'').trim().slice(0,30),
    disabled: best.disabled, ariaBusy: best.getAttribute('aria-busy'), text: (best.textContent||'').trim(), spinners: spinners() });
})()"##;
    let pre = tab
        .evaluate(FIND_PRIMARY, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| {
            v.as_str()
                .and_then(|x| serde_json::from_str::<Value>(x).ok())
        })
        .unwrap_or_else(|| json!({"found": false}));
    if pre["found"].as_bool() == Some(true) {
        let _ = tab.call_method(Network::EmulateNetworkConditions {
            offline: false,
            latency: 5000.0,
            download_throughput: 20000.0,
            upload_throughput: 20000.0,
            connection_Type: None,
            packet_loss: None,
            packet_queue_length: None,
            packet_reordering: None,
        });
        let url_before = tab.get_url();
        let _ = tab.evaluate("window.__uxrSlow && window.__uxrSlow.click()", false);
        std::thread::sleep(std::time::Duration::from_millis(700));
        // Feedback appeared?
        let post = tab
            .evaluate(
                r##"(() => {
  const b = window.__uxrSlow; if (!b) return JSON.stringify({});
  const spinners = document.querySelectorAll('[role="progressbar"],[aria-busy="true"],[class*="spinner" i],[class*="loading" i]').length;
  const t = (document.body ? document.body.innerText : '').toLowerCase();
  return JSON.stringify({ disabled: b.disabled, ariaBusy: b.getAttribute('aria-busy'), text: (b.textContent||'').trim(),
    spinners, loadingText: /loading|saving|please wait|working|processing/.test(t) });
})()"##,
                false,
            )
            .ok().and_then(|r| r.value)
            .and_then(|v| v.as_str().and_then(|x| serde_json::from_str::<Value>(x).ok()))
            .unwrap_or_else(|| json!({}));
        // Only judge if the click didn't navigate away (a nav IS feedback of a sort).
        let navigated = tab.get_url() != url_before;
        let got_feedback = navigated
            || post["disabled"].as_bool() == Some(true) && pre["disabled"].as_bool() != Some(true)
            || post["ariaBusy"].as_str() == Some("true")
            || post["spinners"].as_f64().unwrap_or(0.0) > pre["spinners"].as_f64().unwrap_or(0.0)
            || post["loadingText"].as_bool() == Some(true)
            || (post["text"].as_str() != pre["text"].as_str());
        out["slow_probe"] =
            json!({ "tested": true, "label": pre["label"], "feedback": got_feedback });
        let _ = tab.call_method(Network::EmulateNetworkConditions {
            offline: false,
            latency: 0.0,
            download_throughput: -1.0,
            upload_throughput: -1.0,
            connection_Type: None,
            packet_loss: None,
            packet_queue_length: None,
            packet_reordering: None,
        });
    }
    out
}

/// Fault injection: fail the page's data requests (XHR/fetch only — HTML/JS/CSS load
/// normally) and observe the error UX. Static analysis can't see error messaging because a
/// healthy server never shows it; provoking the failure makes it deterministic.
pub(crate) fn probe_error_state(tab: &headless_chrome::Tab, url: &str) -> Value {
    use headless_chrome::browser::tab::RequestPausedDecision;
    use headless_chrome::protocol::cdp::Fetch;
    use headless_chrome::protocol::cdp::Network::ErrorReason;
    // Only pause XHR + fetch — never the document/script/style, or the app can't boot.
    let patterns = [
        Fetch::RequestPattern {
            url_pattern: None,
            resource_Type: Some(headless_chrome::protocol::cdp::Network::ResourceType::Xhr),
            request_stage: None,
        },
        Fetch::RequestPattern {
            url_pattern: None,
            resource_Type: Some(headless_chrome::protocol::cdp::Network::ResourceType::Fetch),
            request_stage: None,
        },
    ];
    if tab.enable_fetch(Some(&patterns), None).is_err() {
        return json!({ "probed": false });
    }
    tab.enable_request_interception(Arc::new(
        |_t: Arc<headless_chrome::browser::transport::Transport>,
         _s,
         ev: headless_chrome::protocol::cdp::Fetch::events::RequestPausedEvent| {
            RequestPausedDecision::Fail(Fetch::FailRequest {
                request_id: ev.params.request_id,
                error_reason: ErrorReason::Failed,
            })
        },
    ))
    .ok();
    // Reload with data requests doomed.
    let _ = tab.navigate_to(url);
    let _ = tab.wait_until_navigated();
    std::thread::sleep(std::time::Duration::from_millis(1200));
    // Does the page tell the user something went wrong, and offer a way forward?
    let obs = tab
        .evaluate(
            r##"(() => {
  const t = (document.body.innerText || '').toLowerCase();
  const errRe = /error|failed|couldn'?t|could not|unable|went wrong|try again|retry|problem|unavailable|not found|doesn'?t exist|no access|something.{0,10}wrong|not (be )?load/;
  const hasAlert = !!document.querySelector('[role="alert"], [aria-live="assertive"], [aria-live="polite"]');
  const hasErrorText = errRe.test(t);
  const hasRetry = Array.from(document.querySelectorAll('button, a, [role="button"]')).some(b => /retry|try again|reload|refresh/i.test(b.textContent || ''));
  // spinner/blank: still 'loading' or almost no content
  const stuckLoading = /loading|please wait|…/.test(t) && t.length < 400;
  const nearlyEmpty = t.replace(/\s+/g, ' ').trim().length < 40;
  return JSON.stringify({ hasAlert, hasErrorText, hasRetry, stuckLoading, nearlyEmpty, sample: (document.body.innerText||'').replace(/\s+/g,' ').trim().slice(0,120) });
})()"##,
            false,
        )
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_str().and_then(|x| serde_json::from_str::<Value>(x).ok()))
        .unwrap_or_else(|| json!({}));
    let _ = tab.disable_fetch();
    // Restore a clean interceptor (continue everything) for subsequent routes.
    tab.enable_request_interception(Arc::new(
        |_t: Arc<headless_chrome::browser::transport::Transport>, _s, _e| {
            RequestPausedDecision::Continue(None)
        },
    ))
    .ok();
    json!({
        "probed": true,
        "has_error_affordance": obs["hasAlert"].as_bool().unwrap_or(false) || obs["hasErrorText"].as_bool().unwrap_or(false),
        "has_retry": obs["hasRetry"].as_bool().unwrap_or(false),
        "stuck_loading": obs["stuckLoading"].as_bool().unwrap_or(false),
        "nearly_empty": obs["nearlyEmpty"].as_bool().unwrap_or(false),
        "sample": obs["sample"].clone(),
    })
}

// ── interaction states pass (client acts, server judges) ─────────────────────
pub(crate) const TARGETS_JS: &str = r##"(() => {
  window.__uxr = [];
  const seen = new Set(); const out = [];
  // Everything interactive — not just semantic controls. Pointer-ROOT elements (cursor:
  // pointer here, not inherited) are React/framework clickables; draggables need their own
  // hover/state check too. This is how we exercise ALL click/hover/drag handlers, not just
  // <a>/<button>.
  const candidates = new Set(document.querySelectorAll('a, button, [role="button"], summary, [draggable="true"], [onclick]'));
  for (const el of document.querySelectorAll('*')) {
    const cs = getComputedStyle(el);
    const parentCur = el.parentElement ? getComputedStyle(el.parentElement).cursor : '';
    if ((cs.cursor === 'pointer' && parentCur !== 'pointer') ||
        (['grab','grabbing','move'].includes(cs.cursor) && cs.cursor !== parentCur)) {
      candidates.add(el);
    }
  }
  for (const el of candidates) {
    if (el.closest('[aria-hidden="true"]')) continue;
    if (el.getAttribute('aria-current') !== null || el.getAttribute('role') === 'tab' || el.disabled === true) continue;
    const key = el.tagName + '|' + (el.getAttribute('class') || '');
    if (seen.has(key)) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 4 || r.height < 4) continue;
    seen.add(key);
    const label = (el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 40);
    window.__uxr.push(el);
    // Document-coordinate rect (collection runs at scroll 0, add the offset to be safe) so a hover
    // finding can be boxed on the page screenshot, not left picture-less.
    const rect = [Math.round(r.left + window.scrollX), Math.round(r.top + window.scrollY), Math.round(r.width), Math.round(r.height)];
    out.push({ i: window.__uxr.length - 1, key: key.slice(0, 80), label, rect });
    if (out.length >= 18) break;
  }
  return JSON.stringify(out);
})()"##;

pub(crate) fn sig_js(i: u64) -> String {
    format!(
        r##"(() => {{
  const style = n => {{ const cs = getComputedStyle(n); return [cs.color, cs.backgroundColor, cs.borderColor, cs.textDecorationLine, cs.textDecorationColor, cs.boxShadow, cs.outlineStyle, cs.outlineWidth, cs.opacity, cs.transform, cs.filter].join('|'); }};
  // The rendered box, so a hover that GROWS a mark (e.g. an SVG point's `r`, or a
  // scaled child) registers as a change even though no style property in the list moved.
  const box = n => {{ const r = n.getBoundingClientRect(); return Math.round(r.width) + 'x' + Math.round(r.height); }};
  const el = window.__uxr[{i}];
  if (!el) return '';
  let s = style(el) + '#' + box(el); let k = 0;
  for (const d of el.querySelectorAll('*')) {{ if (++k > 6) break; s += '~' + style(d) + '#' + box(d); }}
  // A stretched / overlay link (position:absolute filling a card or row) is transparent
  // itself — its hover feedback lives on the positioned ANCESTOR it covers (the card's
  // background/border). Walk up to that ancestor and fold its feedback styles in, so an
  // ancestor-driven hover isn't misread as "no visible change".
  let a = el.parentElement, up = 0;
  while (a && up < 3) {{ s += '^' + style(a); if (getComputedStyle(a).position !== 'static') break; a = a.parentElement; up++; }}
  return s;
}})()"##
    )
}

/// Read-only form/keyboard probes (part of --states). Nothing here mutates server state:
/// no form is submitted, no destructive control is clicked. The data-lost probe navigates
/// away and back, so it runs LAST — callers must treat the page as reloaded afterwards.
pub(crate) fn forms_pass(tab: &headless_chrome::Tab, url: &str) -> Value {
    let eval_json = |js: &str| -> Value {
        tab.evaluate(js, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
            .unwrap_or(Value::Null)
    };

    // ── keyboard trap: Tab up to 40 times; focus cycling within a small set while other
    // tabbables exist means a keyboard user can't get out (WCAG 2.1.2).
    let mut keyboard_trap = false;
    let mut trap_at = String::new();
    let tabbable_total = tab
        .evaluate(
            r#"Array.from(document.querySelectorAll('a[href],button,input,select,textarea,[tabindex]')).filter(e => !e.disabled && e.tabIndex >= 0 && e.getClientRects().length).length"#,
            false,
        )
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0) as usize;
    if tabbable_total >= 4 {
        let _ = tab.evaluate("document.body.focus()", false);
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for _ in 0..40 {
            if tab.press_key("Tab").is_err() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(15));
            let sig = tab
                .evaluate(
                    // NODE identity, not appearance: a page full of identical "Delete" buttons
                    // must not alias into one "element" (that read as a trap). An expando id on
                    // the node itself distinguishes twins while still catching real revisits.
                    r#"(() => { const e = document.activeElement; if (!e || e === document.body) return '';
  if (!e.__uxrTab) e.__uxrTab = 'n' + (window.__uxrTabSeq = (window.__uxrTabSeq || 0) + 1);
  return (e.__uxrTab + '|' + e.tagName + '#' + (e.id || '') + ':' + (e.textContent || '').trim().slice(0, 20)); })()"#,
                    false,
                )
                .ok()
                .and_then(|r| r.value)
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default();
            if sig.is_empty() {
                continue;
            }
            let c = counts.entry(sig.clone()).or_insert(0);
            *c += 1;
            // Trapped: this element hit 6+ times while most tabbables were never reached.
            if *c >= 6 && counts.len() < tabbable_total.saturating_sub(1) && counts.len() <= 4 {
                keyboard_trap = true;
                trap_at = sig;
                break;
            }
        }
        let _ = tab.press_key("Escape"); // leave any trap-adjacent widget state behind
    }

    // ── password paste: a password field that preventDefault's paste blocks password
    // managers and forces retyping — a security anti-pattern dressed as one.
    let paste = eval_json(
        r#"(() => { const el = document.querySelector('input[type="password"]');
  if (!el || !el.getClientRects().length) return JSON.stringify({probed:false});
  el.focus();
  const ev = new ClipboardEvent('paste', {cancelable: true, bubbles: true});
  const blocked = !el.dispatchEvent(ev);
  const onpasteBlocked = typeof el.onpaste === 'function' || (el.getAttribute('onpaste') || '').includes('false');
  el.blur();
  return JSON.stringify({probed: true, blocked: blocked || onpasteBlocked,
    sel: el.id ? '#' + el.id : 'input[type=password]'}); })()"#,
    );

    // ── inline validation: a CUSTOM-validated email field (type=text, so no native
    // validation) that gives no feedback on invalid blur. Narrow by design: native
    // validation (type=email) or any inline reaction counts as fine.
    let validation = eval_json(
        r#"(() => {
  const el = Array.from(document.querySelectorAll('input[type="text"], input:not([type])')).find(e => {
    const hint = ((e.name || '') + ' ' + (e.id || '') + ' ' + (e.placeholder || '')).toLowerCase();
    return /e-?mail/.test(hint) && e.getClientRects().length;
  });
  if (!el) return JSON.stringify({probed: false});
  const before = document.body.innerText.length;
  el.focus(); el.value = 'not-an-email@';
  el.dispatchEvent(new Event('input', {bubbles: true}));
  el.dispatchEvent(new Event('change', {bubbles: true}));
  el.blur(); el.dispatchEvent(new Event('blur', {bubbles: true}));
  return JSON.stringify({probed: true, before, sel: el.id ? '#' + el.id : 'input', v: el.value});
})()"#,
    );
    let mut no_inline_validation = false;
    let mut validation_sel = String::new();
    if validation["probed"].as_bool() == Some(true) {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let reacted = tab
            .evaluate(
                &format!(
                    r#"(() => {{
  const el = document.querySelector({sel:?}) || document.activeElement;
  const invalidMarked = el && (el.getAttribute('aria-invalid') === 'true' || (el.getAttribute('class') || '').match(/error|invalid/i));
  const alert = !!document.querySelector('[role="alert"]');
  const grew = document.body.innerText.length > {before} + 3;
  return invalidMarked || alert || grew; }})()"#,
                    sel = validation["sel"].as_str().unwrap_or("input"),
                    before = validation["before"].as_f64().unwrap_or(0.0)
                ),
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if !reacted {
            no_inline_validation = true;
            validation_sel = validation["sel"].as_str().unwrap_or("input").to_string();
        }
        // Clear the probe text so later passes/screenshots don't carry it.
        let _ = tab.evaluate(
            &format!(
                r#"(() => {{ const el = document.querySelector({:?}); if (el) {{ el.value = ''; el.dispatchEvent(new Event('input', {{bubbles: true}})); }} }})()"#,
                validation["sel"].as_str().unwrap_or("input")
            ),
            false,
        );
    }

    // ── submit-empty probe: required-unmarked + error-message-vague. Submit the largest
    // form with EMPTY fields in a way that CANNOT navigate (we preventDefault on the
    // capture phase first), then read what the form complained about. Two findings:
    //   - required-unmarked: a field the form rejects when empty but that carries NO
    //     required marker (no `required`, no aria-required) — custom validation enforcing
    //     a rule the markup doesn't announce (screen readers/AT never learn it's required).
    //   - error-message-vague: the error text shown is a content-free generic ("required",
    //     "invalid", "error") that doesn't say WHAT to fix.
    // Conservative by design: only custom-validated forms (native `required` is already the
    // marker), only clear error signals, capped.
    let submit = eval_json(
        r##"(() => {
  let best = null, bestN = 0;
  for (const f of document.querySelectorAll('form')) {
    const n = f.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]), textarea, select').length;
    if (n > bestN) { bestN = n; best = f; }
  }
  if (!best || bestN < 2) return JSON.stringify({ probed: false });
  const f = best;
  // Hard-block navigation: capture-phase preventDefault, and neutralise method/action.
  // preventDefault stops NAVIGATION only — the page's own submit/validation listeners
  // must still run (do NOT stopImmediatePropagation, or their errors never appear).
  const block = (e) => { e.preventDefault(); };
  f.addEventListener('submit', block, { capture: true });
  const beforeText = (document.body.innerText || '').length;
  // Empty every field so "required" rules trip.
  const fields = [...f.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=checkbox]):not([type=radio]), textarea')];
  for (const el of fields) { try { el.value = ''; el.dispatchEvent(new Event('input', {bubbles:true})); } catch(_){} }
  // Fire submit the way a user would (button click → requestSubmit), guarded.
  const btn = f.querySelector('[type=submit], button:not([type=button])');
  try { if (btn) btn.click(); else if (f.requestSubmit) f.requestSubmit(); } catch(_){}
  // Descriptor of each field: is it marked required, and did it get an error signal?
  const nameOf = (el) => (el.getAttribute('aria-label') || el.getAttribute('name') || el.getAttribute('placeholder') || el.id || el.type || 'field');
  const markedRequired = (el) => el.hasAttribute('required') || el.getAttribute('aria-required') === 'true';
  // An error signal near a field: aria-invalid, an error class, or a linked/adjacent message.
  const errorFor = (el) => {
    if (el.getAttribute('aria-invalid') === 'true') return true;
    if (/error|invalid/i.test(el.className || '')) return true;
    const desc = el.getAttribute('aria-describedby');
    if (desc) { for (const id of desc.split(/\s+/)) { const m = document.getElementById(id); if (m && (m.innerText||'').trim() && m.offsetParent !== null) return true; } }
    return false;
  };
  return JSON.stringify({ probed: true, count: fields.length,
    fields: fields.slice(0, 12).map(el => ({ name: nameOf(el).slice(0,40), required: markedRequired(el), errored: errorFor(el), native: !el.checkValidity ? false : !el.checkValidity() })) });
})()"##,
    );
    let mut required_unmarked: Vec<String> = Vec::new();
    let mut vague_msg: Option<String> = None;
    let mut submit_error_count = 0.0;
    let mut error_summary_present = false;
    let mut focus_moved_to_error = false;
    if submit["probed"].as_bool() == Some(true) {
        std::thread::sleep(std::time::Duration::from_millis(300));
        // Re-read error state after the form's async validators settle, and collect any
        // vague error messages now visible.
        let after = eval_json(
            r##"(() => {
  const f = (() => { let best=null,n=0; for (const x of document.querySelectorAll('form')) { const c = x.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]), textarea, select').length; if (c>n){n=c;best=x;} } return best; })();
  if (!f) return JSON.stringify({ msgs: [], errored: [] });
  const errored = [];
  const nameOf = (el) => (el.getAttribute('aria-label') || el.getAttribute('name') || el.getAttribute('placeholder') || el.id || el.type || 'field');
  for (const el of f.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=checkbox]):not([type=radio]), textarea')) {
    const req = el.hasAttribute('required') || el.getAttribute('aria-required') === 'true';
    let err = el.getAttribute('aria-invalid') === 'true' || /error|invalid/i.test(el.className || '');
    if (el.checkValidity && !el.checkValidity()) err = true;
    if (err) errored.push({ name: nameOf(el).slice(0,40), required: req });
  }
  // Visible validation messages: error/invalid nodes, aria-describedby targets of the
  // form's fields, and native validationMessage.
  const msgs = [];
  const push = (t) => { t = (t||'').replace(/\s+/g,' ').trim(); if (t && t.length < 80) msgs.push(t); };
  for (const m of document.querySelectorAll('[role=alert], [class*="err" i], [class*="invalid" i], [aria-live]:not([aria-live=off])')) {
    if (m.offsetParent !== null) push(m.innerText);
  }
  for (const el of f.querySelectorAll('input, textarea, select')) {
    const desc = el.getAttribute('aria-describedby');
    if (desc) for (const id of desc.split(/\s+/)) { const m = document.getElementById(id); if (m && m.offsetParent !== null) push(m.innerText); }
    if (el.validationMessage) push(el.validationMessage);
  }
  // Error-summary + focus management (WCAG 3.3.1 accessible errors): after a failed submit,
  // did an error SUMMARY appear (a region listing the problems / linking to fields), or did
  // focus move to an errored field? Either orients the user; neither leaves them stranded.
  const summaryEl = [...document.querySelectorAll('[role=alert], [class*="summary" i], [aria-live]:not([aria-live=off])')].find(m => {
    if (m.offsetParent === null) return false;
    const t = (m.innerText || '');
    const links = m.querySelectorAll('a[href^="#"]').length;
    const lines = t.split('\n').filter(x => x.trim()).length;
    return links >= 2 || /\b\d+\s+(errors?|problems?|fields?)\b/i.test(t) || /\b(please\s+)?(fix|correct|review)\b/i.test(t) || (lines >= 2 && /error|invalid|required/i.test(t));
  });
  const ae = document.activeElement;
  let focusErrored = false;
  if (ae && ae !== document.body) {
    focusErrored = ae.getAttribute('aria-invalid') === 'true' || /error|invalid/i.test(ae.className || '') || (ae.checkValidity && !ae.checkValidity()) || (summaryEl && summaryEl.contains(ae)) || false;
  }
  return JSON.stringify({ msgs: [...new Set(msgs)].slice(0, 8), errored, summary: !!summaryEl, focusErrored });
})()"##,
        );
        // required-unmarked: an errored field with no required marker (custom validation).
        if let Some(errs) = after["errored"].as_array() {
            for e in errs {
                if e["required"].as_bool() == Some(false) {
                    if let Some(n) = e["name"].as_str() {
                        if required_unmarked.len() < 4 {
                            required_unmarked.push(n.to_string());
                        }
                    }
                }
            }
        }
        // error-message-vague: a message that's a content-free generic — flag conservatively.
        let vague = |m: &str| {
            let ml = m.to_lowercase();
            let ml = ml.trim().trim_end_matches(['.', '!']);
            matches!(
                ml,
                "required"
                    | "this field is required"
                    | "field is required"
                    | "invalid"
                    | "invalid input"
                    | "invalid value"
                    | "error"
                    | "please fill out this field"
                    | "this field is invalid"
                    | "wrong"
                    | "incorrect"
                    | "not valid"
            )
        };
        vague_msg = after["msgs"]
            .as_array()
            .and_then(|ms| ms.iter().find_map(|m| m.as_str().filter(|s| vague(s))))
            .map(String::from);
        submit_error_count = after["errored"].as_array().map(|a| a.len()).unwrap_or(0) as f64;
        error_summary_present = after["summary"].as_bool().unwrap_or(false);
        focus_moved_to_error = after["focusErrored"].as_bool().unwrap_or(false);
    }

    // ── data lost (LAST — navigates): a substantial form (≥4 text fields) that silently
    // drops typed data on navigate-away-and-return, with no guard and no draft restore.
    let mut data_lost = false;
    let mut data_fields = 0.0;
    let setup = eval_json(
        r#"(() => {
  const FIELD = 'input[type="text"], input[type="email"], input:not([type]), textarea';
  // 1) The biggest <form> — unchanged: its field count, and the first field to dirty.
  let el = null, count = 0;
  for (const f of document.querySelectorAll('form')) {
    const fs = f.querySelectorAll(FIELD);
    if (fs.length > count) { count = fs.length; el = fs[0]; }
  }
  // 2) No qualifying <form>? Look for a Save-GATED editor region NOT wrapped in a form — an editor
  //    built from inputs in <div>s (settings panels, doc editors) loses typed data on a navigate-away
  //    just the same. Require an explicit Save/Apply/Update/Publish control (the signal these fields
  //    hold UNCOMMITTED state, not a live search/filter), tie the probe to THAT control's own
  //    container (so a stray field elsewhere can't trigger it), and exclude search/filter boxes.
  if (!el || count < 4) {
    const isSearch = (x) => {
      const t = ((x.name||'')+' '+(x.id||'')+' '+(x.getAttribute('aria-label')||'')+' '+(x.placeholder||'')).toLowerCase();
      return x.type === 'search' || x.getAttribute('role') === 'searchbox'
        || /\b(search|filter|query)\b/.test(t) || !!x.closest('[role="search"]');
    };
    const editableIn = (root) => [...root.querySelectorAll(FIELD)]
      .filter((x) => !isSearch(x) && !x.disabled && !x.readOnly && x.offsetParent !== null);
    const saveBtns = [...document.querySelectorAll('button, [role="button"], input[type="submit"]')]
      .filter((b) => /\b(save|apply|update|publish)\b/i.test((b.textContent || b.value || '').trim()));
    for (const btn of saveBtns) {
      let node = btn;
      for (let i = 0; i < 6 && node; i++, node = node.parentElement) {
        const fs = editableIn(node);
        if (fs.length >= 4) { el = fs[0]; count = fs.length; break; }
      }
      if (el && count >= 4) break;
    }
  }
  if (!el || count < 4) return JSON.stringify({probed: false, fields: count});
  el.value = 'uxlint-draft-probe';
  el.dispatchEvent(new Event('input', {bubbles: true}));
  const guarded = typeof window.onbeforeunload === 'function';
  const key = el.id ? '#' + el.id : (el.name ? '[name="' + el.name + '"]' : 'input');
  return JSON.stringify({probed: true, fields: count, guarded, key});
})()"#,
    );
    if setup["probed"].as_bool() == Some(true) && setup["guarded"].as_bool() != Some(true) {
        data_fields = setup["fields"].as_f64().unwrap_or(0.0);
        // Forward navigations (no bfcache ambiguity): away to a bare probe URL, then back to
        // the form page as a fresh load — did anything restore the draft?
        let away = format!(
            "{}{}uxlint-form-probe",
            url,
            if url.contains('?') { "&" } else { "?" }
        );
        if tab
            .navigate_to(&away)
            .and_then(|t| t.wait_until_navigated().map(|_| ()))
            .is_ok()
        {
            let _ = tab
                .navigate_to(url)
                .and_then(|t| t.wait_until_navigated().map(|_| ()));
            std::thread::sleep(std::time::Duration::from_millis(700));
            let restored = tab
                .evaluate(
                    &format!(
                        r#"(() => {{ const el = document.querySelector({:?}); return !!el && el.value.includes('uxlint-draft-probe'); }})()"#,
                        setup["key"].as_str().unwrap_or("input")
                    ),
                    false,
                )
                .ok()
                .and_then(|r| r.value)
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            data_lost = !restored;
        }
    }

    json!({
        "keyboardTrap": keyboard_trap,
        "keyboardTrapAt": trap_at,
        "passwordPasteBlocked": paste["blocked"].as_bool().unwrap_or(false),
        "passwordPasteSel": paste["sel"].as_str().unwrap_or(""),
        "noInlineValidation": no_inline_validation,
        "noInlineValidationSel": validation_sel,
        "dataLost": data_lost,
        "dataLostFields": data_fields,
        "requiredUnmarked": required_unmarked,
        "errorMessageVague": vague_msg,
        "submitErrorCount": submit_error_count,
        "errorSummaryPresent": error_summary_present,
        "focusMovedToError": focus_moved_to_error,
    })
}

pub(crate) fn states_pass(tab: &headless_chrome::Tab) -> Value {
    let mut hovers = Vec::new();
    let mut focuses = Vec::new();
    let targets: Vec<Value> = tab
        .evaluate(TARGETS_JS, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
        .unwrap_or_default();
    for t in &targets {
        let i = t["i"].as_u64().unwrap_or(0);
        let pt = tab
            .evaluate(
                &format!(
                    r##"(() => {{ const el = window.__uxr[{i}]; el.scrollIntoView({{block:'center'}});
                       // Inline links can wrap: the bounding-box centre falls in the dead gap
                       // between line fragments. Hover the FIRST line box instead.
                       const rects = el.getClientRects();
                       const r = rects.length ? rects[0] : el.getBoundingClientRect();
                       const cx = r.x + r.width/2, cy = r.y + r.height/2;
                       const top = document.elementFromPoint(cx, cy);
                       const ok = !!top && (top === el || el.contains(top) || top.contains(el));
                       return JSON.stringify({{x: cx, y: cy, ok}}); }})()"##
                ),
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()));
        let Some(pt) = pt else { continue };
        if pt["ok"].as_bool() != Some(true) {
            continue;
        }
        let _ =
            tab.move_mouse_to_point(headless_chrome::browser::tab::point::Point { x: 0.0, y: 0.0 });
        const VIS_COUNT: &str = r#"Array.from(document.body.querySelectorAll('*')).filter(e => e.offsetParent !== null).length"#;
        let vis_base = tab
            .evaluate(VIS_COUNT, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let before = tab.evaluate(&sig_js(i), false).ok().and_then(|r| r.value);
        let _ = tab.move_mouse_to_point(headless_chrome::browser::tab::point::Point {
            x: pt["x"].as_f64().unwrap_or(0.0),
            y: pt["y"].as_f64().unwrap_or(0.0),
        });
        // Two frames is enough: hover styles apply immediately and a started transition
        // already shifts computed values — the sig diff doesn't need the animation to END.
        std::thread::sleep(std::time::Duration::from_millis(80));
        let after = tab.evaluate(&sig_js(i), false).ok().and_then(|r| r.value);
        // What did the hover REVEAL document-wide (a menu, a panel)? If focus doesn't
        // reveal the same content, touch and keyboard users can never reach it.
        let vis_hover = tab
            .evaluate(VIS_COUNT, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let revealed = (vis_hover - vis_base).max(0.0);
        let mut revealed_on_focus = -1.0;
        if revealed >= 3.0 {
            let _ = tab.move_mouse_to_point(headless_chrome::browser::tab::point::Point {
                x: 0.0,
                y: 0.0,
            });
            std::thread::sleep(std::time::Duration::from_millis(120));
            let _ = tab.evaluate(&format!("window.__uxr[{i}].focus()"), false);
            std::thread::sleep(std::time::Duration::from_millis(120));
            let vis_focus = tab
                .evaluate(VIS_COUNT, false)
                .ok()
                .and_then(|r| r.value)
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let _ = tab.evaluate(&format!("window.__uxr[{i}].blur()"), false);
            revealed_on_focus = (vis_focus - vis_base).max(0.0);
        }
        // WCAG 1.4.13: content revealed on hover must also appear on keyboard focus.
        const TIP_COUNT: &str = r#"document.querySelectorAll('[role="tooltip"], [data-tooltip], [class*="tooltip" i], [class*="popover" i]').length + Array.from(document.querySelectorAll('[role="tooltip"], [data-tooltip]')).filter(e => e.offsetParent !== null).length"#;
        let tip_hover = tab
            .evaluate(TIP_COUNT, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let _ =
            tab.move_mouse_to_point(headless_chrome::browser::tab::point::Point { x: 0.0, y: 0.0 });
        let mut tooltip_hover_only = false;
        if tip_hover > 0.0 {
            std::thread::sleep(std::time::Duration::from_millis(150));
            let tip_base = tab
                .evaluate(TIP_COUNT, false)
                .ok()
                .and_then(|r| r.value)
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            if tip_base < tip_hover {
                // the hover genuinely revealed something — does focus reveal it too?
                let _ = tab.evaluate(&format!("window.__uxr[{i}].focus()"), false);
                std::thread::sleep(std::time::Duration::from_millis(150));
                let tip_focus = tab
                    .evaluate(TIP_COUNT, false)
                    .ok()
                    .and_then(|r| r.value)
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let _ = tab.evaluate(&format!("window.__uxr[{i}].blur()"), false);
                tooltip_hover_only = tip_focus <= tip_base;
            }
        }
        hovers.push(json!({ "label": t["label"], "key": t["key"], "changed": before != after, "tooltipHoverOnly": tooltip_hover_only,
            "revealed": revealed, "revealedOnFocus": revealed_on_focus, "rect": t["rect"] }));
    }
    // Reset scroll (the hover pass wandered) — and tolerate BODY stops: after programmatic
    // scrolling, Chrome's first Tab press re-anchors sequential focus before landing anywhere.
    let _ = tab.evaluate("window.scrollTo(0, 0)", false);
    let mut seen_keys = std::collections::HashSet::new();
    let mut nulls = 0;
    for _ in 0..25 {
        if tab.press_key("Tab").is_err() {
            break;
        }
        let obs = tab
            .evaluate(
                r##"(() => {
  const el = document.activeElement;
  if (!el || el === document.body) return null;
  const pick = n => { const cs = getComputedStyle(n); return [cs.boxShadow, cs.outlineStyle, cs.outlineWidth, cs.borderColor, cs.backgroundColor, cs.color].join('|'); };
  const focused = pick(el);
  const key = (el.tagName + '|' + (el.getAttribute('class') || '')).slice(0, 80);
  const label = (el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 40);
  const r = el.getBoundingClientRect();
  el.blur();
  const blurred = pick(el);
  el.focus();
  return JSON.stringify({ key, label, changed: focused !== blurred,
    x: Math.round(r.x + scrollX), y: Math.round(r.y + scrollY) });
})()"##,
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()));
        let Some(obs) = obs else {
            nulls += 1;
            if nulls > 3 {
                break;
            }
            continue;
        };
        let key = obs["key"].as_str().unwrap_or("").to_string();
        if !seen_keys.insert(key) {
            continue;
        }
        focuses.push(obs);
    }
    json!({ "hovers": hovers, "focuses": focuses })
}

// ── dialog/disclosure discovery (client clicks safely, server judges) ─────────
// Click controls that look like OPENERS (never dangerous labels), watch what appears, and
// test the component contract live: dialogs → role/aria-modal/label/focus/Escape;
// disclosures → aria-expanded actually flips.
// Buttons discovery_pass must NOT click because they can act immediately and irreversibly. NOT
// including confirm-guarded verbs like rotate/revoke: the native-dialog handler dismisses their
// confirm() (= Cancel), so clicking them is safe AND lets the native-dialog lint observe the dialog.
pub(crate) const DANGEROUS_RE: &str = r"(?i)^(delete|remove|pay|buy|checkout|purchase|submit|send|post|sign out|log ?out|export|generate|run|deploy|publish|upgrade|confirm|save)";

pub(crate) const OPENERS_JS: &str = r##"(() => {
  window.__uxr2 = [];
  const out = [];
  for (const el of document.querySelectorAll('button, [role="button"]')) {
    if (el.closest('[aria-hidden="true"]') || el.disabled === true) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 8 || r.height < 8 || r.bottom < 0 || r.top > innerHeight) continue;
    if (el.closest('form') && (el.getAttribute('type') || 'submit') === 'submit') continue;
    const label = (el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 40);
    window.__uxr2.push(el);
    out.push({ i: window.__uxr2.length - 1, label, expanded: el.getAttribute('aria-expanded') });
    if (out.length >= 8) break;
  }
  return JSON.stringify(out);
})()"##;

pub(crate) const OVERLAY_JS: &str = r##"(() => {
  // Width-vs-content geometry: a centred modal far wider than the widest thing inside it is a
  // near-empty box (the fix-details-without-a-screenshot bug). Excludes the ✕ close chrome pinned
  // to the top-right (it tracks the box width), full-height sheets, and sub-560px dialogs.
  const geom = (el) => {
    const r = el.getBoundingClientRect();
    const out = { dlg_w: Math.round(r.width), content_w: 0, oversized: false };
    if (r.width < 560 || r.height >= innerHeight * 0.9) return out;
    let L = Infinity, R = -Infinity, any = false;
    for (const c of el.querySelectorAll('*')) {
      const b = c.getBoundingClientRect();
      if (b.width < 1 || b.height < 1) continue;
      const cs = getComputedStyle(c);
      if (cs.visibility === 'hidden') continue;
      const interactive = c.matches('a,button,input,select,textarea,summary,[role="button"]');
      if (interactive && b.width <= 56 && b.height <= 56 && b.right >= r.right - 72 && b.top <= r.top + 72) continue;
      const hasText = Array.from(c.childNodes).some(n => n.nodeType === 3 && n.textContent.trim());
      const visual = interactive || hasText || /^(IMG|SVG|VIDEO|CANVAS|TABLE)$/i.test(c.tagName)
        || (cs.backgroundColor !== 'rgba(0, 0, 0, 0)' && cs.backgroundColor !== 'transparent')
        || parseFloat(cs.borderTopWidth) > 0.5;
      if (!visual) continue;
      any = true; L = Math.min(L, b.left); R = Math.max(R, b.right);
    }
    if (!any) return out;
    out.content_w = Math.round(R - L);
    out.oversized = out.content_w / r.width < 0.55 && r.width - out.content_w >= 280;
    return out;
  };
  // A dialog-ish overlay: declared role, native dialog, or a big fixed layer. Must be VISIBLE
  // — a hidden role=dialog pre-rendered in the DOM is not "open".
  const decl = Array.from(document.querySelectorAll('[role="dialog"], [role="alertdialog"], [aria-modal="true"], dialog[open]'))
    .find(e => e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden');
  if (decl) {
    const el = decl;
    return JSON.stringify({
      present: true,
      declared: true,
      modal: el.getAttribute('aria-modal') === 'true' || el.tagName === 'DIALOG',
      labelled: !!(el.getAttribute('aria-label') || el.getAttribute('aria-labelledby')),
      focus_inside: el.contains(document.activeElement) && document.activeElement !== document.body,
      scrollLocked: (function(){ var b=getComputedStyle(document.body), h=getComputedStyle(document.documentElement); return b.overflow==='hidden'||b.overflow==='clip'||h.overflow==='hidden'||h.overflow==='clip'||b.position==='fixed'; })(),
      scrollable: document.documentElement.scrollHeight > window.innerHeight + 4,
      ...geom(el)
    });
  }
  for (const el of document.querySelectorAll('body *')) {
    const cs = getComputedStyle(el);
    if (cs.position === 'fixed' && parseInt(cs.zIndex) >= 10) {
      const r = el.getBoundingClientRect();
      if (r.width >= innerWidth * 0.4 && r.height >= innerHeight * 0.3) {
        return JSON.stringify({
          present: true,
          declared: false,
          modal: false,
          labelled: false,
          focus_inside: el.contains(document.activeElement) && document.activeElement !== document.body,
          scrollLocked: (function(){ var b=getComputedStyle(document.body), h=getComputedStyle(document.documentElement); return b.overflow==='hidden'||b.overflow==='clip'||h.overflow==='hidden'||h.overflow==='clip'||b.position==='fixed'; })(),
          scrollable: document.documentElement.scrollHeight > window.innerHeight + 4,
          ...geom(el)
        });
      }
    }
  }
  return JSON.stringify({ present: false });
})()"##;

pub(crate) fn discovery_pass(tab: &headless_chrome::Tab, base_url: &str) -> Value {
    let mut dialogs = Vec::new();
    let mut disclosures = Vec::new();
    let mut live_gaps = Vec::new();
    const TEXT_LEN: &str = r#"((document.body && document.body.innerText) || '').length"#;
    const HAS_LIVE: &str = r#"!!document.querySelector('[aria-live]:not([aria-live="off"]), [role="status"], [role="alert"], output')"#;
    let dangerous = regex_lite(DANGEROUS_RE);
    let openers: Vec<Value> = tab
        .evaluate(OPENERS_JS, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
        .unwrap_or_default();
    let overlay = |tab: &headless_chrome::Tab| -> Value {
        tab.evaluate(OVERLAY_JS, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
            .unwrap_or_else(|| json!({"present": false}))
    };
    for o in openers.iter().take(8) {
        let label = o["label"].as_str().unwrap_or("").to_string();
        if label.is_empty() || dangerous(&label) {
            continue;
        }
        if overlay(tab)["present"].as_bool() == Some(true) {
            break; // something is already open — don't stack
        }
        let i = o["i"].as_u64().unwrap_or(0);
        let url_before = tab.get_url();
        let text_before = tab
            .evaluate(TEXT_LEN, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        // real click at the element centre
        let clicked = tab
            .evaluate(
                &format!(
                    r##"(() => {{ const el = window.__uxr2[{i}]; if (!el) return null; el.scrollIntoView({{block:'center'}});
                       const r = el.getBoundingClientRect(); return JSON.stringify({{x: r.x+r.width/2, y: r.y+r.height/2}}); }})()"##
                ),
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()));
        let Some(pt) = clicked else { continue };
        if tab
            .click_point(headless_chrome::browser::tab::point::Point {
                x: pt["x"].as_f64().unwrap_or(0.0),
                y: pt["y"].as_f64().unwrap_or(0.0),
            })
            .is_err()
        {
            continue;
        }
        // Poll instead of a fixed wait: most clicks open nothing (full window is the
        // worst case), and a dialog that IS opening shows within a few frames.
        for _ in 0..10 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if overlay(tab)["present"].as_bool() == Some(true) || tab.get_url() != url_before {
                break;
            }
        }
        // SPA navigation? undo and move on.
        if tab.get_url() != url_before {
            let _ = tab.navigate_to(&url_before);
            let _ = tab.wait_until_navigated();
            std::thread::sleep(std::time::Duration::from_millis(500));
            continue;
        }
        let ov = overlay(tab);
        if ov["present"].as_bool() == Some(true) {
            // Dialog contract: Escape must close it.
            let _ = tab.press_key("Escape");
            let mut escaped = false;
            for _ in 0..8 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                if overlay(tab)["present"].as_bool() != Some(true) {
                    escaped = true;
                    break;
                }
            }
            if !escaped {
                // try a close/cancel affordance, else reload to reset
                let _ = tab.evaluate(
                    r##"(() => { for (const el of document.querySelectorAll('button, [role="button"], [aria-label]')) {
                        const t = ((el.getAttribute('aria-label') || el.textContent || '') + '').toLowerCase();
                        if (/close|cancel|dismiss|✕|×/.test(t)) { el.click(); return true; } } return false; })()"##,
                    false,
                );
                std::thread::sleep(std::time::Duration::from_millis(300));
                if overlay(tab)["present"].as_bool() == Some(true) {
                    let _ = tab.navigate_to(&url_before);
                    let _ = tab.wait_until_navigated();
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
            dialogs.push(json!({
                "opener": label,
                "declared": ov["declared"],
                "modal": ov["modal"],
                "labelled": ov["labelled"],
                "focus_inside": ov["focus_inside"],
                "escape_closes": escaped,
                "scroll_locked": ov["scrollLocked"],
                "scrollable": ov["scrollable"],
                "oversized": ov["oversized"],
                "dlg_w": ov["dlg_w"],
                "content_w": ov["content_w"]
            }));
            continue;
        }
        // No overlay: disclosure? did aria-expanded flip on the opener? Read state AND
        // whether the cached node is still connected — a click that re-rendered the
        // component detaches our reference, and a stale node's attribute never updates
        // (a false "state never changed"). Only judge readings we can trust.
        let probe = tab
            .evaluate(
                &format!(
                    "(() => {{ const el = window.__uxr2[{i}]; if (!el) return null; return JSON.stringify({{ex: el.getAttribute('aria-expanded'), live: el.isConnected}}); }})()"
                ),
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()));
        let connected = probe
            .as_ref()
            .map(|p| p["live"].as_bool() == Some(true))
            .unwrap_or(false);
        let before = o["expanded"].as_str().map(str::to_string);
        let after = probe
            .as_ref()
            .and_then(|p| p["ex"].as_str())
            .map(str::to_string);
        // Skip when the node detached (reading untrustworthy) — no finding beats a flaky one.
        if connected && (before.as_deref() == Some("false") || after.is_some() || before.is_some())
        {
            disclosures.push(json!({ "opener": label, "synced": before != after }));
        }
        // Content changed after the activation but the page has NO live region at all —
        // a screen-reader user hears nothing happen (WCAG 4.1.3). Presence-only check:
        // proving the announcement reached the right region is a deeper problem.
        let text_after = tab
            .evaluate(TEXT_LEN, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if (text_after - text_before).abs() >= 20.0 && live_gaps.len() < 3 {
            let has_live = tab
                .evaluate(HAS_LIVE, false)
                .ok()
                .and_then(|r| r.value)
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if !has_live {
                live_gaps
                    .push(json!({ "opener": label, "delta": (text_after - text_before).abs() }));
            }
        }
        // close whatever opened (click the opener again or Escape)
        let _ = tab.press_key("Escape");
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    let _ = base_url; // reserved for future reset logic
    json!({ "dialogs": dialogs, "disclosures": disclosures, "liveGaps": live_gaps })
}

// ── context-switch probe (org/workspace/project selector actually updates the page?) ──────────
// A <select> in the app CHROME (nav/aside/header — not main, not a form) that offers ≥2 values is
// a context switcher: org, workspace, project, language. Switching it must change what the page
// shows. The failure mode this catches: the switcher writes a client store, but every view loaded
// its data once at mount — so nothing refetches and the "switch" is silently inert until a manual
// reload. Detection needs BOTH signals absent: main's text unchanged AND no new network activity
// (two empty orgs legitimately render identical text — but a working switch still refetches).

/// List candidate switchers (cached on window.__uxrcs like the opener probe).
const CONTEXT_SWITCHERS_JS: &str = r##"(() => {
  window.__uxrcs = [];
  const out = [];
  for (const el of document.querySelectorAll('select')) {
    if (el.closest('main') || el.closest('form') || el.closest('[aria-hidden="true"]') || el.disabled) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 8 || r.height < 8) continue;
    const vals = new Set(Array.from(el.options).filter(o => !o.disabled && o.value !== '').map(o => o.value));
    if (vals.size < 2) continue;
    const label = ((el.labels && el.labels[0] && el.labels[0].textContent) || el.getAttribute('aria-label') || el.id || 'context switcher').replace(/\s+/g, ' ').trim().slice(0, 40);
    window.__uxrcs.push(el);
    out.push({ i: window.__uxrcs.length - 1, label });
    if (out.length >= 2) break;
  }
  return JSON.stringify(out);
})()"##;

/// Capture the page's before-state, then flip the switcher to a different option. The value is set
/// through the native prototype setter so framework-controlled selects (React) see the change too.
const CONTEXT_SWITCH_JS: &str = r##"(() => {
  const el = window.__uxrcs[__I__];
  if (!el || !el.isConnected) return null;
  const alt = Array.from(el.options).find(o => !o.disabled && o.value !== '' && o.value !== el.value);
  if (!alt) return null;
  const main = document.querySelector('main') || document.body;
  const before = JSON.stringify({
    ok: true,
    val: el.value,
    text_sig: main.innerText.length + '|' + main.innerText.slice(0, 4000),
    res: performance.getEntriesByType('resource').length
  });
  const set = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
  set.call(el, alt.value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return before;
})()"##;

const CONTEXT_AFTER_JS: &str = r##"(() => {
  const main = document.querySelector('main') || document.body;
  return JSON.stringify({
    text_sig: main.innerText.length + '|' + main.innerText.slice(0, 4000),
    res: performance.getEntriesByType('resource').length
  });
})()"##;

const CONTEXT_REVERT_JS: &str = r##"(() => {
  const el = window.__uxrcs[__I__];
  if (!el || !el.isConnected) return false;
  const set = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
  set.call(el, __VAL__);
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
})()"##;

/// Probe each context switcher once: flip it, wait for the app to react, compare, revert.
pub(crate) fn context_switch_pass(tab: &headless_chrome::Tab) -> Value {
    let mut switches = Vec::new();
    let url_before = tab.get_url();
    let candidates = tab
        .evaluate(CONTEXT_SWITCHERS_JS, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| {
            v.as_str()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
        })
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    for c in candidates {
        let (i, label) = (
            c["i"].as_u64().unwrap_or(0),
            c["label"].as_str().unwrap_or("").to_string(),
        );
        let before = tab
            .evaluate(&CONTEXT_SWITCH_JS.replace("__I__", &i.to_string()), false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
            });
        let Some(before) = before.filter(|b| b["ok"].as_bool() == Some(true)) else {
            continue;
        };
        // Give the app time to react — a route change, a refetch, a re-render.
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let after = tab
            .evaluate(CONTEXT_AFTER_JS, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
            })
            .unwrap_or_default();
        let navigated = tab.get_url() != url_before;
        let changed = navigated || after["text_sig"] != before["text_sig"];
        let refetched = after["res"].as_u64().unwrap_or(0) > before["res"].as_u64().unwrap_or(0);
        // Put the world back: original value (same native-setter path), or the original URL if the
        // switch navigated.
        if navigated {
            let _ = tab.navigate_to(&url_before);
            let _ = tab.wait_until_navigated();
            std::thread::sleep(std::time::Duration::from_millis(500));
        } else {
            let val = serde_json::to_string(before["val"].as_str().unwrap_or(""))
                .unwrap_or_else(|_| "\"\"".into());
            let _ = tab.evaluate(
                &CONTEXT_REVERT_JS
                    .replace("__I__", &i.to_string())
                    .replace("__VAL__", &val),
                false,
            );
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        switches.push(json!({ "opener": label, "changed": changed, "refetched": refetched }));
    }
    json!({ "contextSwitches": switches })
}

/// Destructive-affordance probe (it CLICKS Delete/Remove
/// controls, including through their confirm dialogs — throwaway environments only).
/// The contract it tests: a destructive control either confirms first, or offers undo
/// after. Immediate irreversible deletion is the finding.
pub(crate) fn destructive_pass(tab: &headless_chrome::Tab, base_url: &str) -> Value {
    const TEXT_LEN: &str = r#"((document.body && document.body.innerText) || '').length"#;
    const HAS_UNDO: &str = r#"Array.from(document.querySelectorAll('button, a, [role="button"]')).some(e => /\b(undo|restore)\b/i.test((e.textContent || '') + ' ' + (e.getAttribute('aria-label') || '')) && e.offsetParent !== null)"#;
    // Danger-labelled controls currently on the page (re-counted live each round).
    const COUNT_DANGER: &str = r##"Array.from(document.querySelectorAll('button, [role="button"], a')).filter(el => { const r = el.getBoundingClientRect(); const label = ((el.getAttribute('aria-label')||'')+' '+(el.textContent||'')).replace(/\s+/g,' ').trim(); return !el.disabled && r.width>=8 && r.height>=8 && /^(delete|remove|discard|destroy|clear)/i.test(label); }).length"##;
    // Click the FIRST danger control via its own handler (el.click fires onclick), return its label.
    const CLICK_FIRST: &str = r##"(() => {
  for (const el of document.querySelectorAll('button, [role="button"], a')) {
    const r = el.getBoundingClientRect();
    const label = ((el.getAttribute('aria-label') || '') + ' ' + (el.textContent || '')).replace(/\s+/g, ' ').trim().slice(0, 40);
    if (el.disabled || r.width < 8 || r.height < 8) continue;
    if (!/^(delete|remove|discard|destroy|clear)/i.test(label)) continue;
    el.click();
    return label;
  }
  return '';
})()"##;
    let overlay = |tab: &headless_chrome::Tab| -> Value {
        tab.evaluate(OVERLAY_JS, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
            .unwrap_or_else(|| json!({"present": false}))
    };
    let count_danger = |tab: &headless_chrome::Tab| -> i64 {
        tab.evaluate(COUNT_DANGER, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0) as i64
    };
    let mut results = Vec::new();
    // Up to 3 distinct danger controls. Re-query live each round — no stale handles.
    for _ in 0..3 {
        if count_danger(tab) == 0 {
            break;
        }
        let url_before = tab.get_url();
        let text_before = tab
            .evaluate(TEXT_LEN, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let label = tab
            .evaluate(CLICK_FIRST, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        if label.is_empty() {
            break;
        }
        let mut confirmed = false;
        let mut deleted = false;
        for _ in 0..8 {
            std::thread::sleep(std::time::Duration::from_millis(150));
            if overlay(tab)["present"].as_bool() == Some(true) {
                confirmed = true;
                break;
            }
            let now = tab
                .evaluate(TEXT_LEN, false)
                .ok()
                .and_then(|r| r.value)
                .and_then(|v| v.as_f64())
                .unwrap_or(text_before);
            if text_before - now >= 20.0 {
                deleted = true;
                break;
            }
        }
        if tab.get_url() != url_before {
            let _ = tab.navigate_to(&url_before);
            let _ = tab.wait_until_navigated();
            continue; // navigated away — not a same-page destructive control
        }
        if confirmed {
            // Click through the confirm (this IS the destructive mode) to test for undo.
            let _ = tab.evaluate(
                r##"(() => { for (const el of document.querySelectorAll('[role="dialog"] button, [aria-modal="true"] button, dialog button')) {
                    if (/(delete|remove|confirm|yes|discard)/i.test(el.textContent || '')) { el.click(); return true; } } return false; })()"##,
                false,
            );
            std::thread::sleep(std::time::Duration::from_millis(600));
        }
        let undo = tab
            .evaluate(HAS_UNDO, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        results.push(json!({ "label": label, "confirm": confirmed, "deleted": deleted || confirmed, "undo": undo }));
        if !confirmed && !deleted {
            break; // clicking did nothing observable — stop poking
        }
    }
    let _ = base_url;
    json!({ "destructive": results })
}

/// Action-feedback probe (it CLICKS a constructive action —
/// Add / Create / Save / Publish — on the assumption the test credentials have full
/// permission on a throwaway environment). Two contracts it tests, both "visibility of
/// system status" (Nielsen #1):
///   - action-no-feedback: a mutating action that produces NO visible confirmation (no toast,
///     no state change, no new item) — the user can't tell it worked.
///   - pending-state-missing: an action whose result arrives only after a delay (async work)
///     but that showed no pending indicator meanwhile, so the user may double-submit.
///
/// One action per page; re-queried live; navigation is treated as feedback and restored.
pub(crate) fn feedback_pass(tab: &headless_chrome::Tab, base_url: &str) -> Value {
    const STATE: &str = r##"(() => {
      const toasts = Array.from(document.querySelectorAll('[role="alert"],[role="status"],[aria-live]:not([aria-live="off"]),[class*="toast" i],[class*="snackbar" i],[class*="notification" i]')).filter(e => e.offsetParent !== null && (e.textContent||'').trim()).length;
      return JSON.stringify({ t: ((document.body&&document.body.innerText)||'').length, toasts, elems: document.getElementsByTagName('*').length });
    })()"##;
    const PENDING: &str = r##"(() => {
      for (const e of document.querySelectorAll('[aria-busy="true"],[role="progressbar"],progress,[class*="spinner" i],[class*="loading" i],[class*="loader" i]')) if (e.offsetParent !== null) return true;
      return /\b(saving|loading|processing|submitting|uploading|please wait)\b/i.test(((document.body&&document.body.innerText)||''));
    })()"##;
    // Click the first visible, enabled, constructive-action control via its own handler.
    const CLICK: &str = r##"(() => {
      const RE = /^(add|create|save|apply|update|publish|post|insert|new|upload|send|submit|confirm|generate|invite)\b/i;
      for (const el of document.querySelectorAll('button, [role="button"], input[type="submit"], input[type="button"]')) {
        const r = el.getBoundingClientRect();
        if (el.disabled || el.getAttribute('aria-disabled') === 'true' || r.width < 8 || r.height < 8 || el.offsetParent === null) continue;
        const label = ((el.getAttribute('aria-label') || '') + ' ' + (el.tagName === 'INPUT' ? (el.value || '') : (el.textContent || ''))).replace(/\s+/g, ' ').trim();
        if (!RE.test(label)) continue;
        el.click();
        return label.slice(0, 40);
      }
      return '';
    })()"##;
    let eval_json = |js: &str| -> Value {
        tab.evaluate(js, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
            .unwrap_or(Value::Null)
    };
    let eval_bool = |js: &str| -> bool {
        tab.evaluate(js, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let before = eval_json(STATE);
    if before.is_null() {
        return json!({ "probed": false });
    }
    let url_before = tab.get_url();
    let label = tab
        .evaluate(CLICK, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();
    if label.is_empty() {
        return json!({ "probed": false });
    }
    let (bt, btoast, belems) = (
        before["t"].as_f64().unwrap_or(0.0),
        before["toasts"].as_f64().unwrap_or(0.0),
        before["elems"].as_f64().unwrap_or(0.0),
    );
    let mut pending_seen = false;
    let mut feedback_seen = false;
    let mut delay = 0i64;
    for i in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(150));
        if !pending_seen && eval_bool(PENDING) {
            pending_seen = true;
        }
        let now = eval_json(STATE);
        let (nt, ntoast, nelems) = (
            now["t"].as_f64().unwrap_or(bt),
            now["toasts"].as_f64().unwrap_or(btoast),
            now["elems"].as_f64().unwrap_or(belems),
        );
        let changed = ntoast > btoast
            || (nt - bt).abs() >= 20.0
            || (nelems - belems).abs() >= 1.0
            || tab.get_url() != url_before;
        if changed {
            feedback_seen = true;
            delay = (i + 1) * 150;
            break;
        }
    }
    let navigated = tab.get_url() != url_before;
    if navigated {
        let _ = tab.navigate_to(&url_before);
        let _ = tab.wait_until_navigated();
    }
    let _ = base_url;
    json!({
        "probed": true,
        "label": label,
        "feedbackSeen": feedback_seen,
        "pendingSeen": pending_seen,
        "feedbackDelayMs": delay,
        "navigated": navigated,
    })
}

/// Tiny anchored case-insensitive prefix matcher (avoids a regex dependency).
pub(crate) fn regex_lite(pattern: &str) -> impl Fn(&str) -> bool + '_ {
    let words: Vec<&str> = pattern
        .trim_start_matches("(?i)^(")
        .trim_end_matches(')')
        .split('|')
        .collect();
    move |s: &str| {
        let l = s.to_lowercase();
        words.iter().any(|w| {
            let w = w.replace("log ?out", "logout");
            l.starts_with(&w)
                || (w == "logout" && (l.starts_with("logout") || l.starts_with("log out")))
        })
    }
}
