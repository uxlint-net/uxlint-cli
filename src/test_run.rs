//! Judge-driven navigation: run a test on any site, post the trail as a flow
//! report. Shared by the `test` command and the audit test checks.

use crate::progress::{note, Progress};
use anyhow::{Context, Result};
use headless_chrome::{Browser, LaunchOptions};
use serde_json::{json, Value};
use std::io::IsTerminal;

use crate::project::{base_host, login_url, project_config, project_personas};
use crate::worker::{base_chrome_flags, missing_browser_message};
use crate::{Cli, RunTestArgs};

/// Hop budgets for a test run — each hop is one billed judge call (metered against the org's pooled
/// AI budget). Two defaults, because the two callers want different depth:
///
/// - `DEFAULT_WALK_HOPS` — the standalone `uxlint test` command: the deliberate "really test
///   this flow" tool. Budgeted for a genuine multi-step journey (navigate → fill → submit →
///   navigate → act → confirm), with room for a short compound goal when both steps are quick and
///   on one surface (e.g. "invite a teammate, then remove them"). `--hops` overrides it upward for a
///   longer flow.
/// - `AUDIT_PROBE_HOPS` — a test run inside a full `uxlint audit`, which fans one walk out per
///   declared test (and per viewport). Kept shallow to bound the total judge calls: a "can a user
///   reach and do this" probe with slack for one wrong turn, not a long scripted flow. Declare
///   genuinely long or multi-stage goals and exercise them with the standalone command instead.
pub(crate) const DEFAULT_WALK_HOPS: usize = 10;
pub(crate) const AUDIT_PROBE_HOPS: usize = 6;

/// WAIT re-observe tuning. When the judge returns WAIT (the goal's result is still resolving on this
/// page), the walk re-harvests the SAME page every `WAIT_POLL_MS` for up to `WAIT_MAX_POLLS` polls,
/// stopping the moment the page's actionable state changes — a local, UNBILLED watch, so another
/// judge call is only spent once there's something new to judge. `MAX_CONSECUTIVE_WAITS` bounds how
/// many wait windows in a row we tolerate with no change before calling the flow lost, so a result
/// that never arrives can never hang the walk.
const WAIT_POLL_MS: u64 = 1500;
const WAIT_MAX_POLLS: usize = 30; // ~45s of watching per WAIT — covers a measured single-page hosted audit (~34s) in one window
const MAX_CONSECUTIVE_WAITS: usize = 3; // ~135s total patience before giving up

// ── `uxlint test` with no/declared test selector: list, pick, or resolve one ───────────
//
// `uxlint test` takes the goal as a plain positional argument, so a task the project already
// declares in `[[tests]]` (or on the server) needs no hand-typed `--goal`/`--expect` pair: omit the
// argument entirely to list the declared set (interactively
// on a tty, else a plain numbered list + hint); `test <n-or-name>` resolves against that
// same set and inherits its expect/audience/viewport, so testing one declared test is a single
// short command. Free text that matches nothing declared still runs exactly as before — an
// ad-hoc walk.

/// One entry in the declared-goal set — the SAME merge the audit walks
/// (`crate::audit::merged_tests`): uxlint.toml `[[tests]]` plus the site's server-declared tests.
struct DeclaredTest {
    test: String,
    expect: String,
    importance: String,
    persona: String,
    viewport: String,
}

impl DeclaredTest {
    fn from_value(v: &Value) -> Self {
        DeclaredTest {
            test: v["test"].as_str().unwrap_or_default().to_string(),
            expect: v["expect"].as_str().unwrap_or_default().to_string(),
            importance: v["importance"].as_str().unwrap_or("important").to_string(),
            persona: v["persona"].as_str().unwrap_or_default().to_string(),
            viewport: v["viewport"].as_str().unwrap_or_default().to_string(),
        }
    }

    /// One line for the numbered list / interactive picker, e.g.
    /// ` 3. invite a teammate to your org  [important · user · desktop]`.
    fn label(&self, i: usize) -> String {
        let mut tags = vec![self.importance.as_str()];
        if !self.persona.is_empty() {
            tags.push(&self.persona);
        }
        if !self.viewport.is_empty() {
            tags.push(&self.viewport);
        }
        format!("{:>2}. {}  [{}]", i + 1, self.test, tags.join(" · "))
    }
}

/// The host whose declared tests apply: --site (or UXLINT_SITE) → uxlint.toml's `site` → the
/// --base URL's own host. Same precedence an audit uses to pick a site (`audit::run_audit`);
/// `crate::audit::merged_tests` does the actual fetch, this only picks which host to ask it for.
fn goals_host(site: Option<&str>, base: &str) -> String {
    site.map(str::to_string)
        .or_else(|| project_config().map(|p| p.site))
        .unwrap_or_else(|| base_host(base))
}

/// Resolve the goal argument against the declared set: a 1-based list index, or an exact
/// (case-insensitive, trimmed) name match. `None` means it's free text for an ad-hoc walk — the
/// long-standing behavior. Pure so the addressing rules are unit-testable.
fn resolve_declared(text: &str, declared: &[DeclaredTest]) -> Option<usize> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(n) = text.parse::<usize>() {
        if n >= 1 && n <= declared.len() {
            return Some(n - 1);
        }
    }
    declared
        .iter()
        .position(|g| g.test.trim().eq_ignore_ascii_case(text))
}

/// "mobile" walks the phone viewport; a declared "both"/"all" (a fan-out for the FULL audit) or
/// anything else walks desktop for this single-goal command — there's only one walk to run, so
/// desktop (the more common default) wins; mention the other explicitly via `--viewport mobile`.
fn normalize_viewport(v: &str) -> &'static str {
    if v.eq_ignore_ascii_case("mobile") {
        "mobile"
    } else {
        "desktop"
    }
}

/// Sign the walk in as a declared test's `persona`, if it names one: empty/"anonymous" walks as a
/// logged-out visitor (no login, unchanged from today's ad-hoc default). A name matching
/// `[personas.<name>]` in uxlint.toml signs in at the project's `login_url` using THAT persona's
/// credentials before pursuing the goal — mirroring how the audit walks a persona task. Errors
/// clearly when a persona is named but unresolvable: a silent anonymous fallback there would test
/// the wrong persona and misreport the outcome as if a visitor, not the persona, got lost.
fn login_for_persona(persona: &str) -> Result<Option<(String, String, String)>> {
    if persona.trim().is_empty() || persona.eq_ignore_ascii_case("anonymous") {
        return Ok(None);
    }
    let personas = project_personas();
    let Some(p) = personas.iter().find(|p| p.name == persona) else {
        anyhow::bail!(
            "this goal's persona is {persona:?}, but uxlint.toml has no [personas.{persona}] — declare its username/password there, or walk it as an ad-hoc goal instead"
        );
    };
    if !p.is_form() {
        anyhow::bail!(
            "this goal's persona is {persona:?}, which is a session persona (headers/storage); `uxlint test` signs in via a form — give it a username/password, or run a full audit"
        );
    }
    let Some(url) = login_url() else {
        anyhow::bail!(
            "this goal's persona is {persona:?} (a form login), but uxlint.toml has no login_url to sign in through"
        );
    };
    Ok(Some((url, p.username.clone(), p.password.clone())))
}

/// Lines printed when nothing is declared at all — never blocks; points at how to declare or run
/// ad-hoc. Pure so the render is unit-testable.
fn empty_listing() -> Vec<String> {
    vec![
        "no declared tests for this site — nothing to list.".to_string(),
        "  declare some in uxlint.toml [[tests]] (or PUT them on the server), or run one ad-hoc:".to_string(),
        "  uxlint test --base <url> \"<what a user is trying to do>\"  (optionally --expect <a word on the destination> as a hint)".to_string(),
    ]
}

/// Lines printed for a non-interactive (non-tty) declared-goal listing: the numbered set plus a
/// hint on picking one by number or name next time. Pure so the render is unit-testable without a
/// terminal.
fn non_tty_listing(declared: &[DeclaredTest]) -> Vec<String> {
    let mut lines = vec![format!("{} declared test(s):", declared.len())];
    lines.extend(
        declared
            .iter()
            .enumerate()
            .map(|(i, g)| format!("  {}", g.label(i))),
    );
    lines.push(String::new());
    lines.push("run again with the test's number or name to run it, e.g.:".to_string());
    if let Some(first) = declared.first() {
        lines.push(format!("  uxlint test --base <url> 1   # {}", first.test));
    }
    lines
}

/// No goal argument: an interactive tty gets `inquire::Select` (init's style); a script/CI gets the
/// plain list + hint and is never blocked. Returns the chosen index, or `None` when there was
/// nothing to walk (already reported to `progress`).
fn pick_declared_test(declared: &[DeclaredTest], progress: &dyn Progress) -> Result<Option<usize>> {
    if declared.is_empty() {
        for line in empty_listing() {
            note!(progress, "{line}");
        }
        return Ok(None);
    }
    if std::io::stdin().is_terminal() {
        let labels: Vec<String> = declared
            .iter()
            .enumerate()
            .map(|(i, g)| g.label(i))
            .collect();
        let picked =
            inquire::Select::new("Which declared test to run?", labels.clone()).prompt()?;
        return Ok(labels.iter().position(|l| *l == picked));
    }
    for line in non_tty_listing(declared) {
        note!(progress, "{line}");
    }
    Ok(None)
}

/// Turn the raw CLI args into a concrete walk. The goal argument naming a declared test (by index or name)
/// inherits its expect/audience/viewport, so testing one is a single short command; free text
/// walks exactly as before (ad-hoc); omitting it entirely lists/picks (see `pick_declared_test`) and
/// returns `None` — nothing to walk yet, already reported.
fn resolve_run_test_args(
    cli: &Cli,
    args: &RunTestArgs,
    progress: &dyn Progress,
) -> Result<Option<RunTestArgs>> {
    let text = args.test.trim();
    let text = if text.eq_ignore_ascii_case("list") {
        ""
    } else {
        text
    };
    let host = goals_host(args.site.as_deref(), &args.base);
    let declared: Vec<DeclaredTest> = crate::audit::merged_tests(cli, &host)
        .iter()
        .map(DeclaredTest::from_value)
        .collect();

    let idx = if text.is_empty() {
        match pick_declared_test(&declared, progress)? {
            Some(i) => i,
            None => return Ok(None),
        }
    } else {
        match resolve_declared(text, &declared) {
            Some(i) => i,
            None => return Ok(Some(args.clone())), // free text that matched nothing declared — ad-hoc
        }
    };

    let g = &declared[idx];
    note!(
        progress,
        "{}",
        crate::style::Stream::Err.dim(&format!(
            "  declared test {}/{}: \"{}\"",
            idx + 1,
            declared.len(),
            g.test
        ))
    );
    let mut resolved = args.clone();
    resolved.test = g.test.clone();
    resolved.expect = if g.expect.is_empty() {
        args.expect.clone()
    } else {
        Some(g.expect.clone())
    };
    resolved.viewport = normalize_viewport(&g.viewport).to_string();
    resolved.login = login_for_persona(&g.persona)?;
    Ok(Some(resolved))
}

// ── test run: the server's judge decides, this client acts ────────────────────
// The harvest emits the current page as a STRUCTURED GRAPH NODE (GRAPH.md), NOT a full-page text
// dump: its route-role (A1), its collections {count, linksToDetail, hasCreate} (A2), a bounded set
// of key STATE SIGNALS (headings as short labels, an open dialog's heading, status/confirmation
// regions), plus the structured controls / form-fields it already collects. The server judge decides
// done-vs-next from THAT graph node + the site-map neighbors (read page STATE, no hardcoded
// phrases). "Judgment quality scales with graph context, not model size." Data-safety: every emitted
// label runs through the shared redaction patterns (assets/redact.js, spliced in at build time), and
// every field is length-capped and count-bounded — no secrets, no unbounded prose. Audits target
// TEST accounts. The redaction snippet is THE single source of truth (see redact.rs); this channel
// aliases the shared `uxlintRedact` to `redact`, so it cannot drift from the others.

/// The test-run harvest, with the shared redaction snippet interpolated. Emits the current page as
/// a structured graph node (see `HARVEST_TEMPLATE`). Built once, injected on every hop.
pub(crate) fn harvest_js() -> &'static str {
    static CELL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CELL.get_or_init(|| crate::redact::splice_redact(HARVEST_TEMPLATE))
}
const HARVEST_TEMPLATE: &str = r##"(() => {
  /*__UXLINT_REDACT__*/
  const redact = uxlintRedact;
  // `clean` = whitespace-normalize PLUS secret/email redaction. EVERYTHING that egresses to the
  // server + the LLM judge is `clean`ed — including control labels and form-field labels/options,
  // which double as the click/fill match-key. Redacting them here would normally break matching
  // (the judge picks the redacted label, but the DOM element carries the RAW one), so
  // `click_by_label`/`fill_fields` are made redaction-AWARE: they run each DOM candidate's label
  // through the same `uxlintRedact` before the compare, so a redacted pick (e.g. an "Account —
  // [email]" switcher whose real label held a user's email) still resolves to the right element.
  // `norm` = whitespace-normalize only, kept for internal DOM-role heuristics that never egress.
  const norm = (t) => (t || '').replace(/\s+/g, ' ').trim();
  const clean = (t) => redact(norm(t));
  const vis = (el) => { const r = el.getBoundingClientRect(); return r.width >= 6 && r.height >= 6 && el.offsetParent !== null; };
  const seen = new Set(); const controls = [];
  for (const el of document.querySelectorAll('a, button, [role="button"], summary')) {
    if (el.closest('[aria-hidden="true"]') || el.getAttribute('aria-current') !== null) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 6 || r.height < 6 || el.disabled === true) continue;
    const label = clean(el.getAttribute('aria-label') || el.getAttribute('title') || el.textContent || '').slice(0, 60);
    if (!label || seen.has(label.toLowerCase())) continue;
    seen.add(label.toLowerCase());
    controls.push(label);
    if (controls.length >= 40) break;
  }
  const hints = [];
  for (const p of document.querySelectorAll('main p')) {
    const t = clean(p.textContent || '');
    if (t.length >= 20 && t.length <= 160) hints.push(t);
    if (hints.length >= 3) break;
  }
  // Visible headings as SHORT STATE LABELS (not prose) — the strongest cue of what state a page is
  // in (a "You're on Pro" success heading, a "Your tokens" list, a confirmation-dialog title).
  const root = document.querySelector('main') || document.body;
  const headings = []; const hseen = new Set();
  for (const h of root.querySelectorAll('h1, h2, h3, [role="heading"]')) {
    if (!vis(h)) continue;
    const t = clean(h.textContent || '').slice(0, 80);
    if (!t || hseen.has(t.toLowerCase())) continue;
    hseen.add(t.toLowerCase());
    headings.push(t);
    if (headings.length >= 8) break;
  }
  // Route-role typing (GRAPH.md A1), deterministic from URL shape (+ collection presence below).
  const path = location.pathname.toLowerCase();
  const segs = path.split('/').filter(Boolean);
  let role = 'content';
  if (path === '/' || path === '') role = 'home';
  else if (/login|signin|sign-in|signup|sign-up|register|(^|\/)auth|cli-login|logout/.test(path)) role = 'auth';
  else if (/settings|account|preferences|admin|billing|checkout|subscribe/.test(path)) role = 'settings';
  else if (/(^|\/)(new|create)(\/|$)/.test(path)) role = 'create';
  else if (segs.length >= 2 && /^([0-9]+|[0-9a-f]{6,}|[a-z0-9]+(-[a-z0-9]+)+)$/.test(segs[segs.length - 1])) role = 'detail';
  // Collections (GRAPH.md A2): the largest group of same-structure visible siblings that link out.
  // Scope to MAIN content and skip chrome (nav/aside/header/footer) so a docs sidebar or site nav
  // isn't mistaken for an app-managed collection (which would mis-role the page as an index).
  let coll = null;
  for (const c of root.querySelectorAll('ul, ol, tbody, [role="list"], [role="table"]')) {
    if (c.closest('nav, aside, header, footer, [role="navigation"]')) continue;
    const items = Array.from(c.children).filter(vis);
    if (items.length < 2) continue;
    const linked = items.filter(it => it.querySelector('a[href]')).length;
    if (!coll || items.length > coll.count) {
      const hrefs = items.map(it => { const a = it.querySelector('a[href]'); try { return a ? new URL(a.href).pathname : ''; } catch (e) { return ''; } });
      const linksToDetail = hrefs.some(h => h && h.split('/').filter(Boolean).length >= 2);
      coll = { count: items.length, linked, linksToDetail };
    }
  }
  const hasCreate = [...document.querySelectorAll('a, button, [role="button"]')].some(el => vis(el) && /^(\+|＋|new\b|add\b|create\b|invite\b|start\b)/i.test(clean(el.getAttribute('aria-label') || el.textContent || '')));
  const collections = coll && coll.linked >= 1 ? [{ count: coll.count, linksToDetail: coll.linksToDetail, hasCreate }] : [];
  if (role === 'content' && collections.length && collections[0].linksToDetail) role = 'index';
  // An open dialog / modal is a strong state signal (a confirmation, a success "You're on Pro").
  const dlg = [...document.querySelectorAll('[role="dialog"], [aria-modal="true"], dialog')].find(vis);
  const dialog = dlg ? { open: true, heading: clean((dlg.querySelector('h1,h2,h3,[role="heading"]') || {}).textContent || '').slice(0, 80) } : { open: false };
  // Live status / alert / confirmation regions — short labels, not prose.
  const status = [...document.querySelectorAll('[role="status"], [role="alert"], [aria-live]:not([aria-live="off"])')]
    .filter(vis).map(e => clean(e.textContent || '').slice(0, 80)).filter(Boolean).slice(0, 3);
  // Fillable form fields the user could type into (structured — for create-style goals + as the
  // "this IS where the goal is performed" signal).
  const fields = [];
  for (const el of document.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=checkbox]):not([type=radio]), textarea, select')) {
    if (!vis(el) || el.disabled) continue;
    let label = el.getAttribute('aria-label') || '';
    if (!label && el.id) { const l = document.querySelector('label[for="' + (window.CSS && CSS.escape ? CSS.escape(el.id) : el.id) + '"]'); if (l) label = l.textContent; }
    if (!label) { const l = el.closest('label'); if (l) label = l.textContent; }
    if (!label) label = el.getAttribute('placeholder') || el.getAttribute('name') || '';
    label = clean(label || '').slice(0, 40);
    if (!label) continue;
    const type = el.tagName === 'SELECT' ? 'select' : (el.tagName === 'TEXTAREA' ? 'textarea' : (el.getAttribute('type') || 'text'));
    const opts = el.tagName === 'SELECT' ? Array.from(el.options).map(o => clean(o.textContent || '')).filter(Boolean).slice(0, 8) : undefined;
    fields.push(opts ? { label, type, options: opts } : { label, type });
    if (fields.length >= 15) break;
  }
  const h1 = document.querySelector('main h1, h1');
  return JSON.stringify({ title: h1 ? clean(h1.textContent).slice(0, 60) : clean(document.title).slice(0, 60), route: location.pathname.slice(0, 80), role, controls, hints, headings, collections, dialog, status, fields });
})()"##;

/// Redaction-aware click matcher. `__LABEL__` is replaced with the JSON-encoded picked label; the
/// shared `/*__UXLINT_REDACT__*/` snippet is spliced in so each DOM candidate's label is run through
/// the SAME `uxlintRedact` (then `.slice(0,60)`) the harvest used — a redacted egress label still
/// resolves to its element.
const CLICK_BY_LABEL_TEMPLATE: &str = r##"(() => {
  /*__UXLINT_REDACT__*/
  const want = __LABEL__.toLowerCase();
  for (const el of document.querySelectorAll('a, button, [role="button"], summary')) {
    const raw = (el.getAttribute('aria-label') || el.getAttribute('title') || el.textContent || '').replace(/\s+/g, ' ').trim();
    const lab = uxlintRedact(raw).slice(0, 60);
    if (lab.toLowerCase() === want) {
      el.scrollIntoView({block: 'center'});
      const r = el.getBoundingClientRect();
      return JSON.stringify({x: r.x + r.width/2, y: r.y + r.height/2});
    }
  }
  return null;
})()"##;

pub(crate) fn click_by_label(tab: &headless_chrome::Tab, label: &str) -> bool {
    // The harvested control label the judge picked is REDACTED (see HARVEST_TEMPLATE `clean`), so the
    // match must compare against each DOM candidate's label run through the SAME `uxlintRedact` — a
    // switcher whose real label held "user@x" was uploaded as "[email]" and must still resolve here.
    // `redact(norm(raw)).slice(0,60)` mirrors the harvest's `clean(raw).slice(0,60)` byte-for-byte.
    let js = crate::redact::splice_redact(CLICK_BY_LABEL_TEMPLATE).replace(
        "__LABEL__",
        &serde_json::to_string(label).unwrap_or_else(|_| "\"\"".into()),
    );
    let pt = tab
        .evaluate(&js, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| {
            v.as_str()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
        });
    let Some(pt) = pt else { return false };
    tab.click_point(headless_chrome::browser::tab::point::Point {
        x: pt["x"].as_f64().unwrap_or(0.0),
        y: pt["y"].as_f64().unwrap_or(0.0),
    })
    .is_ok()
}

/// Redaction-aware fill matcher. `__PAYLOAD__` is replaced with the JSON `[{field,value}]`; the
/// shared `/*__UXLINT_REDACT__*/` snippet is spliced in so each DOM candidate's label AND each
/// `<select>` option is run through the SAME `uxlintRedact` the harvest used before comparing —
/// `labelKey` mirrors the harvest's `clean(label).slice(0,40)`, `optKey` mirrors `clean(option)` —
/// so a field/option the judge picked by its REDACTED egress label still resolves to its element.
const FILL_FIELDS_TEMPLATE: &str = r##"(() => {
  /*__UXLINT_REDACT__*/
  const want = __PAYLOAD__;
  const red = uxlintRedact;
  const wsnorm = s => (s || '').replace(/\s+/g, ' ').trim();
  const norm = s => wsnorm(s).toLowerCase();
  const labelKey = s => red(wsnorm(s)).slice(0, 40).toLowerCase();
  const optKey = s => red(wsnorm(s)).toLowerCase();
  const rawLabelOf = (el) => {
    let label = el.getAttribute('aria-label') || '';
    if (!label && el.id) { const l = document.querySelector('label[for="' + (window.CSS && CSS.escape ? CSS.escape(el.id) : el.id) + '"]'); if (l) label = l.textContent; }
    if (!label) { const l = el.closest('label'); if (l) label = l.textContent; }
    if (!label) label = el.getAttribute('placeholder') || el.getAttribute('name') || '';
    return label;
  };
  const els = Array.from(document.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=checkbox]):not([type=radio]), textarea, select'));
  let filled = 0;
  for (const w of want) {
    const target = norm(w.field);
    if (!target) continue;
    const el = els.find(e => { const r = e.getBoundingClientRect(); const lab = labelKey(rawLabelOf(e)); return r.width >= 6 && e.offsetParent !== null && (lab === target || lab.includes(target) || target.includes(lab)); });
    if (!el) continue;
    try {
      el.focus();
      if (el.tagName === 'SELECT') {
        const wv = norm(w.value);
        const opt = Array.from(el.options).find(o => optKey(o.textContent) === wv || optKey(o.textContent).includes(wv));
        if (opt) el.value = opt.value;
      } else {
        el.value = w.value;
      }
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      el.blur();
      filled++;
    } catch (_) {}
  }
  return filled;
})()"##;

/// Fill form fields the judge chose, by matching each value to a field's label. Returns how many
/// were filled. Types the value and fires input/change so framework state updates.
pub(crate) fn fill_fields(tab: &headless_chrome::Tab, values: &[(String, String)]) -> usize {
    let payload = serde_json::to_string(
        &values
            .iter()
            .map(|(f, v)| json!({"field": f, "value": v}))
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".into());
    let js = crate::redact::splice_redact(&FILL_FIELDS_TEMPLATE.replace("__PAYLOAD__", &payload));
    tab.evaluate(&js, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0) as usize
}

/// Best-effort cleanup after a create: click the first delete/remove/undo/discard control and
/// confirm through any dialog, so the walk leaves the site as it found it. Returns true if it
/// clicked something.
pub(crate) fn cleanup_created(tab: &headless_chrome::Tab) -> bool {
    let clicked = tab
        .evaluate(
            r##"(() => {
  for (const el of document.querySelectorAll('button, [role="button"], a')) {
    const r = el.getBoundingClientRect();
    if (r.width < 6 || r.height < 6 || el.offsetParent === null) continue;
    const lab = ((el.getAttribute('aria-label') || '') + ' ' + (el.textContent || '')).replace(/\s+/g, ' ').trim();
    if (/^(delete|remove|discard|undo|trash|archive)\b/i.test(lab)) { el.click(); return true; }
  }
  return false;
})()"##,
            false,
        )
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !clicked {
        return false;
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    let _ = tab.evaluate(
        r##"(() => { for (const el of document.querySelectorAll('[role="dialog"] button, [aria-modal="true"] button, dialog button')) { if (/(delete|remove|confirm|yes|discard)/i.test(el.textContent || '')) { el.click(); return true; } } return false; })()"##,
        false,
    );
    true
}

pub(crate) fn run_test_command(
    cli: &Cli,
    args: &RunTestArgs,
    progress: &dyn Progress,
) -> Result<()> {
    let Some(resolved) = resolve_run_test_args(cli, args, progress)? else {
        return Ok(()); // no goal argument: listed/picked-from-nothing above, already reported
    };
    // The standalone command posts a flow report, not a lint report, so the captured page snapshots
    // aren't used here — they feed the audit path (`run_tests`).
    let (success, hops, flow_url, lost_reason, _walk_pages) = run_test(cli, &resolved, progress)?;
    if let Some(url) = &flow_url {
        note!(
            progress,
            "{}",
            crate::style::Stream::Err.dim(&format!("  flow report: {url}"))
        );
    }
    if success {
        note!(
            progress,
            "  {}",
            crate::style::Stream::Err.green(&format!("✓ goal reached in {hops} hops"))
        );
        Ok(())
    } else {
        note!(
            progress,
            "  {}",
            crate::style::Stream::Err.red(&format!(
                "✖ goal not reached within {} hops — the flow report shows where a user gets lost",
                resolved.hops
            ))
        );
        // Say WHY it gave up right here, not only in the flow report — the reason the test user
        // stopped is the most useful line of the run.
        if let Some(reason) = lost_reason {
            note!(
                progress,
                "  {}",
                crate::style::Stream::Err.dim(&format!("why: {reason}"))
            );
        }
        std::process::exit(1);
    }
}

/// One uninstructed walk toward a goal: (success, hops used, flow-report URL).
/// Login-form fill (phase 1): locate the username/email field (and password, if the form has one)
/// and set them firing input/change so reactive frameworks commit the bound state. Submitting is a
/// SEPARATE step (SUBMIT_JS) after a short wait — a framework often keeps the submit button disabled
/// until it has processed the input event, so clicking in the same tick does nothing.
pub(crate) const FILL_JS: &str = r#"(() => {
  const email = __EMAIL__, pw = __PW__;
  const q = s => document.querySelector(s);
  const e = q('input[type=email]') || q('input[autocomplete=username]') || q('input[name*="email" i]')
         || q('input[name*="user" i]') || q('input[id*="email" i]') || q('input[type=text]');
  const p = q('input[type=password]');
  if (!e) return 'no-username-field';
  const set = (el, v) => { el.focus(); el.value = v;
    el.dispatchEvent(new Event('input', {bubbles:true})); el.dispatchEvent(new Event('change', {bubbles:true})); };
  set(e, email);
  if (p && pw) set(p, pw);
  return 'filled';
})()"#;

/// Login-form submit (phase 2): click the (now-enabled) login button, else submit the form.
pub(crate) const SUBMIT_JS: &str = r#"(() => {
  const p = document.querySelector('input[type=password]');
  const e = document.querySelector('input[autocomplete=username], input[type=email], input[type=text]');
  const form = (p && p.form) || (e && e.form);
  const btn = [...document.querySelectorAll('button[type=submit], input[type=submit], button')]
    .find(b => !b.disabled && /log ?in|sign ?in|continue|submit|next/i.test(b.textContent || b.value || ''));
  if (btn) { btn.click(); return 'clicked'; }
  if (form && form.requestSubmit) { form.requestSubmit(); return 'requestSubmit'; }
  if (form) { form.submit(); return 'submit'; }
  return 'no-submit';
})()"#;

/// A structural fingerprint of a harvested page, used during a WAIT to detect that the pending
/// result has RESOLVED. It keeps the parts the judge would ACT on — route, title, headings,
/// collection sizes, dialog, controls, fields — plus the status text with digits stripped (so a
/// live "running 3s → 5s" counter doesn't read as a change), and drops the rest. So the walk
/// re-consults (and re-bills) the judge only when something actionable actually changed.
fn wait_fingerprint(view: &Value) -> String {
    let field = |k: &str| view.get(k).cloned().unwrap_or(Value::Null).to_string();
    let strip_digits = |s: String| {
        s.chars()
            .filter(|c| !c.is_ascii_digit())
            .collect::<String>()
    };
    format!(
        "route={}|title={}|headings={}|collections={}|dialog={}|controls={}|fields={}|status={}",
        field("route"),
        field("title"),
        field("headings"),
        field("collections"),
        field("dialog"),
        field("controls"),
        field("fields"),
        strip_digits(field("status")),
    )
}

/// Capture a full collector snapshot of the tab's CURRENT state as a lint-ready page — but only the
/// first time this walk lands on a given route, so repeated hops on one page don't pile up and the
/// heavy collector runs at most once per distinct state. These are the interaction-reached views
/// (post-click / post-submit redirects, JS-navigated pages) the link-crawl never sees; the audit
/// dedups them against the crawl before the deterministic lints run on them. Best-effort: any failure
/// just skips this state, and a hard cap stops a pathological walk from flooding the report.
fn capture_walk_state(
    tab: &headless_chrome::Tab,
    vp: &str,
    seen: &mut std::collections::HashSet<String>,
    out: &mut Vec<Value>,
) {
    if out.len() >= 8 {
        return;
    }
    let route = tab
        .evaluate("location.pathname", false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    // A real page path only: `about:blank` (pathname "blank") and data:/chrome: transitions a "lost"
    // hop can land on aren't pages to lint. Dedup so repeated hops on one route capture it once.
    if !route.starts_with('/') || !seen.insert(route.clone()) {
        return;
    }
    let Ok(res) = tab.evaluate(crate::redact::collector_js(), false) else {
        return;
    };
    let Some(Value::String(snap_json)) = res.value else {
        return;
    };
    if let Ok(snapshot) = serde_json::from_str::<Value>(&snap_json) {
        out.push(json!({ "route": route, "viewport": vp, "snapshot": snapshot }));
    }
}

/// Wait for a client-rendered login form to actually appear before filling it. An SPA login derives
/// its form AFTER navigation (a `/v1/auth/methods` fetch, then a render), so a fixed settle can fire
/// the fill before the fields exist — the "no-username-field" flake that leaves an authed walk unable
/// to sign in. Polls up to ~5s for a username/email or password input, then returns (the caller fills
/// regardless — a login with no detectable fields is a real "couldn't sign in", not a timeout).
pub(crate) fn wait_for_login_form(tab: &headless_chrome::Tab) {
    const SEL: &str =
        "input[type=email],input[autocomplete=username],input[name*='email' i],input[name*='user' i],input[type=password]";
    for _ in 0..25 {
        let ready = tab
            .evaluate(&format!("!!document.querySelector({SEL:?})"), false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if ready {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// One walk's result: `(reached, hops used, flow-report URL, give-up reason on a lost walk, the
/// novel-state page captures for the audit's deterministic lints)`. The give-up reason is what the
/// test user looked for and couldn't find — surfaced in the flow report and the test-lost finding.
pub(crate) type WalkResult = (bool, usize, Option<String>, Option<String>, Vec<Value>);

pub(crate) fn run_test(
    cli: &Cli,
    args: &RunTestArgs,
    progress: &dyn Progress,
) -> Result<WalkResult> {
    let http = reqwest::blocking::Client::new();
    // A fresh Chrome can fail to launch under load — the audit's worker-pool browsers may still be
    // winding down when the tests start. Without a retry that flake silently drops the whole
    // signed-in walk (the goal then reads as unreachable). A couple of attempts makes it reliable.
    // Walk the goal at its declared viewport — a phone window for "mobile", desktop otherwise —
    // so a task is validated where it's actually expected to work.
    let window = if args.viewport.eq_ignore_ascii_case("mobile") {
        (390, 844)
    } else {
        (1440, 900)
    };
    let launch = || {
        Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .args(base_chrome_flags())
                .window_size(Some(window))
                .build()?,
        )
    };
    let mut browser = launch();
    for attempt in 1..=2u64 {
        if browser.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500 * attempt));
        browser = launch();
    }
    let browser = browser.with_context(missing_browser_message)?;
    let tab = browser.new_tab()?;
    crate::worker::hide_opted_out_chrome(&tab);
    // Tests now run concurrently (several browsers at once), so a single navigation can be
    // slower under that load than the library's ~20s default. Give each nav generous headroom so a
    // busy machine doesn't fail an otherwise-fine walk.
    tab.set_default_timeout(std::time::Duration::from_secs(35));
    if !args.headers.is_empty() {
        let mut hdrs = std::collections::HashMap::new();
        for hd in &args.headers {
            if let Some((k, v)) = hd.split_once(':') {
                hdrs.insert(k.trim(), v.trim());
            }
        }
        tab.set_extra_http_headers(hdrs)?;
    }
    if !args.storage.is_empty() {
        tab.navigate_to(&args.base)?;
        tab.wait_until_navigated()?;
        for kv in &args.storage {
            if let Some((k, v)) = kv.split_once('=') {
                tab.evaluate(&format!("localStorage.setItem({:?}, {:?})", k, v), false)?;
            }
        }
    }
    // Role login: drive the login form ourselves so the walk runs as a real user of that role.
    // The form-fill is best-effort and heuristic (fields vary across sites); on SPA logins the
    // submit is a fetch + client-side redirect, so we lean on a settle sleep rather than a nav event.
    if let Some((login_url, email, password)) = &args.login {
        // `[credentials.login] url` may be a bare path ("/login"); Chrome needs an absolute URL.
        // The full-audit path pre-joins it with the base, but the standalone `test` passes the
        // raw path — join it here so both callers navigate to a valid URL.
        let login_url = if login_url.starts_with("http") {
            login_url.clone()
        } else {
            format!("{}{}", args.base.trim_end_matches('/'), login_url)
        };
        tab.navigate_to(&login_url)?;
        tab.wait_until_navigated()?;
        std::thread::sleep(std::time::Duration::from_millis(300));
        wait_for_login_form(&tab); // SPA form renders after a fetch — don't fill an empty page
        let fill = FILL_JS
            .replace(
                "__EMAIL__",
                &serde_json::to_string(email).unwrap_or_else(|_| "\"\"".into()),
            )
            .replace(
                "__PW__",
                &serde_json::to_string(password).unwrap_or_else(|_| "\"\"".into()),
            );
        let filled = tab
            .evaluate(&fill, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(str::to_string));
        std::thread::sleep(std::time::Duration::from_millis(450)); // let the framework enable submit / commit bound state
        let submitted = tab
            .evaluate(SUBMIT_JS, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(str::to_string));
        // Don't wait_until_navigated: an SPA login is a fetch + client-side redirect that may fire no
        // nav event — a settle sleep covers both the round-trip and the post-auth redirect.
        std::thread::sleep(std::time::Duration::from_millis(1600));
        if filled.as_deref() == Some("no-username-field")
            || submitted.as_deref() == Some("no-submit")
        {
            note!(
                progress,
                "    (login form: fill={filled:?} submit={submitted:?})"
            );
        }
    } else {
        tab.navigate_to(&args.base)?;
        tab.wait_until_navigated()?;
        std::thread::sleep(std::time::Duration::from_millis(900));
    }

    let mut tried: Vec<String> = Vec::new();
    let mut trail: Vec<String> = Vec::new();
    let mut steps: Vec<Value> = Vec::new(); // structured trail → server flow report
    let mut lost_reason: Option<String> = None; // the judge's give-up reason on the last dead-end
    let mut did_fill = false; // whether a mutate walk actually submitted a form (drives cleanup on DONE)
    let mut waits = 0usize; // consecutive WAITs with no page change — bounded so a walk can't hang
                            // Full snapshots of the NOVEL states this walk lands on, for the deterministic lints (see
                            // `capture_walk_state`). Deduped by route within the walk; the audit dedups vs the crawl.
    let vp = if args.viewport.eq_ignore_ascii_case("mobile") {
        "mobile"
    } else {
        "desktop"
    };
    let mut seen_routes: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut walk_pages: Vec<Value> = Vec::new();
    for hop in 0..args.hops {
        // Per-walk hop position — shared by the single-goal `uxlint test` command and each
        // walk inside a multi-goal audit, so both get it for free.
        note!(
            progress,
            "{}",
            crate::style::Stream::Err.dim(&format!("    hop {}/{}", hop + 1, args.hops))
        );
        // One content-based judge call per hop. The server reads the CURRENT (post-action) page
        // STATE — headings + a bounded text snippet on top of the controls — and either declares the
        // goal already accomplished HERE (DONE), picks the next action (click/fill), or gives up. No
        // hardcoded phrase/verb/expect lists on this side any more: whether we've arrived is the
        // judge's content-based call, not a substring match.
        let view: Value = tab
            .evaluate(harvest_js(), false)?
            .value
            .and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
            .unwrap_or_default();
        // Lint-capture the landed state before deciding the next action.
        capture_walk_state(&tab, vp, &mut seen_routes, &mut walk_pages);
        let page = view["title"].as_str().unwrap_or("?").to_string();
        match request_step(cli, &http, args, &view, &tried)? {
            Step::Done(evidence) => {
                // The judge read the live page and says the goal is accomplished here. If this was a
                // mutate walk that created something, best-effort clean up before leaving.
                if did_fill && cleanup_created(&tab) {
                    note!(progress, "  (cleaned up the created item)");
                }
                if !trail.is_empty() {
                    note!(
                        progress,
                        "{}",
                        crate::style::Stream::Err.dim(&format!("    {}", trail.join("  ▸  ")))
                    );
                }
                if !evidence.is_empty() {
                    note!(
                        progress,
                        "{}",
                        crate::style::Stream::Err.dim(&format!("    done: {evidence}"))
                    );
                }
                let url = post_flow(cli, &http, args, "success", hop, &steps, None);
                return Ok((true, hop, url, None, std::mem::take(&mut walk_pages)));
            }
            Step::Budget => {
                // The org's pooled AI budget is spent — end cleanly, posting whatever partial
                // trail we have, rather than with an ambiguous error. The FIRST step of the NEXT walk
                // hits this same refusal up front, so a spent org never fails silently.
                note!(
                    progress,
                    "  {}",
                    crate::style::Stream::Err.yellow(&format!(
                        "AI budget exhausted — ending walk early ({} hop{} so far)",
                        hop,
                        if hop == 1 { "" } else { "s" }
                    ))
                );
                lost_reason =
                    Some("the AI-call budget ran out before the goal was reached".to_string());
                let url = post_flow(
                    cli,
                    &http,
                    args,
                    "lost",
                    hop,
                    &steps,
                    lost_reason.as_deref(),
                );
                return Ok((
                    false,
                    hop,
                    url,
                    lost_reason,
                    std::mem::take(&mut walk_pages),
                ));
            }
            Step::Click(label) => {
                waits = 0; // a real action — reset the consecutive-wait guard
                trail.push(format!("{page} → {label}"));
                steps.push(json!({"page": page, "action": label}));
                if !click_by_label(&tab, &label) {
                    note!(progress, "  ✖ could not click \"{label}\"");
                    lost_reason = Some(format!(
                        "tried to click \u{201c}{label}\u{201d} but the control didn't respond"
                    ));
                    let url = post_flow(
                        cli,
                        &http,
                        args,
                        "lost",
                        hop + 1,
                        &steps,
                        lost_reason.as_deref(),
                    );
                    return Ok((
                        false,
                        hop + 1,
                        url,
                        lost_reason,
                        std::mem::take(&mut walk_pages),
                    ));
                }
                tried.push(label);
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
            Step::Fill { values, submit } => {
                waits = 0; // a real action — reset the consecutive-wait guard
                           // Create-style goal: fill the form the judge chose and submit it. Whether it worked is
                           // judged by the NEXT hop's harvest (a confirmation / the created item now on the page),
                           // not by matching a success word here.
                let n = fill_fields(&tab, &values);
                trail.push(format!("{page} → filled {n} field(s) + submit"));
                steps.push(json!({"page": page, "action": format!("fill {n} fields and submit")}));
                if !submit.is_empty() {
                    click_by_label(&tab, &submit);
                } else {
                    let _ = tab.evaluate(
                        "(() => { const f = document.querySelector('form'); if (f && f.requestSubmit) f.requestSubmit(); else if (f) f.submit(); })()",
                        false,
                    );
                }
                did_fill = true;
                std::thread::sleep(std::time::Duration::from_millis(1200));
            }
            Step::Back { reason } => {
                let lost = tried.is_empty();
                let label = if lost { "(lost)" } else { "(back)" };
                trail.push(format!("{page} → {label}"));
                let mut st = json!({"page": page, "action": label});
                if !reason.is_empty() {
                    st["reason"] = json!(reason);
                    // Keep the latest give-up reason — whichever dead-end the walk ends on is the one
                    // the report leads with.
                    lost_reason = Some(reason.clone());
                    note!(
                        progress,
                        "{}",
                        crate::style::Stream::Err.dim(&format!("    stuck: {reason}"))
                    );
                }
                steps.push(st);
                if lost {
                    break;
                }
                // Go back, but KEEP the control that led into this dead end in `tried` — so the judge
                // explores a DIFFERENT branch next time instead of re-picking it. (Popping it here made
                // a judge that deterministically prefers one wrong control — e.g. the "Account — <email>"
                // user menu for a billing goal — loop forever: back → re-pick the same → lost → back …)
                let _ = tab.evaluate("history.back()", false);
                std::thread::sleep(std::time::Duration::from_millis(900));
            }
            Step::Wait { reason } => {
                // The judge says the goal's result is still being produced on THIS page (an async step
                // of a natural-language plan). Re-observe the SAME page locally — no navigation, no
                // judge call — until its actionable state changes, so the NEXT hop can act on the
                // result once it exists. Billing the judge only on change is the whole point: one WAIT
                // call, then a free local watch, then one more call when there's something new.
                trail.push(format!("{page} → wait ({reason})"));
                steps.push(json!({"page": page, "action": format!("wait for {reason}")}));
                note!(
                    progress,
                    "{}",
                    crate::style::Stream::Err.dim(&format!("    waiting for {reason}…"))
                );
                let before = wait_fingerprint(&view);
                let mut changed = false;
                for _ in 0..WAIT_MAX_POLLS {
                    std::thread::sleep(std::time::Duration::from_millis(WAIT_POLL_MS));
                    let now: Value = tab
                        .evaluate(harvest_js(), false)?
                        .value
                        .and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
                        .unwrap_or_default();
                    if wait_fingerprint(&now) != before {
                        changed = true;
                        break;
                    }
                }
                if changed {
                    waits = 0; // the page resolved — the next hop judges the new state
                } else {
                    // No change within one wait window. A few in a row is fine (a genuinely slow
                    // result), but never hang: after MAX_CONSECUTIVE_WAITS give up honestly.
                    waits += 1;
                    if waits >= MAX_CONSECUTIVE_WAITS {
                        note!(progress, "  ✖ gave up waiting for \"{reason}\" to resolve");
                        lost_reason = Some(format!(
                            "waited for \u{201c}{reason}\u{201d} to finish, but the page never changed"
                        ));
                        let url = post_flow(
                            cli,
                            &http,
                            args,
                            "lost",
                            hop + 1,
                            &steps,
                            lost_reason.as_deref(),
                        );
                        return Ok((
                            false,
                            hop + 1,
                            url,
                            lost_reason,
                            std::mem::take(&mut walk_pages),
                        ));
                    }
                }
            }
        }
    }
    // The action taken on the LAST hop is never judged inside the loop (there's no next hop to harvest
    // its result), so spend one final content-based judge call on where we landed — accepting only a
    // DONE. Budget-out or any non-DONE falls through to the honest `lost` report — no hops remain to
    // keep walking anyway.
    let view: Value = tab
        .evaluate(harvest_js(), false)?
        .value
        .and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
        .unwrap_or_default();
    if let Step::Done(evidence) = request_step(cli, &http, args, &view, &tried)? {
        if did_fill && cleanup_created(&tab) {
            note!(progress, "  (cleaned up the created item)");
        }
        note!(
            progress,
            "{}",
            crate::style::Stream::Err.dim(&format!("    {}", trail.join("  ▸  ")))
        );
        if !evidence.is_empty() {
            note!(
                progress,
                "{}",
                crate::style::Stream::Err.dim(&format!("    done: {evidence}"))
            );
        }
        let url = post_flow(cli, &http, args, "success", args.hops, &steps, None);
        return Ok((true, args.hops, url, None, std::mem::take(&mut walk_pages)));
    }
    note!(
        progress,
        "{}",
        crate::style::Stream::Err.dim(&format!("    {}", trail.join("  ▸  ")))
    );
    // Ran the hop budget out without ever reaching the goal (and without a mid-walk give-up that set
    // a reason) — say exactly that, so the report never just reports "lost" with no explanation.
    if lost_reason.is_none() {
        lost_reason = Some(format!(
            "kept navigating for all {} hops without reaching the goal",
            args.hops
        ));
    }
    let url = post_flow(
        cli,
        &http,
        args,
        "lost",
        args.hops,
        &steps,
        lost_reason.as_deref(),
    );
    Ok((false, args.hops, url, lost_reason, walk_pages))
}

/// The judge's decision for one hop, from reading the CURRENT page's live content.
pub(crate) enum Step {
    /// The goal is accomplished on THIS page — carries the judge's on-page evidence phrase.
    Done(String),
    /// Click this control to make progress (label copied from the harvested set).
    Click(String),
    /// Fill these `(field, value)` pairs and submit via `submit` (a mutate/create walk only).
    Fill {
        values: Vec<(String, String)>,
        submit: String,
    },
    /// Nothing here helps / give up — go back a page if we can, else the walk is lost. Carries the
    /// judge's reason (what it looked for and couldn't find), surfaced in the flow report and the
    /// audit's test-lost finding. Empty when the judge gave no reason.
    Back { reason: String },
    /// The goal's result is being produced on THIS page right now (a running job, a "preparing"
    /// status). Re-observe the same page until its state changes, rather than navigating away —
    /// this is what lets one natural-language goal span an async step (create → wait → act on it).
    Wait { reason: String },
    /// The billing org's pooled AI budget is exhausted — end the walk cleanly.
    Budget,
}

/// One test-run judge call: send the harvested page STATE (title, headings, text snippet, hints,
/// controls, site map, and — for a mutate walk — the fillable fields) to `/v1/tests/step` and parse
/// the single content-based decision. This is the ONLY place the walk asks "have we arrived?" — the
/// server judges arrival from the page's actual content in this same call, so there are no hardcoded
/// confirmation/verb/expect lists on the client. Exactly one billed judge call per hop, metered
/// against the org's pooled AI budget server-side.
pub(crate) fn request_step(
    cli: &Cli,
    http: &reqwest::blocking::Client,
    args: &RunTestArgs,
    view: &Value,
    tried: &[String],
) -> Result<Step> {
    let resp = http
        .post(format!("{}/v1/tests/step", cli.server))
        .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
        .json(&json!({
            "test": args.test,
            "page_title": view["title"],
            // The CURRENT page as a structured graph node (GRAPH.md) — a FRESH harvest each hop, so the
            // node reflects the live state after the last action: controls/collections that VANISHED
            // (the "Upgrade to Pro" control gone after upgrading, a deleted collection item, an
            // empty-state after cleanup) are simply absent from this harvest, and new/changed ones are
            // present. Nothing is carried over append-only; the judge always sees the reconciled node.
            "route": view["route"],
            "role": view["role"],
            "headings": view["headings"],
            "collections": view["collections"],
            "dialog": view["dialog"],
            "status": view["status"],
            "hints": view["hints"],
            "controls": view["controls"],
            "tried": tried,
            "site_map": args.site_map.iter().map(|(r, t)| json!({"route": r, "title": t})).collect::<Vec<_>>(),
            // The page's form fields — the judge reads them to recognize "this IS the place the goal
            // is performed" (e.g. a sign-up form) AND to fill+submit them. A test run may write:
            // uxlint IS a tester, and a test plan is the user's own, run locally against their own app.
            "fields": view["fields"].clone(),
        }))
        .send()?;
    if resp.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
        let body: Value = resp.json().unwrap_or_default();
        if body["action"].as_str() == Some("budget_exhausted") {
            return Ok(Step::Budget);
        }
        anyhow::bail!(
            "test run step failed: 402 — {}",
            body["error"].as_str().unwrap_or("payment required")
        );
    }
    if !resp.status().is_success() {
        anyhow::bail!(
            "test run step failed: {} — {}",
            resp.status(),
            resp.text().unwrap_or_default()
        );
    }
    let step: Value = resp.json()?;
    Ok(match step["action"].as_str() {
        Some("done") => Step::Done(step["evidence"].as_str().unwrap_or("").to_string()),
        Some("wait") => Step::Wait {
            reason: step["reason"].as_str().unwrap_or("").to_string(),
        },
        Some("click") => Step::Click(step["label"].as_str().unwrap_or("").to_string()),
        Some("fill") => {
            let values: Vec<(String, String)> = step["values"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| {
                            Some((
                                v["field"].as_str()?.to_string(),
                                v["value"].as_str().unwrap_or("").to_string(),
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default();
            Step::Fill {
                values,
                submit: step["submit"].as_str().unwrap_or("").to_string(),
            }
        }
        _ => Step::Back {
            reason: step["reason"].as_str().unwrap_or("").to_string(),
        },
    })
}

/// Save the trail server-side as a rendered flow report (chart + why-confusing + suggested
/// modification). Best-effort: a test-run run still succeeds if the save doesn't.
pub(crate) fn post_flow(
    cli: &Cli,
    http: &reqwest::blocking::Client,
    args: &RunTestArgs,
    outcome: &str,
    hops: usize,
    steps: &[Value],
    lost_reason: Option<&str>,
) -> Option<String> {
    if steps.is_empty() {
        return None;
    }
    let resp = http
        .post(format!("{}/v1/flows", cli.server))
        .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
        .json(&json!({
            "test": args.test,
            "base_url": args.base,
            "outcome": outcome,
            "hops": hops,
            "steps": steps,
            "lost_reason": lost_reason,
        }))
        .send();
    resp.ok()
        .filter(|r| r.status().is_success())
        .and_then(|r| r.json::<Value>().ok())
        .and_then(|v| v["report_url"].as_str().map(str::to_string))
}

#[cfg(test)]
mod harvest_redaction_tests {
    use super::*;

    /// The egress side: the harvest must run control labels, field labels, AND `<select>` options
    /// through `clean` (redaction), not the whitespace-only `norm` — otherwise a menu/switcher/field
    /// labelled with a user's email or name ships raw to the server + the LLM judge (the M3 leak).
    #[test]
    fn harvest_redacts_control_and_field_labels_for_egress() {
        let js = harvest_js();
        assert!(
            js.contains("const label = clean(el.getAttribute('aria-label')"),
            "control labels must be clean()'d for egress, not norm()"
        );
        assert!(
            js.contains("label = clean(label || '').slice(0, 40)"),
            "form-field labels must be clean()'d for egress"
        );
        assert!(
            js.contains(".map(o => clean(o.textContent || ''))"),
            "<select> option text must be clean()'d for egress"
        );
    }

    /// The match side: both matchers must splice the shared redaction snippet and run each DOM
    /// candidate through `uxlintRedact` before comparing — so a redacted egress label still resolves.
    #[test]
    fn both_matchers_are_redaction_aware() {
        for (name, built) in [
            (
                "click_by_label",
                crate::redact::splice_redact(CLICK_BY_LABEL_TEMPLATE),
            ),
            (
                "fill_fields",
                crate::redact::splice_redact(FILL_FIELDS_TEMPLATE),
            ),
        ] {
            assert!(
                built.contains(crate::redact::REDACT_JS),
                "{name} must embed the shared redaction snippet"
            );
            assert!(
                built.contains("uxlintRedact"),
                "{name} must run DOM candidates through uxlintRedact before comparing"
            );
            assert!(
                !built.contains("/*__UXLINT_REDACT__*/"),
                "{name} still has an un-spliced marker"
            );
        }
    }

    /// End-to-end invariant, modelled with the shared Rust mirror (proven to agree with the
    /// in-browser `uxlintRedact` by redact.rs's node/corpus tests): a PII-bearing control label is
    /// REDACTED in what egresses, yet the matcher — applying the SAME transform to the raw DOM label
    /// — still produces an equal key, so the judge's redacted pick stays clickable.
    #[test]
    fn pii_control_label_redacted_for_egress_yet_still_matchable() {
        use crate::redact::redact_secrets;
        // Harvest: `clean(raw).slice(0,60)` == redact(norm(raw)) truncated to 60.
        let raw = "Account — jane.doe@example.com";
        let norm: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
        let egressed: String = redact_secrets(&norm).chars().take(60).collect();
        // Matcher (click_by_label): the SAME transform applied to the live DOM label.
        let matcher_key: String = redact_secrets(&norm).chars().take(60).collect();

        assert!(
            egressed.contains("[email]"),
            "PII redacted for egress: {egressed}"
        );
        assert!(
            !egressed.contains("jane.doe@example.com"),
            "raw email must not egress: {egressed}"
        );
        assert_eq!(
            egressed.to_lowercase(),
            matcher_key.to_lowercase(),
            "the judge's redacted pick still resolves to the element"
        );
    }
}

#[cfg(test)]
mod declared_goal_tests {
    use super::*;

    fn goal(
        g: &str,
        expect: &str,
        importance: &str,
        persona: &str,
        viewport: &str,
    ) -> DeclaredTest {
        DeclaredTest {
            test: g.to_string(),
            expect: expect.to_string(),
            importance: importance.to_string(),
            persona: persona.to_string(),
            viewport: viewport.to_string(),
        }
    }

    #[test]
    fn resolve_declared_by_1_based_index() {
        let declared = vec![
            goal("sign in", "login", "critical", "anonymous", ""),
            goal("add a site", "sites", "important", "user", ""),
        ];
        assert_eq!(resolve_declared("1", &declared), Some(0));
        assert_eq!(resolve_declared("2", &declared), Some(1));
        assert_eq!(
            resolve_declared(" 2 ", &declared),
            Some(1),
            "trims whitespace"
        );
    }

    #[test]
    fn resolve_declared_index_out_of_range_or_zero_is_not_an_index() {
        let declared = vec![goal("sign in", "login", "critical", "anonymous", "")];
        assert_eq!(
            resolve_declared("0", &declared),
            None,
            "1-based — 0 isn't a valid index"
        );
        assert_eq!(resolve_declared("2", &declared), None, "past the end");
    }

    #[test]
    fn resolve_declared_by_case_insensitive_name() {
        let declared = vec![goal("Sign In", "login", "critical", "anonymous", "")];
        assert_eq!(resolve_declared("sign in", &declared), Some(0));
        assert_eq!(resolve_declared("SIGN IN", &declared), Some(0));
        assert_eq!(
            resolve_declared(" Sign In ", &declared),
            Some(0),
            "trims whitespace"
        );
    }

    #[test]
    fn resolve_declared_free_text_matching_nothing_is_ad_hoc() {
        let declared = vec![goal("sign in", "login", "critical", "anonymous", "")];
        assert_eq!(
            resolve_declared("do something nobody declared", &declared),
            None
        );
        assert_eq!(resolve_declared("", &declared), None);
    }

    #[test]
    fn normalize_viewport_only_mobile_stays_mobile() {
        assert_eq!(normalize_viewport("mobile"), "mobile");
        assert_eq!(normalize_viewport("MOBILE"), "mobile");
        assert_eq!(normalize_viewport("desktop"), "desktop");
        assert_eq!(
            normalize_viewport("both"),
            "desktop",
            "a fan-out viewport picks desktop for a single walk"
        );
        assert_eq!(normalize_viewport(""), "desktop");
    }

    #[test]
    fn declared_goal_label_includes_number_importance_persona_viewport() {
        let g = goal(
            "invite a teammate to your org",
            "invite",
            "important",
            "user",
            "desktop",
        );
        let label = g.label(2); // 0-based index 2 → printed as "3."
        assert!(label.starts_with(" 3."), "1-based numbering: {label}");
        assert!(label.contains("invite a teammate to your org"));
        assert!(
            label.contains("important") && label.contains("user") && label.contains("desktop"),
            "{label}"
        );
    }

    #[test]
    fn declared_goal_label_omits_empty_persona_and_viewport() {
        // A server-declared test (no persona/viewport columns) shouldn't print stray " · " gaps.
        let g = goal("find what uxlint costs", "pricing", "critical", "", "");
        let label = g.label(0);
        assert!(label.contains("critical"));
        assert!(
            !label.contains(" · ]") && !label.ends_with("· ]"),
            "{label}"
        );
    }

    #[test]
    fn non_tty_listing_numbers_every_goal_and_hints_at_picking_one() {
        let declared = vec![
            goal("sign in", "login", "critical", "anonymous", ""),
            goal("add a site", "sites", "important", "user", ""),
        ];
        let lines = non_tty_listing(&declared);
        assert!(lines[0].contains("2 declared test"));
        assert!(lines
            .iter()
            .any(|l| l.contains("1.") && l.contains("sign in")));
        assert!(lines
            .iter()
            .any(|l| l.contains("2.") && l.contains("add a site")));
        assert!(
            lines.iter().any(|l| l.contains("uxlint test")),
            "hints how to pick one next time"
        );
    }

    #[test]
    fn empty_listing_never_blocks_and_points_at_ad_hoc() {
        let lines = empty_listing();
        assert!(lines
            .iter()
            .any(|l| l.to_lowercase().contains("no declared tests")));
        assert!(
            lines
                .iter()
                .any(|l| l.contains("test") && l.contains("--expect")),
            "still names the ad-hoc escape hatch"
        );
    }

    #[test]
    fn login_for_persona_anonymous_and_empty_need_no_login() {
        assert!(login_for_persona("").unwrap().is_none());
        assert!(login_for_persona("anonymous").unwrap().is_none());
        assert!(
            login_for_persona("Anonymous").unwrap().is_none(),
            "case-insensitive"
        );
    }
}

#[cfg(test)]
mod wait_tests {
    use super::wait_fingerprint;
    use serde_json::json;

    fn running(status: &str) -> serde_json::Value {
        // A site page while its audit job is in progress: no report row yet, a running status.
        json!({
            "route": "/sites/7",
            "title": "example.com",
            "headings": ["Reports"],
            "collections": [{ "count": 0, "hasCreate": false }],
            "dialog": { "open": false },
            "controls": ["Audit again"],
            "fields": [],
            "status": [status],
        })
    }

    #[test]
    fn a_live_counter_in_status_is_not_a_change() {
        // The whole point of stripping digits: "running 3s" → "running 5s" must NOT end the wait,
        // or we'd re-bill the judge every poll while nothing actionable changed.
        assert_eq!(
            wait_fingerprint(&running("Auditing… 3s")),
            wait_fingerprint(&running("Auditing… 5s")),
        );
    }

    #[test]
    fn the_report_landing_is_a_change() {
        // When the job resolves the page gains a report row (a collection item + a control to open
        // it) — that IS actionable, so the fingerprint must differ and the wait must end.
        let before = running("Auditing…");
        let mut after = running("Auditing…");
        after["collections"] = json!([{ "count": 1, "hasCreate": false, "linksToDetail": true }]);
        after["controls"] = json!(["Audit again", "View report"]);
        assert_ne!(wait_fingerprint(&before), wait_fingerprint(&after));
    }

    #[test]
    fn a_status_word_change_is_a_change() {
        // "Auditing…" → "Report ready" is a real transition even if no control moved.
        assert_ne!(
            wait_fingerprint(&running("Auditing…")),
            wait_fingerprint(&running("Report ready")),
        );
    }

    #[test]
    fn an_unchanged_page_has_a_stable_fingerprint() {
        assert_eq!(
            wait_fingerprint(&running("Auditing…")),
            wait_fingerprint(&running("Auditing…"))
        );
    }
}
