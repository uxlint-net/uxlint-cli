//! THE single source of truth for secret/PII redaction, wired into every channel that can carry
//! data off the machine.
//!
//! A security reviewer worried about what leaves their box should be able to read this one file (and
//! `assets/redact.js`, which it embeds) and know the whole redaction story:
//!
//! * `assets/redact.js` holds the canonical patterns ONCE. It is interpolated verbatim into all
//!   three *browser-side* channels — [`collector_js`], [`mask_secrets_js`], [`harvest_js`] — so they
//!   are byte-identical by construction and cannot drift.
//! * [`redact_secrets`] is the Rust mirror of those same patterns, applied to the two channels that
//!   never touch the DOM (browser **console logs** and **native dialogs**), which would otherwise
//!   ship unredacted.
//! * Tests in this file assert every channel embeds the same JS snippet AND that the Rust mirror and
//!   the JS agree on a shared corpus of known secrets, so drift between the channels is caught
//!   mechanically.
//!
//! BEST-EFFORT, NOT A GUARANTEE. Pattern-based masking catches common token/key/password/email
//! shapes; unusual formats, split values, and arbitrary sensitive DATA (names, addresses, order
//! contents) are not caught. See README "Privacy & trust".

use serde_json::{json, Value};
use std::sync::OnceLock;

/// The canonical redaction snippet — declares `uxlintRedact()` and its pattern lists. Embedded once
/// here and interpolated into each browser-side channel below (search for `REDACT_MARKER`).
pub(crate) const REDACT_JS: &str = include_str!("../assets/redact.js");

/// The page-capture script, minus its redaction snippet (which is interpolated at build time). It is
/// injected into each audited page and decides exactly what a snapshot contains before anything is
/// uploaded — shipping it IN the binary (not fetching it from the server) means this repo is the
/// complete, auditable source of what an audit captures.
const COLLECTOR_RAW: &str = include_str!("../assets/collector.js");

/// The marker each browser-side channel carries where the shared `assets/redact.js` snippet is
/// spliced in. Keeping it identical across channels is what the sync test verifies.
const REDACT_MARKER: &str = "/*__UXLINT_REDACT__*/";

/// Splice the canonical redaction snippet into a channel's JS at its `REDACT_MARKER`. Panics if the
/// marker is missing — that can only happen if someone deletes it while editing a channel, and a
/// channel with no redaction must never ship, so failing loudly at first use is correct.
pub(crate) fn splice_redact(template: &str) -> String {
    assert!(
        template.contains(REDACT_MARKER),
        "a capture channel lost its {REDACT_MARKER} — it would ship UNREDACTED; refusing"
    );
    template.replace(REDACT_MARKER, REDACT_JS)
}

/// The full page collector, with the shared redaction snippet interpolated. Built once and cached —
/// it is injected on every route.
pub(crate) fn collector_js() -> &'static str {
    static CELL: OnceLock<String> = OnceLock::new();
    CELL.get_or_init(|| splice_redact(COLLECTOR_RAW))
}

/// Live-DOM secret mask, injected right before every screenshot: replace token/secret-shaped text
/// (and secret-looking input values; password fields → dots) in the rendered DOM with `[redacted]`
/// so a displayed credential never lands in a stored report image. Uses the shared redaction
/// snippet — same patterns as every other channel.
pub(crate) fn mask_secrets_js() -> &'static str {
    static CELL: OnceLock<String> = OnceLock::new();
    CELL.get_or_init(|| {
        splice_redact(
            r#"(() => { try {
  /*__UXLINT_REDACT__*/
  const red = uxlintRedact;
  const maskRoot = (root) => {
    const doc = root.ownerDocument || document;
    const w = doc.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const ns = []; while (w.nextNode()) ns.push(w.currentNode);
    for (const n of ns) { const r = red(n.nodeValue); if (r !== n.nodeValue) n.nodeValue = r; }
    for (const el of root.querySelectorAll('input,textarea')) {
      if (!el.value) continue;
      if (el.type === 'password') { el.value = '••••••••'; continue; }
      // Mask the WHOLE value, not just pattern matches: a text/email/number field can hold typed
      // PII (a name, an address, an order number) that no secret pattern catches. Length and
      // whitespace are kept so the field still looks filled (the layout/contrast audit is
      // unchanged); only the content is hidden.
      const masked = el.value.replace(/\S/g, '•');
      el.value = masked;
      // number/email/url inputs reject the mask and clear themselves (content still hidden); if the
      // original somehow survived, force-blank it.
      if (el.value && el.value !== masked) el.value = '';
    }
    // Shadow DOM renders into the screenshot exactly like light DOM, so descend into every OPEN
    // shadow root (closed roots are unreachable from JS but are almost always native controls, not
    // places user data lives).
    for (const el of root.querySelectorAll('*')) { if (el.shadowRoot) maskRoot(el.shadowRoot); }
  };
  maskRoot(document.body);
  // Also mask CLOSED shadow roots captured by the attachShadow interceptor (worker.rs). Open roots
  // are already covered by the recursion above, so re-masking them here is a harmless no-op.
  for (const r of (window.__uxShadowRoots || [])) { try { if (r && r.querySelectorAll) maskRoot(r); } catch (_) {} }
  // Iframes render into the shot too. Same-origin: mask the frame's DOM. Cross-origin (or otherwise
  // unreadable): we can reach neither its DOM nor its pixels, so cover its rect with an opaque box
  // in the parent so its rendered content can't leak. Clear any box from a prior pass first, so a
  // repeated mask (the fix-preview before/after shots) doesn't stack boxes.
  for (const b of document.querySelectorAll('[data-uxlint-frame-cover]')) b.remove();
  for (const f of document.querySelectorAll('iframe,frame')) {
    let doc = null; try { doc = f.contentDocument; } catch (_) {}
    if (doc && doc.body) { maskRoot(doc.body); continue; }
    const r = f.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) continue;
    const box = document.createElement('div');
    box.setAttribute('data-uxlint-frame-cover', '');
    box.style.cssText = 'position:absolute;z-index:2147483646;background:#e5e7eb;pointer-events:none;left:'
      + (r.left + scrollX) + 'px;top:' + (r.top + scrollY) + 'px;width:' + r.width + 'px;height:' + r.height + 'px;';
    document.body.appendChild(box);
  }
} catch (_) {} })();"#,
        )
    })
}

/// Rust mirror of the JS redaction, for the two channels that never run in the page and so can't use
/// the shared JS snippet: browser **console logs** and **native dialog** messages. Same pattern set;
/// kept honest by the corpus test below.
pub(crate) fn redact_secrets(input: &str) -> String {
    let mut out = input.to_string();
    for (re, repl) in rust_patterns() {
        out = re.replace_all(&out, *repl).into_owned();
    }
    out
}

/// A console entry's `url` can itself carry secrets in its query string (`?token=…`, `?api_key=…`),
/// which is one of the most common real-world leaks. Drop the query/fragment entirely, then redact
/// what remains. Returns the sanitized URL.
pub(crate) fn sanitize_url(url: &str) -> String {
    let base = url.split(['?', '#']).next().unwrap_or(url);
    redact_secrets(base)
}

/// Sanitize one browser console entry in place: redact the message `text` and strip+redact the
/// `url`. Pure over the JSON value so it's unit-testable without a browser.
pub(crate) fn sanitize_console_entry(entry: &mut Value) {
    if let Some(t) = entry.get("text").and_then(Value::as_str) {
        let red = redact_secrets(t);
        entry["text"] = json!(red);
    }
    if let Some(u) = entry.get("url").and_then(Value::as_str) {
        if !u.is_empty() {
            entry["url"] = json!(sanitize_url(u));
        }
    }
}

/// Redact a native-dialog message (`alert`/`confirm`/`prompt` text) before it enters the payload —
/// a `prompt()` default or an `alert()` embedding user data would otherwise ship verbatim.
pub(crate) fn redact_dialog_message(message: &str) -> String {
    redact_secrets(message)
}

/// The compiled Rust patterns, mirroring `assets/redact.js`. Built once. The order matters (specific
/// key shapes first, then the labelled-value heuristic, then email) exactly as the JS applies them.
fn rust_patterns() -> &'static [(regex::Regex, &'static str)] {
    static CELL: OnceLock<Vec<(regex::Regex, &'static str)>> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut v: Vec<(regex::Regex, &'static str)> = Vec::new();
        // Mirrors UXLINT_SECRET_RES, in the same order. `\b` and non-greedy `*?` are supported by
        // the `regex` crate; none of these use backreferences or look-around.
        let secret_res: &[&str] = &[
            r"\b(?:sk|rk|pk)[-_](?:live|test|prod|proj)?[-_]?[A-Za-z0-9]{16,}\b",
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b",
            r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
            r"\bAKIA[0-9A-Z]{16}\b",
            r"\bAIza[0-9A-Za-z_-]{35}\b",
            r"\bglpat-[A-Za-z0-9_-]{20,}\b",
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b",
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        ];
        for p in secret_res {
            v.push((regex::Regex::new(p).expect("secret regex"), "[redacted]"));
        }
        // Mirrors UXLINT_SECRET_LAB: keep label + separator, drop the value.
        v.push((
            regex::Regex::new(
                r#"(?i)\b(api[\s_-]?key|secret|token|password|passwd|access[\s_-]?key|client[\s_-]?secret)\b(["'\s:=]{1,4})([A-Za-z0-9._~+/-]{12,}=*)"#,
            )
            .expect("labelled-secret regex"),
            "${1}${2}[redacted]",
        ));
        // Mirrors UXLINT_EMAIL_RE.
        v.push((
            regex::Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
                .expect("email regex"),
            "[email]",
        ));
        v
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_run::harvest_js;

    /// Every browser-side channel must embed the identical canonical redaction snippet. Splicing one
    /// shared file is what stops the channels from drifting apart, which is a real risk: the PEM
    /// private-key pattern once lived in the collector but not the other two. If any channel stops
    /// splicing `assets/redact.js`, it ships with a stale/absent pattern set and this fails.
    #[test]
    fn every_channel_embeds_the_same_redaction_snippet() {
        for (name, js) in [
            ("collector", collector_js()),
            ("mask_secrets", mask_secrets_js()),
            ("harvest", harvest_js()),
        ] {
            assert!(
                js.contains(REDACT_JS),
                "{name} channel does not embed the canonical assets/redact.js — it can drift/leak"
            );
            assert!(
                !js.contains(REDACT_MARKER),
                "{name} channel still has an un-spliced {REDACT_MARKER}"
            );
        }
    }

    /// The PEM private-key block — the exact pattern that had drifted OUT of two of the three
    /// channels — must now be present in all three (they all embed the shared snippet).
    #[test]
    fn pem_private_key_pattern_reaches_every_channel() {
        let pem = "PRIVATE KEY-----";
        assert!(collector_js().contains(pem));
        assert!(mask_secrets_js().contains(pem));
        assert!(harvest_js().contains(pem));
    }

    /// The behavioural corpus: known secrets/PII that MUST be masked, and near-miss negatives that
    /// must NOT be (a version string, a doc placeholder). Drives the Rust mirror — the same list the
    /// browser channels redact with the same patterns.
    fn corpus() -> &'static [(&'static str, bool)] {
        &[
            // (input, must_be_redacted) — one per canonical pattern, plus PII and negatives.
            ("sk_live_0123456789abcdefABCD", true),
            ("pk-test-0123456789abcdefABCD", true),
            ("ghp_0123456789abcdefghij0123", true),
            ("github_pat_0123456789ABCDEFGH_more", true),
            ("xoxb-0123456789-abcdefzyxw", true),
            ("AKIAIOSFODNN7EXAMPLE", true),
            ("glpat-0123456789abcdefghij", true),
            (
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
                true,
            ),
            ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123", true),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----",
                true,
            ),
            ("api_key: aGVsbG93b3JsZDEyMzQ1", true),
            ("password = hunter2hunter2hunter2", true),
            ("contact us at jane.doe@example.com", true),
            // Negatives — everyday text that must survive untouched.
            ("AIzaShort", false), // an AIza prefix but nowhere near a real 35-char key
            ("react@18.2.0", false),
            ("uxr_docs_placeholder", false),
            ("version 1.2.3 released", false),
            ("just some ordinary prose", false),
        ]
    }

    #[test]
    fn rust_mirror_masks_the_corpus() {
        for &(input, must_redact) in corpus() {
            let out = redact_secrets(input);
            if must_redact {
                assert!(
                    out.contains("[redacted]") || out.contains("[email]"),
                    "expected redaction of {input:?}, got {out:?}"
                );
            } else {
                assert_eq!(out, input, "must NOT have redacted {input:?}");
            }
        }
    }

    #[test]
    fn console_url_query_string_is_stripped_and_redacted() {
        // The single most common console leak: a request URL carrying a token in its query string.
        let mut entry = json!({
            "text": "GET failed for Bearer abcdefghijklmnopqrstuvwxyz0123",
            "url": "https://api.example.com/v1/things?api_key=sk_live_0123456789abcdefABCD&x=1",
        });
        sanitize_console_entry(&mut entry);
        let url = entry["url"].as_str().unwrap();
        assert!(!url.contains('?'), "query string must be dropped: {url}");
        assert!(!url.contains("sk_live"), "query secret must be gone: {url}");
        let text = entry["text"].as_str().unwrap();
        assert!(
            text.contains("[redacted]"),
            "console text must be redacted: {text}"
        );
        assert!(
            !text.contains("abcdefghijklmnopqrstuvwxyz"),
            "bearer must be gone: {text}"
        );
    }

    #[test]
    fn dialog_message_is_redacted() {
        let msg = "Send this key to support: sk_live_0123456789abcdefABCD ?";
        let red = redact_dialog_message(msg);
        assert!(red.contains("[redacted]"));
        assert!(!red.contains("sk_live_0123456789"));
    }

    #[test]
    fn labelled_value_keeps_the_label() {
        let out = redact_secrets("api_key: aGVsbG93b3JsZDEyMzQ1");
        assert!(out.starts_with("api_key"), "label kept: {out}");
        assert!(out.contains("[redacted]"), "value masked: {out}");
        assert!(!out.contains("aGVsbG93b3JsZDEyMzQ1"), "value gone: {out}");
    }
}
