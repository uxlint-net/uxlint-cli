//! Behavioural gate on `hiddenByDisclosure` in `assets/collector.js` — the guard that keeps a
//! COLLAPSED subtree out of the occlusion hit test, which is the entire input to the server's
//! `occluded-control` rule.
//!
//! Reported from the field on 2026-08-29: a pinned "on this page" jump list, rendered as a closed
//! `<details>`, had every link inside it flagged as covered by the paragraph that occupies that
//! space. Being unreachable until the disclosure is expanded is what a disclosure IS, and the
//! `<summary>` beside it is a visible control that expands it — so there was nothing to fix, and
//! the finding cost a reader the time to prove that.
//!
//! The predicate is lifted out of the shipped collector rather than copied, so a change to it fails
//! here.

use std::process::Command;

const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const m = src.match(/function hiddenByDisclosure[\s\S]*?\n\t\}/);
if (!m) throw new Error('collector has no hiddenByDisclosure — did the disclosure guard get renamed?');
const hiddenByDisclosure = eval('(' + m[0] + ')');

let bad = 0;
const fail = (msg) => { bad++; console.log('FAIL: ' + msg); };
const yes = (got, what) => { if (!got) fail(what + ' — expected the occlusion to be discounted'); };
const no = (got, what) => { if (got) fail(what + ' — expected the occlusion to STAND'); };

// An ancestor chain, innermost first, as the collector materialises it.
const el = (tag, open, cv) => ({ tag, open: !!open, cv: cv || 'visible' });

// THE report: a link inside a closed <details> jump list.
yes(hiddenByDisclosure([el('A'), el('LI'), el('UL'), el('DETAILS', false), el('DIV')]),
	'a link inside a closed <details>');
// A custom disclosure that collapses with content-visibility instead of <details>.
yes(hiddenByDisclosure([el('BUTTON'), el('DIV', false, 'hidden'), el('SECTION')]),
	'a control under a content-visibility:hidden ancestor');

// The OPEN disclosure is where a cover would actually matter — it must still be reported.
no(hiddenByDisclosure([el('A'), el('LI'), el('UL'), el('DETAILS', true), el('DIV')]),
	'a link inside an OPEN <details>');
// And an ordinary control under ordinary chrome is untouched: this guard must not swallow the rule.
no(hiddenByDisclosure([el('BUTTON'), el('DIV'), el('MAIN')]), 'a control with no disclosure above it');
no(hiddenByDisclosure([]), 'an empty chain');
// `content-visibility: auto` is a rendering OPTIMISATION on content that is meant to be seen —
// only `hidden` means "this subtree is deliberately not shown".
no(hiddenByDisclosure([el('BUTTON'), el('DIV', false, 'auto')]), 'content-visibility:auto is not hidden');
// The shortest real chain: a control whose immediate parent is the closed disclosure.
yes(hiddenByDisclosure([el('SPAN'), el('DETAILS', false)]), 'a control directly inside a closed <details>');

console.log(bad ? 'FAILURES: ' + bad : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn a_closed_disclosure_is_not_an_occlusion() {
    let dir = std::env::temp_dir().join("uxlint-collector-disclosure-occlusion");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let driver = dir.join("driver.js");
    std::fs::write(&driver, DRIVER).expect("write driver");
    let out = Command::new("node")
        .arg(&driver)
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/collector.js"))
        .output()
        .expect("node is required to gate the collector");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}{stderr}");
}
