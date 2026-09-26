//! Behavioural gate on `clippedToNothing` in `assets/collector.js` — the reading behind `srOnly`,
//! which the server's `Element::visually_hidden` uses to keep screen-reader-only content out of the
//! visual rules (`occluded-control`, `text-clipping`, `tap-target`, `heading-attachment`).
//!
//! Reported from the field on 2026-09-26: both `occluded-control` and `text-clipping` fired on a
//! "Skip to content" link built sr-only-until-focused. Its padding outweighs the sr-only rule's
//! `padding: 0`, so the box measures 32×16 — past the server's 1×1 test — while the clip paints none
//! of it. Only the clip itself says it is hidden.
//!
//! The predicate is lifted out of the shipped collector rather than copied, so a change to it fails
//! here.

use std::process::Command;

const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const m = src.match(/\tfunction clippedToNothing[\s\S]*?\n\t\}/);
if (!m) throw new Error('collector has no clippedToNothing — did the sr-only reading get renamed?');
const clippedToNothing = eval('(' + m[0] + ')');

let bad = 0;
const fail = (msg) => { bad++; console.log('FAIL: ' + msg); };
const yes = (got, what) => { if (!got) fail(what + ' — expected visually HIDDEN'); };
const no = (got, what) => { if (got) fail(what + ' — expected visible'); };

// Computed style as the browser reports it.
const cs = (position, clip, clipPath) => ({ position, clip: clip || 'auto', clipPath: clipPath || 'none' });

// THE report: Tailwind v3 / Bootstrap sr-only — `clip: rect(0, 0, 0, 0)` on an absolute box.
yes(clippedToNothing(cs('absolute', 'rect(0px, 0px, 0px, 0px)')), 'the classic sr-only clip');
yes(clippedToNothing(cs('absolute', 'rect(1px, 1px, 1px, 1px)')), 'the old rect(1px…) spelling');
// Tailwind v4 / Bootstrap 5.3 spell it with clip-path.
yes(clippedToNothing(cs('absolute', 'auto', 'inset(50%)')), 'clip-path: inset(50%)');

// The focused skip link: `focus:not-sr-only` resets the clip, and it must read as visible again.
no(clippedToNothing(cs('absolute')), 'an absolutely positioned box with no clip');
// `clip` does nothing on a static box, so a stray declaration there hides nothing.
no(clippedToNothing(cs('static', 'rect(0px, 0px, 0px, 0px)')), 'a clip on a static box');
// A real crop that leaves something showing is not a hidden element.
no(clippedToNothing(cs('absolute', 'rect(0px, 120px, 40px, 0px)')), 'a clip that shows a 120×40 window');
no(clippedToNothing(cs('relative', 'auto', 'inset(10%)')), 'a partial clip-path inset');
no(clippedToNothing(cs('relative', 'auto', 'circle(50%)')), 'a round avatar mask');

console.log(bad ? 'FAILURES: ' + bad : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn a_clipped_to_nothing_element_is_visually_hidden() {
    let dir = std::env::temp_dir().join("uxlint-collector-sr-only");
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
