//! Behavioural gate on `pointClippedOut` in `assets/collector.js` — the guard that stops the
//! occlusion hit test from reading a point the control does not occupy, which is the entire input to
//! the server's `occluded-control` rule.
//!
//! Reported from the field on 2026-08-29: a sidebar built the ordinary way — a flex column with a
//! pinned header, an `overflow-y-auto` middle and a pinned footer — reported EVERY nav link below
//! the fold of that middle band as occluded. Those links are scrolled out of the visible strip, so
//! their rects resolve to coordinates the pinned footer paints, and `elementFromPoint` duly returned
//! the footer. Dozens of instances from one sidebar, none of them a defect: the links are reachable
//! by scrolling the container.
//!
//! The predicate is lifted out of the shipped collector rather than copied, so a change to it fails
//! here.

use std::process::Command;

const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const m = src.match(/function pointClippedOut[\s\S]*?\n\t\}/);
if (!m) throw new Error('collector has no pointClippedOut — did the scroll-clip guard get renamed?');
const pointClippedOut = eval('(' + m[0] + ')');

let bad = 0;
const fail = (msg) => { bad++; console.log('FAIL: ' + msg); };
const yes = (got, what) => { if (!got) fail(what + ' — expected the probe to be discounted'); };
const no = (got, what) => { if (got) fail(what + ' — expected the probe to STAND'); };

// The reported layout: a 260px sidebar whose scrollable middle runs y 64→640, above a pinned footer.
const scroller = { left: 0, top: 64, right: 260, bottom: 640 };

// A nav item scrolled BELOW the visible strip — its centre lands on the pinned footer.
yes(pointClippedOut(130, 700, [scroller]), 'a nav link scrolled past the bottom of its container');
// …and one scrolled above it, which is the same thing at the other end.
yes(pointClippedOut(130, 20, [scroller]), 'a nav link scrolled above the top of its container');
// A horizontally scrolled toolbar: the same argument on the other axis.
yes(pointClippedOut(400, 300, [{ left: 0, top: 200, right: 260, bottom: 400 }]), 'a control scrolled out sideways');

// The item actually IN the visible strip is still checked — the guard must not swallow the rule.
no(pointClippedOut(130, 300, [scroller]), 'a nav link inside its scroll container');
// No clipping ancestor at all: an ordinary control in normal flow, where a cover is a real defect.
no(pointClippedOut(130, 300, []), 'a control with nothing clipping it');
// On the boundary counts as inside — a control flush with the container edge is visible.
no(pointClippedOut(0, 64, [scroller]), 'a point exactly on the container edge');
// Nested scrollers: outside the OUTER one is out, even when inside the inner one's box.
yes(pointClippedOut(130, 700, [{ left: 0, top: 640, right: 260, bottom: 900 }, scroller]),
	'a point inside the inner clip but outside the outer one');

console.log(bad ? 'FAILURES: ' + bad : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn a_control_scrolled_out_of_its_container_is_not_occluded() {
    let dir = std::env::temp_dir().join("uxlint-collector-scroll-clip");
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
