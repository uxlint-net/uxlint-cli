//! Behavioural gate on `scrollsClearOfBottomBar` in `assets/collector.js` — the guard that stops the
//! occlusion hit test from reporting a control as covered by a bar pinned to the viewport's bottom
//! edge when the page can scroll it clear, which is the whole input to the server's
//! `occluded-control` rule for that layout.
//!
//! Reported from the field on 2026-09-26: on mobile, list-row controls under a fixed bottom tab bar
//! were reported covered at the initial scroll position. The page has bottom padding for exactly that
//! bar, so one flick lifts every row clear of it and they are fully usable. The half that must NOT
//! regress is the page with no such room: its last row is under the bar however far you scroll.
//!
//! The predicate is lifted out of the shipped collector rather than copied, so a change to it fails
//! here.

use std::process::Command;

const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const m = src.match(/\tfunction scrollsClearOfBottomBar[\s\S]*?\n\t\}/);
if (!m) throw new Error('collector has no scrollsClearOfBottomBar — did the bottom-bar guard get renamed?');
const scrollsClearOfBottomBar = eval('(' + m[0] + ')');

let bad = 0;
const fail = (msg) => { bad++; console.log('FAIL: ' + msg); };
const yes = (got, what) => { if (!got) fail(what + ' — expected the cover to be discounted'); };
const no = (got, what) => { if (got) fail(what + ' — expected the cover to STAND'); };

// A 390×844 phone with a 64px tab bar pinned along the bottom edge.
const VH = 844;
const tabBar = { top: 780, bottom: 844 };

// THE report: a row whose control ends at 820, under the bar, with the page's bottom padding (and
// the rest of the list) leaving 900px to scroll.
yes(scrollsClearOfBottomBar(tabBar, 820, VH, 900), 'a list row the page can scroll clear of the tab bar');
// Just enough room is enough: 40px lifts a bottom edge at 820 to the bar's top at 780.
yes(scrollsClearOfBottomBar(tabBar, 820, VH, 40), 'exactly enough scroll left');

// The real defect: the page ends here — no padding, no more list — so the last row never clears.
no(scrollsClearOfBottomBar(tabBar, 820, VH, 0), 'the last row of a page with no room below it');
no(scrollsClearOfBottomBar(tabBar, 820, VH, 20), 'too little room to clear the bar');
// A TOP bar is not this guard's business: nothing scrolls a control down from under a header.
no(scrollsClearOfBottomBar({ top: 0, bottom: 56 }, 40, VH, 900), 'a control under a sticky header');
// A full-height side rail reaches the bottom edge too, but it is not a bar along it.
no(scrollsClearOfBottomBar({ top: 0, bottom: 844 }, 820, VH, 900), 'a control under a full-height rail');

console.log(bad ? 'FAILURES: ' + bad : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn a_control_the_page_scrolls_clear_of_a_bottom_bar_is_not_occluded() {
    let dir = std::env::temp_dir().join("uxlint-collector-bottom-bar");
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
