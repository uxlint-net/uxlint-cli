//! Behavioural gate on `navSubItem` in `assets/collector.js` — the split between a nav's TOP-LEVEL
//! destinations and the tier below them, which is what the server's `nav-overload` and
//! `nav-pattern-mismatch` rules count.
//!
//! Reported from the field on 2026-08-29: a sidebar was reported as 19 primary destinations and drew
//! a choice-overload finding. The top-level product destinations were within 7±2; the tail was the
//! sub-nav for the section the user was already inside, rendered as a disclosure that is collapsed
//! everywhere else. Grouping a long nav into disclosed sections is the fix this rule RECOMMENDS, so
//! counting the opened group as overload penalises the shape we ask for.
//!
//! The predicate is lifted out of the shipped collector rather than copied, so a change to it fails
//! here.

use std::process::Command;

const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const m = src.match(/function navSubItem[\s\S]*?\n\t\}/);
if (!m) throw new Error('collector has no navSubItem — did the nav tier split get renamed?');
const navSubItem = eval('(' + m[0] + ')');

let bad = 0;
const fail = (msg) => { bad++; console.log('FAIL: ' + msg); };
const yes = (got, what) => { if (!got) fail(what + ' — expected a SECOND-TIER item'); };
const no = (got, what) => { if (got) fail(what + ' — expected a TOP-LEVEL destination'); };

// Ancestors from the link up to (but not including) the nav root, innermost first.
const li = (disclosure) => ({ tag: 'LI', disclosure: !!disclosure });
const ul = { tag: 'UL', disclosure: false };
const div = { tag: 'DIV', disclosure: false };

// The ordinary sidebar item: <nav><ul><li><a>.
no(navSubItem([li(), ul]), 'a plain top-level nav item');
no(navSubItem([li(), ul, div]), 'a top-level item under a wrapper div');
no(navSubItem([]), 'a link directly in the nav');

// THE report: an item inside an expanded disclosure group — the current section's sub-nav.
yes(navSubItem([li(), ul, li(true), ul]), 'an item inside an expanded accordion section');
// The same shape spelled with <details>.
yes(navSubItem([li(), ul, { tag: 'DETAILS', disclosure: false }, div]), 'an item inside a <details> group');
// A plain nested list with no ARIA at all is still a tier below.
yes(navSubItem([li(), ul, li(), ul]), 'an item in a nested sub-list');

// The toggle ITSELF stays top-level: <li><a aria-expanded>Admin</a><ul>… — Admin is a destination
// that opens a tier, not a member of one. (The collector excludes the element's own toggle when it
// builds the chain, so its parent arrives with disclosure: false.)
no(navSubItem([li(false), ul]), 'the accordion item that opens the group');

console.log(bad ? 'FAILURES: ' + bad : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn a_disclosed_sub_nav_is_not_a_top_level_destination() {
    let dir = std::env::temp_dir().join("uxlint-collector-nav-tier");
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
