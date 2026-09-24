//! Behavioural gate on `data-uxlint-ignore` in `assets/collector.js`: a subtree marked non-shipping
//! must be absent from the element table entirely, and its descendants with it.
//!
//! Reported from the field on 2026-08-26: an audit pointed at a local dev server sees UI no user will
//! ever meet — a debug panel, an environment banner, a bypass-login block behind a dev flag. The
//! findings are accurate about what was on screen and describe nothing anyone can ship a fix for, and
//! worse, a page's dominant accent hue gets measured off an amber debug panel.
//!
//! The predicate is lifted out of the shipped collector's own walk rather than restated, so a change
//! to it fails here.

use std::process::Command;

const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');

// The exact guard the element walk runs, lifted by shape so a rename or a loosened test fails here.
const m = src.match(/if \(el\.hasAttribute\('data-uxlint-ignore'\)[\s\S]*?\n\t\t\}/);
if (!m) throw new Error('collector has no data-uxlint-ignore guard in the element walk');
const body = m[0];

let bad = 0;
const fail = (msg) => { bad++; console.log('FAIL: ' + msg); };

// Rebuild the walk around the lifted guard: the same WeakSet, the same document order.
const walk = (nodes) => {
	const ignoredSet = new WeakSet();
	const kept = [];
	const step = new Function('el', 'ignoredSet', 'kept',
		body.replace(/continue;/, 'return;') + '\n kept.push(el.name);');
	for (const el of nodes) step(el, ignoredSet, kept);
	return kept;
};
const el = (name, attrs, parent) => {
	const n = {
		name,
		_a: attrs || {},
		parentElement: parent || null,
		hasAttribute: (k) => Object.prototype.hasOwnProperty.call(n._a, k),
	};
	return n;
};

// A debug panel wrapping a heading and a status chip, beside the page's real content.
const body_ = el('body');
const panel = el('debug-panel', { 'data-uxlint-ignore': '' }, body_);
const panelHead = el('debug-h1', {}, panel);
const panelChip = el('debug-chip', {}, panelHead); // two levels down
const real = el('main', {}, body_);
const realHead = el('h1', {}, real);

const kept = walk([body_, panel, panelHead, panelChip, real, realHead]);

if (kept.includes('debug-panel')) fail('the marked element itself must be dropped');
if (kept.includes('debug-h1')) fail('a child of the marked element must be dropped');
if (kept.includes('debug-chip')) fail('a GRANDchild of the marked element must be dropped');
if (!kept.includes('main')) fail('the page\'s own content must survive');
if (!kept.includes('h1')) fail('content beside the ignored subtree must survive');
if (!kept.includes('body')) fail('an unmarked root must survive');

console.log(bad ? 'FAILURES: ' + bad : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn a_subtree_marked_non_shipping_never_reaches_the_element_table() {
    let dir = std::env::temp_dir().join("uxlint-collector-ignore-subtree");
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
