//! Behavioural gate on `factBesideAction` in `assets/collector.js` — the reading that marks a section
//! holding a short fact and ONE action as content (`Section.hasMedia`), which is the whole input to
//! the server's decision that such a section is not `section-empty`.
//!
//! Reported from the field on 2026-09-26: `section-empty` fired on "Payment method" (a card summary
//! plus an Update button) and on a settings summary card linking to billing. The fact sits in a
//! `<div>`/`<span>` the word count never reads, and one action alone was deliberately not content.
//! The half that must NOT regress: a heading over a lone button with nothing to say beside it, and a
//! page region that merely happens to contain the action under a different heading.
//!
//! The predicate is lifted out of the shipped collector rather than copied, so a change to it fails
//! here.

use std::process::Command;

const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const m = src.match(/\tfunction factBesideAction[\s\S]*?\n\t\}/);
if (!m) throw new Error('collector has no factBesideAction — did the section-action reading get renamed?');
global.document = { body: { tag: 'BODY' } };
const factBesideAction = eval('(' + m[0] + ')');

let bad = 0;
const fail = (msg) => { bad++; console.log('FAIL: ' + msg); };
const yes = (got, what) => { if (!got) fail(what + ' — expected a COMPLETE section'); };
const no = (got, what) => { if (got) fail(what + ' — expected the section to stay EMPTY'); };

// A minimal DOM: a tag, own text, children; innerText concatenates, contains walks the subtree.
function el(tag, text, kids) {
	const n = { tagName: tag, _text: text || '', children: kids || [], parentElement: null };
	for (const k of n.children) k.parentElement = n;
	Object.defineProperty(n, 'innerText', { get: () => [n._text, ...n.children.map((k) => k.innerText)].filter(Boolean).join('\n') });
	n.contains = (o) => o === n || n.children.some((k) => k.contains(o));
	n.querySelectorAll = (sel) => {
		const out = [];
		const walk = (x) => { for (const k of x.children) { if (/^H[1-4]$/.test(k.tagName) && sel.includes('h')) out.push(k); walk(k); } };
		walk(n);
		return out;
	};
	return n;
}
const within = (card) => { const page = el('MAIN', '', [card]); page.parentElement = document.body; return card; };

// THE report: "Payment method" over "Visa •••• 4242" and an Update button, in one card.
{
	const h = el('H3', 'Payment method'), b = el('BUTTON', 'Update');
	within(el('SECTION', '', [h, el('DIV', 'Visa •••• 4242'), b]));
	yes(factBesideAction(h, b), 'a card summary beside its Update button');
}
// …and the plan card linking to billing, the fact one level down in a <span>.
{
	const h = el('H2', 'Plan'), a = el('A', 'Manage billing');
	within(el('DIV', '', [el('HEADER', '', [h]), el('DIV', '', [el('SPAN', 'Free · 3 of 5 sites')]), a]));
	yes(factBesideAction(h, a), 'a plan summary beside a billing link');
}

// A heading over a lone button with nothing beside it keeps no promise.
{
	const h = el('H2', 'Billing'), b = el('BUTTON', 'Manage');
	within(el('SECTION', '', [h, b]));
	no(factBesideAction(h, b), 'a heading and a lone button');
}
// A container holding the action under ANOTHER heading is a page region, not this section's card.
{
	const h = el('H2', 'Overview'), h2 = el('H2', 'Danger zone'), b = el('BUTTON', 'Delete');
	within(el('DIV', '', [h, el('P', 'Some other text'), h2, b]));
	no(factBesideAction(h, b), 'an action that belongs to the next heading');
}

console.log(bad ? 'FAILURES: ' + bad : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn a_short_fact_beside_one_action_is_a_complete_section() {
    let dir = std::env::temp_dir().join("uxlint-collector-section-action");
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
