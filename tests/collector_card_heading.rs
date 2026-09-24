//! Behavioural gate on `repeatedItemHeading` in `assets/collector.js` — the guard that marks a
//! heading as `Section.card`, which is the whole input to the server's decision that a heading is a
//! LABEL on a repeated item rather than a section promise (`section-empty`).
//!
//! Reported from the field on 2026-08-30: `section-empty` fired on a card title in a grid of people,
//! calling a person's name "a promise without information" while the card carried a profession and a
//! ruleset chip beneath it. The server's old test for this was a run of short same-level headings,
//! which is data-dependent — give most cards a bio and one card none, and the bio-less card is no
//! longer part of a run, so it alone gets reported.
//!
//! The half that must NOT regress is a document: `<main>` holding several `<section>`s is repetition
//! too, and each of those headings IS a promise. Geometry separates them — a grid puts peers beside
//! each other, a document stacks them.
//!
//! The predicate is lifted out of the shipped collector rather than copied, so a change to it fails
//! here.

use std::process::Command;

const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const m = src.match(/\tfunction repeatedItemHeading[\s\S]*?\n\t\}/);
if (!m) throw new Error('collector has no repeatedItemHeading — did the card guard get renamed?');
const repeatedItemHeading = eval('(' + m[0] + ')');

let bad = 0;
const fail = (msg) => { bad++; console.log('FAIL: ' + msg); };
const yes = (got, what) => { if (!got) fail(what + ' — expected a card LABEL'); };
const no = (got, what) => { if (got) fail(what + ' — expected a section PROMISE'); };

// A minimal DOM good enough for the predicate: tag, class, a box, and parent/children wiring.
function el(tag, cls, rect, kids) {
	const n = {
		tagName: tag,
		_cls: cls || '',
		_rect: rect || { top: 0, bottom: 10, left: 0, right: 10 },
		children: kids || [],
		parentElement: null,
		getAttribute: (k) => (k === 'class' ? n._cls : null),
		getClientRects: () => (n._rect ? [n._rect] : []),
		getBoundingClientRect: () => n._rect,
	};
	for (const k of n.children) k.parentElement = n;
	return n;
}
const box = (top, left) => ({ top, bottom: top + 300, left, right: left + 300 });
const body = el('BODY');

// THE report: a 2x2 grid of person cards. The h3 is the card's title, nested in a header wrapper.
function personCard(top, left, cls) {
	return el('DIV', cls || 'card', box(top, left), [
		el('DIV', 'card-head', box(top, left), [el('H3', 'name', box(top, left))]),
	]);
}
const gridKids = [personCard(0, 0), personCard(0, 320), personCard(320, 0), personCard(320, 320)];
el('DIV', 'grid', box(0, 0), gridKids);
const cardTitle = gridKids[0].children[0].children[0];
yes(repeatedItemHeading(cardTitle, body), 'a card title in a 2x2 grid of people');
// The lone bio-less card in a grid whose other cards have prose: identical structure, so identical
// verdict. This is the case the old word-count run could not see.
yes(repeatedItemHeading(gridKids[3].children[0].children[0], body), 'the last card in that grid');

// A document is NOT a card grid, however many sections it has: full-width, stacked, no peer beside.
const secs = [0, 400, 800].map((t) => el('SECTION', 'prose', { top: t, bottom: t + 380, left: 0, right: 900 },
	[el('H2', 'title', { top: t, bottom: t + 40, left: 0, right: 900 })]));
el('MAIN', '', box(0, 0), secs);
no(repeatedItemHeading(secs[1].children[0], body), 'an h2 in one of three stacked <section>s');

// A list item's heading is a label whatever the layout — a <ul> of one still reads as a list.
const li = el('LI', 'row', box(0, 0), [el('H3', '', box(0, 0))]);
el('UL', 'list', box(0, 0), [li]);
yes(repeatedItemHeading(li.children[0], body), 'a heading inside an <li>');

// Two cards side by side are not yet a collection — the >= 3 floor keeps a two-column feature block
// (each with a real heading and real copy) firing normally.
const pairKids = [personCard(0, 0), personCard(0, 320)];
el('DIV', 'pair', box(0, 0), pairKids);
no(repeatedItemHeading(pairKids[0].children[0].children[0], body), 'one of only two side-by-side cards');

// An unrendered template row is not a peer: three real cards plus a hidden one still needs three real.
const withHidden = [personCard(0, 0), personCard(0, 320)];
const hidden = personCard(0, 640);
hidden._rect = null;
withHidden.push(hidden);
el('DIV', 'grid', box(0, 0), withHidden);
no(repeatedItemHeading(withHidden[0].children[0].children[0], body), 'two rendered cards plus a hidden template');

// Depth guard: a heading buried five wrappers below the repeated card must not reach it, or the walk
// would eventually find SOME repetition on any real page.
let deep = el('H4', 'x', box(0, 0));
let wrap = deep;
for (let i = 0; i < 5; i++) wrap = el('DIV', 'w' + i, box(0, 0), [wrap]);
const deepKids = [el('DIV', 'card', box(0, 0), [wrap]), personCard(0, 320), personCard(0, 640)];
el('DIV', 'grid', box(0, 0), deepKids);
no(repeatedItemHeading(deep, body), 'a heading five wrappers inside a card');

console.log(bad ? 'FAILURES: ' + bad : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn a_card_title_in_a_grid_is_a_label_not_a_promise() {
    let dir = std::env::temp_dir().join("uxlint-collector-card-heading");
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
