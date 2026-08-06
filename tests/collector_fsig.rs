//! Behavioural gate on the collector's COMPONENT-FAMILY signature (`fsig` in `assets/collector.js`).
//!
//! `fsig` is a judgement call made in browser JS — "is this class token a generated hash, a state, a
//! variant of one component?" — and its failure mode is silent: over-collapse files two genuinely
//! different components under one root cause, and nobody notices until a report blames the wrong
//! component. So the rules are pinned here, against the SHIPPED source (the functions are lifted out
//! of `assets/collector.js` itself, never copied), with as much weight on what must NOT merge as on
//! what must.
//!
//! Runs the assertions in `node`, which the collector's own syntax gate (`node --check
//! assets/collector.js`) already requires; if node isn't on PATH the test says so and skips rather
//! than failing a Rust-only machine.

use std::process::Command;

/// The driver: lifts `STATE_CLASS`, `GENERIC_STUB`, `hashish`, `familyToken`, `sigOf`, `esig` and
/// `fsig` out of the collector by brace-matching their declarations, then exercises them against a
/// table of cases. Prints one line per failure and exits non-zero if there were any.
const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
function grab(name, kind) {
	const head = kind === 'fn' ? 'function ' + name + '(' : 'const ' + name + ' =';
	const i = src.indexOf('\t' + head);
	if (i < 0) throw new Error('collector has no ' + name + ' — did it get renamed?');
	if (kind !== 'fn') return src.slice(i, src.indexOf('\n', i));
	let depth = 0;
	for (let k = src.indexOf('{', i); k < src.length; k++) {
		if (src[k] === '{') depth++;
		else if (src[k] === '}' && !--depth) return src.slice(i, k + 1);
	}
	throw new Error('unbalanced braces in ' + name);
}
const m = new Function([
	grab('STATE_CLASS', 'const'), grab('GENERIC_STUB', 'const'), grab('sigOf', 'fn'),
	grab('esig', 'fn'), grab('hashish', 'fn'), grab('familyToken', 'fn'), grab('fsig', 'fn'),
].join('\n') + '\nreturn { hashish, familyToken, esig, fsig };')();

let bad = 0;
const fail = (msg) => { console.log('FAIL ' + msg); bad++; };
const eq = (got, want, msg) => { if (got !== want) fail(msg + ': got ' + JSON.stringify(got) + ', want ' + JSON.stringify(want)); };

// A generated hash must be recognised as one …
for (const t of ['1qz9irk', 'lz0uxg', 'tbnvsp', 'x1y2', 'hXlPTf', 'kQwWXy', 'iJKvXn', 'pqjvzy'])
	if (!m.hashish(t)) fail('hashish(' + t + ') should be true');
// … and a NAME must never be, or the family signature starts eating real component identity.
for (const t of ['root', 'base', 'body', 'flex', 'card', 'header', 'active', 'Button', 'MuiChip',
	'hStack', 'navBar', 'sizeSmall', 'colorSuccess', 'containedPrimary', 'elevation0', 'bp4', 'col6'])
	if (m.hashish(t)) fail('hashish(' + t + ') should be false');

// Token reduction: hashes and states go, identity stays.
eq(m.familyToken('css-1qz9irk'), '', 'emotion class dropped');
eq(m.familyToken('hXlPTf'), '', 'styled-components style class dropped');
eq(m.familyToken('active'), '', 'state class dropped');
eq(m.familyToken('is-open'), '', 'is- state class dropped');
eq(m.familyToken('sc-gzVnrw'), 'sc-gzVnrw', 'styled-components componentId kept');
eq(m.familyToken('svelte-1x2abc'), 'svelte-1x2abc', 'svelte component id kept');
eq(m.familyToken('Button_root__x1y2'), 'Button-root', 'CSS-Modules hash suffix stripped');
eq(m.familyToken('MuiChip-root'), 'MuiChip-root', 'library component class kept');
eq(m.familyToken('nav-link'), 'nav-link', 'hand-written class kept');
eq(m.familyToken('card-header'), 'card-header', 'BEM element kept when its block is absent');

// Minimal element stand-in — exactly the surface esig/fsig read.
const el = (tag, cls, kids) => ({
	tagName: tag.toUpperCase(),
	children: (kids || []).map((k) => el(k, '')),
	getAttribute: (a) => (a === 'class' ? cls : null),
	hasAttribute: () => false,
});
const same = (a, b, msg) => { if (m.fsig(a) !== m.fsig(b)) fail(msg + ': should share one family'); };
const apart = (a, b, msg) => { if (m.fsig(a) === m.fsig(b)) fail(msg + ': must NOT share a family'); };

// MERGE — one component, several renderings.
const chip = (tone, hash) => el('span', 'MuiChip-root MuiChip-sizeSmall MuiChip-color' + tone + ' ' + hash + ' css-1yjs9ne');
same(chip('Warning', 'css-b3n7ha'), chip('Success', 'css-9rr4ap'), 'chip colour props');
same(chip('Warning', 'css-b3n7ha'), chip('Default', 'css-lz0uxg'), 'chip default tone');
same(el('a', 'sc-gzVnrw iJKvXn'), el('a', 'sc-gzVnrw iJKvXn kQwWXy'), 'active nav item');
same(el('a', 'nav-link'), el('a', 'nav-link is-active'), 'active nav item (hand-written)');
same(el('a', 'btn btn-primary'), el('a', 'btn btn-outline-primary btn-lg'), 'button variants');
same(el('button', 'MuiButtonBase-root MuiButton-root MuiButton-containedPrimary css-1qz9irk'),
	el('button', 'MuiButtonBase-root MuiButton-root MuiButton-outlinedNeutral css-9tvbxr'), 'MUI button variants');
// Coverage dedupe still keeps the variants apart — the two signatures must NOT collapse into one.
if (m.esig(chip('Warning', 'css-b3n7ha')) === m.esig(chip('Success', 'css-9rr4ap')))
	fail('esig must still separate a warning chip from a success chip');

// DO NOT MERGE — the expensive mistake. Each pair is two different components.
apart(el('div', 'card'), el('div', 'card-header'), 'card vs card-header');
apart(el('div', 'MuiPaper-root css-1ptxhkd'), el('div', 'MuiPaper-root MuiStatCard-root css-1ptxhkd'), 'paper vs stat card');
apart(el('div', 'css-abc123'), el('div', 'css-def456'), 'two hash-only components');
apart(el('span', 'current'), el('span', ''), 'state-only class vs no class at all');
apart(el('a', 'bg-brand text-white'), el('a', 'bg-surface text-ink'), 'two tailwind treatments');
apart(el('a', 'MuiButton-root'), el('button', 'MuiButton-root'), 'link vs button');
apart(el('div', 'stat', ['span']), el('div', 'stat', ['svg', 'span']), 'different child shape');

// With nothing generated, stateful or variant-shaped in the class set, fsig must equal esig — that
// identity is what lets the capture omit the field entirely and cost no bytes on most sites (it held
// for every element of 13 of the 15 clean-corpus sites when this landed).
for (const c of ['panel', 'nav-link', '', 'grid gap-4 md:grid-cols-2', 'MuiChip-root'])
	if (m.fsig(el('div', c)) !== m.esig(el('div', c))) fail('fsig should equal esig for: ' + JSON.stringify(c));

console.log(bad ? bad + ' failure(s)' : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn the_component_family_signature_merges_variants_but_never_components() {
    let dir = std::env::temp_dir().join("uxlint-fsig-test");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let driver = dir.join("driver.js");
    std::fs::write(&driver, DRIVER).expect("write driver");
    let collector = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/collector.js");

    let out = match Command::new("node").arg(&driver).arg(collector).output() {
        Ok(out) => out,
        // The collector is browser JS; a machine with no node can't run it. Say so loudly rather
        // than failing — CI and the documented gate both have node.
        Err(e) => {
            eprintln!(
                "SKIPPED: node not runnable ({e}) — collector fsig behaviour unverified here"
            );
            return;
        }
    };
    assert!(
        out.status.success(),
        "collector fsig behaviour changed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
