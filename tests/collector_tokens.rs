//! Behavioural gate on the collector's DESIGN-TOKEN value filter (`colorToken` in
//! `assets/collector.js`).
//!
//! `tokens` used to read a fixed list of uxlint's own custom-property names, so it was `{}` on every
//! site with a different vocabulary. Enumerating the site's own custom properties instead moves one
//! decision into the browser — "is this token value a COLOUR?" — and that decision has a silent,
//! poisonous failure mode: a 2D canvas KEEPS ITS PREVIOUS `fillStyle` when handed something that
//! isn't a colour, so the naive version files `--spacing: 4px`, `--radius: 10px` and every easing
//! curve in the map as pure black. Nothing errors; the palette rules just quietly gain a handful of
//! fake declared blacks per page. So it is pinned here, against the SHIPPED source (the functions
//! are lifted out of `assets/collector.js` itself, never copied).
//!
//! Runs the assertions in `node` — no canvas there, so `cctx` is a stand-in that models the one
//! browser behaviour under test (invalid assignment ignored, valid assignment normalised). Like
//! `collector_fsig.rs`, a machine without node says so and skips rather than failing.

use std::process::Command;

/// Lifts `oklabToRgb`, `parseColor` and `colorToken` out of the collector by brace-matching their
/// declarations, hands them a canvas stand-in, and exercises them against a table of cases.
const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
function grab(name) {
	const head = 'function ' + name + '(';
	const i = src.indexOf('\t' + head);
	if (i < 0) throw new Error('collector has no ' + name + ' — did it get renamed?');
	let depth = 0;
	for (let k = src.indexOf('{', i); k < src.length; k++) {
		if (src[k] === '{') depth++;
		else if (src[k] === '}' && !--depth) return src.slice(i, k + 1);
	}
	throw new Error('unbalanced braces in ' + name);
}

// The canvas stand-in. Two behaviours, and they are the whole reason this test exists:
//   1. assigning an INVALID colour leaves fillStyle at its previous value (the trap), and
//   2. assigning a valid one normalises it.
// Deliberately does NOT clamp or reformat rgb() — that keeps the collector's own clamp under test
// rather than the stand-in's.
const NAMED = { white: '#ffffff', black: '#000000', red: '#ff0000', rebeccapurple: '#663399' };
const cctx = {
	_v: '#000000',
	set fillStyle(v) {
		v = String(v).trim();
		const named = NAMED[v.toLowerCase()];
		if (named) { this._v = named; return; }
		if (v.toLowerCase() === 'transparent') { this._v = 'rgba(0, 0, 0, 0)'; return; }
		if (/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(v)) {
			this._v = v.length === 4 ? '#' + v.slice(1).split('').map((c) => c + c).join('') : v.toLowerCase();
			return;
		}
		if (/^rgba?\(/i.test(v) || /^hsla?\(/i.test(v)) { this._v = v; return; }
		/* invalid — keep the previous value, exactly as a real 2D context does */
	},
	get fillStyle() { return this._v; },
};

const m = new Function('cctx', [grab('oklabToRgb'), grab('parseColor'), grab('colorToken')].join('\n')
	+ '\nreturn { parseColor, colorToken };')(cctx);

let bad = 0;
const fail = (msg) => { console.log('FAIL ' + msg); bad++; };
const eq = (v, want) => { const got = m.colorToken(v); if (got !== want) fail(JSON.stringify(v) + ': got ' + JSON.stringify(got) + ', want ' + JSON.stringify(want)); };

// COLOURS — every form a real token set ships, normalised to what the server's parser can read
// (hex and rgb only; a raw oklch() arrives unreadable, which is half of why this landed).
eq('#fbfaf7', 'rgb(251, 250, 247)');
eq('  #fff  ', 'rgb(255, 255, 255)');
eq('rgb(226 222 214)', 'rgb(226, 222, 214)');
eq('white', 'rgb(255, 255, 255)');
eq('rebeccapurple', 'rgb(102, 51, 153)');
// Exactly the value a real Chromium capture produced for `--brand-600: oklch(0.55 0.21 28.5)`.
eq('oklch(0.55 0.21 28.5)', 'rgb(208, 30, 26)');
eq('oklab(0.55 0.15 0.06)', 'rgb(190, 63, 69)');
// Alpha survives, and the rgb triple stays first so a parser that reads only the first three
// numbers still gets the colour.
eq('rgba(0, 0, 0, 0.5)', 'rgba(0, 0, 0, 0.5)');
eq('transparent', 'rgba(0, 0, 0, 0)');

// NOT COLOURS — the trap. Every one of these is a real token from a real design system, and every
// one of them lands as rgb(0, 0, 0) if the two-sentinel probe in colorToken is weakened.
for (const v of [
	'12px', '10px', '0.75rem', '1.5', '600', 'ui-sans-serif, system-ui, sans-serif',
	'cubic-bezier(0.2, 0.8, 0.2, 1)', '0 1px 2px rgba(0,0,0,.18)', 'currentColor', 'inherit',
	'none', 'url(/logo.svg)', '', '   ', 'Menlo, monospace',
]) eq(v, null);

// Hostile / malformed input must be dropped, not sanitised into the map.
eq('x'.repeat(65), null);                 // over the length cap
eq('#fff; --x: red', null);               // a declaration, not a value
eq('{ color: red }', null);

// Out-of-gamut oklch clamps into 0-255 instead of emitting a negative or >255 channel.
const wide = m.colorToken('oklch(0.99 0.4 140)');
if (!/^rgb\((\d{1,3}), (\d{1,3}), (\d{1,3})\)$/.test(wide || '')) fail('out-of-gamut oklch should clamp to a legal rgb(), got ' + JSON.stringify(wide));

console.log(bad ? bad + ' failure(s)' : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn the_design_token_filter_keeps_colours_and_drops_everything_else() {
    let dir = std::env::temp_dir().join("uxlint-tokens-test");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let driver = dir.join("driver.js");
    std::fs::write(&driver, DRIVER).expect("write driver");
    let collector = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/collector.js");

    let out = match Command::new("node").arg(&driver).arg(collector).output() {
        Ok(out) => out,
        // The collector is browser JS; a machine with no node can't run it. Say so loudly rather
        // than failing — CI and the documented gate both have node.
        Err(e) => {
            eprintln!("SKIPPED: node not runnable ({e}) — collector token filter unverified here");
            return;
        }
    };
    assert!(
        out.status.success(),
        "collector design-token filter changed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
