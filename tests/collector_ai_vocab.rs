//! Behavioural gate on how the collector decides a control is an AI-GENERATION control
//! (`aiGenControls` in `assets/collector.js`), which is the entire input to the server's
//! `manual-alternative` rule.
//!
//! The rule's claim is strong — "there is no way to author this by hand" — so the evidence has to be
//! too. Two words in that vocabulary are not: "ai" and "magic" collide with ordinary product
//! language ("Send magic link" on any passwordless sign-in, "Magic: The Gathering" on a card-game
//! site, any product or set name containing either). One such page reported the rule wrong from the
//! field: three buttons on a page with no generated content anywhere were read as AI controls, and
//! the finding asked its author to add hand-authoring to a workflow that was already entirely by
//! hand.
//!
//! So weak vocabulary counts only where STRONG evidence — a generation verb or a wand/robot glyph —
//! is also present on the page. This pins that rule against the SHIPPED source: the regexes are
//! lifted out of `assets/collector.js` rather than copied, so a change to them fails here.

use std::process::Command;

/// Lifts the three AI vocabulary literals out of the collector and re-implements ONLY the counting
/// line they feed (`strongHits + (strongHits > 0 ? weakHits : 0)`), then exercises both against a
/// table of real-world control names.
const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
function grabConst(name) {
	const m = src.match(new RegExp('const ' + name + ' = (/.*?/[a-z]*);'));
	if (!m) throw new Error('collector has no ' + name + ' — did the AI vocabulary get renamed?');
	return eval(m[1]);
}
const AI_STRONG = grabConst('AI_STRONG');
const AI_WEAK = grabConst('AI_WEAK');
const AI_GLYPH = grabConst('AI_GLYPH');

// The shipped counting rule, mirrored: weak names count only alongside strong evidence.
function countAi(names) {
	let strong = 0, weak = 0;
	for (const n of names) {
		if (AI_GLYPH.test(n) || AI_STRONG.test(n)) strong++;
		else if (AI_WEAK.test(n)) weak++;
	}
	return strong + (strong > 0 ? weak : 0);
}

let bad = 0;
const fail = (m) => { bad++; console.log('FAIL: ' + m); };
const eq = (got, want, what) => { if (got !== want) fail(what + ' — expected ' + want + ', got ' + got); };

// The field report: a card-game page whose buttons carry set names and "Draft this set". No
// generated content anywhere, so nothing may be counted.
eq(countAi([
	'Bloomburrow BLB · 2024 · 261 cards Draft this set →',
	'Duskmourn: House of Horror DSK · 2024 · 276 cards Draft this set →',
	'Aetherdrift DFT · 2025 · 291 cards Draft this set →',
]), 0, 'a card-game draft page is not an AI workflow');

// Weak words alone, on pages that have nothing to do with generation.
eq(countAi(['Send magic link', 'Sign in']), 0, 'passwordless sign-in is not AI generation');
eq(countAi(['Search every Magic card', 'Build a deck']), 0, 'a game name is not AI generation');

// Strong evidence stands on its own…
eq(countAi(['Generate summary', 'Regenerate']), 2, 'generation verbs are strong evidence');
eq(countAi(['✨ Draft with AI']), 1, 'a wand glyph is strong evidence');
eq(countAi(['Magic eraser']), 1, 'magic + a generation verb is strong');

// …and once it is present, the weak names on the same page are counted too — that page really is
// an AI surface, and "AI settings" beside "Regenerate" is part of it.
eq(countAi(['Regenerate', 'AI settings', 'Magic fill']), 3, 'weak names count alongside strong ones');

console.log(bad ? bad + ' failure(s)' : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn ai_control_detection_needs_more_than_a_colliding_word() {
    let dir = std::env::temp_dir().join("uxlint-ai-vocab-test");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let driver = dir.join("driver.js");
    std::fs::write(&driver, DRIVER).expect("write driver");
    let collector = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/collector.js");

    let out = match Command::new("node").arg(&driver).arg(collector).output() {
        Ok(out) => out,
        // The collector is browser JS; a machine with no node can't run it. Say so loudly rather
        // than failing — CI and the documented gate both have node.
        Err(e) => {
            eprintln!("SKIPPED: node not runnable ({e}) — AI vocabulary unverified here");
            return;
        }
    };
    assert!(
        out.status.success(),
        "collector AI-control detection changed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
