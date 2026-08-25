//! Behavioural gate on how the collector decides a role-less element is a DIALOG (`widgetGuess` in
//! `assets/collector.js`), which is the entire input to the server's `widget-missing-role` rule for
//! that kind.
//!
//! The claim the rule then makes is loud — "screen readers announce a generic element where a dialog
//! should be" — and its fix adds `role="dialog" aria-modal="true"`. Get it wrong and a screen reader
//! announces a modal that never opens or closes. That is what happened from the field on
//! 2026-08-23: a design-token rename put the word "drawer" into an always-visible sidebar's utility
//! classes, and a persistent `<aside>` — not dismissible, no focus trap, no overlay — started being
//! reported as a role-less dialog.
//!
//! So the NAME alone can no longer decide it: a landmark is never a dialog, and the name must be
//! corroborated by something that dismisses the thing. This pins that against the SHIPPED source —
//! the predicate and its regexes are lifted out of `assets/collector.js` rather than copied, so a
//! change to them fails here.

use std::process::Command;

/// Lifts `looksLikeDialog` and the two regexes it closes over out of the collector, then exercises
/// the real function against the shapes that matter.
const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
function grab(re, what) {
	const m = src.match(re);
	if (!m) throw new Error('collector has no ' + what + ' — did the dialog guess get renamed?');
	return m[0];
}
const DIALOG_NAME = eval(grab(/\/\\b\(modal\|dialog\|drawer\)\\b\/i/, 'DIALOG_NAME'));
const DIALOG_LANDMARK = eval(grab(/\/\^\(\?:ASIDE\|NAV\|HEADER\|FOOTER\|MAIN\)\$\//, 'DIALOG_LANDMARK'));
const looksLikeDialog = eval('(' + grab(/function looksLikeDialog[\s\S]*?\n\t\}/, 'looksLikeDialog') + ')');

let bad = 0;
const fail = (m) => { bad++; console.log('FAIL: ' + m); };
const yes = (got, what) => { if (!got) fail(what + ' — expected a dialog guess'); };
const no = (got, what) => { if (got) fail(what + ' — expected NO dialog guess'); };

// The field report: a persistent sidebar whose utility classes gained "drawer".
no(looksLikeDialog('ASIDE', 'app-drawer sidebar w-72', 288, false), 'an always-visible <aside> named "drawer"');
// …and it stays clean even if something inside it happens to close something else.
no(looksLikeDialog('ASIDE', 'app-drawer sidebar w-72', 288, true), 'a landmark is never a dialog, dismissible or not');
for (const tag of ['NAV', 'HEADER', 'FOOTER', 'MAIN']) {
	no(looksLikeDialog(tag, 'modal-layer', 800, true), 'a <' + tag.toLowerCase() + '> landmark named like a modal');
}

// A name with nothing behind it is not evidence: the whole point of the fix.
no(looksLikeDialog('DIV', 'drawer-shadow z-40', 420, false), 'a "drawer" with nothing that dismisses it');
no(looksLikeDialog('DIV', 'modal-backdrop-token', 900, false), 'a token named "modal" on undismissible chrome');

// The real thing still guesses: a role-less div, named like a dialog, with a close control.
yes(looksLikeDialog('DIV', 'modal panel', 480, true), 'a role-less modal with a close control');
yes(looksLikeDialog('SECTION', 'c-dialog is-open', 640, true), 'a dialog spelled as a <section>');
yes(looksLikeDialog('DIV', 'side-drawer open', 360, true), 'a genuine dismissible drawer');

// The size floor stands: a 200px-wide chip named "modal-trigger" is not the dialog.
no(looksLikeDialog('DIV', 'modal-trigger', 120, true), 'a control too small to be the dialog itself');

// The vocabulary is unchanged, and still not matched by ordinary words that contain it.
no(looksLikeDialog('DIV', 'dialogue-history', 500, true), 'a "dialogue" transcript is not a dialog');
no(looksLikeDialog('DIV', 'model-picker', 500, true), '"model" is not "modal"');
if (!DIALOG_NAME.test('drawer') || !DIALOG_LANDMARK.test('ASIDE')) fail('the lifted regexes are not the shipped ones');

console.log(bad ? 'FAILURES: ' + bad : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn the_dialog_guess_needs_behaviour_not_a_class_name() {
    let dir = std::env::temp_dir().join("uxlint-collector-widget-guess");
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
