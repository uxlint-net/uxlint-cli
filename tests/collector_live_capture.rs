//! Behavioural gate on `isLiveCapture` in `assets/collector.js` — the guard that keeps a live camera
//! feed out of `autoplayNoControl`, which is the whole input to the server's `autoplay-motion` rule.
//!
//! Reported from the field on 2026-08-31: the flagged autoplaying video was a real-time local camera
//! self-view in a video-conferencing surface. The user starts it explicitly and governs it with the
//! call's own mute and camera controls, and the advice the rule gives — add playback controls, honour
//! prefers-reduced-motion — would make the feature worse, because a frozen self-view is a broken one.
//!
//! The predicate is lifted out of the shipped collector rather than copied, so a change to it fails
//! here.

use std::process::Command;

const DRIVER: &str = r#"
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const m = src.match(/\tfunction isLiveCapture[\s\S]*?\n\t\}/);
if (!m) throw new Error('collector has no isLiveCapture — did the live-stream guard get renamed?');
const isLiveCapture = eval('(' + m[0] + ')');

let bad = 0;
const fail = (msg) => { bad++; console.log('FAIL: ' + msg); };
const yes = (got, what) => { if (!got) fail(what + ' — expected a LIVE stream'); };
const no  = (got, what) => { if (got)  fail(what + ' — expected an ordinary media file'); };

// A <video>/<audio> as the predicate sees it: attributes, an optional <source>, a readyState.
const media = ({ srcObject, src, source, readyState }) => ({
	srcObject: srcObject || null,
	readyState: readyState || 0,
	getAttribute: (k) => (k === 'src' ? (src || null) : null),
	querySelector: (sel) => (sel === 'source[src]' && source ? {} : null),
});

// THE report: a camera self-view. getUserMedia hands you a MediaStream, attached via srcObject.
yes(isLiveCapture(media({ srcObject: { id: 'stream' } })), 'a camera feed attached via srcObject');
// A remote peer's video in the same call — same shape, same answer.
yes(isLiveCapture(media({ srcObject: { id: 'peer' }, readyState: 4 })), 'a WebRTC remote track');
// A framework that cleared srcObject between renders still leaves a playing element with no file.
yes(isLiveCapture(media({ readyState: 2 })), 'a stream-fed element with no src and data flowing');

// The decorative autoplaying hero this rule exists for: a real file, and it must still be counted.
no(isLiveCapture(media({ src: '/hero.mp4', readyState: 4 })), 'an autoplaying hero video');
no(isLiveCapture(media({ source: true, readyState: 4 })), 'a video with a <source> child');
// An element that has not loaded anything and names no file is NOT evidence of a stream — it is an
// empty <video>, and guessing "live" there would silence the rule on a lazy-loaded hero.
no(isLiveCapture(media({})), 'an empty video element that never started');

console.log(bad ? 'FAILURES: ' + bad : 'ok');
process.exit(bad ? 1 : 0);
"#;

#[test]
fn a_live_camera_feed_is_not_uncontrolled_autoplay() {
    let dir = std::env::temp_dir().join("uxlint-collector-live-capture");
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
