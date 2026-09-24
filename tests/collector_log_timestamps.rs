//! Clock timestamps must preserve ordering; their character offset is not a timestamp.
use std::process::Command;

#[test]
fn clock_times_preserve_chronology_and_reject_invalid_values() {
    let script = r#"
const fs = require('fs');
const source = fs.readFileSync('assets/collector.js', 'utf8');
const start = source.indexOf('const stamp = (k) => {');
const end = source.indexOf('\n\t\t\t\t};', start);
if (start < 0 || end < 0) throw Error('timestamp reader missing');
const stamp = new Function(source.slice(start, end + 7) + '; return stamp;')();
const read = text => stamp({ querySelector: () => null, textContent: text });
for (const [text, expected] of [['12:00 am', 0], ['12:00 pm', 43200], ['1:02:03 pm', 46923], ['23:59', 86340]]) {
  if (read(text) !== expected) throw Error(text + ': ' + read(text));
}
if (!(read('at 09:00') < read('at 14:00') && read('at 14:00') > read('at 10:00'))) throw Error('shuffled rows lost their ordering');
for (const text of ['25:00', '12:75', 'nothing']) if (!Number.isNaN(read(text))) throw Error('invalid time accepted: ' + text);
"#;
    let out = Command::new("node")
        .args(["-e", script])
        .output()
        .expect("node");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
