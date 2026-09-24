//! Is the app answering at `--base` the one this site's audits have been of?
//!
//! Reported from the field on 2026-08-29 as a SAFETY gap: a second project's dev server took the port
//! this project hard-codes (its own first instance had the framework default, so it incremented onto
//! ours). An audit run then would have crawled an unrelated app, filed the report under this site,
//! grepped this project's source for the fixes, and tried the configured persona's credentials
//! against a stranger's login form — all silently, which is worse than a dead socket.
//!
//! So the first fetch of the root is fingerprinted — title, app name, icon, manifest — and compared
//! with what this machine saw the last time it audited this site at this base. A clear mismatch stops
//! the audit BEFORE any browser, credential or report is involved. Deliberately conservative: it only
//! calls a mismatch when at least two signals were present both times and EVERY one of them differs,
//! because a false alarm here blocks a real audit, and one shared signal (the same icon) is enough to
//! say it's plausibly the same app mid-redesign.
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Fingerprint {
    pub title: String,
    /// `application-name`, `og:site_name` or `apple-mobile-web-app-title` — the app's own name for
    /// itself, which survives page-title changes.
    pub app_name: String,
    pub icon: String,
    pub manifest: String,
}

/// The value of `attr` in one tag's source (`<meta name="x" content="y">`), quoted either way.
fn attr(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find(attr) {
        let at = from + i;
        from = at + attr.len();
        // Whole attribute name only: `name` must not match inside `data-name` or `rename`.
        let before_ok = at == 0 || lower.as_bytes()[at - 1].is_ascii_whitespace();
        let rest = lower[from..].trim_start();
        if !before_ok || !rest.starts_with('=') {
            continue;
        }
        let skipped = lower.len() - rest.len() + 1;
        let val = tag[skipped..].trim_start();
        let (q, body) = match val.chars().next()? {
            '"' | '\'' => (val.chars().next()?, &val[1..]),
            _ => (' ', val),
        };
        let end = body.find(|c: char| c == q || (q == ' ' && (c == '>' || c.is_whitespace())));
        return Some(body[..end.unwrap_or(body.len())].trim().to_string());
    }
    None
}

/// Fingerprint a page's HTML. Only the `<head>`-ish tags are read; a malformed page just yields
/// fewer signals, never an error.
pub(crate) fn fingerprint_of(html: &str) -> Fingerprint {
    let mut fp = Fingerprint::default();
    let lower = html.to_ascii_lowercase();
    if let (Some(s), Some(e)) = (lower.find("<title"), lower.find("</title>")) {
        if let Some(gt) = lower[s..].find('>') {
            let start = s + gt + 1;
            if start <= e {
                fp.title = html[start..e]
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
            }
        }
    }
    let mut rest = 0;
    while let Some(i) = lower[rest..].find('<') {
        let s = rest + i;
        let Some(len) = lower[s..].find('>') else {
            break;
        };
        let tag = &html[s..s + len];
        rest = s + len;
        let tl = &lower[s..s + len];
        if tl.starts_with("<meta") && fp.app_name.is_empty() {
            let key = attr(tag, "name")
                .or_else(|| attr(tag, "property"))
                .unwrap_or_default();
            if matches!(
                key.to_ascii_lowercase().as_str(),
                "application-name" | "og:site_name" | "apple-mobile-web-app-title"
            ) {
                fp.app_name = attr(tag, "content").unwrap_or_default();
            }
        } else if tl.starts_with("<link") {
            let rel = attr(tag, "rel").unwrap_or_default().to_ascii_lowercase();
            let href = attr(tag, "href").unwrap_or_default();
            if rel.split_whitespace().any(|r| r == "icon") && fp.icon.is_empty() {
                fp.icon = href;
            } else if rel == "manifest" && fp.manifest.is_empty() {
                fp.manifest = href;
            }
        }
    }
    fp
}

/// `Some(the signals that differ)` when `now` is clearly a DIFFERENT app from `before`: at least two
/// signals present on both sides, and none of them equal. Anything less is not evidence enough to
/// block an audit, so it is `None`.
pub(crate) fn different_app(before: &Fingerprint, now: &Fingerprint) -> Option<Vec<String>> {
    let pairs = [
        ("title", &before.title, &now.title),
        ("app name", &before.app_name, &now.app_name),
        ("icon", &before.icon, &now.icon),
        ("manifest", &before.manifest, &now.manifest),
    ];
    let both: Vec<_> = pairs
        .iter()
        .filter(|(_, a, b)| !a.is_empty() && !b.is_empty())
        .collect();
    if both.len() < 2 || both.iter().any(|(_, a, b)| a == b) {
        return None;
    }
    Some(
        both.iter()
            .map(|(what, a, b)| format!("{what}: was \"{a}\", now \"{b}\""))
            .collect(),
    )
}

/// `~/.cache/uxlint/targets.json` (XDG_CACHE_HOME honoured) — where this machine remembers each
/// site's fingerprint. Local on purpose: the port collision this guards against is a property of one
/// machine, and a hosted worker (a fresh container per job) simply never has a prior to compare.
fn cache_file() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache")))?;
    Some(base.join("uxlint").join("targets.json"))
}

/// Fetch `base`'s root anonymously and compare it with what this machine last saw for `site` there.
/// `Err` (with the message to show) only on a clear mismatch; a fetch failure, a first sighting or an
/// inconclusive comparison all proceed — and a same-app or first sighting is recorded for next time.
/// `accept` (`--accept-target`) records the new fingerprint without comparing.
pub(crate) fn check_target(base: &str, site: Option<&str>, accept: bool) -> Result<(), String> {
    let Some(path) = cache_file() else {
        return Ok(());
    };
    let Ok(http) = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    else {
        return Ok(());
    };
    let Some(html) = http
        .get(base)
        .send()
        .ok()
        .filter(|r| r.status().is_success())
        .and_then(|r| r.text().ok())
    else {
        return Ok(()); // unreachable targets fail on their own, with a better message, in the crawl
    };
    let now = fingerprint_of(&html);
    let key = format!("{}|{}", site.unwrap_or(""), base.trim_end_matches('/'));
    let mut all: std::collections::BTreeMap<String, Fingerprint> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if !accept {
        if let Some(diff) = all.get(&key).and_then(|before| different_app(before, &now)) {
            return Err(format!(
                "the app answering at {base} doesn't look like the one this machine last audited as {} — \
                 {}.\n\nStopped before opening a browser, sending any credentials or filing a report: \
                 another project's dev server may have taken this port. If this IS your app now (it was \
                 renamed or re-branded), re-run with --accept-target to record it, or delete its entry in \
                 {}.",
                site.unwrap_or("this site"),
                diff.join("; "),
                path.display()
            ));
        }
    }
    all.insert(key, now);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(s) = serde_json::to_string_pretty(&all) {
        let _ = std::fs::write(&path, s);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: &str = r#"<!doctype html><html><head><title>H3 Director</title>
        <meta name="application-name" content="H3"><link rel="icon" href="/favicon.svg">
        <link rel="manifest" href="/site.webmanifest"></head><body></body></html>"#;

    #[test]
    fn reads_the_signals_an_app_names_itself_with() {
        let fp = fingerprint_of(OURS);
        assert_eq!(fp.title, "H3 Director");
        assert_eq!(fp.app_name, "H3");
        assert_eq!(fp.icon, "/favicon.svg");
        assert_eq!(fp.manifest, "/site.webmanifest");
        // og:site_name counts, unquoted attributes parse, and `data-name` is not `name`.
        let fp = fingerprint_of(
            r#"<meta data-name="x" property=og:site_name content=Acme><link rel="shortcut icon" href=/i.png>"#,
        );
        assert_eq!((fp.app_name.as_str(), fp.icon.as_str()), ("Acme", "/i.png"));
    }

    /// THE 2026-08-29 report: someone else's dev server on our port.
    #[test]
    fn another_app_on_the_same_port_is_caught() {
        let theirs = fingerprint_of(
            r#"<title>Vite + React</title><link rel="icon" type="image/svg+xml" href="/vite.svg">"#,
        );
        let diff = different_app(&fingerprint_of(OURS), &theirs).expect("a different app");
        assert!(diff.iter().any(|d| d.contains("Vite + React")), "{diff:?}");
    }

    /// A false alarm blocks a real audit, so anything short of clear evidence proceeds.
    #[test]
    fn the_same_app_mid_redesign_is_not_blocked() {
        let ours = fingerprint_of(OURS);
        // New title, same icon: plausibly the same app.
        let retitled = Fingerprint {
            title: "H3 — Films".into(),
            ..ours.clone()
        };
        assert_eq!(different_app(&ours, &retitled), None);
        // Only ONE comparable signal: not enough to call it.
        let sparse = fingerprint_of("<title>Something else</title>");
        assert_eq!(different_app(&ours, &sparse), None);
        // Nothing known before (first sighting): nothing to compare.
        assert_eq!(different_app(&Fingerprint::default(), &ours), None);
    }
}
