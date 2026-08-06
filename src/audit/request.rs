//! Assembles the exact `/v1/audit` POST body. `build_audit_request` is pure and is the one place
//! the upload payload is defined, so a reviewer can read it to see everything the client sends.
//! `write_dry_run` dumps that same payload to disk instead of sending it.

use super::provenance::AuditProvenance;
use crate::progress::{note, Progress};
use anyhow::Result;
use serde_json::{json, Value};

/// Everything the audit is about to POST, gathered in one place so `build_audit_request` can render
/// the exact body a reviewer would want to inspect — "here is everything we send to the server".
/// Deliberately borrows its inputs; it holds no credentials, headers, or storage values (those drive
/// the browser only and never reach here — the `no_credentials_in_payload` test guards that).
pub(crate) struct AuditRequestInputs<'a> {
    pub(crate) base_url: &'a str,
    pub(crate) org: Option<&'a str>,
    pub(crate) site: Option<&'a str>,
    pub(crate) pages: &'a [Value],
    pub(crate) tests: &'a [Value],
    pub(crate) anon_checks: &'a [Value],
    pub(crate) login_discoverable: bool,
    pub(crate) no_judge: bool,
    pub(crate) nf_probe: &'a Value,
    pub(crate) favicon_status: Option<i64>,
    pub(crate) back_probe: &'a Value,
    pub(crate) open_redirect: &'a Value,
    /// Styleguide existence probe ({path, present}) — whether a real page lives at the conventional
    /// (or configured) styleguide path. Clears `styleguide-missing` for an unlinked design-system page.
    pub(crate) styleguide: &'a Value,
    pub(crate) bot_blocked_routes: &'a [String],
    pub(crate) labels: &'a [String],
    pub(crate) timed_out: bool,
    pub(crate) timeout_detail: Option<&'a Value>,
    pub(crate) provenance: &'a AuditProvenance,
    pub(crate) theme: Option<&'a Value>,
    pub(crate) site_type: Option<&'a str>,
    /// `desktop_only` route globs (uxlint.toml) — the server demotes findings on these routes at a
    /// below-desktop width to `info`. Empty ⇒ every route is graded at every viewport as before.
    pub(crate) desktop_only: &'a [String],
}

/// Assemble the exact JSON body POSTed to `/v1/audit`. THE single visible place where the upload
/// payload is defined — pure (no IO), so `--dry-run` can print it and tests can assert exactly which
/// fields ride to the server and that no credential ever does.
pub(crate) fn build_audit_request(i: &AuditRequestInputs) -> Value {
    json!({
        "base_url": i.base_url,
        "pages": i.pages,
        "org": i.org,
        "site": i.site,
        "tests": i.tests,
        "anon_checks": i.anon_checks,
        "login_discoverable": i.login_discoverable,
        "no_judge": i.no_judge,
        "nf_probe": i.nf_probe,
        "favicon_status": i.favicon_status,
        "back_probe": i.back_probe,
        "open_redirect": i.open_redirect,
        "styleguide": i.styleguide,
        "bot_blocked_routes": i.bot_blocked_routes,
        "labels": i.labels,
        "timed_out": i.timed_out,
        "timeout_detail": i.timeout_detail,
        // The CLI/collector version behind this capture. Always sent (NOT suppressed by
        // --no-provenance): it's not identifying provenance, it's the tool version, and the server
        // records it so a stale hosted worker (an old collector) is visible on the report at a glance.
        "cli_version": env!("CARGO_PKG_VERSION"),
        // Provenance (suppressible via --no-provenance — then these are null/empty).
        "git_sha": i.provenance.git_sha,
        "git_branch": i.provenance.git_branch,
        "runner": i.provenance.runner,
        "change_url": i.provenance.change_url,
        "theme": i.theme,
        "site_type": i.site_type,
        "desktop_only": i.desktop_only,
    })
}

/// `--dry-run`: write the exact `/v1/audit` payload to `dir` and return WITHOUT sending anything to
/// the server. Screenshots (base64 JPEG) are split out into viewable `.jpg` files next to a
/// `request.json` whose `screenshot` fields point at them — so a reviewer can open the pictures AND
/// read every text field that would upload. Returns a small marker report (the caller skips the
/// normal report print for a dry run).
pub(crate) fn write_dry_run(
    payload: &Value,
    dir: &std::path::Path,
    progress: &(dyn Progress + Sync),
) -> Result<Value> {
    use base64::Engine as _;
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("--dry-run: couldn't create {}: {e}", dir.display()))?;
    let mut out = payload.clone();
    let mut shots_written = 0usize;
    if let Some(pages) = out.get_mut("pages").and_then(Value::as_array_mut) {
        for (idx, page) in pages.iter_mut().enumerate() {
            let route = page.get("route").and_then(Value::as_str).unwrap_or("route");
            let viewport = page.get("viewport").and_then(Value::as_str).unwrap_or("vp");
            let slug: String = route
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect();
            let Some(shot_b64) = page.get("screenshot").and_then(Value::as_str) else {
                continue;
            };
            if shot_b64.is_empty() {
                continue;
            }
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(shot_b64) {
                let fname = format!("page-{idx:02}-{viewport}-{slug}.jpg");
                if std::fs::write(dir.join(&fname), &bytes).is_ok() {
                    // Replace the giant base64 blob with a pointer to the JPEG so request.json stays
                    // readable while still showing that a screenshot WOULD be sent for this page.
                    page["screenshot"] = json!(format!("(screenshot → {fname})"));
                    shots_written += 1;
                }
            }
        }
    }
    let req_path = dir.join("request.json");
    std::fs::write(
        &req_path,
        serde_json::to_string_pretty(&out).unwrap_or_default(),
    )
    .map_err(|e| anyhow::anyhow!("--dry-run: couldn't write {}: {e}", req_path.display()))?;
    let page_count = out
        .get("pages")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    {
        let st = crate::style::Stream::Err;
        note!(
            progress,
            "\n{}  {}",
            st.header("▸ dry run"),
            st.bold("nothing was sent to the server")
        );
        note!(
            progress,
            "{}",
            st.dim(&format!(
                "  wrote the exact POST body to {} ({page_count} page(s), {shots_written} screenshot(s))",
                req_path.display()
            ))
        );
        note!(
            progress,
            "{}",
            st.dim("  review request.json + the .jpg files to see precisely what an audit would upload")
        );
    }
    Ok(json!({
        "dry_run": true,
        "output_dir": dir.display().to_string(),
        "pages": page_count,
        "screenshots": shots_written,
    }))
}
