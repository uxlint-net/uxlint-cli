//! Project provenance attached to the report — git sha/branch, machine/runner, and a link to
//! the change under review. All CONVENIENCE metadata, suppressible with `--no-provenance`.
//! Pure/near-pure; `build_audit_request` stays pure over the gathered `AuditProvenance`.

/// Best-effort git provenance of the audited project (the CWD's repo): (short sha, branch).
/// Both `None` when there's no repo or git isn't installed — provenance is a nice-to-have.
pub(crate) fn git_provenance() -> (Option<String>, Option<String>) {
    let run = |args: &[&str]| -> Option<String> {
        let out = std::process::Command::new("git").args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!s.is_empty()).then_some(s)
    };
    (
        run(&["rev-parse", "--short", "HEAD"]),
        run(&["rev-parse", "--abbrev-ref", "HEAD"]),
    )
}

/// Build "the change" link from its parts (pure, so it's unit-testable without touching env vars).
/// Prefers a PR link when `ghref` names one (`refs/pull/<N>/merge` or `/head`, the documented shape
/// of `GITHUB_REF` on a `pull_request`-triggered run) — a PR is more useful to land on than one of
/// its commits. Falls back to a commit link when only `sha` is known. `None` when there isn't even
/// a repo, or a repo with neither a PR ref nor a sha (nothing to link).
fn change_url_from_parts(
    repo: Option<&str>,
    server: &str,
    ghref: Option<&str>,
    sha: Option<&str>,
) -> Option<String> {
    let repo = repo?.trim();
    if repo.is_empty() {
        return None;
    }
    let server = server.trim_end_matches('/');
    if let Some(r) = ghref {
        if let Some(rest) = r.strip_prefix("refs/pull/") {
            let pr = rest.split('/').next().unwrap_or("");
            if !pr.is_empty() && pr.chars().all(|c| c.is_ascii_digit()) {
                return Some(format!("{server}/{repo}/pull/{pr}"));
            }
        }
    }
    let sha = sha?.trim();
    (!sha.is_empty()).then(|| format!("{server}/{repo}/commit/{sha}"))
}

/// Best-effort "what change is this" link for CI runs that didn't pass `--change-url` explicitly.
/// GitHub Actions sets `GITHUB_REPOSITORY`/`GITHUB_SHA`/`GITHUB_REF`/`GITHUB_SERVER_URL`
/// unconditionally on every run (documented default environment variables), so this needs no
/// per-workflow configuration to work. `None` outside GitHub Actions (or any CI that doesn't set
/// these) — the report simply carries no change link, which is the honest answer.
fn change_url_from_env() -> Option<String> {
    let repo = std::env::var("GITHUB_REPOSITORY").ok();
    let server = std::env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".into());
    let ghref = std::env::var("GITHUB_REF").ok();
    let sha = std::env::var("GITHUB_SHA").ok();
    change_url_from_parts(repo.as_deref(), &server, ghref.as_deref(), sha.as_deref())
}

/// Which machine ran this audit, for the report's provenance — so a team can tell a laptop run
/// against staging from a CI run from our hosted worker. `UXLINT_RUNNER` overrides (our hosted
/// audit-worker sets it to "uxlint worker"); otherwise the local machine's hostname.
fn runner() -> String {
    if let Ok(r) = std::env::var("UXLINT_RUNNER") {
        let r = r.trim();
        if !r.is_empty() {
            return r.chars().take(60).collect();
        }
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .or_else(|| std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "unknown".to_string())
        .chars()
        .take(60)
        .collect()
}

/// Project provenance attached to the report: which commit, which branch, which machine, and a link
/// to the change under review. All of it is CONVENIENCE metadata (telling runs apart in the
/// dashboard), and all of it can be suppressed with `--no-provenance` — a branch name or hostname
/// can itself be sensitive. Gathering it touches git/env/hostname; `build_audit_request` stays pure
/// over the gathered value.
#[derive(Debug, Default, Clone)]
pub(crate) struct AuditProvenance {
    pub(crate) git_sha: Option<String>,
    pub(crate) git_branch: Option<String>,
    /// The machine/runner name (or an empty string when suppressed).
    pub(crate) runner: String,
    pub(crate) change_url: Option<String>,
}

impl AuditProvenance {
    /// Gather provenance for this run. `--change-url` (`change_url_flag`) wins when given, else it's
    /// sniffed from GitHub Actions' env. `suppress` (from `--no-provenance`) returns the empty value
    /// so NONE of it leaves the machine.
    pub(crate) fn collect(change_url_flag: Option<&str>, suppress: bool) -> Self {
        if suppress {
            return AuditProvenance {
                runner: String::new(),
                ..Default::default()
            };
        }
        let (git_sha, git_branch) = git_provenance();
        AuditProvenance {
            git_sha,
            git_branch,
            runner: runner(),
            change_url: change_url_flag
                .map(str::to_string)
                .or_else(change_url_from_env),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_url_env_sniff_prefers_the_pr_ref() {
        // GITHUB_REF on a pull_request-triggered run is `refs/pull/<N>/merge` — link to the PR
        // itself (more useful to land on than one of its commits), even though a sha is also known.
        let url = change_url_from_parts(
            Some("acme/site"),
            "https://github.com",
            Some("refs/pull/42/merge"),
            Some("deadbeef"),
        );
        assert_eq!(url.as_deref(), Some("https://github.com/acme/site/pull/42"));
    }

    #[test]
    fn change_url_env_sniff_falls_back_to_the_commit() {
        // A push (not a PR) run: GITHUB_REF names a branch, not a PR — fall back to the commit link.
        let url = change_url_from_parts(
            Some("acme/site"),
            "https://github.com",
            Some("refs/heads/main"),
            Some("deadbeef"),
        );
        assert_eq!(
            url.as_deref(),
            Some("https://github.com/acme/site/commit/deadbeef")
        );
    }

    #[test]
    fn change_url_env_sniff_absent_without_a_repo() {
        // Outside GitHub Actions (or any CI that doesn't set these) there's no repo to link — the
        // report must carry no change link rather than a bogus/partial one.
        assert_eq!(
            change_url_from_parts(None, "https://github.com", None, Some("deadbeef")),
            None
        );
        assert_eq!(
            change_url_from_parts(Some(""), "https://github.com", None, Some("deadbeef")),
            None
        );
        assert_eq!(
            change_url_from_parts(Some("acme/site"), "https://github.com", None, None),
            None
        );
    }

    #[test]
    fn change_url_respects_a_custom_server_url() {
        // GITHUB_SERVER_URL differs on GitHub Enterprise Server — honour it rather than
        // hardcoding github.com.
        let url = change_url_from_parts(
            Some("acme/site"),
            "https://ghe.acme.internal",
            None,
            Some("deadbeef"),
        );
        assert_eq!(
            url.as_deref(),
            Some("https://ghe.acme.internal/acme/site/commit/deadbeef")
        );
    }
}
