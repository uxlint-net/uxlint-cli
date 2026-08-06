//! CLI update notice + `uxlint update` self-update. Reads **GitHub Releases**, the channel the
//! release workflow actually publishes to (`.github/workflows/release.yml` → `softprops/action-gh-release`):
//!   * the newest version comes from `GET {api}/repos/{repo}/releases/latest` → `tag_name`;
//!   * a pinned release's artifact is `{origin}/{repo}/releases/download/v{version}/uxlint-{target}.tar.gz`,
//!     the newest release's is `{origin}/{repo}/releases/latest/download/uxlint-{target}.tar.gz`,
//!     and each has a `.sha256` sidecar beside it.
//!
//! `web/static/install.sh` is the reference client for this same channel — this module mirrors its
//! origin/repo defaults, its os/arch → asset-name mapping, and its download →
//! verify-before-touching-disk → install discipline.
//!
//! This module USED to read a self-hosted channel (`{origin}/releases/latest.json`, served by a
//! since-deleted `server/src/releases.rs`). That channel died with the WP41 split — it only existed
//! while the repo was private — so `uxlint update` could not install anything at all. `install.sh`
//! was migrated to GitHub Releases at the split and this module was not; pointing both at one
//! channel is the whole point of this rework, so if you change the layout here, change it there too.
//!
//! The default origin was also `uxlint.dev`, which IS NOT OUR DOMAIN — we are uxlint.net. That made
//! the (dead) update path point at a third party, and it is why every default in this file is now
//! pinned to github.com / uxlint.net explicitly. Do not reintroduce `uxlint.dev` anywhere.
//!
//! PRIVACY (this CLI is public — see TRUST-AUDIT.md): the background notice is a single anonymous
//! `GET` of a PUBLIC JSON endpoint. It sends no version, no machine id, and no identifying header —
//! only a static `User-Agent: uxlint` (deliberately WITHOUT the version, so the request says nothing
//! about this run or this machine), which GitHub's API rejects requests for lacking.
//! It is opt-out (`UXLINT_NO_UPDATE_CHECK=1` or uxlint.toml's `update_check = false`), silent in CI
//! and whenever stderr isn't a terminal, never blocks (short timeout), and never fails the calling
//! command — any error (network, parse, cache I/O) is swallowed and the command proceeds exactly
//! as if the check had been skipped.
//!
//! `uxlint update` verifies the downloaded tarball's sha256 BEFORE touching the installed binary —
//! a mismatch aborts leaving it untouched — and only ever executes the local `tar` binary against a
//! file *this process* downloaded and hashed; it never runs anything the server tells it to run.
//! `--to <version>` pins WHICH release that is; the version string is validated to be exactly
//! `MAJOR.MINOR.PATCH` before it is interpolated into a URL (`sanitize_version`), so a pinned
//! update can still only ever reach a release artifact under our own origin — the server names a
//! version, never a URL and never a command.
//!
//! ALIGNMENT (`alignment` + `print_server_alignment`): separate from the notice above and pointed
//! somewhere else entirely. The notice asks "is there a newer public release?"; alignment asks "am
//! I the CLI THE SERVER THIS RUN POINTS AT expects?" — which may be an OLDER release (a self-hosted
//! or enterprise deployment pinned back) and is never simply "the latest". The answer rides along
//! on the `/v1/me` the audit already pre-flights (`audit::setup::fetch_me`), costing no extra round
//! trip, and it stays silent unless it has something true and useful to say: a dev/local server, a
//! server too old to have an opinion, or a CLI at-or-ahead of the expected version all print
//! nothing, because a check that nags on every local run is a check developers turn off.

use anyhow::{bail, Context, Result};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The host release artifacts are downloaded from — GitHub, matching `install.sh`'s
/// `UXLINT_INSTALL_ORIGIN` default. Overridable via `UXLINT_UPDATE_ORIGIN` so the mock server used
/// in local verification (and CI, one day) can point this at a non-production origin.
pub(crate) fn update_origin() -> String {
    std::env::var("UXLINT_UPDATE_ORIGIN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://github.com".to_string())
}

/// `owner/name` of the public repo the releases hang off — `install.sh`'s `UXLINT_INSTALL_REPO`.
fn update_repo() -> String {
    std::env::var("UXLINT_UPDATE_REPO")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "uxlint-net/uxlint-cli".to_string())
}

/// GitHub's API host, which is a DIFFERENT host from the download origin — so the mock-server
/// override has to be its own knob rather than being derived from `update_origin`.
fn update_api() -> String {
    std::env::var("UXLINT_UPDATE_API")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://api.github.com".to_string())
}

/// Where `install.sh` is served, for the "or reinstall with the one-liner" half of the notice. NOT
/// derived from `update_origin` any more: artifacts come from github.com, the script does not.
const INSTALL_SCRIPT_URL: &str = "https://uxlint.net/install.sh";

/// The release asset URL for a platform, pinned to `version` or resolved to whatever is newest.
/// Pure, so the two layouts — GitHub's `releases/download/v{version}/{asset}` for a pinned tag and
/// its `releases/latest/download/{asset}` redirect otherwise — are unit-testable without a network.
/// Note the `v` prefix: the tags are `v0.1.11` while every version we handle internally is bare.
fn asset_url(origin: &str, repo: &str, target: &str, version: Option<&str>) -> String {
    let base = origin.trim_end_matches('/');
    match version {
        Some(v) => format!("{base}/{repo}/releases/download/v{v}/uxlint-{target}.tar.gz"),
        None => format!("{base}/{repo}/releases/latest/download/uxlint-{target}.tar.gz"),
    }
}

const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Once-a-day cache of the update check, so a normal run doesn't hit the network every time.
/// `~/.cache/uxlint/update-check.json` (XDG_CACHE_HOME honoured) — mirrors where the test-outcome
/// cache lives (`audit.rs::test_cache_file`), just a different leaf file instead of a subdir.
fn cache_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    Some(base.join("uxlint").join("update-check.json"))
}

/// Cache contents: (unix seconds of the last actual fetch, newest version last observed — `None`
/// until a fetch has ever succeeded). Plain `serde_json::Value`, not a derived struct — matches how
/// every other piece of client-local JSON state in this crate is handled (no serde-derive types).
fn read_cache(path: &Path) -> Option<(u64, Option<String>)> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    Some((
        v["last_check"].as_u64().unwrap_or(0),
        v["latest"].as_str().map(str::to_string),
    ))
}

fn write_cache(path: &Path, last_check: u64, latest: Option<&str>) {
    // Best-effort only — a failure here (read-only cache dir, disk full) must never surface as a
    // command failure; the next run just re-checks.
    if let Some(dir) = path.parent() {
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    let v = serde_json::json!({ "last_check": last_check, "latest": latest });
    let _ = std::fs::write(path, v.to_string());
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const ONE_DAY_SECS: u64 = 24 * 60 * 60;

/// Is a fresh network check due, given when the cache says the last one ran? Pure so the once/day
/// cadence is unit-testable without touching the filesystem or a clock.
fn check_due(last_check: Option<u64>, now: u64) -> bool {
    match last_check {
        None => true,
        Some(t) => now.saturating_sub(t) >= ONE_DAY_SECS,
    }
}

/// Should the notice (network check AND print) be skipped entirely? Pure decision over
/// already-read signals — no env/tty reads in here — so every combination is unit-testable without
/// mutating process-global state.
fn skip_notice(env_opt_out: bool, toml_disabled: bool, ci_env: bool, stderr_is_tty: bool) -> bool {
    env_opt_out || toml_disabled || ci_env || !stderr_is_tty
}

fn env_opt_out() -> bool {
    std::env::var("UXLINT_NO_UPDATE_CHECK")
        .map(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

/// Generic CI detection: `CI` is the one env var essentially every CI system sets (GitHub Actions,
/// GitLab, CircleCI, Travis, Buildkite, …) — good enough to silence unsolicited stderr chatter in a
/// pipeline without a provider-specific allowlist. The stderr-is-a-tty check below already covers
/// most piped/non-interactive cases; this is belt-and-braces for a CI runner that happens to attach
/// a pty to the job.
fn env_ci() -> bool {
    std::env::var_os("CI")
        .is_some_and(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
}

/// Parse a (possibly `v`-prefixed) `MAJOR.MINOR.PATCH` into a comparable tuple. Extra dot segments
/// are ignored (so a future `1.2.3-rc1`-shaped string still compares on its numeric prefix so long
/// as the first non-digit stops the parse cleanly); anything that doesn't start with three
/// dot-separated numbers is unparseable — callers treat that as "don't know, don't notify".
fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().strip_prefix('v').unwrap_or(s.trim());
    let mut parts = s.split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    // The patch segment may carry a pre-release/build suffix (e.g. "3-rc1"); take its leading
    // digits only rather than failing the whole parse.
    let patch_raw = parts.next()?;
    let digits: String = patch_raw
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let patch: u64 = digits.parse().ok()?;
    Some((major, minor, patch))
}

/// Is `latest` strictly newer than `current`? `false` (never notify/update) if either fails to
/// parse — an unparseable version is more likely a dev build (`0.1.0` with local changes) or a
/// malformed response than a real regression, and staying silent is the safe default.
fn is_newer(current: &str, latest: &str) -> bool {
    match (parse_version(current), parse_version(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// The one gentle line printed when an update is available — names both versions and both upgrade
/// paths (`uxlint update`, and the install.sh one-liner `install.sh` itself documents).
fn notice_text(current: &str, latest: &str, install_url: &str) -> String {
    format!(
        "uxlint {latest} is available (you're on {current}) — run `uxlint update`, or: curl -fsSL {install_url} | sh",
    )
}

/// Best-effort fetch of the newest published version — GitHub's `releases/latest` names it in
/// `tag_name` (`v0.1.11`), which we return bare (`0.1.11`) so every version string in this module
/// has one shape. Short timeout; any failure (network, non-2xx, unparseable body, a tag that isn't
/// a version) collapses to `None` so the caller treats "couldn't check" identically to "nothing to
/// report". The `User-Agent` is mandatory — GitHub's API 403s without one — and is deliberately
/// static, carrying no version or machine detail (see the module's PRIVACY note).
fn fetch_latest_version(api: &str, repo: &str, timeout: Duration) -> Option<String> {
    let http = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent("uxlint")
        .build()
        .ok()?;
    let resp = http
        .get(format!(
            "{}/repos/{repo}/releases/latest",
            api.trim_end_matches('/')
        ))
        .send()
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().ok()?;
    let tag = body["tag_name"].as_str()?;
    // Validate rather than trust: a tag is attacker-influenceable only by whoever can publish a
    // release, but this value flows into a URL path below, so it must survive the same check a
    // `--to` argument does.
    sanitize_version(tag.strip_prefix('v').unwrap_or(tag))
}

/// Entry point called once near the top of `main` for a normal command run: best-effort, never
/// blocks (2s network timeout), never fails the command, silent in CI/non-tty/opted-out. See the
/// module doc for exactly what it does and does not send.
pub(crate) fn maybe_print_update_notice() {
    if skip_notice(
        env_opt_out(),
        crate::project::project_update_check_disabled(),
        env_ci(),
        std::io::stderr().is_terminal(),
    ) {
        return;
    }
    let Some(path) = cache_path() else { return };
    let now = unix_now();
    let (last_check, mut latest) = read_cache(&path).unwrap_or((0, None));
    if check_due(Some(last_check).filter(|&t| t > 0), now) {
        // Whatever the fetch returns (Some or None), the check DID run — record it now so an
        // unreachable/offline origin doesn't retry every single command invocation.
        if let Some(v) = fetch_latest_version(&update_api(), &update_repo(), Duration::from_secs(2))
        {
            latest = Some(v);
        }
        write_cache(&path, now, latest.as_deref());
    }
    if let Some(latest) = &latest {
        if is_newer(CARGO_PKG_VERSION, latest) {
            eprintln!(
                "{}",
                notice_text(CARGO_PKG_VERSION, latest, INSTALL_SCRIPT_URL)
            );
        }
    }
}

// ──────────────────────────────────── server alignment ─────────────────────────────────────────

/// What the server this run points at thinks of the CLI driving it — the pure decision over the
/// `cli` block of `/v1/me` (`{"expected","min","dev"}`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Alignment {
    /// Nothing to say. At or ahead of what this server expects, OR the server is a dev/local
    /// deployment running unreleased code, OR it's an older server with no opinion at all. All
    /// three are SILENT on purpose — see the module doc.
    Aligned,
    /// Behind the release this server is aligned with, but new enough that it still trusts the
    /// capture: a one-line advisory, subject to the same quiet discipline as the update notice.
    Behind { expected: String },
    /// Older than the oldest capture this server trusts. The findings themselves may be WRONG (a
    /// stale collector once kept firing a lint the collector had already fixed), so this one is
    /// about correctness, not chatter: it prints unconditionally.
    Unsupported {
        min: String,
        expected: Option<String>,
    },
}

/// Decide what to say about `current` given the server's `cli` block. Pure, so every branch —
/// including the two back-compat silences — is unit-testable without a server or a terminal.
///
/// An absent block, an absent field, or a version string that doesn't parse all collapse to
/// `Aligned`: "don't know" must never become "nag", exactly as `is_newer` treats an unparseable
/// version. Note the comparison is `current < min` / `current < expected` — being AHEAD of either
/// (a dev build, or a CLI newer than a pinned-back deployment) is not a problem and never prints.
pub(crate) fn alignment(current: &str, cli_block: Option<&serde_json::Value>) -> Alignment {
    let Some(block) = cli_block else {
        return Alignment::Aligned; // a server that predates this contract — back-compat, say nothing
    };
    if block["dev"].as_bool() == Some(true) {
        return Alignment::Aligned; // dev/local server: routinely aligned with a version no release has
    }
    let expected = block["expected"].as_str();
    if let Some(min) = block["min"].as_str() {
        if is_newer(current, min) {
            return Alignment::Unsupported {
                min: min.to_string(),
                expected: expected.map(str::to_string),
            };
        }
    }
    if let Some(expected) = expected {
        if is_newer(current, expected) {
            return Alignment::Behind {
                expected: expected.to_string(),
            };
        }
    }
    Alignment::Aligned
}

/// The loud line: this CLI predates what the server trusts, so the findings may be wrong. Names the
/// floor, and points at the version the server actually wants (falling back to the floor when the
/// server sent no `expected`) with the exact command that installs it.
fn unsupported_text(current: &str, min: &str, expected: Option<&str>) -> String {
    format!(
        "warning: uxlint {current} is older than this server supports (it trusts {min} and newer) — \
         findings from this run may be wrong. Fix it: uxlint update --to {}",
        expected.unwrap_or(min),
    )
}

/// The quiet line: aligned enough to be trusted, just not the version this server was built
/// against. Names the exact version and the exact command — never "the latest release", which for a
/// pinned-back deployment would be the wrong advice.
fn behind_text(current: &str, expected: &str) -> String {
    format!(
        "note: this server expects uxlint {expected} (you're on {current}) — run `uxlint update --to {expected}`"
    )
}

/// Print whatever `alignment` decided, from the `cli` block of the `/v1/me` the audit already
/// fetched. The `Unsupported` case deliberately IGNORES the opt-out/CI/tty gating that silences the
/// update notice: `UXLINT_NO_UPDATE_CHECK` silences chatter, and a CLI whose capture the server no
/// longer trusts isn't chatter. The `Behind` advisory does honour it — a user who silenced update
/// nagging once shouldn't have to do it twice.
pub(crate) fn print_server_alignment(cli_block: Option<&serde_json::Value>) {
    let st = crate::style::Stream::Err;
    match alignment(CARGO_PKG_VERSION, cli_block) {
        Alignment::Aligned => {}
        Alignment::Unsupported { min, expected } => {
            eprintln!(
                "{}",
                st.red(&unsupported_text(
                    CARGO_PKG_VERSION,
                    &min,
                    expected.as_deref()
                ))
            );
        }
        Alignment::Behind { expected } => {
            if skip_notice(
                env_opt_out(),
                crate::project::project_update_check_disabled(),
                env_ci(),
                std::io::stderr().is_terminal(),
            ) {
                return;
            }
            eprintln!("{}", st.dim(&behind_text(CARGO_PKG_VERSION, &expected)));
        }
    }
}

// ─────────────────────────────────────────── self-update ───────────────────────────────────────

/// The `{os}-{arch}` vocabulary CI publishes under (`server/src/releases.rs::TARGETS`,
/// `.github/workflows/release.yml`, `install.sh`) — `linux`/`macos` × `x64`/`arm64`; deliberately
/// no Windows arm (see those files' comments: `client/src/reaper.rs` doesn't compile there).
fn current_target() -> Result<&'static str> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "macos",
        other => bail!(
            "uxlint ships linux and macOS builds only (no {other} build) — see web/static/install.sh; \
             build from source if you're on something else"
        ),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => bail!(
            "unsupported architecture '{other}' — uxlint publishes x86_64/aarch64 builds only"
        ),
    };
    Ok(match (os, arch) {
        ("linux", "x64") => "linux-x64",
        ("linux", "arm64") => "linux-arm64",
        ("macos", "x64") => "macos-x64",
        ("macos", "arm64") => "macos-arm64",
        _ => unreachable!("os/arch are each mapped to one of two values above"),
    })
}

/// Is `dir` writable by us right now? Probed by actually creating (and removing) a throwaway file
/// — the only reliable cross-platform answer; permission BITS alone can lie (ACLs, read-only
/// mounts, containers).
fn dir_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".uxlint-write-probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// `text` is a `.sha256` sidecar's contents — sha256sum/shasum's own format, `"<hex>  <filename>"`
/// — same shape install.sh parses with `awk '{print $1}'`. Returns just the hex digest, lowercased
/// for a case-insensitive compare against our own computed digest.
fn parse_sha256_sidecar(text: &str) -> Option<String> {
    let hex = text.split_whitespace().next()?;
    (!hex.is_empty()).then(|| hex.to_lowercase())
}

/// Validate a version this process did not author — `--to`'s argument, typically copied from what a
/// server said it wants — and return it in the canonical (no `v` prefix) form used to build a
/// release URL. STRICT ON PURPOSE: this string is interpolated into a URL PATH, so it must be
/// exactly `MAJOR.MINOR.PATCH` (plus an optional alphanumeric/dot pre-release suffix). No slashes,
/// no `..`, no scheme, no whitespace, no query — a pinned update can therefore only ever reach a
/// release artifact under our own origin, never an arbitrary URL someone else chose. Pure.
fn sanitize_version(s: &str) -> Option<String> {
    let v = s.trim();
    let v = v.strip_prefix('v').unwrap_or(v);
    // A real version is short; a long one is someone trying something.
    if v.is_empty() || v.len() > 64 || v.contains("..") {
        return None;
    }
    if !v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return None;
    }
    // Exactly three numeric segments before any `-suffix`.
    let nums = v.split_once('-').map_or(v, |(n, _)| n);
    let segs: Vec<&str> = nums.split('.').collect();
    if segs.len() != 3
        || segs
            .iter()
            .any(|s| s.is_empty() || !s.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    Some(v.to_string())
}

/// Are these the same release? Compared on the CANONICAL strings (not `parse_version`'s numeric
/// tuple), so a pin at `0.1.3` is not satisfied by an installed `0.1.3-rc1`. Pure.
fn same_version(a: &str, b: &str) -> bool {
    fn canon(s: &str) -> &str {
        let s = s.trim();
        s.strip_prefix('v').unwrap_or(s)
    }
    canon(a) == canon(b)
}

/// Is there anything to install, given the running version and the one asked for? Pure, and the
/// only place the pinned/unpinned difference lives.
///
/// UNPINNED (`uxlint update`) keeps the old rule: only ever move FORWARD, so a stale `latest.json`
/// can't walk a user backwards. PINNED (`--to X`) may move EITHER WAY on purpose — the whole point
/// of the flag is that the server this run points at may be aligned with an OLDER release than the
/// newest public one (a self-hosted deployment pinned back), and "install what that server wants"
/// has to be able to mean "downgrade".
fn install_needed(current: &str, wanted: &str, pinned: bool) -> bool {
    if pinned {
        !same_version(current, wanted)
    } else {
        is_newer(current, wanted)
    }
}

/// What `--check` prints for a pending install. Named the pinned way when pinned, so the line the
/// user is told to run is the line that does what they asked (including a downgrade). Pure.
fn check_text(current: &str, wanted: &str, pinned: bool) -> String {
    if pinned {
        format!("uxlint {wanted} is available (you're on {current}) — run `uxlint update --to {wanted}` to install it")
    } else {
        format!("uxlint {wanted} is available (you're on {current}) — run `uxlint update` to install it")
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `uxlint update [--check] [--to <version>]`. Without `--to`, fetches `latest.json` and installs
/// the newest release (no-op when already newest). With `--to`, installs THAT release — up or down
/// — resolving the artifact straight from the release channel's documented layout
/// (`{origin}/releases/{version}/{target}.tar.gz`) instead of `latest.json`, which only ever
/// describes the newest build. That's what makes "match the server this run points at" possible: a
/// self-hosted or pinned-back deployment's expected CLI is frequently NOT the latest release.
///
/// Either way the discipline is identical, and unchanged: download this platform's tarball, verify
/// its sha256 against the `.sha256` sidecar BEFORE writing anything permanent, extract the `uxlint`
/// binary (shells out to the system `tar`, exactly as `install.sh` does — no archive-parsing crate,
/// no code from the tarball ever executes), then atomically replace the running binary (temp file in
/// the SAME directory, `chmod +x`, `rename` over the current path). A checksum mismatch aborts
/// before any of that — the installed binary is left untouched. `--check` never installs. The
/// `--to` argument is validated by `sanitize_version` before it reaches a URL.
pub(crate) fn run_update(check_only: bool, to: Option<&str>) -> Result<()> {
    let target = current_target()?;
    let origin = update_origin();
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let repo = update_repo();
    let base = origin.trim_end_matches('/').to_string();

    // Which release we're installing, and where its tarball lives. Both paths resolve a CONCRETE
    // version first: the unpinned one asks GitHub what "latest" currently means rather than riding
    // its `releases/latest/download` redirect blind, because `install_needed` and every message
    // below need the number, and pinning the URL to it means the bytes we hash are the bytes of the
    // version we just decided to install (the redirect could move under a concurrent release).
    let (wanted, url): (String, String) = match to {
        Some(pin) => {
            let v = sanitize_version(pin)
                .with_context(|| format!("--to expects a version like 0.1.11, not {pin:?}"))?;
            (v.clone(), asset_url(&base, &repo, target, Some(&v)))
        }
        None => {
            let latest = fetch_latest_version(&update_api(), &repo, Duration::from_secs(15))
                .with_context(|| {
                    format!(
                        "could not resolve the latest uxlint release from {}",
                        update_api()
                    )
                })?;
            let url = asset_url(&base, &repo, target, Some(&latest));
            (latest, url)
        }
    };
    // The old self-hosted channel published a second, inline copy of each digest in latest.json,
    // which this code cross-checked against the sidecar. GitHub Releases publishes one `.sha256`
    // per asset and nothing else, so there is no second copy to disagree with — the sidecar is the
    // digest, and it is still verified before anything touches disk.
    let inline_sha: Option<String> = None;
    let pinned = to.is_some();

    if !install_needed(CARGO_PKG_VERSION, &wanted, pinned) {
        if pinned {
            println!("uxlint {CARGO_PKG_VERSION} is already installed");
        } else {
            println!("uxlint {CARGO_PKG_VERSION} is already the newest version ({wanted})");
        }
        return Ok(());
    }

    if check_only {
        println!("{}", check_text(CARGO_PKG_VERSION, &wanted, pinned));
        return Ok(());
    }

    let current_exe = std::env::current_exe().context("could not locate the running binary")?;
    let exe_dir = current_exe
        .parent()
        .context("running binary has no parent directory")?;
    if !dir_writable(exe_dir) {
        bail!(
            "{} isn't writable — refusing to replace the installed binary there.\n\
             Reinstall instead: curl -fsSL {}/install.sh | sh\n\
             (installed via mise? `mise upgrade uxlint`)",
            exe_dir.display(),
            origin.trim_end_matches('/'),
        );
    }

    println!("uxlint update: downloading {wanted} ({target}) from {origin}");
    let tarball = http
        .get(&url)
        .send()
        .with_context(|| format!("download failed: {url}"))?
        .error_for_status()
        .with_context(|| {
            format!("no {target} build published for uxlint {wanted} at {base}/releases/{wanted}/")
        })?
        .bytes()
        .context("reading tarball body")?;

    // Verify against the standalone `.sha256` sidecar (the same file install.sh fetches and
    // checks) — not just latest.json's inline field — so a tampered tarball is caught even if
    // latest.json and the sidecar disagree; either mismatch aborts.
    let sum_url = format!("{url}.sha256");
    let sidecar_text = http
        .get(&sum_url)
        .send()
        .with_context(|| format!("checksum download failed: {sum_url}"))?
        .text()
        .context("reading .sha256 body")?;
    let expected = parse_sha256_sidecar(&sidecar_text)
        .with_context(|| format!("empty/malformed checksum file: {sum_url}"))?;
    let actual = sha256_hex(&tarball);
    if actual != expected {
        bail!(
            "checksum mismatch for {target} tarball — expected {expected}, got {actual}. \
             Not installing; the currently installed binary is untouched."
        );
    }
    if let Some(inline) = inline_sha.as_deref() {
        if !inline.eq_ignore_ascii_case(&actual) {
            bail!(
                "checksum mismatch: latest.json's inline sha256 for {target} disagrees with the .sha256 \
                 sidecar. Not installing; the currently installed binary is untouched."
            );
        }
    }
    println!("uxlint update: checksum OK ({actual})");

    // Extract via the system `tar` — same tool install.sh assumes is present, and the ONLY code
    // from this tarball that ever runs is `uxlint` itself, after this process (not the tarball)
    // has invoked it via `mv`/`rename`. No tar-parsing crate, no code execution from the archive.
    let work_dir = std::env::temp_dir().join(format!(
        "uxlint-update-{}-{}",
        std::process::id(),
        unix_now()
    ));
    std::fs::create_dir_all(&work_dir)
        .context("could not create a scratch directory to extract into")?;
    let tarball_path = work_dir.join(format!("uxlint-{target}.tar.gz"));
    std::fs::write(&tarball_path, &tarball)
        .context("could not write tarball to scratch directory")?;
    let status = std::process::Command::new("tar")
        .args([
            "xzf",
            tarball_path.to_str().unwrap_or_default(),
            "-C",
            work_dir.to_str().unwrap_or_default(),
            "uxlint",
        ])
        .status()
        .context("'tar' is required to extract the release but was not found on PATH")?;
    anyhow::ensure!(
        status.success(),
        "tar extraction failed (unexpected tarball layout)"
    );
    let extracted = work_dir.join("uxlint");
    anyhow::ensure!(
        extracted.is_file(),
        "extracted archive has no 'uxlint' binary — unexpected tarball layout"
    );

    // Atomic replace: write to a temp file NEXT TO the running binary (same filesystem, so the
    // final rename is atomic), chmod it executable, then rename over the current path. Renaming
    // over a running binary is fine on Unix — the process keeps its already-open inode; the next
    // invocation resolves the new directory entry.
    let tmp_path = exe_dir.join(format!(".uxlint-update-{}.tmp", std::process::id()));
    std::fs::copy(&extracted, &tmp_path)
        .context("could not stage the new binary next to the running one")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))
            .context("could not mark the new binary executable")?;
    }
    std::fs::rename(&tmp_path, &current_exe).context("could not replace the running binary")?;
    let _ = std::fs::remove_dir_all(&work_dir);

    println!(
        "uxlint update: {CARGO_PKG_VERSION} → {wanted} installed at {}",
        current_exe.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing_handles_v_prefix_and_bare() {
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("v0.4.2"), Some((0, 4, 2)));
        assert_eq!(parse_version("0.1.0"), Some((0, 1, 0)));
    }

    #[test]
    fn version_parsing_takes_leading_digits_of_a_suffixed_patch() {
        assert_eq!(parse_version("v1.2.3-rc1"), Some((1, 2, 3)));
    }

    #[test]
    fn version_parsing_rejects_garbage() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("not-a-version"), None);
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("v1.x.3"), None);
    }

    #[test]
    fn newer_older_equal_comparison() {
        assert!(is_newer("0.1.0", "0.2.0"));
        assert!(is_newer("0.1.0", "v0.1.1"));
        assert!(is_newer("v1.0.0", "2.0.0"));
        assert!(
            !is_newer("0.2.0", "0.1.0"),
            "older latest must not be reported as an update"
        );
        assert!(
            !is_newer("0.1.0", "0.1.0"),
            "equal versions are not an update"
        );
        assert!(!is_newer("0.1.0", "v0.1.0"));
    }

    #[test]
    fn unparseable_versions_never_trigger_a_notice() {
        assert!(!is_newer("0.1.0", "garbage"));
        assert!(!is_newer("garbage", "0.1.0"));
    }

    #[test]
    fn cache_due_when_never_checked_or_a_day_has_passed() {
        assert!(check_due(None, 1_000));
        assert!(check_due(Some(0), ONE_DAY_SECS));
        assert!(check_due(Some(0), ONE_DAY_SECS + 1));
        assert!(
            !check_due(Some(1_000), 1_000 + ONE_DAY_SECS - 1),
            "not due yet — same day"
        );
        assert!(!check_due(Some(1_000), 1_000), "just checked");
    }

    #[test]
    fn skip_gating_covers_every_opt_out() {
        // Baseline: nothing opts out, stderr IS a tty → don't skip.
        assert!(!skip_notice(false, false, false, true));
        // Any single signal skips it.
        assert!(
            skip_notice(true, false, false, true),
            "UXLINT_NO_UPDATE_CHECK=1"
        );
        assert!(
            skip_notice(false, true, false, true),
            "uxlint.toml update_check = false"
        );
        assert!(skip_notice(false, false, true, true), "CI env var set");
        assert!(
            skip_notice(false, false, false, false),
            "stderr is not a terminal (piped/non-tty)"
        );
    }

    #[test]
    fn notice_names_both_versions_and_both_upgrade_paths() {
        let msg = notice_text("0.1.0", "0.2.0", INSTALL_SCRIPT_URL);
        assert!(msg.contains("0.2.0"), "{msg}");
        assert!(msg.contains("0.1.0"), "{msg}");
        assert!(msg.contains("uxlint update"), "{msg}");
        assert!(
            msg.contains("curl -fsSL https://uxlint.net/install.sh | sh"),
            "{msg}"
        );
    }

    #[test]
    fn every_default_points_at_a_domain_we_own() {
        // uxlint.dev is NOT ours — it belongs to someone else. It was the default `--server`, the
        // default update origin and the advertised install URL, which meant a default run shipped a
        // customer's capture and bearer token to a third party. Nothing in this crate may name it.
        assert!(!INSTALL_SCRIPT_URL.contains("uxlint.dev"));
        assert!(INSTALL_SCRIPT_URL.starts_with("https://uxlint.net/"));
        for s in [update_origin(), update_repo(), update_api()] {
            assert!(!s.contains("uxlint.dev"), "{s}");
        }
        assert!(!notice_text("0.1.0", "0.2.0", INSTALL_SCRIPT_URL).contains("uxlint.dev"));
    }

    #[test]
    fn sha256_hex_matches_a_known_vector() {
        // sha256("") — a well-known test vector, independent of any file on disk.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_sidecar_parses_the_sha256sum_format() {
        assert_eq!(
            parse_sha256_sidecar("deadbeef  uxlint-linux-x64.tar.gz\n"),
            Some("deadbeef".to_string())
        );
        assert_eq!(
            parse_sha256_sidecar("ABCDEF  uxlint-macos-arm64.tar.gz"),
            Some("abcdef".to_string())
        );
        assert_eq!(parse_sha256_sidecar(""), None);
        assert_eq!(parse_sha256_sidecar("   \n"), None);
    }

    // ── server alignment ────────────────────────────────────────────────────────────────────────
    // The five branches the audit-time check turns on. `alignment` is pure, so each is pinned here
    // without a server, a terminal, or an installed binary.

    fn cli_block(expected: &str, min: &str, dev: bool) -> serde_json::Value {
        serde_json::json!({ "expected": expected, "min": min, "dev": dev })
    }

    #[test]
    fn alignment_flags_a_cli_older_than_the_server_trusts() {
        assert_eq!(
            alignment("0.1.8", Some(&cli_block("0.1.11", "0.1.9", false))),
            Alignment::Unsupported {
                min: "0.1.9".into(),
                expected: Some("0.1.11".into())
            },
            "below `min` the capture itself isn't trusted — this is the loud case"
        );
    }

    #[test]
    fn alignment_advises_between_min_and_expected() {
        assert_eq!(
            alignment("0.1.10", Some(&cli_block("0.1.11", "0.1.9", false))),
            Alignment::Behind {
                expected: "0.1.11".into()
            }
        );
        // The floor itself is trusted — `min` is inclusive.
        assert_eq!(
            alignment("0.1.9", Some(&cli_block("0.1.11", "0.1.9", false))),
            Alignment::Behind {
                expected: "0.1.11".into()
            }
        );
    }

    #[test]
    fn alignment_is_silent_at_or_ahead_of_expected() {
        assert_eq!(
            alignment("0.1.11", Some(&cli_block("0.1.11", "0.1.9", false))),
            Alignment::Aligned,
            "exactly aligned"
        );
        assert_eq!(
            alignment("0.2.0", Some(&cli_block("0.1.11", "0.1.9", false))),
            Alignment::Aligned,
            "being AHEAD is never a problem — nagging here would train users to ignore the check"
        );
    }

    #[test]
    fn alignment_is_silent_against_a_dev_server() {
        // A dev/local deployment runs unreleased server code and is routinely aligned with a
        // version no release has — it must never nag, whichever side of `expected` we're on.
        assert_eq!(
            alignment("0.1.8", Some(&cli_block("0.1.99", "0.1.99", true))),
            Alignment::Aligned
        );
        assert_eq!(
            alignment("0.1.11", Some(&cli_block("0.1.99", "0.1.12", true))),
            Alignment::Aligned
        );
    }

    #[test]
    fn alignment_is_silent_when_the_server_has_no_cli_block() {
        // Back-compat: a server that predates this contract says nothing, so neither do we.
        assert_eq!(alignment("0.1.0", None), Alignment::Aligned);
        // …as does one whose block is empty, partial, or unparseable — "don't know" is not "nag".
        assert_eq!(
            alignment("0.1.0", Some(&serde_json::json!({}))),
            Alignment::Aligned
        );
        assert_eq!(
            alignment("0.1.0", Some(&serde_json::Value::Null)),
            Alignment::Aligned
        );
        assert_eq!(
            alignment("0.1.0", Some(&serde_json::json!({ "expected": "garbage" }))),
            Alignment::Aligned
        );
    }

    #[test]
    fn alignment_uses_min_alone_when_expected_is_missing() {
        assert_eq!(
            alignment("0.1.8", Some(&serde_json::json!({ "min": "0.1.9" }))),
            Alignment::Unsupported {
                min: "0.1.9".into(),
                expected: None
            }
        );
    }

    #[test]
    fn alignment_messages_name_the_exact_version_and_command() {
        let loud = unsupported_text("0.1.8", "0.1.9", Some("0.1.11"));
        assert!(loud.contains("0.1.8"), "{loud}");
        assert!(loud.contains("0.1.9"), "names the floor: {loud}");
        assert!(
            loud.contains("uxlint update --to 0.1.11"),
            "installs what the SERVER wants, not latest: {loud}"
        );
        // With no `expected`, the floor is the best available target.
        assert!(unsupported_text("0.1.8", "0.1.9", None).contains("uxlint update --to 0.1.9"));

        let quiet = behind_text("0.1.10", "0.1.11");
        assert!(quiet.contains("0.1.10"), "{quiet}");
        assert!(quiet.contains("uxlint update --to 0.1.11"), "{quiet}");
        assert!(
            !quiet.contains("install.sh"),
            "the pinned path is the only correct advice here: {quiet}"
        );
    }

    // ── uxlint update --to ──────────────────────────────────────────────────────────────────────

    #[test]
    fn update_to_parses_off_the_command_line() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from(["uxlint", "update", "--to", "0.1.11"])
            .expect("--to parses");
        match cli.cmd {
            crate::Cmd::Update { check, to } => {
                assert!(!check);
                assert_eq!(to.as_deref(), Some("0.1.11"));
            }
            _ => panic!("expected the update subcommand"),
        }
        // Bare `uxlint update` still means "latest".
        let bare = crate::Cli::try_parse_from(["uxlint", "update"]).expect("bare update parses");
        match bare.cmd {
            crate::Cmd::Update { check, to } => {
                assert!(!check);
                assert_eq!(to, None);
            }
            _ => panic!("expected the update subcommand"),
        }
    }

    #[test]
    fn pinned_versions_are_url_safe_or_rejected() {
        assert_eq!(sanitize_version("0.1.11"), Some("0.1.11".into()));
        assert_eq!(sanitize_version("v0.1.11"), Some("0.1.11".into()));
        // Surrounding whitespace is a copy-paste artifact, not an attack — trimmed, then held to
        // the same shape as everything else.
        assert_eq!(sanitize_version(" 1.2.3 "), Some("1.2.3".into()));
        assert_eq!(sanitize_version("0.1.11\n"), Some("0.1.11".into()));
        assert_eq!(sanitize_version("1.2.3-rc1"), Some("1.2.3-rc1".into()));
        // Anything that could steer the fetch somewhere other than a release artifact under our
        // own origin is rejected BEFORE it reaches a URL.
        for bad in [
            "",
            "latest",
            "1.2",
            "../../etc/passwd",
            "0.1.11/../0.9.9",
            "0.1.11?x=1",
            "https://evil.example/x.tar.gz",
            "0.1.11 && rm -rf /",
            "0.1.11\n0.9.9",
            "0.1.11%2f..",
            "1.2.3-a..b",
        ] {
            assert_eq!(sanitize_version(bad), None, "must reject {bad:?}");
        }
        // …and absurd length, which no real version has.
        assert_eq!(sanitize_version(&"1.2.3-".repeat(20)), None);
    }

    #[test]
    fn pinning_may_downgrade_but_bare_update_never_does() {
        // A pin installs whatever it names — a self-hosted server aligned with an older CLI wants
        // that older CLI, so "downgrade" is the feature, not a bug.
        assert!(install_needed("0.1.11", "0.1.9", true), "pinned downgrade");
        assert!(install_needed("0.1.9", "0.1.11", true), "pinned upgrade");
        assert!(
            !install_needed("0.1.11", "v0.1.11", true),
            "already at the pinned version — nothing to do"
        );
        // Unpinned keeps the old forward-only rule.
        assert!(install_needed("0.1.9", "0.1.11", false));
        assert!(
            !install_needed("0.1.11", "0.1.9", false),
            "a stale latest.json must never walk a user backwards"
        );
        assert!(!install_needed("0.1.11", "0.1.11", false));
    }

    #[test]
    fn pinned_check_text_suggests_the_pinned_command() {
        assert!(check_text("0.1.11", "0.1.9", true).contains("uxlint update --to 0.1.9"));
        let bare = check_text("0.1.9", "0.1.11", false);
        assert!(bare.contains("run `uxlint update`"), "{bare}");
        assert!(!bare.contains("--to"), "{bare}");
    }

    #[test]
    fn target_mapping_matches_the_release_channels_vocabulary() {
        // Doesn't assert a specific value (that depends on the machine running the test) — just
        // that whatever it resolves to, if anything, is one of the four TARGETS server/src/releases.rs
        // and install.sh publish/detect.
        if let Ok(t) = current_target() {
            assert!(["linux-x64", "linux-arm64", "macos-x64", "macos-arm64"].contains(&t));
        }
    }
}
