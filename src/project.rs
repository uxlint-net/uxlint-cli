//! uxlint.toml project identity: walk up from cwd like .git, plus the route
//! normalisation helpers the crawler shares.

use serde_json::{json, Value};

/// Locate uxlint.toml walking up: (containing dir, parsed value).
pub(crate) fn find_project_toml() -> Option<(std::path::PathBuf, toml::Value)> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if let Ok(text) = std::fs::read_to_string(dir.join("uxlint.toml")) {
            return text.parse().ok().map(|v| (dir.clone(), v));
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// One checked-in `[[tests]]` entry: a product requirement the audit runs as an uninstructed user.
#[derive(Debug, Clone)]
pub(crate) struct ProjectTest {
    pub(crate) test: String,
    pub(crate) expect: String,
    /// "critical" | "important" | "minor" — gates whether a failed test fails the audit.
    pub(crate) importance: String,
    /// Which `[personas.<name>]` the task runs as: a persona name, or "anonymous" (logged out).
    /// Empty ⇒ unspecified (logged-out first, then the crawl's signed-in session if there is one).
    pub(crate) persona: String,
    /// Where the task is expected: "desktop" | "mobile" | "both" | "" (unspecified → desktop).
    pub(crate) viewport: String,
}

/// The parsed `uxlint.toml` for the project the audit runs in — the checked-in identity + defaults.
/// A named struct (not a positional tuple) so a reviewer can see at a glance exactly which of these
/// fields ride into an audit and where (`org`/`site` name the report, `tests` are run, provenance
/// is added separately in `build_audit_request`).
#[derive(Debug, Clone)]
pub(crate) struct ProjectConfig {
    pub(crate) org: String,
    pub(crate) site: String,
    /// Default audit base URL (`base = "http://…"`) written by `uxlint init` — where `uxlint audit`
    /// (no `--base`) points the browser. `--base` still overrides. `None` when unset (older config).
    pub(crate) base: Option<String>,
    /// Default routes (`routes = [...]`), joined with commas; `None` when unset.
    pub(crate) routes: Option<String>,
    pub(crate) tests: Vec<ProjectTest>,
    /// Crawl budget (`crawl = N`); 0 = no crawl beyond the seeds.
    pub(crate) crawl: usize,
    /// `[theme]` — declared visual language (corners/accent/description), sent for type-aware lints.
    pub(crate) theme: Option<Value>,
    /// `site_type` (e.g. "saas") — drives type-specific lints.
    pub(crate) site_type: Option<String>,
    /// `styleguide` — where the design-system page lives, for the styleguide-existence probe. A PATH
    /// (default `/styleguide` when unset) the client renders to confirm the page exists even when it's
    /// deliberately UNLINKED; the `"off"` sentinel (from `styleguide = false`) opts out. Lets
    /// `styleguide-missing` clear without linking the page into the crawl.
    pub(crate) styleguide: Option<String>,
    /// `exclude` — route patterns the crawl must never audit.
    pub(crate) exclude: Vec<String>,
    /// `desktop_only` — route glob patterns for DESKTOP-PRIMARY surfaces (authoring/GM tools that show
    /// a "use a bigger screen" state on a phone). Sent to the server, which demotes findings captured
    /// on these routes below the desktop width to `info` — so a mobile layout complaint there doesn't
    /// gate CI or read as an error. Same wildcard grammar as `exclude`.
    pub(crate) desktop_only: Vec<String>,
}

pub(crate) fn project_config() -> Option<ProjectConfig> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let p = dir.join("uxlint.toml");
        if let Ok(text) = std::fs::read_to_string(&p) {
            let v: toml::Value = text.parse().ok()?;
            let org = v.get("org")?.as_str()?.to_string();
            let site = v.get("site")?.as_str()?.to_string();
            let base = v
                .get("base")
                .and_then(|b| b.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let routes = v.get("routes").and_then(|r| r.as_array()).map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            });
            // [[tests]] — checked-in product requirements: test / expect / importance / persona /
            // viewport. `persona` names which [personas.<name>] the task runs as: "anonymous" (a
            // logged-out visitor) or a declared persona (run signed in as them). `viewport` is WHERE
            // the task is expected — "desktop" or "mobile" — so a desktop-only task isn't run (or
            // judged unreachable) on a phone. Empty = unspecified (desktop).
            let tests: Vec<ProjectTest> = v
                .get("tests")
                .and_then(|g| g.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|g| {
                            Some(ProjectTest {
                                test: g.get("test")?.as_str()?.to_string(),
                                expect: g.get("expect")?.as_str()?.to_string(),
                                importance: g
                                    .get("importance")
                                    .and_then(|i| i.as_str())
                                    .unwrap_or("important")
                                    .to_string(),
                                persona: g
                                    .get("persona")
                                    .and_then(|a| a.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                viewport: g
                                    .get("viewport")
                                    .and_then(|w| w.as_str())
                                    .unwrap_or("")
                                    .to_lowercase(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let crawl = v
                .get("crawl")
                .and_then(|c| c.as_integer())
                .unwrap_or(0)
                .max(0) as usize;
            // [theme]: declared visual language — corners / accent / description.
            let theme = v.get("theme").map(|t| {
                json!({
                    "corners": t.get("corners").and_then(|x| x.as_str()),
                    "accent": t.get("accent").and_then(|x| x.as_str()),
                    "description": t.get("description").and_then(|x| x.as_str()),
                })
            });
            // What kind of site this is (saas / marketing / docs / …) — top-level so it never
            // collides with the `site = "host"` string. Drives type-specific lints.
            let site_type = v
                .get("site_type")
                .and_then(|x| x.as_str())
                .map(|s| s.to_lowercase());
            // styleguide = "/design-system" (a path) or styleguide = false (opt out). A path overrides
            // the default `/styleguide` the existence probe renders; `false` → the "off" sentinel, which
            // reports the styleguide "present" so the lint stays quiet.
            let styleguide = v.get("styleguide").and_then(|x| {
                if let Some(b) = x.as_bool() {
                    (!b).then(|| "off".to_string())
                } else {
                    x.as_str().map(|s| s.trim().to_string())
                }
            });
            // exclude = ["/example/before", "/example/*"] — routes to keep out of the audit.
            let exclude = v
                .get("exclude")
                .and_then(|e| e.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            // desktop_only = ["/dashboard/scenarios/*/pages/*"] — desktop-primary surfaces whose
            // mobile findings the server demotes to `info` (same array-of-globs shape as exclude).
            let desktop_only = v
                .get("desktop_only")
                .and_then(|e| e.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            return Some(ProjectConfig {
                org,
                site,
                base,
                routes,
                tests,
                crawl,
                theme,
                site_type,
                styleguide,
                exclude,
                desktop_only,
            });
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// The project's declared overall audit timeout in SECONDS, if uxlint.toml sets a top-level
/// `timeout` (e.g. `timeout = 420` for a big, slow site). The one knob a project checks in to widen
/// the browser-phase budget for everyone who audits from this repo. The `--timeout` flag overrides
/// it; absent both, the audit uses the 5-minute default. Only a positive value counts — a `0` or a
/// negative is ignored (falls through to the default) rather than making the audit hang or fail.
pub(crate) fn project_timeout() -> Option<u64> {
    let (_, v) = find_project_toml()?;
    let n = v.get("timeout").and_then(|t| t.as_integer())?;
    (n > 0).then_some(n as u64)
}

/// Has this project opted in to sharing feedback signals with uxlint — a top-level `feedback =
/// true` in uxlint.toml? DEFAULT FALSE: a project with no `feedback` key, or an explicit
/// `feedback = false`, keeps the MCP `feedback` tool hidden entirely (see `UxlintMcp::new` —
/// `ToolRouter::remove_route` drops it from both `list_tools` and `call_tool`). Standalone
/// accessor, same shape as `project_timeout` — the caller doesn't need the whole project_config
/// tuple for one bool.
pub(crate) fn project_feedback_enabled() -> bool {
    let Some((_, v)) = find_project_toml() else {
        return false;
    };
    v.get("feedback").and_then(|f| f.as_bool()).unwrap_or(false)
}

/// Has this project opted OUT of the update-notice check — a top-level `update_check = false` in
/// uxlint.toml? DEFAULT TRUE (the check is opt-out, not opt-in, unlike `feedback`): the notice is a
/// public, no-data-sent GET (see `update.rs`), so the bar for running it by default is much lower
/// than for `feedback`, which shares signals about findings. Absent key or any non-`false` value
/// leaves the check enabled.
pub(crate) fn project_update_check_disabled() -> bool {
    let Some((_, v)) = find_project_toml() else {
        return false;
    };
    v.get("update_check").and_then(|f| f.as_bool()) == Some(false)
}

/// A persona: a named test identity the audit signs in as, declared under `[personas.<name>]`.
/// Either a FORM login (`username` + `password`, submitted at the site-wide `login_url`) OR a SESSION
/// (pre-set `headers` / `storage` replayed on every request — for a target the hosted server can't
/// drive a login form on, e.g. dev/staging behind a cookie). Every value runs through `${VAR}`
/// interpolation so real secrets live in the environment, not the file:
///   login_url = "/login"
///   default_persona = "admin"           # who the general crawl signs in as (omit ⇒ logged out)
///   [personas.admin]
///   username = "admin@acme.test"
///   password = "${ADMIN_PW}"
///   [personas.ci]                        # a session persona — no form
///   headers = ["Cookie: sid=dev-session"]
///   storage = ["auth_token=dev-token"]
/// A `[[tests]]` with `persona = "admin"` runs signed in as that persona; `"anonymous"` runs logged out.
#[derive(Debug, Clone, Default)]
pub(crate) struct Persona {
    pub name: String,
    /// Form login username/email — empty for a session persona.
    pub username: String,
    pub password: String,
    /// Session auth: cookies/headers + localStorage entries replayed to reach a logged-in app.
    pub headers: Vec<String>,
    pub storage: Vec<String>,
}

impl Persona {
    /// A form-login persona has a username to submit; a session persona instead carries headers/storage.
    pub(crate) fn is_form(&self) -> bool {
        !self.username.is_empty()
    }
}

/// The site's login-form URL (top-level `login_url`) — where form personas sign in. `None` when unset
/// (a session-only project, or the walker discovers the login page itself).
pub(crate) fn login_url() -> Option<String> {
    let (_, v) = find_project_toml()?;
    v.get("login_url")
        .and_then(|u| u.as_str())
        .map(|s| interp_env(s.trim()))
        .filter(|s| !s.is_empty())
}

/// Every declared persona, parsed from `[personas.<name>]`.
pub(crate) fn project_personas() -> Vec<Persona> {
    let Some((_, v)) = find_project_toml() else {
        return Vec::new();
    };
    personas_from(&v)
}

fn personas_from(v: &toml::Value) -> Vec<Persona> {
    let Some(personas) = v.get("personas").and_then(|r| r.as_table()) else {
        return Vec::new();
    };
    let list = |cfg: &toml::Value, key: &str| {
        cfg.get(key)
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .map(interp_env)
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    personas
        .iter()
        .map(|(name, cfg)| Persona {
            name: name.clone(),
            username: cfg
                .get("username")
                .and_then(|e| e.as_str())
                .map(interp_env)
                .unwrap_or_default(),
            password: cfg
                .get("password")
                .and_then(|p| p.as_str())
                .map(interp_env)
                .unwrap_or_default(),
            headers: list(cfg, "headers"),
            storage: list(cfg, "storage"),
        })
        .collect()
}

/// The credentials the general CRAWL replays — resolved from `default_persona`. A form persona
/// becomes a `login` submitted at `login_url`; a session persona becomes its headers/storage. Empty
/// when no default persona is set (the crawl runs logged out). Same shape the audit already consumes.
#[derive(Default)]
pub(crate) struct ProjectCredentials {
    pub headers: Vec<String>,
    pub storage: Vec<String>,
    pub login: Option<(String, String, String)>, // url, username, password
}

pub(crate) fn project_credentials() -> ProjectCredentials {
    let Some((_, v)) = find_project_toml() else {
        return ProjectCredentials::default();
    };
    credentials_from(&v)
}

fn credentials_from(v: &toml::Value) -> ProjectCredentials {
    let Some(def) = v
        .get("default_persona")
        .and_then(|d| d.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return ProjectCredentials::default();
    };
    let Some(p) = personas_from(v).into_iter().find(|p| p.name == def) else {
        return ProjectCredentials::default();
    };
    persona_creds(v, p)
}

/// Resolve one persona to the credentials the crawl replays: a form persona becomes a `login` submitted
/// at `login_url`; a session persona becomes its headers/storage. Shared by the default-persona crawl
/// and the multi-state crawl (`credentials_for`).
fn persona_creds(v: &toml::Value, p: Persona) -> ProjectCredentials {
    if p.is_form() {
        // A form persona signs in at login_url; without one there's nothing to submit against.
        let url = v
            .get("login_url")
            .and_then(|u| u.as_str())
            .map(|s| interp_env(s.trim()))
            .unwrap_or_default();
        ProjectCredentials {
            headers: Vec::new(),
            storage: Vec::new(),
            login: (!url.is_empty()).then_some((url, p.username, p.password)),
        }
    } else {
        ProjectCredentials {
            headers: p.headers,
            storage: p.storage,
            login: None,
        }
    }
}

/// The auth STATES the crawl captures each route under (`audit_states = ["anonymous", "member"]`).
/// Empty when unset — the audit runs its single default state exactly as before. Each entry names a
/// `[personas.<name>]` (or the literal `anonymous` for a logged-out capture).
pub(crate) fn audit_states() -> Vec<String> {
    let Some((_, v)) = find_project_toml() else {
        return Vec::new();
    };
    v.get("audit_states")
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Credentials for a NAMED persona (the multi-state crawl audits a route under several). The literal
/// `anonymous` — or an unknown/missing persona — yields empty creds, i.e. a logged-OUT capture.
pub(crate) fn credentials_for(name: &str) -> ProjectCredentials {
    match find_project_toml() {
        Some((_, v)) => credentials_for_in(&v, name),
        None => ProjectCredentials::default(),
    }
}

fn credentials_for_in(v: &toml::Value, name: &str) -> ProjectCredentials {
    if name.eq_ignore_ascii_case("anonymous") {
        return ProjectCredentials::default(); // a logged-out capture
    }
    match personas_from(v).into_iter().find(|p| p.name == name) {
        Some(p) => persona_creds(v, p),
        None => ProjectCredentials::default(),
    }
}

/// A reviewed finding the project chooses to suppress — by rule, optionally scoped to paths.
pub(crate) struct Suppress {
    pub(crate) rule: String,
    /// Path patterns (same matching as `exclude`: exact or prefix). Empty = every path.
    pub(crate) paths: Vec<String>,
}

/// Findings to drop from the report: issues you've reviewed and won't fix. Unlike `exclude`
/// (which skips whole ROUTES), the route is still audited — only the named rule's findings on
/// matching paths are suppressed. Parsed from `[[suppress]]` tables:
///   [[suppress]]
///   rule = "request-failed"
///   paths = ["/example"]        # optional; omit to suppress the rule on every page
///   reason = "the example embeds a prod report id that 404s locally"   # documentation only
pub(crate) fn suppressions() -> Vec<Suppress> {
    let Some((_, v)) = find_project_toml() else {
        return Vec::new();
    };
    let Some(arr) = v.get("suppress").and_then(|s| s.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|s| {
            let rule = s.get("rule")?.as_str()?.to_string();
            let paths = s
                .get("paths")
                .and_then(|p| p.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            Some(Suppress { rule, paths })
        })
        .collect()
}

/// Drop suppressed findings from the report and adjust the headline counts by the DISTINCT
/// (route, rule, sel) findings removed (so a desktop+mobile pair counts once). Returns the DISTINCT
/// rules that were suppressed — a suppression is an implicit "reject" the caller reports as feedback.
pub(crate) fn apply_suppressions(report: &mut serde_json::Value, sup: &[Suppress]) -> Vec<String> {
    if sup.is_empty() {
        return Vec::new();
    }
    let (mut de, mut dw, mut di) = (0i64, 0i64, 0i64);
    let mut dropped = std::collections::HashSet::new();
    let mut rules = std::collections::BTreeSet::new();
    if let Some(pages) = report["pages"].as_array_mut() {
        for page in pages {
            let route = page["route"].as_str().unwrap_or("").to_string();
            if let Some(findings) = page["findings"].as_array_mut() {
                findings.retain(|f| {
                    let rule = f["rule"].as_str().unwrap_or("");
                    let hit = sup.iter().any(|s| {
                        s.rule == rule && (s.paths.is_empty() || route_excluded(&route, &s.paths))
                    });
                    if hit {
                        rules.insert(rule.to_string());
                        let key = format!("{route}|{rule}|{}", f["sel"].as_str().unwrap_or(""));
                        if dropped.insert(key) {
                            match f["severity"].as_str() {
                                Some("error") => de += 1,
                                Some("warn") => dw += 1,
                                _ => di += 1,
                            }
                        }
                    }
                    !hit
                });
            }
        }
    }
    let dec = |v: &mut serde_json::Value, d: i64| {
        *v = serde_json::json!((v.as_i64().unwrap_or(0) - d).max(0));
    };
    dec(&mut report["errors"], de);
    dec(&mut report["warnings"], dw);
    dec(&mut report["infos"], di);
    rules.into_iter().collect()
}

/// Replace `${VAR}` occurrences with the environment variable's value (empty if unset).
fn interp_env(s: &str) -> String {
    if !s.contains("${") {
        return s.to_string();
    }
    // Re-read the project .env every call so ${VAR} credential values HOT-RELOAD when the file
    // changes — the running process's own env is fixed at spawn and would otherwise go stale, so a
    // rotated password wouldn't take effect until the MCP reconnected. The .env file wins over the
    // possibly-stale process env; a var in neither resolves to empty.
    let dotenv = read_project_dotenv();
    let lookup = |var: &str| {
        dotenv
            .get(var)
            .cloned()
            .or_else(|| std::env::var(var).ok())
            .unwrap_or_default()
    };
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        if let Some(end) = rest[start + 2..].find('}') {
            let var = &rest[start + 2..start + 2 + end];
            out.push_str(&lookup(var));
            rest = &rest[start + 2 + end + 1..];
        } else {
            out.push_str(&rest[start..]);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

/// The project's `.env` (next to uxlint.toml) as a map — read fresh so credential `${VAR}`s
/// hot-reload. `KEY=VALUE` lines; blanks/`#` comments skipped; surrounding quotes stripped.
fn read_project_dotenv() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let Some((dir, _)) = find_project_toml() else {
        return map;
    };
    let Ok(contents) = std::fs::read_to_string(dir.join(".env")) else {
        return map;
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let (k, v) = (k.trim(), v.trim().trim_matches('"').trim_matches('\''));
            if !k.is_empty() {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    map
}

/// Normalize a route for dedup: strip query/fragment, trailing slash.
pub(crate) fn norm_route(h: &str) -> String {
    let h = h.split(['?', '#']).next().unwrap_or(h);
    if h.len() > 1 {
        h.trim_end_matches('/')
    } else {
        h
    }
    .to_string()
}

/// Does this path segment look like an ID (a numeric key, hash, uuid, or slug) rather than a
/// stable route word? Pure digits (`861`), or a longish token that mixes in a digit
/// (`uop679y52crs`, a uuid) — but NOT human route words (`about`, `settings`, `v1`).
fn seg_is_id(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    let all_digits = s.bytes().all(|b| b.is_ascii_digit());
    all_digits || (has_digit && s.len() >= 6)
}

/// Collapse a path to its ROUTE TEMPLATE, replacing id-like segments with `{id}`. So
/// `/sites/861/r/uop679y52crs` and `/sites/59/r/m69dm4ang6o3` both become `/sites/{id}/r/{id}`.
/// The crawl uses this to audit each page TYPE once instead of every instance — we lint the
/// template, not the data behind it.
pub(crate) fn route_template(path: &str) -> String {
    path.split('/')
        .map(|s| if seg_is_id(s) { "{id}" } else { s })
        .collect::<Vec<_>>()
        .join("/")
}

/// The structural vocabulary of a layout skeleton — roles, regions, and arrangement words. Any
/// token NOT in here is treated as data (a label, a heading's text, a tier name) and dropped from
/// the fingerprint.
const STRUCT_VOCAB: &[&str] = &[
    "page",
    "header",
    "nav",
    "main",
    "aside",
    "footer",
    "form",
    "article",
    "section",
    "dialog",
    "field",
    "button",
    "link",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "img",
    "table",
    "tree",
    "tablist",
    "disclosure",
    "list",
    "menu",
    "cards",
    "columns",
    "column",
    "stacked",
    "grid",
    "row",
    "rows",
    "side",
    "vertically",
];

/// A STRUCTURAL fingerprint of a page derived from its layout skeleton. Keeps the structural
/// vocabulary, nesting depth, braces, and the `×` "repeated-run" marker; drops exact counts,
/// coordinates, group labels, and text. So the SAME shape with different DB data collapses to one
/// fingerprint (a 10-row and a 50-row list, two reports of different sites) while genuinely
/// different structures stay distinct (an EMPTY list's empty-state block vs a POPULATED list, a
/// report WITH a site-map vs one without). Used to sample structurally-distinct pages when crawling.
pub(crate) fn structure_fingerprint(skeleton: &str) -> u64 {
    let mut sig = String::with_capacity(skeleton.len() / 2);
    for line in skeleton.lines() {
        let indent = line.len() - line.trim_start().len();
        sig.push('\n');
        sig.push((b'0' + (indent.min(9) as u8)) as char); // nesting depth (structural), not data
        sig.push('|');
        let mut tok = String::new();
        for ch in line.chars() {
            if ch.is_ascii_alphanumeric() || ch == ':' {
                tok.push(ch.to_ascii_lowercase());
            } else {
                push_struct_token(&tok, &mut sig);
                tok.clear();
                if ch == '{' || ch == '}' || ch == '×' {
                    sig.push(ch);
                    sig.push(' ');
                }
            }
        }
        push_struct_token(&tok, &mut sig);
    }
    // FNV-1a 64.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in sig.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Emit a token to the fingerprint only if it's structural (in the vocab). `field:text` keeps its
/// type; pure numbers and arbitrary label words are dropped.
fn push_struct_token(tok: &str, sig: &mut String) {
    if tok.is_empty() {
        return;
    }
    let base = tok.split(':').next().unwrap_or(tok);
    if STRUCT_VOCAB.contains(&base) {
        sig.push_str(tok);
        sig.push(' ');
    }
}

/// Local/private targets are the user's own dev server — parallelism can go full throttle
/// there; rate limits and bot walls only exist on public hosts.
pub(crate) fn is_local_target(base: &str) -> bool {
    let host = base
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(['/', ':'])
        .next()
        .unwrap_or("");
    host == "localhost"
        || host == "::1"
        || host == "0.0.0.0"
        || host.starts_with("127.")
        || host.starts_with("192.168.")
        || host.starts_with("10.")
        || host.ends_with(".local")
        || host.ends_with(".localhost")
}

/// host:port of a base URL — the site identity a report attaches to.
pub(crate) fn base_host(base: &str) -> String {
    reqwest::Url::parse(base)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(p) => format!("{h}:{p}"),
                None => h.to_string(),
            })
        })
        .unwrap_or_default()
}

/// Is this route excluded by the project's `exclude` list? A pattern matches the route
/// exactly, matches everything beneath it ("/example" also excludes "/example/before"),
/// or uses `*` wildcards anywhere — trailing ("/example/*") OR mid-path ("/sites/*/r/*",
/// the in-app report viewer). A `*` matches any run of characters, slashes included.
pub(crate) fn route_excluded(route: &str, excludes: &[String]) -> bool {
    let r = norm_route(route);
    excludes.iter().any(|p| {
        let p = p.trim();
        if p.contains('*') {
            glob_match(p, &r)
        } else {
            let pn = norm_route(p);
            r == pn || r.starts_with(&format!("{pn}/"))
        }
    })
}

/// Minimal, whole-string glob: `*` matches any (possibly empty) sequence of characters,
/// every other byte matches literally. Two-pointer with backtracking on the last `*`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1; // re-consume from just after the star, swallowing one more text byte
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Never crawl into destructive-looking URLs or assets.
pub(crate) fn skip_route(r: &str) -> bool {
    let rl = r.to_lowercase();
    [
        "logout", "signout", "sign-out", "delete", "destroy", "remove",
    ]
    .iter()
    .any(|d| rl.contains(d))
        || [
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf", ".zip", ".mp4", ".css", ".js", ".ico",
            ".xml",
        ]
        .iter()
        .any(|e| rl.ends_with(e))
}

#[cfg(test)]
mod credential_tests {
    use super::{credentials_from, personas_from};

    fn toml(s: &str) -> toml::Value {
        s.parse().expect("test toml")
    }

    /// The crawl signs in as `default_persona`, borrowing that persona's username/password and the
    /// site-wide `login_url` — the case our own uxlint.toml relies on.
    #[test]
    fn the_crawl_signs_in_as_the_default_persona() {
        let v = toml(
            r#"
            login_url = "/login"
            default_persona = "user"
            [personas.user]
            username = "test@acme.dev"
            password = "s3cret"
            "#,
        );
        assert_eq!(
            credentials_from(&v).login,
            Some(("/login".into(), "test@acme.dev".into(), "s3cret".into()))
        );
    }

    /// A session persona as the default: its headers/storage become the crawl auth, no form login.
    #[test]
    fn a_session_default_persona_yields_headers_not_a_login() {
        let v = toml(
            r#"
            default_persona = "ci"
            [personas.ci]
            headers = ["Cookie: sid=dev"]
            storage = ["auth=tok"]
            "#,
        );
        let c = credentials_from(&v);
        assert_eq!(c.login, None);
        assert_eq!(c.headers, vec!["Cookie: sid=dev".to_string()]);
        assert_eq!(c.storage, vec!["auth=tok".to_string()]);
    }

    /// The multi-state crawl resolves a NAMED persona (or `anonymous`), independent of `default_persona`.
    #[test]
    fn credentials_for_resolves_a_named_persona_or_anonymous() {
        let v = toml(
            r#"
            default_persona = "anon-is-not-this"
            [personas.member]
            headers = ["Cookie: sid=dev"]
            storage = ["auth=tok"]
            "#,
        );
        // A named session persona → its headers/storage (regardless of default_persona).
        let m = super::credentials_for_in(&v, "member");
        assert_eq!(m.headers, vec!["Cookie: sid=dev".to_string()]);
        assert_eq!(m.storage, vec!["auth=tok".to_string()]);
        // `anonymous` → empty creds (a logged-out capture).
        let a = super::credentials_for_in(&v, "anonymous");
        assert!(a.headers.is_empty() && a.storage.is_empty() && a.login.is_none());
        // An unknown persona name → empty, never a half-login.
        let u = super::credentials_for_in(&v, "nobody");
        assert!(u.headers.is_empty() && u.storage.is_empty() && u.login.is_none());
    }

    /// No `default_persona` ⇒ the crawl runs logged out (no login, no headers).
    #[test]
    fn no_default_persona_means_logged_out() {
        let v = toml(
            r#"
            [personas.user]
            username = "u@acme.dev"
            password = "pw"
            "#,
        );
        let c = credentials_from(&v);
        assert_eq!(c.login, None);
        assert!(c.headers.is_empty() && c.storage.is_empty());
    }

    /// A form persona named as default but with no `login_url` has nothing to submit against → no login.
    #[test]
    fn a_form_default_without_a_login_url_yields_no_login() {
        let v = toml(
            r#"
            default_persona = "user"
            [personas.user]
            username = "u@acme.dev"
            password = "pw"
            "#,
        );
        assert_eq!(credentials_from(&v).login, None);
    }

    /// A `default_persona` naming something undeclared must not silently half-log-in as nobody.
    #[test]
    fn an_unknown_default_persona_yields_no_login() {
        let v = toml(
            r#"
            login_url = "/login"
            default_persona = "nobody"
            [personas.user]
            username = "u@acme.dev"
            "#,
        );
        assert_eq!(credentials_from(&v).login, None);
    }

    /// Cross-parser guard for hosted audits: the server reconstructs a site's uxlint.toml with
    /// `toml_edit` and the worker writes it for THIS parser (`toml`) to read. Both follow the TOML
    /// spec, but pin it: a representative server-shaped config (personas + default_persona + login_url
    /// + tests + routes/exclude/crawl) must parse here and yield the persona/login the server sealed.
    #[test]
    fn a_server_reconstructed_config_parses_here() {
        let cfg = r#"
org = "acme"
site = "acme.com"
routes = ["/", "/pricing"]
exclude = ["/admin/*"]
crawl = 5
login_url = "/login"
default_persona = "admin"

[[tests]]
test = "sign up for a trial"
expect = "reaches a working signup form"
importance = "critical"
persona = "admin"

[personas.admin]
username = "admin@acme.com"
password = "s3cret-admin"
"#;
        let v: toml::Value = cfg
            .parse()
            .expect("the CLI's toml parser reads the server-built config");
        let personas = personas_from(&v);
        assert!(personas.iter().any(|p| p.name == "admin"
            && p.username == "admin@acme.com"
            && p.password == "s3cret-admin"));
        // default_persona + login_url resolve to the login the crawl actually uses.
        assert_eq!(
            credentials_from(&v).login,
            Some((
                "/login".into(),
                "admin@acme.com".into(),
                "s3cret-admin".into()
            ))
        );
    }

    #[test]
    fn personas_parse_with_and_without_passwords() {
        let v = toml(
            r#"
            [personas.user]
            username = "u@acme.dev"
            password = "pw"
            [personas.admin]
            username = "a@acme.dev"
            "#,
        );
        let mut r = personas_from(&v);
        r.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(
            (
                r[0].name.as_str(),
                r[0].username.as_str(),
                r[0].password.as_str()
            ),
            ("admin", "a@acme.dev", "")
        );
        assert_eq!(
            (
                r[1].name.as_str(),
                r[1].username.as_str(),
                r[1].password.as_str()
            ),
            ("user", "u@acme.dev", "pw")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::route_template;

    #[test]
    fn collapses_ids_but_keeps_route_words() {
        // Same page type, different data → same template.
        assert_eq!(
            route_template("/sites/861/r/uop679y52crs"),
            "/sites/{id}/r/{id}"
        );
        assert_eq!(
            route_template("/sites/59/r/m69dm4ang6o3"),
            "/sites/{id}/r/{id}"
        );
        assert_eq!(route_template("/sites/861"), "/sites/{id}");
        // Distinct page types stay distinct — no digits to collapse.
        assert_eq!(route_template("/settings/billing"), "/settings/billing");
        assert_eq!(
            route_template("/settings/organizations"),
            "/settings/organizations"
        );
        // Short version-ish words are NOT ids.
        assert_eq!(route_template("/v1/docs"), "/v1/docs");
        assert_eq!(route_template("/"), "/");
    }

    #[test]
    fn exclude_patterns_match_exact_prefix_and_globs() {
        use super::route_excluded;
        let ex = vec![
            "/example".to_string(),
            "/r/".to_string(),
            "/sites/*/r/*".to_string(),
        ];
        // exact + "beneath" for a bare pattern
        assert!(route_excluded("/example", &ex));
        assert!(route_excluded("/example/before", &ex));
        // "/r/" is the public viewer prefix; the reports LIST must survive it
        assert!(route_excluded("/r/abc123", &ex));
        assert!(!route_excluded("/reports", &ex));
        // mid-path glob excludes the in-app report viewer but not the site or list pages
        assert!(route_excluded("/sites/536/r/uop679y52crs", &ex));
        assert!(!route_excluded("/sites/536", &ex));
        assert!(!route_excluded("/sites", &ex));
    }

    #[test]
    fn report_instances_share_one_template() {
        let a = route_template("/sites/861/r/uop679y52crs");
        let b = route_template("/sites/861/r/m69dm4ang6o3");
        let c = route_template("/sites/861/r/tlzcmwm6110o");
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    use super::structure_fingerprint;

    #[test]
    fn same_shape_different_data_collapses() {
        // A 10-row and a 50-row list of the same shape differ only in the collapsed count and the
        // row labels — both data. Same fingerprint.
        let ten = "PAGE 1200×3000\n  main\n    10× stacked vertically — each { link, h3, p } — Report abc, Report def";
        let fifty = "PAGE 1200×9000\n  main\n    50× stacked vertically — each { link, h3, p } — Report xyz, Report qux";
        assert_eq!(structure_fingerprint(ten), structure_fingerprint(fifty));
    }

    #[test]
    fn empty_state_differs_from_populated_list() {
        // An empty list renders an empty-state block, not a repeated run — genuinely different UX.
        let empty = "PAGE 1200×800\n  main\n    section — “No reports yet”\n      button";
        let full = "PAGE 1200×9000\n  main\n    50× stacked vertically — each { link, h3, p }";
        assert_ne!(structure_fingerprint(empty), structure_fingerprint(full));
    }

    #[test]
    fn structural_variant_within_a_type_differs() {
        // A report WITH a site-map (extra section) is a different structure than one without.
        let with_map = "PAGE 1200×5000\n  main\n    section — map\n      img\n    12× cards a 3-column grid — each { h3, p }";
        let no_map = "PAGE 1200×5000\n  main\n    12× cards a 3-column grid — each { h3, p }";
        assert_ne!(
            structure_fingerprint(with_map),
            structure_fingerprint(no_map)
        );
    }
}
