//! `uxlint init` — interactive setup wizard for the getting-started flow. It signs you in (opening a
//! browser only if there's no stored token), lets you pick the org and then the site this project's
//! reports attach to, optionally captures the login credentials uxlint replays to reach your app
//! behind its auth, tests them, and writes `uxlint.toml` — with any secret going to a gitignored
//! `.env` next to it as a `${VAR}` reference, never inline.

use anyhow::{Context, Result};
use inquire::{Confirm, Password, PasswordDisplayMode, Select, Text};
use serde_json::{json, Value};
use std::io::Write; // writeln! into the .env / uxlint.toml files

use crate::login::stored_credential;
use crate::Cli;

pub(crate) struct InitArgs {
    pub org: Option<String>,
    pub site: Option<String>,
    pub routes: String,
    /// The audit base URL to store (`--url`). When set, skips the interactive base prompt; the one
    /// way `--offline` can persist a `base`.
    pub url: Option<String>,
    pub web: String,
    pub offline: bool,
}

/// How uxlint should sign in to the target app, captured from the wizard.
///
/// `inline` decides where the secret goes. A throwaway local-dev/test login is CHECKED IN — its
/// value sits directly in uxlint.toml, self-contained and reproducible from a clone (that is the
/// point of a project test credential). A real secret is not: it goes to a gitignored `.env` and
/// the toml gets a `${VAR}` reference (`var` names the key).
enum Creds {
    /// A header replayed on every request, e.g. `Cookie: session=…`.
    Header {
        name: String,
        var: String,
        value: String,
        inline: bool,
    },
    /// Sign in via the login form each run.
    Login {
        url: String,
        username: String,
        var: String,
        password: String,
        inline: bool,
    },
}

impl Creds {
    fn inline(&self) -> bool {
        match self {
            Creds::Header { inline, .. } | Creds::Login { inline, .. } => *inline,
        }
    }
}

pub(crate) fn run_init(cli: &Cli, args: &InitArgs) -> Result<()> {
    // --offline: no server, no prompts — write straight from flags (CI / air-gapped). On an
    // existing project it re-points org/site IN PLACE, keeping the curated routes/goals/comments.
    if args.offline {
        let org = args.org.clone().context("--offline needs --org")?;
        let site = args.site.clone().context("--offline needs --site")?;
        if let Ok(existing) = std::fs::read_to_string("uxlint.toml") {
            std::fs::write("uxlint.toml", update_identity(&existing, &org, &site))?;
            println!("↻ updated org/site in uxlint.toml (org {org:?}, site {site:?}) — everything else kept, unchecked (--offline)");
            return Ok(());
        }
        // --offline asks nothing, so `feedback` is simply left out of the file — the accessor
        // (`project::project_feedback_enabled`) defaults an absent key to false anyway.
        write_toml(&org, &site, args.url.as_deref(), &args.routes, None, None)?;
        println!("wrote uxlint.toml (org {org:?}, site {site:?}) — unchecked (--offline)");
        return Ok(());
    }

    let token = ensure_token(cli, &args.web)?;
    let http = reqwest::blocking::Client::new();
    let me: Value = http
        .get(format!("{}/v1/me", cli.server))
        .bearer_auth(&token)
        .send()
        .context("server unreachable — is it up? (or use --offline)")?
        .error_for_status()
        .context("that token isn't valid — try `uxlint auth logout` then re-run")?
        .json()?;
    eprintln!(
        "✓ signed in as {}",
        me["email"].as_str().unwrap_or("(unknown)")
    );

    // ── existing project: update ONLY what was asked for, keep everything else ─────
    // Re-running init on a set-up project must NOT clobber its curated routes, exclude, roles,
    // goals or comments. Offer the two things worth re-running init for — the sign-in credentials
    // and the org/site the reports file to — and rewrite exactly those, in place. Explicit
    // --org/--site flags are the non-interactive way to re-point the project (no prompts).
    if let Ok(existing) = std::fs::read_to_string("uxlint.toml") {
        let (org_f, site_f) = existing_identity(&existing);
        eprintln!(
            "uxlint.toml detected (org {}, site {}).",
            org_f.as_deref().unwrap_or("?"),
            site_f.as_deref().unwrap_or("?")
        );
        let flagged = args.org.is_some() || args.site.is_some();
        let (change_identity, change_creds) = if flagged {
            (true, false)
        } else {
            match pick(
                "What do you want to update? (routes, goals, comments — everything else — is kept)",
                &[
                    "sign-in credentials".to_string(),
                    "org & site (where reports are filed)".to_string(),
                    "credentials and org & site".to_string(),
                    "nothing — leave it as is".to_string(),
                ],
            )? {
                0 => (false, true),
                1 => (true, false),
                2 => (true, true),
                _ => {
                    println!("No changes made — uxlint.toml left as it is.");
                    return Ok(());
                }
            }
        };

        let mut updated = existing;
        let mut site = site_f.clone().unwrap_or_default();
        let mut identity_note = String::new();
        if change_identity {
            let orgs = me["orgs"].as_array().cloned().unwrap_or_default();
            anyhow::ensure!(
                !orgs.is_empty(),
                "your account has no orgs — unexpected; contact support"
            );
            let org = pick_org(&orgs, args.org.as_deref())?;
            let org_id = org["id"].as_i64().context("org id")?;
            let org_name = org["name"].as_str().unwrap_or("").to_string();
            let is_admin = org["role"].as_str() == Some("admin");
            let new_site = pick_site(
                &http,
                cli,
                &token,
                org,
                org_id,
                is_admin,
                args.site.as_deref(),
            )?;
            updated = update_identity(&updated, &org_name, &new_site);
            identity_note = format!("org {org_name:?}, site {new_site:?}");
            site = new_site;
        }
        if change_creds {
            let c = capture_credentials()?;
            let default_base = if site.is_empty() {
                "http://localhost:5173".into()
            } else {
                format!("http://{site}")
            };
            let base = ask_default(
                "What URL should uxlint audit (a reachable base, e.g. http://localhost:5173)",
                &default_base,
            )?;
            if test_credentials(&base, &c) == CredCheck::Failed
                && !ask_yes_no(
                    "Those credentials didn't sign in. Update uxlint.toml anyway?",
                    false,
                )?
            {
                eprintln!("Aborted — uxlint.toml unchanged.");
                return Ok(());
            }
            if !c.inline() {
                write_env_secret(&c)?;
            }
            updated = update_credentials(&updated, &c);
            println!(
                "  {}",
                if c.inline() {
                    "the login is checked in (fine for a throwaway local-dev test account)"
                } else {
                    "the secret is in .env (gitignored) as a ${VAR} reference"
                }
            );
        }
        std::fs::write("uxlint.toml", updated)?;
        let what = match (change_identity, change_creds) {
            (true, true) => format!("the credentials and the identity ({identity_note})"),
            (true, false) => format!("the identity ({identity_note})"),
            _ => "the credentials".to_string(),
        };
        println!(
            "\n↻ updated {what} in uxlint.toml — kept routes, goals, and your other sections."
        );
        return Ok(());
    }

    let orgs = me["orgs"].as_array().cloned().unwrap_or_default();
    anyhow::ensure!(
        !orgs.is_empty(),
        "your account has no orgs — unexpected; contact support"
    );

    // ── org ──────────────────────────────────────────────────────────────────
    let org = pick_org(&orgs, args.org.as_deref())?;
    let org_id = org["id"].as_i64().context("org id")?;
    let org_name = org["name"].as_str().unwrap_or("").to_string();
    let is_admin = org["role"].as_str() == Some("admin");

    // ── site ─────────────────────────────────────────────────────────────────
    let site = pick_site(
        &http,
        cli,
        &token,
        org,
        org_id,
        is_admin,
        args.site.as_deref(),
    )?;

    // ── audit base URL ─────────────────────────────────────────────────────────
    // Asked ALWAYS (not just when there are credentials) and stored as `base` in uxlint.toml, so a
    // bare `uxlint audit` from this project points here. Default to a detected local dev server, else
    // the site's host. `--url` skips the prompt entirely.
    let base = if let Some(u) = args.url.clone() {
        u
    } else {
        let default_base = detect_local_host()
            .map(|h| format!("http://{h}"))
            .unwrap_or_else(|| format!("http://{site}"));
        ask_default(
            "What URL should uxlint audit (a reachable base, e.g. http://localhost:5173)",
            &default_base,
        )?
    };

    // ── credentials (optional) ────────────────────────────────────────────────
    let creds = prompt_credentials()?;
    if let Some(c) = &creds {
        // A DEFINITE failure (signed out) is worth stopping for — writing credentials that don't
        // work just moves the discovery to a confusing AUTH WALL on the first audit. An inconclusive
        // check doesn't block: it's best-effort, and it may just be that the app isn't up yet.
        if test_credentials(&base, c) == CredCheck::Failed
            && !ask_yes_no(
                "Those credentials didn't sign in. Save uxlint.toml anyway?",
                false,
            )?
        {
            eprintln!(
                "Aborted — nothing written. Re-run `uxlint init` once the credentials are right."
            );
            return Ok(());
        }
    }

    // ── feedback opt-in ────────────────────────────────────────────────────────
    // Prompt DEFAULTS TRUE (most projects should help improve the product), but the toml key is
    // always written EXPLICITLY — `feedback = true` or `feedback = false` — so a re-read of the file
    // never has to guess. The accessor's own absent-key default is FALSE, for projects that skip
    // this prompt entirely (--offline, or a config hand-written without the key).
    let feedback = ask_yes_no(
        "Help improve uxlint by sharing feedback? Shares only general, anonymized signals about which lints helped — never your app's content. You can change this anytime in uxlint.toml.",
        true,
    )?;

    // ── write .env (real secrets only) then uxlint.toml ───────────────────────
    if let Some(c) = &creds {
        if !c.inline() {
            write_env_secret(c)?;
        }
    }
    write_toml(
        &org_name,
        &site,
        Some(&base),
        &args.routes,
        creds.as_ref(),
        Some(feedback),
    )?;
    println!("\n✓ wrote uxlint.toml — org {org_name:?}, site {site:?}, base {base:?}");
    match creds.as_ref() {
        Some(c) if c.inline() => {
            println!("  the login is checked in (fine for a throwaway local-dev test account)")
        }
        Some(_) => println!(
            "  credentials written; the secret is in .env (gitignored) as a ${{VAR}} reference"
        ),
        None => {}
    }
    println!(
        "  feedback sharing: {}",
        if feedback {
            "on — thanks! flip it off anytime with feedback = false in uxlint.toml"
        } else {
            "off — turn it on anytime with feedback = true in uxlint.toml"
        }
    );
    println!("  next: uxlint audit   (uses the base above; pass --base <url> to override)");
    Ok(())
}

// ── auth ───────────────────────────────────────────────────────────────────────

/// A usable bearer token: an explicit --api-key/UXLINT_API_KEY, else a stored login token, else
/// run the browser sign-in and use the token it stores.
fn ensure_token(cli: &Cli, web: &str) -> Result<String> {
    if let Some(k) = cli.api_key.as_deref() {
        if !k.is_empty() {
            return Ok(k.to_string());
        }
    }
    if let Some(t) = stored_credential() {
        return Ok(t);
    }
    eprintln!("First, sign in.");
    crate::login::run_login(web, &cli.server)?;
    stored_credential().context("sign-in finished but no token was stored")
}

// ── pickers ──────────────────────────────────────────────────────────────────

fn pick_org<'a>(orgs: &'a [Value], preselect: Option<&str>) -> Result<&'a Value> {
    if let Some(name) = preselect {
        return orgs
            .iter()
            .find(|o| {
                o["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            })
            .with_context(|| {
                let names: Vec<&str> = orgs.iter().filter_map(|o| o["name"].as_str()).collect();
                format!("no org named {name:?} — yours: {}", names.join(", "))
            });
    }
    if orgs.len() == 1 {
        eprintln!("Org: {} (only one)", orgs[0]["name"].as_str().unwrap_or(""));
        return Ok(&orgs[0]);
    }
    let labels: Vec<String> = orgs
        .iter()
        .map(|o| {
            let kind = if o["kind"].as_str() == Some("personal") {
                " (personal)"
            } else {
                ""
            };
            format!("{}{kind}", o["name"].as_str().unwrap_or(""))
        })
        .collect();
    // Default the cursor to the personal workspace — it always exists (created at sign-up) and
    // needs no admin on anyone else to file a site under, so it's the sane default for "just get
    // started" while a team org still shows up right there to arrow onto.
    let default = orgs
        .iter()
        .position(|o| o["kind"].as_str() == Some("personal"))
        .unwrap_or(0);
    let i = pick_default("Org", &labels, default)?;
    Ok(&orgs[i])
}

fn pick_site(
    http: &reqwest::blocking::Client,
    cli: &Cli,
    token: &str,
    org: &Value,
    org_id: i64,
    is_admin: bool,
    preselect: Option<&str>,
) -> Result<String> {
    let hosts: Vec<String> = org["sites"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s["host"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if let Some(s) = preselect {
        return Ok(s.to_string());
    }
    // A dev server already running on a common local port is a strong hint at what this project
    // audits — offer it instead of making every init type a host by hand.
    let detected = detect_local_host();
    let mut items = hosts.clone();
    items.push("+ add a new site".to_string());
    let default = detected
        .as_deref()
        .and_then(|d| hosts.iter().position(|h| h == d))
        .unwrap_or(items.len() - 1); // no existing site matches — default to "add a new site"
    let i = pick_default("Site", &items, default)?;
    if i < hosts.len() {
        return Ok(hosts[i].clone());
    }
    // Create a new site.
    let host = loop {
        let h = match detected.as_deref() {
            Some(d) => ask_default("New site host (e.g. staging.acme.com or localhost:5173)", d)?,
            None => ask("New site host (e.g. staging.acme.com or localhost:5173): ")?,
        };
        if !h.is_empty() {
            break h;
        }
        eprintln!("  a host is required");
    };
    let org_name = org["name"].as_str().unwrap_or("this org");
    if is_admin {
        let resp = http
            .post(format!("{}/v1/orgs/{org_id}/sites", cli.server))
            .bearer_auth(token)
            .json(&json!({ "host": host }))
            .send()?;
        if resp.status().is_success() {
            eprintln!("  ✓ created site {host:?} in this org");
        } else if resp.status() == reqwest::StatusCode::CONFLICT {
            eprintln!("  site {host:?} already exists — using it");
        } else if resp.status() == reqwest::StatusCode::FORBIDDEN {
            // Shouldn't happen (the caller's own /v1/me role said admin) — but the server is the
            // authority, so a stale/raced role still gets the same clear message as the client-side
            // check below rather than a bare status code.
            eprintln!("  ✖ {org_name:?} says you're not an admin there after all — ask an org admin to add {host:?} in Settings, or re-run `uxlint init` and pick your personal workspace.");
        } else {
            eprintln!("  note: couldn't create it now ({}) — ask an org admin to add it, or pick your personal workspace.", resp.status());
        }
    } else {
        // Only an org admin can add a site to a TEAM org (server-enforced, `POST
        // /v1/orgs/{id}/sites`) — and the first audit against an undeclared team site is rejected
        // the same way, not auto-created, so don't imply it'll sort itself out.
        eprintln!(
            "  you're a member (not an admin) of {org_name:?} — only an org admin can create a site there."
        );
        eprintln!("  ask an org admin to add {host:?} in Settings, or re-run `uxlint init` and pick your personal workspace instead.");
    }
    Ok(host)
}

/// Best-effort guess at the host this project audits: probe common local dev-server ports and
/// offer the first one that's actually listening. There's no reliable framework-agnostic way to
/// read a "the app runs here" fact out of an arbitrary project, so this asks the machine instead
/// of the config — if your dev server is up, `localhost:<port>` becomes the prompt's default;
/// otherwise init falls back to asking outright. Never blocks: a closed port is a normal case
/// (nothing running yet), not an error.
fn detect_local_host() -> Option<String> {
    const PORTS: [u16; 8] = [5173, 3000, 8080, 4200, 4321, 5000, 8000, 3001];
    first_listening_port(&PORTS, std::time::Duration::from_millis(150))
}

/// The first port in `ports` with something listening on localhost, as `localhost:<port>` —
/// split out from `detect_local_host` so a test can bind a real listener and confirm detection
/// actually happens, instead of trusting the loop by inspection.
fn first_listening_port(ports: &[u16], timeout: std::time::Duration) -> Option<String> {
    ports.iter().find_map(|&port| {
        std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            timeout,
        )
        .ok()
        .map(|_| format!("localhost:{port}"))
    })
}

// ── credentials ──────────────────────────────────────────────────────────────

fn prompt_credentials() -> Result<Option<Creds>> {
    if !ask_yes_no("Does auditing your app require signing in?", false)? {
        return Ok(None);
    }
    Ok(Some(capture_credentials()?))
}

/// Capture how uxlint signs in — method, values, and where the secret lives. Split from
/// `prompt_credentials` so the update path can ask its own gate ("update credentials?") instead of
/// the new-project "does it need sign-in?" one.
fn capture_credentials() -> Result<Creds> {
    eprintln!("How does uxlint sign in?");
    let m = pick(
        "Method",
        &[
            "paste a session cookie / header".to_string(),
            "username + password on the login form".to_string(),
        ],
    )?;
    let creds = if m == 0 {
        eprintln!("  Sign in to your app in a browser, then copy a request's Cookie header");
        eprintln!("  (devtools ▸ Network ▸ any request ▸ Request Headers ▸ Cookie).");
        let raw = loop {
            let r = ask("Header (e.g. `Cookie: session=abc123`): ")?;
            if !r.is_empty() {
                break r;
            }
        };
        let (name, value) = match raw.split_once(':') {
            Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
            None => ("Cookie".to_string(), raw.trim().to_string()),
        };
        Creds::Header {
            name,
            var: "UXLINT_AUTH_HEADER".to_string(),
            value,
            inline: false,
        }
    } else {
        let url = ask_default("Login page (path or full URL)", "/login")?;
        let username = loop {
            let u = ask("Username / email: ")?;
            if !u.is_empty() {
                break u;
            }
        };
        let password = read_secret("Password (hidden): ")?;
        Creds::Login {
            url,
            username,
            var: "UXLINT_LOGIN_PASSWORD".to_string(),
            password,
            inline: false,
        }
    };
    // Where the secret lives. A checked-in test login for local dev belongs IN uxlint.toml, so the
    // config is self-contained; a real secret must not be committed and goes to .env instead.
    let inline = ask_yes_no(
        "Is this a throwaway login for local-dev testing, safe to commit to uxlint.toml? (No → it's a real secret, kept in .env)",
        true,
    )?;
    Ok(match creds {
        Creds::Header {
            name, var, value, ..
        } => Creds::Header {
            name,
            var,
            value,
            inline,
        },
        Creds::Login {
            url,
            username,
            var,
            password,
            ..
        } => Creds::Login {
            url,
            username,
            var,
            password,
            inline,
        },
    })
}

/// What a credential check concluded. `Failed` is a DEFINITE signed-out result (a 401, a login
/// redirect, or the login form driven and no session produced) — the only one that prompts
/// "save anyway?". `Unknown` is "couldn't tell from here" (no Chrome, unreachable host, or the
/// coarse HTTP-body heuristic on a JS app) — best-effort by design, so it never blocks the write.
#[derive(PartialEq)]
enum CredCheck {
    Ok,
    Failed,
    Unknown,
}

/// Verifies the captured credentials against the running app. The login-form case drives the real
/// browser (`verify_login`); the header case is a coarser HTTP probe. Never fatal — it returns a
/// verdict the caller acts on, and the first real audit is always the final word.
fn test_credentials(base: &str, creds: &Creds) -> CredCheck {
    eprint!("  testing… ");
    let http = match reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(12))
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            eprintln!("skipped (couldn't build client)");
            return CredCheck::Unknown;
        }
    };
    match creds {
        Creds::Header { name, value, .. } => {
            match http.get(base).header(name.as_str(), value).send() {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_redirection() {
                        let loc = resp
                            .headers()
                            .get("location")
                            .and_then(|l| l.to_str().ok())
                            .unwrap_or("");
                        if is_login_path(loc) {
                            eprintln!("⚠ redirected to {loc} — that cookie looks signed OUT (double-check it)");
                            CredCheck::Failed
                        } else {
                            eprintln!("✓ reachable (redirects to {loc})");
                            CredCheck::Ok
                        }
                    } else if status == reqwest::StatusCode::UNAUTHORIZED
                        || status == reqwest::StatusCode::FORBIDDEN
                    {
                        eprintln!("⚠ {status} — that cookie looks signed OUT (double-check it)");
                        CredCheck::Failed
                    } else if status.is_success() {
                        let body = resp.text().unwrap_or_default();
                        if looks_like_login(&body) {
                            // A JS app's shell always looks login-ish over plain HTTP, so this is a
                            // hint, not a verdict — don't block on it.
                            eprintln!("⚠ loaded, but the page still looks like a login screen — the first audit will confirm");
                            CredCheck::Unknown
                        } else {
                            eprintln!("✓ looks signed in");
                            CredCheck::Ok
                        }
                    } else {
                        eprintln!("⚠ {status} from {base}");
                        CredCheck::Unknown
                    }
                }
                Err(e) => {
                    eprintln!("⚠ couldn't reach {base}: {e}");
                    CredCheck::Unknown
                }
            }
        }
        Creds::Login {
            url,
            username,
            password,
            ..
        } => {
            // Drive the ACTUAL form in a browser — the same login the audit does — rather than an
            // HTTP form POST, which can't sign in to a JS-rendered login and would cry wolf on good
            // credentials. Slower (it launches Chrome), but it's the only answer worth trusting.
            match crate::worker::verify_login(base, url, username, password) {
                Ok(true) => {
                    eprintln!("✓ signed in — the form accepted these credentials");
                    CredCheck::Ok
                }
                Ok(false) => {
                    eprintln!(
                        "⚠ filled the form at {} but the app still looks signed OUT — check the login URL, username and password",
                        absolutize(base, url)
                    );
                    CredCheck::Failed
                }
                // No Chrome, unreachable host: can't confirm here — the first audit signs in the
                // same way and will say for sure.
                Err(e) => {
                    eprintln!("⚠ couldn't verify the login in a browser ({e}) — the first audit will confirm");
                    CredCheck::Unknown
                }
            }
        }
    }
}

// ── file writes ──────────────────────────────────────────────────────────────

/// Append the credential's secret to `.env` (creating it, and adding it to `.gitignore`) so the
/// value stays out of the checked-in toml. Existing keys are left untouched.
fn write_env_secret(creds: &Creds) -> Result<()> {
    let (var, value) = match creds {
        Creds::Header { var, value, .. } => (var, value),
        Creds::Login { var, password, .. } => (var, password),
    };
    let existing = std::fs::read_to_string(".env").unwrap_or_default();
    if existing
        .lines()
        .any(|l| l.trim_start().starts_with(&format!("{var}=")))
    {
        eprintln!("  .env already defines {var} — left as-is");
    } else {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(".env")?;
        if !existing.is_empty() && !existing.ends_with('\n') {
            writeln!(f)?;
        }
        writeln!(f, "{var}={value}")?;
    }
    ensure_gitignored(".env");
    Ok(())
}

/// Make sure `.gitignore` keeps `entry` out of git (secrets must never be committed).
fn ensure_gitignored(entry: &str) {
    let existing = std::fs::read_to_string(".gitignore").unwrap_or_default();
    if existing.lines().any(|l| l.trim() == entry) {
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(".gitignore")
    {
        if !existing.is_empty() && !existing.ends_with('\n') {
            let _ = writeln!(f);
        }
        let _ = writeln!(f, "{entry}");
    }
}

/// The persona + crawl-sign-in section text (with its explanatory comment). Shared by the fresh-file
/// template and the in-place update so both spell it the same way. Emits the top-level
/// `login_url`/`default_persona` keys FIRST (they must precede any table) then the `[personas.<name>]`
/// table. When the credential is a checked-in dev login (`inline`), the value sits right here;
/// otherwise it's a `${VAR}` reference resolved from `.env`.
fn credentials_block(creds: &Creds) -> String {
    match creds {
        Creds::Header {
            name,
            value,
            var,
            inline,
        } => {
            let (secret, note) = if *inline {
                (value.clone(), "A checked-in header for local-dev testing — the value sits here in the config.")
            } else {
                (format!("${{{var}}}"), "The secret lives in .env (gitignored); ${VAR} pulls it in at audit time, so it never enters the repo.")
            };
            format!(
                "# The persona the crawl signs in as — a session cookie/header (no login form). {note}\n\
                 default_persona = \"session\"\n[personas.session]\nheaders = [\"{name}: {secret}\"]\n"
            )
        }
        Creds::Login {
            url,
            username,
            password,
            var,
            inline,
        } => {
            let (secret, note) = if *inline {
                (password.clone(), "A checked-in test login for local dev — the password sits here so the config is self-contained.")
            } else {
                (
                    format!("${{{var}}}"),
                    "The password lives in .env (gitignored); ${VAR} pulls it in at audit time.",
                )
            };
            format!(
                "# The persona the crawl signs in as, via the login form at login_url. {note}\n\
                 login_url = {url:?}\ndefault_persona = \"user\"\n[personas.user]\nusername = {username:?}\npassword = {secret:?}\n"
            )
        }
    }
}

/// Write a FRESH uxlint.toml (no existing file). The in-place update path is `update_credentials`.
/// `feedback`: `Some(bool)` writes the opt-in EXPLICITLY (`feedback = true` or `= false`);
/// `None` (the `--offline` path, which prompts for nothing) leaves the key out entirely, falling
/// back to the accessor's own absent-key default of `false`.
fn write_toml(
    org: &str,
    site: &str,
    base: Option<&str>,
    routes: &str,
    creds: Option<&Creds>,
    feedback: Option<bool>,
) -> Result<()> {
    let routes_toml: Vec<String> = routes
        .split(',')
        .map(|r| format!("{:?}", r.trim()))
        .collect();
    let mut body = format!(
        "# uxlint.toml — this project's identity on uxlint (check this in).\n\
         # Audits run from this directory attach their reports to this org's site, even from\n\
         # localhost, and `uxlint audit` uses `routes` as its default set.\n\
         org = {org:?}\nsite = {site:?}\nroutes = [{}]\n",
        routes_toml.join(", ")
    );
    // The audit target: a bare `uxlint audit` points the browser here; `--base` overrides. Written
    // when init learned it (a prompt / --url), so the URL lives with the project instead of being
    // retyped every run.
    if let Some(b) = base.map(str::trim).filter(|b| !b.is_empty()) {
        body.push_str(&format!("base = {b:?}\n"));
    }
    if let Some(fb) = feedback {
        body.push_str(&format!(
            "\n# Share general, anonymized signals (which lints helped) with uxlint to improve the\n\
             # product — never your app's content. Off by default; `uxlint init` asks at setup.\n\
             feedback = {fb}\n"
        ));
    }
    if let Some(c) = creds {
        body.push('\n');
        body.push_str(&credentials_block(c));
    }
    std::fs::write("uxlint.toml", body)?;
    Ok(())
}

/// Update JUST the credentials of an existing config, leaving org/site/routes/exclude/roles/goals
/// and every comment exactly as the author wrote them. Re-running `uxlint init` on a real project
/// must refresh the login without eating the curated bits around it.
///
/// Text surgery, not a TOML round-trip: the `toml` crate can't preserve comments or ordering, and
/// this file is mostly comments worth keeping. We splice out any existing `[credentials…]` section — and
/// the contiguous comment block that introduces it, so its prose doesn't go stale — then drop the
/// new block in its place (or before the first section if there was none).
fn update_credentials(existing: &str, creds: &Creds) -> String {
    let lines: Vec<&str> = existing.lines().collect();
    let is_section = |l: &str| l.trim_start().starts_with('[');
    let is_cred_header = |l: &str| {
        let t = l.trim_start();
        t.starts_with("[credentials]") || t.starts_with("[credentials.")
    };

    // The span to remove: the first [credentials…] header, back over its leading comment block, and
    // forward across only its OWN header(s) and key lines. A blank line or a comment ends the span —
    // trailing comments introduce the NEXT section (e.g. the prose above [roles.user]) and must be
    // left with it, not swallowed here.
    let block = lines.iter().position(|l| is_cred_header(l)).map(|h| {
        let mut start = h;
        while start > 0 {
            let prev = lines[start - 1].trim_start();
            if prev.starts_with('#') || prev.is_empty() {
                start -= 1;
            } else {
                break;
            }
        }
        let mut end = h + 1;
        while end < lines.len() {
            let l = lines[end];
            let t = l.trim_start();
            if is_cred_header(l) {
                end += 1; // a [credentials.login] sub-table right under [credentials]
            } else if t.is_empty() || t.starts_with('#') || is_section(l) {
                break; // blank / comment / another section — the credentials body has ended
            } else {
                end += 1; // one of this section's key = value lines
            }
        }
        (start, end)
    });

    let new_block = credentials_block(creds);
    let mut out: Vec<String> = Vec::new();
    match block {
        Some((start, end)) => {
            out.extend(lines[..start].iter().map(|s| s.to_string()));
            // Keep a blank line before the block if there was content above it.
            if start > 0 && !lines[start - 1].trim().is_empty() {
                out.push(String::new());
            }
            out.extend(new_block.trim_end().lines().map(|s| s.to_string()));
            // One blank before whatever follows, unless it's already blank.
            if end < lines.len() && !lines[end].trim().is_empty() {
                out.push(String::new());
            }
            out.extend(lines[end..].iter().map(|s| s.to_string()));
        }
        None => {
            // No credentials section today: put one before the first section, else at the end.
            let insert = lines
                .iter()
                .position(|l| is_section(l))
                .unwrap_or(lines.len());
            out.extend(lines[..insert].iter().map(|s| s.to_string()));
            out.push(String::new());
            out.extend(new_block.trim_end().lines().map(|s| s.to_string()));
            out.push(String::new());
            out.extend(lines[insert..].iter().map(|s| s.to_string()));
        }
    }
    let mut s = out.join("\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Rewrite the top-level `org` / `site` identity lines IN PLACE, leaving every other line —
/// comments, routes, exclude, goals, sections — untouched. A key that isn't in the file yet is
/// inserted before the first section (top-level keys can't legally appear after one), or appended
/// on a section-less file.
fn update_identity(existing: &str, org: &str, site: &str) -> String {
    // A top-level `key = …` assignment line (not a comment, not inside a section).
    let is_key = |l: &str, key: &str| {
        let t = l.trim_start();
        !t.starts_with('#')
            && t.strip_prefix(key)
                .map(str::trim_start)
                .is_some_and(|r| r.starts_with('='))
    };
    let mut out: Vec<String> = Vec::new();
    let (mut wrote_org, mut wrote_site) = (false, false);
    let mut in_top = true;
    for l in existing.lines() {
        if in_top && l.trim_start().starts_with('[') {
            if !wrote_org {
                out.push(format!("org = {org:?}"));
                wrote_org = true;
            }
            if !wrote_site {
                out.push(format!("site = {site:?}"));
                wrote_site = true;
            }
            in_top = false;
        }
        if in_top && is_key(l, "org") {
            out.push(format!("org = {org:?}"));
            wrote_org = true;
        } else if in_top && is_key(l, "site") {
            out.push(format!("site = {site:?}"));
            wrote_site = true;
        } else {
            out.push(l.to_string());
        }
    }
    if !wrote_org {
        out.push(format!("org = {org:?}"));
    }
    if !wrote_site {
        out.push(format!("site = {site:?}"));
    }
    let mut s = out.join("\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// The `org`/`site` an existing uxlint.toml already declares (top-level string keys), for the
/// "found your project" message and the audit-base default. Coarse line scan — enough for both.
fn existing_identity(existing: &str) -> (Option<String>, Option<String>) {
    let val = |key: &str| {
        existing
            .lines()
            .map(str::trim)
            .take_while(|l| !l.starts_with('[')) // top-level only, before any section
            .find_map(|l| l.strip_prefix(key)?.trim().strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    };
    (val("org"), val("site"))
}

// ── small prompt/util helpers ────────────────────────────────────────────────
//
// These wrap `inquire` so each prompt is one call that returns a String/bool/usize. inquire renders
// to STDERR, which keeps stdout clean for anything machine-readable, and refuses to prompt when
// stdin isn't a terminal (a piped or CI invocation), returning an error rather than a silent empty
// line. That's why the non-interactive paths (`--offline`, and every `--org`/`--site` flag) resolve
// BEFORE reaching a prompt: a genuinely-needed prompt with no tty should fail loudly, not guess.

fn ask(prompt: &str) -> Result<String> {
    // inquire draws its own separator, so strip any trailing ": "/whitespace from the label.
    Ok(Text::new(prompt.trim_end_matches([' ', ':'])).prompt()?)
}

fn ask_default(prompt: &str, default: &str) -> Result<String> {
    Ok(Text::new(prompt).with_default(default).prompt()?)
}

fn ask_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    Ok(Confirm::new(prompt).with_default(default_yes).prompt()?)
}

/// Arrow-key selection from a list (type to filter). Returns the chosen index so callers keep
/// mapping it back to their own data.
fn pick(label: &str, items: &[String]) -> Result<usize> {
    pick_default(label, items, 0)
}

/// Same as `pick`, but the cursor starts on `default` instead of the first item — so hitting
/// enter without moving picks the sane default (e.g. the personal org, or a detected site) while
/// every option is still right there to arrow onto.
fn pick_default(label: &str, items: &[String], default: usize) -> Result<usize> {
    // Select owns the options, so hand it indices paired with labels and read the index back —
    // cheaper and clearer than searching for the returned string in the original slice.
    let options: Vec<Choice> = items
        .iter()
        .enumerate()
        .map(|(i, s)| Choice(i, s.clone()))
        .collect();
    let start = default.min(options.len().saturating_sub(1));
    Ok(Select::new(label, options)
        .with_starting_cursor(start)
        .prompt()?
        .0)
}

/// A `(index, label)` option: `Display` is the label the user sees and filters on; the index is
/// what `pick` returns.
struct Choice(usize, String);
impl std::fmt::Display for Choice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.1)
    }
}

/// Read a secret without echoing it. inquire masks the input itself (no `stty` toggling), and
/// without confirmation — this is entering an existing password, not choosing a new one.
fn read_secret(prompt: &str) -> Result<String> {
    Ok(Password::new(prompt.trim_end_matches([' ', ':']))
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()?)
}

fn is_login_path(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("login") || p.contains("signin") || p.contains("sign-in") || p.contains("/auth")
}

fn looks_like_login(body: &str) -> bool {
    let b = body.to_lowercase();
    b.contains("type=\"password\"")
        || b.contains("type='password'")
        || b.contains("action=\"login")
        || b.contains("action=\"/login")
}

/// Resolve a possibly-relative login URL against the audit base.
fn absolutize(base: &str, url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!(
            "{}/{}",
            base.trim_end_matches('/'),
            url.trim_start_matches('/')
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real listener on one of the "candidate" ports is detected; a port nothing is bound to
    /// (picked by the OS, so it's never one already in use) is not.
    #[test]
    fn first_listening_port_finds_a_bound_port_and_skips_a_closed_one() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let bound_port = listener.local_addr().unwrap().port();
        // A second ephemeral bind picks a fresh, currently-unbound port to stand in for "closed".
        let closed_port = {
            let probe =
                std::net::TcpListener::bind("127.0.0.1:0").expect("bind another ephemeral port");
            let p = probe.local_addr().unwrap().port();
            drop(probe); // release it immediately so nothing is listening there
            p
        };
        let timeout = std::time::Duration::from_millis(200);
        assert_eq!(
            first_listening_port(&[closed_port, bound_port], timeout),
            Some(format!("localhost:{bound_port}")),
            "should skip the closed port and detect the bound one"
        );
        assert_eq!(
            first_listening_port(&[closed_port], timeout),
            None,
            "nothing listens on a closed port"
        );
    }

    fn login_creds() -> Creds {
        Creds::Login {
            url: "/login".into(),
            username: "wayfind-dogfood".into(),
            var: "UXLINT_LOGIN_PASSWORD".into(),
            password: "uxlint-dev".into(),
            inline: false,
        }
    }

    /// A checked-in dev login writes its password straight into the toml — no .env, no ${VAR}.
    #[test]
    fn an_inline_credential_puts_the_value_in_the_toml() {
        let c = Creds::Login {
            url: "/login".into(),
            username: "wayfind-dogfood".into(),
            var: "UXLINT_LOGIN_PASSWORD".into(),
            password: "uxlint-dev".into(),
            inline: true,
        };
        let block = credentials_block(&c);
        assert!(
            block.contains("password = \"uxlint-dev\""),
            "inline value expected:\n{block}"
        );
        assert!(
            !block.contains("${"),
            "an inline credential must not reference a var:\n{block}"
        );
        assert!(
            block.contains("checked-in"),
            "the comment should say it's checked in"
        );
    }

    /// A real secret is a ${VAR} reference, never the value.
    #[test]
    fn a_secret_credential_is_a_var_reference() {
        let block = credentials_block(&login_creds()); // inline: false
        assert!(
            block.contains("password = \"${UXLINT_LOGIN_PASSWORD}\""),
            "{block}"
        );
        assert!(
            !block.contains("uxlint-dev"),
            "the secret value must not appear in the toml:\n{block}"
        );
    }

    /// A curated config: comments, exclude, an `as="user"` credentials block, roles and goals. The
    /// update must swap ONLY the credentials and leave every other line byte-for-byte.
    const CURATED: &str = r#"# uxlint.toml — this project's identity
org = "Personal"
site = "uxlint.net"
routes = ["/", "/docs", "/pricing"]

exclude = ["/example", "/r/"]

# The credentials the client replays. `as = "user"` borrows from [roles.user].
[credentials.login]
url = "/login"
as = "user"

# The test account, also used by the tests below.
[roles.user]
email = "wayfind-dogfood"
password = "${UXLINT_DEV_PASSWORD}"

[[tests]]
goal = "sign up for an account"
audience = "anonymous"
"#;

    #[test]
    fn update_swaps_credentials_and_keeps_the_rest() {
        let out = update_credentials(CURATED, &login_creds());
        // credentials became explicit (login_creds is a .env secret → ${VAR} reference)
        assert!(out.contains("username = \"wayfind-dogfood\""), "{out}");
        assert!(
            out.contains("password = \"${UXLINT_LOGIN_PASSWORD}\""),
            "credentials swapped in:\n{out}"
        );
        assert!(
            !out.contains("as = \"user\""),
            "old as=user block must be gone:\n{out}"
        );
        // and the preserved [roles.user] keeps its OWN password reference, untouched
        assert!(
            out.contains("password = \"${UXLINT_DEV_PASSWORD}\""),
            "roles password preserved:\n{out}"
        );
        // everything else survives, verbatim
        for kept in [
            "org = \"Personal\"",
            "site = \"uxlint.net\"",
            "routes = [\"/\", \"/docs\", \"/pricing\"]",
            "exclude = [\"/example\", \"/r/\"]",
            "[roles.user]",
            "email = \"wayfind-dogfood\"",
            "[[tests]]",
            "goal = \"sign up for an account\"",
        ] {
            assert!(out.contains(kept), "lost {kept:?} from:\n{out}");
        }
        // the roles/goals sections still parse as TOML after the splice
        toml::from_str::<toml::Value>(&out).expect("result must be valid TOML");
    }

    #[test]
    fn update_identity_swaps_org_and_site_and_keeps_the_rest() {
        let out = update_identity(CURATED, "Wayfind Team", "staging.acme.com");
        assert!(out.contains("org = \"Wayfind Team\""), "{out}");
        assert!(out.contains("site = \"staging.acme.com\""), "{out}");
        assert!(!out.contains("uxlint.net"), "old site must be gone:\n{out}");
        // every other line survives, verbatim — including the sections and their keys
        for kept in [
            "# uxlint.toml — this project's identity",
            "routes = [\"/\", \"/docs\", \"/pricing\"]",
            "exclude = [\"/example\", \"/r/\"]",
            "[credentials.login]",
            "as = \"user\"",
            "[roles.user]",
            "email = \"wayfind-dogfood\"",
            "[[tests]]",
        ] {
            assert!(out.contains(kept), "lost {kept:?} from:\n{out}");
        }
        toml::from_str::<toml::Value>(&out).expect("result must be valid TOML");
    }

    #[test]
    fn update_identity_inserts_missing_keys_before_the_first_section() {
        let bare = "# hand-rolled\nroutes = [\"/\"]\n\n[[tests]]\ngoal = \"x\"\n";
        let out = update_identity(bare, "Personal", "app.example");
        let org_at = out.find("org = \"Personal\"").expect("org inserted");
        let goals_at = out.find("[[tests]]").unwrap();
        assert!(
            org_at < goals_at,
            "identity must be top-level, before the first section:\n{out}"
        );
        toml::from_str::<toml::Value>(&out).expect("valid TOML");
    }

    #[test]
    fn update_identity_leaves_section_keys_alone() {
        // A `site = …` INSIDE a section is someone else's key — only the top-level identity moves.
        let t = "org = \"A\"\nsite = \"a.example\"\n\n[widget]\nsite = \"keep-me\"\n";
        let out = update_identity(t, "B", "b.example");
        assert!(out.contains("site = \"b.example\""), "{out}");
        assert!(
            out.contains("site = \"keep-me\""),
            "section-scoped key must survive:\n{out}"
        );
    }

    #[test]
    fn update_keeps_the_comment_that_introduces_the_next_section() {
        // The prose above [roles.user] belongs to it, not to the credentials block above it — a
        // trailing comment must survive the splice (it didn't, the first time).
        let out = update_credentials(CURATED, &login_creds());
        assert!(
            out.contains("# The test account, also used by the tests below."),
            "the [roles.user] comment was swallowed:\n{out}"
        );
        // and it still sits directly above [roles.user]
        let comment_at = out.find("# The test account").unwrap();
        let roles_at = out.find("[roles.user]").unwrap();
        assert!(
            comment_at < roles_at && roles_at - comment_at < 80,
            "comment should hug [roles.user]:\n{out}"
        );
    }

    #[test]
    fn update_drops_the_stale_credentials_comment() {
        let out = update_credentials(CURATED, &login_creds());
        assert!(
            !out.contains("borrows from [roles.user]"),
            "stale intro comment should be replaced:\n{out}"
        );
        assert!(
            out.contains("via the login form at login_url"),
            "new comment should be present"
        );
    }

    #[test]
    fn update_inserts_when_there_is_no_credentials_section() {
        let no_creds = "org = \"Personal\"\nsite = \"acme.dev\"\nroutes = [\"/\"]\n\n[[tests]]\ntest = \"x\"\n";
        let out = update_credentials(no_creds, &login_creds());
        assert!(out.contains("[personas.user]"));
        assert!(out.contains("[[tests]]"), "existing goals kept");
        // the persona (and its top-level login_url/default_persona) go BEFORE the first section, so
        // the top-level keys stay valid TOML.
        assert!(
            out.find("login_url").unwrap() < out.find("[[tests]]").unwrap(),
            "{out}"
        );
        toml::from_str::<toml::Value>(&out).expect("valid TOML");
    }

    /// Re-running init on an OLD-schema file migrates it: the legacy `[credentials]` header block is
    /// removed and replaced by the new login persona.
    #[test]
    fn update_replaces_a_legacy_credentials_block() {
        let legacy = "org = \"A\"\nsite = \"b\"\nroutes = [\"/\"]\n\n[credentials]\nheaders = [\"Cookie: x=1\"]\n";
        let out = update_credentials(legacy, &login_creds());
        assert!(
            !out.contains("Cookie: x=1"),
            "old header creds gone:\n{out}"
        );
        assert!(out.contains("[personas.user]"));
        assert!(
            out.contains("username = \"wayfind-dogfood\""),
            "new login written:\n{out}"
        );
        toml::from_str::<toml::Value>(&out).expect("valid TOML");
    }

    #[test]
    fn existing_identity_reads_top_level_org_and_site() {
        let (org, site) = existing_identity(CURATED);
        assert_eq!(org.as_deref(), Some("Personal"));
        assert_eq!(site.as_deref(), Some("uxlint.net"));
        // a `site`-looking key inside a section must not be mistaken for the top-level one
        let tricky = "org = \"O\"\nsite = \"real\"\n[roles.user]\nsite = \"nope\"\n";
        assert_eq!(existing_identity(tricky).1.as_deref(), Some("real"));
    }
}
