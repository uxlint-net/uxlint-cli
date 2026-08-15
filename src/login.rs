//! `uxlint auth login` — browser-based auth. Opens the web app, which (once you're signed in) mints a
//! personal access token and hands it back to a one-shot localhost listener; we store it at
//! ~/.config/uxlint/credentials and read it as a fallback below --api-key / UXLINT_API_KEY.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The web app to send someone to, for a link they can actually click. In production the Axum server
/// serves the SPA itself (`UXLINT_WEB_DIR`), so the API origin IS the web origin and deriving one
/// from the other is correct rather than a guess; `UXLINT_WEB_URL` overrides it for local dev, where
/// Vite serves the app on its own port.
pub(crate) fn web_base(server: &str) -> String {
    std::env::var("UXLINT_WEB_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| server.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// Why we can't authenticate. The two cases read completely differently to a human and must not
/// share one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialProblem {
    /// No credential at all: never signed in, or signed out. An onboarding moment.
    Missing,
    /// A credential exists and the server REFUSED it. Usually revoked — an admin or an org admin can
    /// invalidate tokens, and incident response rotates them — occasionally a token minted for a
    /// different server. Telling this person to "sign in" implies they never did, which sends them
    /// hunting for a mistake they did not make.
    Rejected,
}

/// What to tell someone whose credential is missing or refused, and how to fix it — including a URL
/// they can click, because "run this command" is useless advice to whoever is reading it relayed
/// through a coding agent.
///
/// `for_agent` switches the AUDIENCE, not just the wording: an MCP client is a model that cannot open
/// a browser or run a terminal command, so its copy has to tell it to relay the link and the command
/// to the human. Without that, agents report "authentication failed" and stop.
pub(crate) fn credential_help(server: &str, problem: CredentialProblem, for_agent: bool) -> String {
    let web = web_base(server);
    let lead = match problem {
        CredentialProblem::Missing => {
            "uxlint isn't signed in, so it can't reach the server.".to_string()
        }
        CredentialProblem::Rejected => "uxlint's saved credential was refused by the server — it has \
             most likely been revoked (an admin can invalidate tokens, and incident response rotates \
             them). It needs replacing; nothing is wrong with your setup."
            .to_string(),
    };
    // The link differs by problem, and the difference matters. A refused token means an ACCOUNT
    // exists — send them straight to the token page. A missing credential often means no account at
    // all (the plugin installs in one click, long before anyone signs up), so they get the sign-in
    // page, which also creates accounts, with `next` set so signing in LANDS on the token page rather
    // than the dashboard with a hunt ahead of them. Pointing a signed-out stranger at /settings just
    // bounces them to a login page that then forgets where they were going.
    let (verb, url) = match problem {
        CredentialProblem::Missing => (
            "Sign in (or create an account)",
            format!("{web}/login?next=%2Fsettings"),
        ),
        CredentialProblem::Rejected => ("Mint a replacement", format!("{web}/settings")),
    };
    let mut out = format!(
        "{lead}\n\n{verb} here:\n  {url}\n  (then: Access tokens → Create)\n\n\
         Then save the token:\n  \
         • uxlint auth login      — opens that page and stores the token for you\n  \
         • or set UXLINT_API_KEY=uxt_… in the environment"
    );
    if problem == CredentialProblem::Rejected {
        out.push_str(
            "\n\nThe old credential is dead — a revoked token never comes back, so re-running \
             without replacing it fails exactly the same way.",
        );
    }
    if for_agent {
        out.push_str(
            "\n\nYou can't do this yourself — opening a browser and running a terminal command are \
             the user's to do. Show them the link and the command above, then call this tool again \
             once they confirm: the credential is re-read on every call, so there is nothing to \
             restart.",
        );
    } else {
        out.push_str(&format!("\n\nServer: {server}"));
    }
    out
}

/// Where the token lives. XDG_CONFIG_HOME/uxlint/credentials, else ~/.config/uxlint/credentials.
pub(crate) fn cred_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("uxlint").join("credentials"))
}

/// A token saved by a prior `uxlint auth login`, if any.
pub(crate) fn stored_credential() -> Option<String> {
    let t = std::fs::read_to_string(cred_path()?)
        .ok()?
        .trim()
        .to_string();
    (!t.is_empty()).then_some(t)
}

fn store_credential(token: &str) -> Result<PathBuf> {
    let path = cred_path().context("no HOME/XDG_CONFIG_HOME to store credentials")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, token)?;
    // Best-effort tighten perms to owner-only (0600) on unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

fn open_browser(url: &str) {
    // Best-effort — every platform gets a try, and we always print the URL as a fallback.
    for cmd in ["xdg-open", "open"] {
        if std::process::Command::new(cmd).arg(url).spawn().is_ok() {
            return;
        }
    }
}

/// How long to hold the callback port open. A returning user finishes in seconds, but someone
/// WITHOUT an account goes create-account → switch to their inbox → find the email → click the
/// verification link → come back — a path that routinely runs past a couple of minutes. Long
/// enough to cover that, short enough that a login against a server that will never answer ends
/// by itself.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// How often to reassure a long-waiting user the command hasn't hung. Only the sign-up path
/// (email verification) takes long enough for silence to look broken.
const PROGRESS_EVERY: Duration = Duration::from_secs(30);

/// Block on the one-shot listener until the browser hits it with `?token=…`, then reply with a
/// friendly close-me page and return the token.
fn wait_for_token(listener: &TcpListener) -> Result<String> {
    // Poll rather than block forever: if the web app is down the browser never comes back, and a
    // command that hangs with no output tells you less than one that says what it was waiting for.
    listener.set_nonblocking(true).ok();
    let start = Instant::now();
    let deadline = start + CALLBACK_TIMEOUT;
    let mut next_progress = start + PROGRESS_EVERY;
    loop {
        let (mut stream, _) = match listener.accept() {
            Ok(conn) => conn,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let now = Instant::now();
                if now >= deadline {
                    bail!(
                        "gave up after {} minutes — the browser never came back with a token. Is the web app running?",
                        CALLBACK_TIMEOUT.as_secs() / 60
                    );
                }
                if now >= next_progress {
                    eprintln!(
                        "  still waiting… creating an account? check your inbox for the verification link, then come back and sign in."
                    );
                    next_progress = now + PROGRESS_EVERY;
                }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e).context("callback listener failed"),
        };
        stream.set_nonblocking(false).ok(); // the read below wants to block
        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]);
        let line = req.lines().next().unwrap_or("");
        // "GET /?token=uxt_… HTTP/1.1"
        let token = line
            .split_whitespace()
            .nth(1)
            .and_then(|path| path.split_once("token="))
            .map(|(_, rest)| rest.split('&').next().unwrap_or("").to_string());
        match token {
            Some(t) if !t.is_empty() => {
                let body = "<!doctype html><meta charset=utf-8><title>uxlint</title><body style=\"font-family:system-ui;background:#0a0c11;color:#e6e8ee;display:grid;place-items:center;height:100vh;margin:0\"><div style=\"text-align:center\"><h2>You're signed in.</h2><p style=\"color:#9aa3b2\">Return to your terminal — you can close this tab.</p></div>";
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                return Ok(urldecode(&t));
            }
            _ => {
                // favicon or a bare hit — 204 and keep waiting.
                let _ = write!(
                    stream,
                    "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
                );
            }
        }
    }
}

fn urldecode(s: &str) -> String {
    // Tokens are [A-Za-z0-9_]; the only realistic escape is a stray %XX. Minimal decoder.
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Who a token belongs to — only the server can say, so ask it. Returns the account's email.
fn whoami(server: &str, token: &str) -> Result<String> {
    let url = format!("{}/v1/me", server.trim_end_matches('/'));
    let res = reqwest::blocking::Client::new()
        .get(&url)
        .bearer_auth(token)
        .timeout(Duration::from_secs(10))
        .send()
        .with_context(|| format!("could not reach the uxlint server at {server}"))?;
    let body: serde_json::Value = res.json().context("the server's reply wasn't JSON")?;
    if body["authenticated"].as_bool() != Some(true) {
        bail!(
            "the server rejected that token: {}",
            body["error"].as_str().unwrap_or("not authenticated")
        );
    }
    Ok(body["email"]
        .as_str()
        .unwrap_or("(unknown account)")
        .to_string())
}

pub(crate) fn run_login(web: &str, server: &str) -> Result<()> {
    let listener =
        TcpListener::bind("127.0.0.1:0").context("could not open a local callback port")?;
    let port = listener.local_addr()?.port();
    let url = format!("{}/cli-login?port={port}", web.trim_end_matches('/'));
    // Say what each half IS. "Opening http://…:49173/cli-login?port=39549" invites you to read
    // 39549 as the server's port and go looking for a site there; it's this process, waiting for
    // one request. Naming the host matters too: a session on 127.0.0.1 is a DIFFERENT session from
    // one on localhost, so "I signed out but it logged me straight back in" is usually the app open
    // on the other spelling of this machine.
    eprintln!("Signing in via {}", web.trim_end_matches('/'));
    eprintln!("  {url}");
    eprintln!("  (if your browser didn't open, paste that URL into it)");
    eprintln!("  port={port} is this command listening for the token — not a site to visit.");
    open_browser(&url);
    let token = wait_for_token(&listener)?;
    // VERIFY before claiming anything. Without contacting the server, we'd store whatever landed on
    // the callback and print "Logged in" — the message would really be about a file write, and a
    // stale or revoked token would report success exactly like a good one. The first you'd hear of
    // it would be a 401 in the middle of some later command.
    let email = whoami(server, &token)?;
    let path = store_credential(&token)?;
    println!(
        "Logged in as {email} — credentials saved to {}",
        path.display()
    );
    Ok(())
}

/// A sign-in the CALLER can't drive: start the same browser flow `run_login` runs, but return the
/// link instead of blocking on it, and finish it on a background thread.
///
/// This is the MCP case. A tool call can't sit for fifteen minutes waiting for a human to find their
/// password, and the model on the other end can't open a browser — but it CAN show a link. So we open
/// the callback port now, hand back the URL, and let the click do the rest: whoever opens it signs in
/// (creating an account if they need one — `/cli-login` bounces through `/login` and comes back),
/// the web app mints a token, and it lands in the same credentials file `uxlint auth login` writes.
/// The next tool call re-reads that file and simply works, with nothing to restart.
///
/// Single-flight, because the failing tool call that produces the link is exactly the call an agent
/// retries: without this, every retry would open another port and print a different link, and the one
/// the user finally clicked would be answering a listener nobody was waiting on.
pub(crate) fn pending_login_url(web: &str, server: &str) -> Result<String> {
    /// The link we handed out and a flag the waiting thread sets when it's finished with the port.
    struct Pending {
        url: String,
        done: Arc<AtomicBool>,
    }
    static PENDING: OnceLock<Mutex<Option<Pending>>> = OnceLock::new();
    let cell = PENDING.get_or_init(|| Mutex::new(None));
    let mut slot = cell.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = slot.as_ref() {
        if !p.done.load(Ordering::Relaxed) {
            return Ok(p.url.clone());
        }
    }

    let listener =
        TcpListener::bind("127.0.0.1:0").context("could not open a local callback port")?;
    let port = listener.local_addr()?.port();
    let url = format!("{}/cli-login?port={port}", web.trim_end_matches('/'));
    let done = Arc::new(AtomicBool::new(false));

    std::thread::spawn({
        let (done, server) = (done.clone(), server.to_string());
        move || {
            // Everything here goes to stderr: under `uxlint mcp` stdout is the JSON-RPC channel, and
            // a line of chat on it makes the whole server look broken to its client.
            match wait_for_token(&listener).and_then(|token| {
                // VERIFY before storing, exactly as run_login does — a token we never checked would
                // sit on disk looking valid until some later call 401s.
                let email = whoami(&server, &token)?;
                store_credential(&token)?;
                Ok(email)
            }) {
                Ok(email) => eprintln!("uxlint: signed in as {email} — credentials saved"),
                Err(e) => eprintln!("uxlint: sign-in didn't complete: {e}"),
            }
            done.store(true, Ordering::Relaxed);
        }
    });

    *slot = Some(Pending {
        url: url.clone(),
        done,
    });
    Ok(url)
}

pub(crate) fn run_logout() -> Result<()> {
    if let Some(path) = cred_path() {
        if path.exists() {
            std::fs::remove_file(&path)?;
            println!("Logged out — removed {}", path.display());
            return Ok(());
        }
    }
    println!("Already logged out (no stored credentials).");
    Ok(())
}

/// `uxlint auth status` — who (if anyone) this CLI is signed in as, and against which server.
/// Never fails the process on a bad/expired token (this is a look-up, not a gate) — it just says
/// so plainly, the same honesty `run_login` already applies before ever claiming success.
pub(crate) fn run_status(server: &str) -> Result<()> {
    let Some(token) = stored_credential() else {
        println!("Not signed in — run `uxlint auth login` first.");
        return Ok(());
    };
    match whoami(server, &token) {
        Ok(email) => println!("Signed in as {email} ({server})"),
        Err(e) => println!("A token is saved, but it didn't check out against {server}: {e}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_revoked_credential_does_not_read_as_never_signed_in() {
        // The distinction this whole helper exists for. Someone whose token was just revoked HAS
        // signed in; telling them they haven't sends them hunting for a setup mistake they didn't
        // make, and an agent relaying it walks them through first-run all over again.
        let rejected = credential_help("https://uxlint.net", CredentialProblem::Rejected, false);
        assert!(rejected.contains("revoked"), "{rejected}");
        assert!(!rejected.contains("isn't signed in"), "{rejected}");
        // And it must say the old one is gone for good, or the obvious move is to retry as-is.
        assert!(rejected.contains("never comes back"), "{rejected}");

        let missing = credential_help("https://uxlint.net", CredentialProblem::Missing, false);
        assert!(missing.contains("isn't signed in"), "{missing}");
        assert!(!missing.contains("revoked"), "{missing}");
    }

    #[test]
    fn both_cases_offer_a_link_and_a_command() {
        // "Run uxlint auth login" is useless to whoever is reading this relayed through an agent in
        // a chat window, and a link alone is useless in CI. Every message carries both.
        for p in [CredentialProblem::Missing, CredentialProblem::Rejected] {
            let m = credential_help("https://uxlint.net", p, false);
            assert!(m.contains("https://uxlint.net/"), "{m}");
            assert!(m.contains("uxlint auth login"), "{m}");
            assert!(m.contains("UXLINT_API_KEY"), "{m}");
        }
    }

    #[test]
    fn nobody_signed_in_gets_a_sign_in_url_that_resumes_at_the_token_page() {
        // Whoever hits this may have no ACCOUNT — the plugin installs in one click, and the first
        // thing it does is fail this check. /settings would bounce them to a login page that then
        // forgets where they were headed, so the link is the sign-in page with `next` set.
        let m = credential_help("https://uxlint.net", CredentialProblem::Missing, false);
        assert!(
            m.contains("https://uxlint.net/login?next=%2Fsettings"),
            "{m}"
        );
        assert!(m.contains("create an account"), "{m}");

        // A refused token means the account already exists — sending that person to a sign-in page
        // implies they never signed up, which is the confusion this helper exists to avoid.
        let r = credential_help("https://uxlint.net", CredentialProblem::Rejected, false);
        assert!(r.contains("https://uxlint.net/settings"), "{r}");
        assert!(!r.contains("create an account"), "{r}");
    }

    #[test]
    fn the_agent_variant_tells_the_model_to_hand_it_over() {
        // An MCP client can't open a browser or run a shell command. Unless it's told to relay, it
        // reports "authentication failed" and stops, and the user never sees the way out.
        let a = credential_help("https://uxlint.net", CredentialProblem::Rejected, true);
        assert!(a.contains("can't do this yourself"), "{a}");
        assert!(a.contains("call this tool again"), "{a}");
        // And it must NOT ask for a restart: the credential is re-read per call now, so telling an
        // agent to have the user restart their editor invents a step that makes a working setup
        // look broken.
        assert!(a.contains("nothing to restart"), "{a}");
        assert!(!a.contains("restart the editor"), "{a}");
        // The human-facing variant shouldn't carry agent instructions.
        let h = credential_help("https://uxlint.net", CredentialProblem::Rejected, false);
        assert!(!h.contains("can't do this yourself"), "{h}");
    }

    #[test]
    fn the_link_follows_the_server_this_run_points_at() {
        // A self-hosted deployment's user must not be sent to our hosted settings page. In prod the
        // API origin serves the SPA, so deriving it is right; UXLINT_WEB_URL covers local dev.
        let m = credential_help(
            "https://uxlint.example.com",
            CredentialProblem::Missing,
            false,
        );
        assert!(m.contains("https://uxlint.example.com/login"), "{m}");
        assert!(!m.contains("uxlint.net"), "{m}");
    }

    #[test]
    fn a_pending_sign_in_hands_out_one_link_not_one_per_call() {
        // The call that produces this link is exactly the call an agent retries. A second port per
        // retry would leave the user clicking a link whose listener nobody is waiting on — the flow
        // would complete in the browser and the CLI would still be signed out.
        let a = pending_login_url("https://uxlint.example.com", "https://uxlint.example.com")
            .expect("a local callback port");
        let b = pending_login_url("https://uxlint.example.com", "https://uxlint.example.com")
            .expect("a local callback port");
        assert_eq!(a, b, "a retry must reuse the live listener");
        // It's the real cli-login flow, not the settings page — clicking it mints the token itself.
        assert!(
            a.starts_with("https://uxlint.example.com/cli-login?port="),
            "{a}"
        );
        let port: u16 = a.rsplit('=').next().unwrap().parse().expect("a real port");
        assert!(port > 0);
    }
}
