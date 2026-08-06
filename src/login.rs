//! `uxlint auth login` — browser-based auth. Opens the web app, which (once you're signed in) mints a
//! personal access token and hands it back to a one-shot localhost listener; we store it at
//! ~/.config/uxlint/credentials and read it as a fallback below --api-key / UXLINT_API_KEY.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

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
