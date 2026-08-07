//! Test-only: every default this binary SHIPS has to be right on a stranger's machine, not on ours.
//!
//! Two bugs of exactly one shape got out. `--server` defaulted to `https://uxlint.dev` — a domain we
//! do not own (we are uxlint.net) — so a released binary posted every default run's capture AND its
//! bearer token to a third party. `uxlint auth login --web` defaulted to `http://127.0.0.1:49173`,
//! the port a `just dev` web app happens to listen on here, so browser login simply did not work for
//! anyone outside this repo. Both compiled, both passed clippy, both passed the whole test suite:
//! a default is just a string, and nothing had an opinion about what the string pointed at.
//!
//! So this walks the LIVE clap tree (the same introspection `docs_json` publishes the reference
//! from, so it can't drift from what the binary accepts) and states the opinion: a shipped default
//! that names a location must name OUR production one. It covers hidden commands and hidden args
//! too — hidden from `--help` is not hidden from the user's run.
//!
//! What it deliberately does NOT do: ban dev hosts from help text or examples. `--base
//! http://localhost:5173` is the right example for a CLI you point at your own dev server; the
//! defect is a dev host baked in as the value the binary USES when the user says nothing.

use clap::{Command, CommandFactory};

/// The one domain we own. A shipped default that names any other host is either a typo-squat of our
/// own name (`uxlint.dev`) or someone else's server; both are the same bug.
const OUR_DOMAIN: &str = "uxlint.net";

/// Hosts that exist only on the machine the binary was built on. `0.0.0.0`/`::1` are here for the
/// same reason as localhost: they resolve somewhere on every machine, so a default naming one fails
/// silently (a connection refused, or worse, whatever ELSE is listening) instead of loudly.
const DEV_HOSTS: &[&str] = &["localhost", "127.0.0.1", "0.0.0.0", "[::1]", "::1"];

/// Legitimate exceptions, if one ever exists: (command path, `--flag`, WHY it is right for a user).
/// Empty on purpose — a shipped default pointing at a developer's machine has, so far, always been
/// the bug. Add an entry only with a reason that survives being read by the next person; an
/// unexplained entry here is how a check stops meaning anything.
const DEV_DEFAULT_DEBT: &[(&str, &str, &str)] = &[];

/// One default value found on the command tree.
struct Shipped {
    /// Full command path, e.g. `uxlint auth login`.
    path: String,
    /// `--long` spelling, or the positional's id.
    arg: String,
    value: String,
}

/// Every default on the tree, hidden commands and hidden args included — hidden from `--help` is
/// not hidden from the run, and `ci` (our hidden back-compat alias) is a full command.
fn shipped_defaults(cmd: &Command, path: &str, out: &mut Vec<Shipped>) {
    let full = if path.is_empty() {
        cmd.get_name().to_string()
    } else {
        format!("{path} {}", cmd.get_name())
    };
    for a in cmd.get_arguments() {
        let arg = a
            .get_long()
            .map(|l| format!("--{l}"))
            .unwrap_or_else(|| a.get_id().to_string());
        for v in a.get_default_values() {
            out.push(Shipped {
                path: full.clone(),
                arg: arg.clone(),
                value: v.to_string_lossy().to_string(),
            });
        }
    }
    for sub in cmd.get_subcommands() {
        shipped_defaults(sub, &full, out);
    }
}

/// The host a default NAMES, if it names one: `https://host/path`, or a bare `host:port`. Returns
/// `None` for values that aren't locations (`/`, `desktop:1440x900,mobile:390x844`, `member`) — the
/// check has nothing to say about those, and guessing would make it noisy.
fn host_named(value: &str) -> Option<String> {
    let rest = match value.split_once("://") {
        Some((_scheme, rest)) => rest,
        // No scheme: only a bare `host:port` counts as a location. Requiring a numeric port is what
        // keeps `desktop:1440x900` (a viewport spec) out of this check.
        None => {
            let (h, port) = value.split_once(':')?;
            if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            return (!h.is_empty()).then(|| h.to_ascii_lowercase());
        }
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Strip userinfo and port; keep the brackets on an IPv6 literal so `[::1]` stays recognisable.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = match host.strip_prefix('[') {
        Some(v6) => format!("[{}]", v6.split(']').next().unwrap_or(v6)),
        None => host.split(':').next().unwrap_or(host).to_string(),
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// An address that only routes on the author's own network: RFC1918, loopback, link-local, CGNAT.
/// A default naming one is a dev value however plausible the number looks.
fn is_private_host(host: &str) -> bool {
    if DEV_HOSTS.contains(&host) || host.ends_with(".local") || host.ends_with(".localhost") {
        return true;
    }
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false;
    };
    match ip {
        // CGNAT is 100.64.0.0/10, not all of 100.x — 100.1.2.3 is a public address someone owns,
        // and a check that calls it "a dev host" would wave a real wrong default through as
        // private rather than flagging it as a domain we do not own.
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        // Loopback, unique-local (fc00::/7) and link-local (fe80::/10).
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.segments()[0] & 0xfe00 == 0xfc00
                || v6.segments()[0] & 0xffc0 == 0xfe80
        }
    }
}

fn allowed(d: &Shipped) -> bool {
    DEV_DEFAULT_DEBT
        .iter()
        .any(|(p, a, _)| *p == d.path && *a == d.arg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> Vec<Shipped> {
        let mut out = Vec::new();
        shipped_defaults(&crate::Cli::command(), "", &mut out);
        out
    }

    /// `uxlint auth login --web` shipped as `http://127.0.0.1:49173` for months: right here, wrong
    /// everywhere else, and login was simply broken for every user outside this repo. Nothing failed
    /// because nothing was checking. This is that check.
    #[test]
    fn no_shipped_default_points_at_a_developers_machine() {
        let bad: Vec<String> = defaults()
            .iter()
            .filter(|d| !allowed(d))
            .filter(|d| host_named(&d.value).is_some_and(|h| is_private_host(&h)))
            .map(|d| format!("{} {} = {:?}", d.path, d.arg, d.value))
            .collect();
        assert!(
            bad.is_empty(),
            "these defaults point at the machine they were written on, so a released binary uses \
             them against a host that does not exist for the user:\n  {}\n\
             Ship the production value and let a developer opt in via the flag or its env var.",
            bad.join("\n  ")
        );
    }

    /// The `--server` half of the same bug: a default that named `uxlint.dev`, which is not our
    /// domain, sent captures and bearer tokens to a stranger. Any host outside `uxlint.net` in a
    /// shipped default is that bug, whoever owns the host.
    #[test]
    fn no_shipped_default_names_a_domain_we_do_not_own() {
        let bad: Vec<String> = defaults()
            .iter()
            .filter(|d| !allowed(d))
            .filter(|d| {
                host_named(&d.value).is_some_and(|h| {
                    !is_private_host(&h)
                        && h != OUR_DOMAIN
                        && !h.ends_with(&format!(".{OUR_DOMAIN}"))
                })
            })
            .map(|d| format!("{} {} = {:?}", d.path, d.arg, d.value))
            .collect();
        assert!(
            bad.is_empty(),
            "these defaults name a host we do not own — a default run would send this user's \
             capture and bearer token there:\n  {}\n\
             We are {OUR_DOMAIN}.",
            bad.join("\n  ")
        );
    }

    /// The walk has to actually reach the places the bugs lived, or both tests above pass by finding
    /// nothing. `uxlint auth login --web` is a NESTED subcommand's arg and `--server` is a global on
    /// the root: pin both, so a refactor that stops walking the tree fails here instead of quietly
    /// turning the checks into no-ops.
    #[test]
    fn the_walk_reaches_the_defaults_that_actually_bit_us() {
        let all = defaults();
        let find = |path: &str, arg: &str| {
            all.iter()
                .find(|d| d.path == path && d.arg == arg)
                .map(|d| d.value.clone())
        };
        assert_eq!(
            find("uxlint auth login", "--web").as_deref(),
            Some("https://uxlint.net"),
            "the nested `auth login --web` default is not being walked (or has regressed)"
        );
        assert_eq!(
            find("uxlint", "--server").as_deref(),
            Some("https://uxlint.net"),
            "the root's global --server default is not being walked (or has regressed)"
        );
        // A tree walk that only ever saw two args would still pass the two tests above.
        assert!(
            all.len() > 10,
            "only {} defaults found — the walk is not descending the command tree",
            all.len()
        );
    }

    /// The classifier is the whole check: too eager and it flags viewport specs until someone
    /// deletes it, too shy and it waves the next bug through.
    #[test]
    fn a_location_is_told_from_a_plain_value() {
        for (v, want) in [
            ("https://uxlint.net", Some("uxlint.net")),
            ("http://127.0.0.1:49173", Some("127.0.0.1")),
            (
                "https://user:pw@api.uxlint.net:8443/v1",
                Some("api.uxlint.net"),
            ),
            ("http://[::1]:49800", Some("[::1]")),
            ("localhost:5173", Some("localhost")),
            // Not locations — a default the check must stay silent about.
            ("/", None),
            ("desktop:1440x900,mobile:390x844", None),
            ("member", None),
            ("uxlint-dry-run", None),
            ("", None),
        ] {
            assert_eq!(host_named(v).as_deref(), want, "host_named({v:?})");
        }
        for private in [
            "localhost",
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.9",
            "172.16.0.1",
            "[::1]",
            "dev.local",
            "100.64.0.1",
            "fe80::1",
        ] {
            assert!(is_private_host(private), "{private} is a dev host");
        }
        // 100.1.2.3 is PUBLIC: CGNAT is 100.64.0.0/10, so a check that swallowed all of 100.x would
        // silently exempt a real third-party host from the domain check.
        for public in [
            "uxlint.net",
            "api.uxlint.net",
            "8.8.8.8",
            "uxlint.dev",
            "100.1.2.3",
        ] {
            assert!(!is_private_host(public), "{public} is not a dev host");
        }
    }
}
