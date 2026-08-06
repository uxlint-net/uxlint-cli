//! `uxlint site` — manage sites (create/delete/list) and their members from the CLI. Thin wrappers
//! over the server API; org defaults to your personal workspace unless `--org` names a team.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::Cli;

fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::new()
}

fn key(cli: &Cli) -> Result<&str> {
    cli.api_key
        .as_deref()
        .filter(|k| !k.is_empty())
        .context("no API key — run `uxlint auth login` or set UXLINT_API_KEY")
}

/// The caller's world: orgs + the sites they can see (membership-gated server-side).
fn me(cli: &Cli) -> Result<Value> {
    let v: Value = http()
        .get(format!("{}/v1/me", cli.server))
        .bearer_auth(key(cli)?)
        .send()
        .context("server unreachable")?
        .json()?;
    if v["authenticated"] == json!(false) || v["orgs"].is_null() {
        bail!("not signed in — check your API key (uxlint auth login)");
    }
    Ok(v)
}

/// Resolve an org id: by name (case-insensitive) if given, else the personal workspace.
fn resolve_org(me: &Value, org: Option<&str>) -> Result<(i64, String)> {
    let orgs = me["orgs"].as_array().cloned().unwrap_or_default();
    let pick = match org {
        Some(name) => orgs
            .iter()
            .find(|o| {
                o["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            })
            .with_context(|| format!("you're not in an org named \"{name}\""))?,
        None => orgs
            .iter()
            .find(|o| o["kind"] == json!("personal"))
            .or_else(|| orgs.first())
            .context("no org found for this account")?,
    };
    Ok((
        pick["id"].as_i64().unwrap_or_default(),
        pick["name"].as_str().unwrap_or("").to_string(),
    ))
}

fn find_site(me: &Value, org_id: i64, host: &str) -> Option<i64> {
    me["orgs"]
        .as_array()?
        .iter()
        .find(|o| o["id"].as_i64() == Some(org_id))?["sites"]
        .as_array()?
        .iter()
        .find(|s| s["host"].as_str() == Some(host))?["id"]
        .as_i64()
}

pub(crate) fn create(cli: &Cli, host: &str, org: Option<&str>) -> Result<()> {
    let me = me(cli)?;
    let (org_id, org_name) = resolve_org(&me, org)?;
    let resp: Value = http()
        .post(format!("{}/v1/orgs/{org_id}/sites", cli.server))
        .bearer_auth(key(cli)?)
        .json(&json!({ "host": host }))
        .send()?
        .json()?;
    match resp["id"].as_i64() {
        Some(id) => {
            println!(
                "created site {} [{id}] in {org_name}",
                resp["host"].as_str().unwrap_or(host)
            );
            Ok(())
        }
        None => bail!(
            "create failed: {}",
            resp["error"].as_str().unwrap_or("unexpected response")
        ),
    }
}

pub(crate) fn delete(cli: &Cli, host: &str, org: Option<&str>) -> Result<()> {
    let me = me(cli)?;
    let (org_id, _) = resolve_org(&me, org)?;
    let sid =
        find_site(&me, org_id, host).with_context(|| format!("no site \"{host}\" in that org"))?;
    let resp = http()
        .delete(format!("{}/v1/orgs/{org_id}/sites/{sid}", cli.server))
        .bearer_auth(key(cli)?)
        .send()?;
    anyhow::ensure!(
        resp.status().is_success(),
        "delete failed ({})",
        resp.status()
    );
    println!("deleted site {host}");
    Ok(())
}

pub(crate) fn list(cli: &Cli) -> Result<()> {
    let me = me(cli)?;
    for o in me["orgs"].as_array().cloned().unwrap_or_default() {
        println!(
            "{} ({})",
            o["name"].as_str().unwrap_or("?"),
            o["kind"].as_str().unwrap_or("")
        );
        let sites = o["sites"].as_array().cloned().unwrap_or_default();
        if sites.is_empty() {
            println!("  (no sites)");
        }
        for s in sites {
            println!(
                "  {} [{}]",
                s["host"].as_str().unwrap_or("?"),
                s["id"].as_i64().unwrap_or(0)
            );
        }
    }
    Ok(())
}

pub(crate) fn add_user(
    cli: &Cli,
    host: &str,
    email: &str,
    role: &str,
    org: Option<&str>,
) -> Result<()> {
    let me = me(cli)?;
    let (org_id, _) = resolve_org(&me, org)?;
    let sid =
        find_site(&me, org_id, host).with_context(|| format!("no site \"{host}\" in that org"))?;
    let resp: Value = http()
        .post(format!("{}/v1/sites/{sid}/members", cli.server))
        .bearer_auth(key(cli)?)
        .json(&json!({ "email": email, "role": role }))
        .send()?
        .json()?;
    match resp["account_id"].as_i64() {
        Some(_) => {
            println!(
                "added {email} as {} on {host}",
                resp["role"].as_str().unwrap_or(role)
            );
            Ok(())
        }
        None => bail!(
            "add failed: {}",
            resp["error"].as_str().unwrap_or("unexpected response")
        ),
    }
}

pub(crate) fn remove_user(cli: &Cli, host: &str, email: &str, org: Option<&str>) -> Result<()> {
    let me = me(cli)?;
    let (org_id, _) = resolve_org(&me, org)?;
    let sid =
        find_site(&me, org_id, host).with_context(|| format!("no site \"{host}\" in that org"))?;
    // The DELETE endpoint takes an account id; resolve it from the roster by email.
    let roster: Value = http()
        .get(format!("{}/v1/sites/{sid}/members", cli.server))
        .bearer_auth(key(cli)?)
        .send()?
        .json()?;
    let aid = roster["members"]
        .as_array()
        .and_then(|ms| ms.iter().find(|m| m["email"].as_str() == Some(email)))
        .and_then(|m| m["account_id"].as_i64())
        .with_context(|| format!("{email} isn't a member of {host}"))?;
    let resp = http()
        .delete(format!("{}/v1/sites/{sid}/members/{aid}", cli.server))
        .bearer_auth(key(cli)?)
        .send()?;
    anyhow::ensure!(
        resp.status().is_success(),
        "remove failed ({})",
        resp.status()
    );
    println!("removed {email} from {host}");
    Ok(())
}
