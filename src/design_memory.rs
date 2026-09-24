//! Checked-in, explicitly approved design decisions. Loaded afresh for every guidance call so a
//! new session gets the same contract and an intentional revision takes effect without restarting.
//! No network, automatic approval, lint suppression or writes to the contract.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read, path::Path};

const FILE: &str = "uxlint.design.json";
const MAX_BYTES: u64 = 32_768;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    version: u32,
    revision: u32,
    status: Approval,
    site: String,
    #[serde(default)]
    tokens: BTreeMap<String, String>,
    #[serde(default)]
    components: BTreeMap<String, String>,
    #[serde(default)]
    pages: BTreeMap<String, String>,
    #[serde(default)]
    journeys: Vec<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    exceptions: Vec<String>,
}

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Approval {
    Draft,
    Approved,
}

fn parse(text: &str, site: &str) -> Result<Contract, &'static str> {
    let c: Contract =
        serde_json::from_str(text).map_err(|_| "invalid JSON or unsupported fields")?;
    if c.version != 1 || c.revision == 0 {
        return Err("expected version 1 and a positive revision");
    }
    if c.site != site {
        return Err("site does not match this project's uxlint.toml");
    }
    if c.tokens.is_empty() && c.components.is_empty() && c.pages.is_empty() && c.journeys.is_empty()
    {
        return Err("contract contains no design decisions");
    }
    Ok(c)
}

fn from_dir(start: &Path) -> Result<Option<Contract>, String> {
    for dir in start.ancestors() {
        let config = dir.join("uxlint.toml");
        if !config.exists() {
            continue;
        }
        // Stop at the nearest project boundary even if it has no contract. Never borrow a parent
        // workspace's approved design for a nested project that has its own identity.
        let path = dir.join(FILE);
        if !path.exists() {
            return Ok(None);
        }
        let error = |msg| {
            format!("Design memory unavailable: {FILE}: {msg}. Correct it before relying on project decisions.")
        };
        let config: toml::Value = std::fs::read_to_string(config)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| error("cannot read project identity"))?;
        let site = config
            .get("site")
            .and_then(|v| v.as_str())
            .ok_or_else(|| error("project site is missing"))?;
        let mut text = String::new();
        std::fs::File::open(path)
            .map_err(|_| error("cannot read file"))?
            .take(MAX_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|_| error("cannot read UTF-8 file"))?;
        if text.len() as u64 > MAX_BYTES {
            return Err(error("file exceeds 32 KiB"));
        }
        return parse(&text, site).map(Some).map_err(error);
    }
    Ok(None)
}

pub(crate) fn guidance() -> String {
    let Ok(dir) = std::env::current_dir() else {
        return "Design memory unavailable: cannot read the project directory.\n\n".into();
    };
    render(from_dir(&dir))
}

fn render(result: Result<Option<Contract>, String>) -> String {
    match result {
        Err(error) => format!("{error}\n\n"),
        Ok(None) => String::new(),
        Ok(Some(c)) if c.status == Approval::Draft => format!(
            "Design memory: {FILE} revision {} is a DRAFT. Ask the project owner to review its decisions before treating them as approved. Do not approve it merely to clear a lint.\n\n", c.revision),
        Ok(Some(c)) => format!(
            "Approved project design — {FILE}, revision {}. Preserve these decisions across edits. Use the references to understand the existing design; they have not been fetched or validated by this tool. Exceptions are context for review, not automatic lint suppressions. If a decision conflicts with an accessibility or functional finding, explain the conflict; do not remove functionality or silently rewrite the contract. The owner must approve an intentional redesign and increment revision.\n{}\n\n",
            c.revision, serde_json::to_string_pretty(&c).expect("serializable contract")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "uxlint-design-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn contract(status: &str) -> String {
        serde_json::json!({"version":1,"revision":1,"status":status,"site":"example.test",
            "tokens":{"accent":"var(--brand)"},"components":{"button":"Use PrimaryButton"}})
        .to_string()
    }
    #[test]
    fn draft_does_not_inject_unapproved_decisions() {
        let text = render(Ok(Some(parse(&contract("draft"), "example.test").unwrap())));
        assert!(text.contains("DRAFT"));
        assert!(!text.contains("PrimaryButton"));
    }
    #[test]
    fn approved_decisions_survive_a_fresh_read_and_revision() {
        let dir = TempDir::new();
        std::fs::write(dir.path().join("uxlint.toml"), "site = 'example.test'").unwrap();
        let path = dir.path().join(FILE);
        std::fs::write(&path, contract("approved")).unwrap();
        assert!(render(from_dir(dir.path())).contains("PrimaryButton"));
        let revised = contract("approved").replace("\"revision\":1", "\"revision\":2");
        std::fs::write(&path, &revised).unwrap();
        assert!(render(from_dir(dir.path())).contains("revision 2"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), revised);
    }
    #[test]
    fn identity_version_and_project_boundaries_are_enforced() {
        assert!(parse(&contract("approved"), "another.test").is_err());
        assert!(parse(
            &contract("approved").replace("\"version\":1", "\"version\":2"),
            "example.test"
        )
        .is_err());
        let dir = TempDir::new();
        std::fs::write(dir.path().join("uxlint.toml"), "site = 'example.test'").unwrap();
        std::fs::write(dir.path().join(FILE), contract("approved")).unwrap();
        let child = dir.path().join("nested");
        std::fs::create_dir(&child).unwrap();
        assert!(from_dir(&child).unwrap().is_some());
        std::fs::write(child.join("uxlint.toml"), "site = 'nested.test'").unwrap();
        assert!(from_dir(&child).unwrap().is_none());
    }
    #[test]
    fn malformed_or_oversized_contract_is_visible_not_silently_ignored() {
        let dir = TempDir::new();
        std::fs::write(dir.path().join("uxlint.toml"), "site = 'example.test'").unwrap();
        let path = dir.path().join(FILE);
        for text in ["bad json".to_string(), "x".repeat(MAX_BYTES as usize + 1)] {
            std::fs::write(&path, text).unwrap();
            assert!(render(from_dir(dir.path())).contains("Design memory unavailable"));
        }
    }
}
