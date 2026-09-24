//! `uxlint mcp --supervise`: keep ONE MCP session with the agent while the uxlint behind it upgrades.
//!
//! A Claude Code plugin can auto-update, but the running MCP server is the OLD binary until the agent
//! restarts — so an update didn't reach anyone until they restarted Claude, and the old process lived
//! on (reported 2026-09-24). The plugin launcher now starts this supervisor instead of the server
//! itself. It relays newline-delimited JSON-RPC between the agent and a child `uxlint mcp`, and when
//! the PLUGIN has been updated to a newer version (Claude Code's own auto-update — nothing here
//! upgrades anything the user didn't opt into), it:
//!
//!   1. installs that version's binary (checksum-verified; `update::install_version_at`),
//!   2. starts it and replays the agent's original `initialize` into it (its reply is swallowed),
//!   3. routes every NEW request to it and tells the agent `notifications/tools/list_changed`,
//!   4. lets the old child finish what it was doing, then closes it — and kills it if it lingers.
//!
//! The agent never sees the connection drop. The routing is a pure state machine (`Router`) so the
//! awkward parts — ids the two children both use for their own requests to the agent, a cancel for a
//! call the old child is still running — are unit-tested line by line.
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

/// What the I/O shell should do after the router has seen a line.
#[derive(Debug, PartialEq)]
pub(crate) enum Action {
    ToAgent(String),
    ToChild(u32, String),
    /// Close this child's stdin: it has nothing in flight and is no longer current.
    Retire(u32),
}

struct Child {
    /// The agent requests this child owes a reply to (JSON-encoded ids).
    inflight: HashSet<String>,
    /// Set while the replayed `initialize` is outstanding — the reply is ours, not the agent's.
    resume_id: Option<String>,
    retiring: bool,
}

/// The routing core. Knows nothing about processes: lines in, `Action`s out.
pub(crate) struct Router {
    current: u32,
    children: HashMap<u32, Child>,
    /// The agent's own `initialize` request and `initialized` notification, replayed into each new child.
    init_line: Option<Value>,
    initialized_line: Option<String>,
    /// Requests a child sent the AGENT (sampling, elicitation, roots…), by the id we renamed them to.
    /// Two children can both use id 0 for their own requests, so the agent sees `u{gen}:{id}` and the
    /// reply is routed back and renamed.
    agent_bound: HashMap<String, (u32, Value)>,
}

fn key(id: &Value) -> String {
    id.to_string()
}

impl Router {
    pub(crate) fn new() -> Self {
        let mut children = HashMap::new();
        children.insert(
            0,
            Child {
                inflight: HashSet::new(),
                resume_id: None,
                retiring: false,
            },
        );
        Router {
            current: 0,
            children,
            init_line: None,
            initialized_line: None,
            agent_bound: HashMap::new(),
        }
    }

    /// A line from the agent.
    pub(crate) fn on_agent(&mut self, line: &str) -> Vec<Action> {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            return vec![Action::ToChild(self.current, line.to_string())];
        };
        let method = v.get("method").and_then(Value::as_str);
        match (method, v.get("id")) {
            // A request: remember who owes the reply.
            (Some(m), Some(id)) => {
                if m == "initialize" {
                    self.init_line = Some(v.clone());
                }
                let cur = self.current;
                if let Some(c) = self.children.get_mut(&cur) {
                    c.inflight.insert(key(id));
                }
                vec![Action::ToChild(cur, line.to_string())]
            }
            // A notification. A cancel goes to whichever child is running that request.
            (Some(m), None) => {
                if m == "notifications/initialized" {
                    self.initialized_line = Some(line.to_string());
                }
                let target = (m == "notifications/cancelled")
                    .then(|| v.pointer("/params/requestId").map(key))
                    .flatten()
                    .and_then(|k| {
                        self.children
                            .iter()
                            .find(|(_, c)| c.inflight.contains(&k))
                            .map(|(g, _)| *g)
                    })
                    .unwrap_or(self.current);
                vec![Action::ToChild(target, line.to_string())]
            }
            // The agent's reply to a request a CHILD made: route back, restore that child's own id.
            (None, Some(id)) => {
                let Some((gen, orig)) = id.as_str().and_then(|s| self.agent_bound.remove(s)) else {
                    return vec![Action::ToChild(self.current, line.to_string())];
                };
                let mut v = v;
                v["id"] = orig;
                vec![Action::ToChild(gen, v.to_string())]
            }
            (None, None) => vec![Action::ToChild(self.current, line.to_string())],
        }
    }

    /// A line from child `gen`.
    pub(crate) fn on_child(&mut self, gen: u32, line: &str) -> Vec<Action> {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            return vec![Action::ToAgent(line.to_string())];
        };
        let method = v.get("method").and_then(Value::as_str).map(str::to_string);
        match (method, v.get("id").cloned()) {
            // The child asks the agent something: give the request an id no other child can hold.
            (Some(_), Some(id)) => {
                let renamed = format!("u{gen}:{}", key(&id));
                self.agent_bound.insert(renamed.clone(), (gen, id));
                let mut v = v;
                v["id"] = json!(renamed);
                vec![Action::ToAgent(v.to_string())]
            }
            (Some(_), None) => vec![Action::ToAgent(line.to_string())],
            // A reply to the agent — or to our replayed initialize.
            (None, Some(id)) => {
                let k = key(&id);
                let Some(c) = self.children.get_mut(&gen) else {
                    return vec![];
                };
                if c.resume_id.as_deref() == Some(k.as_str()) {
                    c.resume_id = None;
                    return self.promote(gen);
                }
                c.inflight.remove(&k);
                let mut out = vec![Action::ToAgent(line.to_string())];
                if c.retiring && c.inflight.is_empty() {
                    out.push(Action::Retire(gen));
                }
                out
            }
            (None, None) => vec![Action::ToAgent(line.to_string())],
        }
    }

    /// Child `gen` has been started to replace the current one: the lines to write to it so it's in the
    /// same session the agent already opened. Empty when the agent hasn't initialized yet — then the
    /// new child just becomes current and receives the agent's own handshake.
    pub(crate) fn adopt(&mut self, gen: u32) -> Vec<Action> {
        let resume = format!("\"__uxlint_resume_{gen}\"");
        let replay = self.init_line.clone().map(|mut v| {
            v["id"] = json!(format!("__uxlint_resume_{gen}"));
            v.to_string()
        });
        self.children.insert(
            gen,
            Child {
                inflight: HashSet::new(),
                resume_id: replay.as_ref().map(|_| resume),
                retiring: false,
            },
        );
        match replay {
            Some(line) => vec![Action::ToChild(gen, line)],
            None => self.promote(gen),
        }
    }

    /// `gen` is initialized: it takes every new request, the agent is told the tools may have changed,
    /// and every older child retires as soon as it has nothing in flight.
    fn promote(&mut self, gen: u32) -> Vec<Action> {
        let mut out = Vec::new();
        if let Some(n) = &self.initialized_line {
            out.push(Action::ToChild(gen, n.clone()));
        }
        self.current = gen;
        for (g, c) in self.children.iter_mut().filter(|(g, _)| **g != gen) {
            c.retiring = true;
            if c.inflight.is_empty() {
                out.push(Action::Retire(*g));
            }
        }
        if self.init_line.is_some() {
            out.push(Action::ToAgent(
                json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}).to_string(),
            ));
        }
        out
    }

    /// A child's process ended. Its unanswered requests would hang the agent forever — answer them with
    /// an error so the agent can retry (which lands on the current child).
    pub(crate) fn child_exited(&mut self, gen: u32) -> Vec<Action> {
        let Some(c) = self.children.remove(&gen) else {
            return vec![];
        };
        self.agent_bound.retain(|_, (g, _)| *g != gen);
        c.inflight
            .into_iter()
            .filter_map(|k| serde_json::from_str::<Value>(&k).ok())
            .map(|id| {
                Action::ToAgent(
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32603,
                        "message": "uxlint restarted while this call was running — please retry it"}})
                    .to_string(),
                )
            })
            .collect()
    }

    pub(crate) fn current(&self) -> u32 {
        self.current
    }
}

/// The plugin version Claude Code has installed for THIS plugin now — `None` when this isn't a plugin
/// launch or it can't be read. Read from Claude Code's own record (`plugins/installed_plugins.json`),
/// matched by the plugin's cache directory, so a plugin with auto-update OFF is never upgraded behind
/// the user's back: we follow exactly what Claude Code installed, nothing newer.
fn installed_plugin_version() -> Option<String> {
    let root = std::path::PathBuf::from(std::env::var_os("CLAUDE_PLUGIN_ROOT")?);
    let plugin_dir = root.parent()?.to_path_buf(); // …/cache/<marketplace>/<plugin>/
    let config = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".claude"))
        })?;
    let text =
        std::fs::read_to_string(config.join("plugins").join("installed_plugins.json")).ok()?;
    installed_version_in(&text, &plugin_dir)
}

/// Pure half of `installed_plugin_version`: the version of the install whose path sits in `plugin_dir`.
fn installed_version_in(json_text: &str, plugin_dir: &std::path::Path) -> Option<String> {
    let v: Value = serde_json::from_str(json_text).ok()?;
    let plugins = v.get("plugins").unwrap_or(&v).as_object()?;
    plugins
        .values()
        .flat_map(|e| e.as_array().into_iter().flatten())
        .find_map(|inst| {
            let path = std::path::Path::new(inst["installPath"].as_str()?);
            (path.parent()? == plugin_dir)
                .then(|| inst["version"].as_str().map(str::to_string))
                .flatten()
        })
}

/// A runnable uxlint of exactly `version`: the plugin data directory's version-scoped copy (the same
/// place the launcher puts it), installed there — verified — if it isn't yet.
fn binary_for(version: &str) -> anyhow::Result<std::path::PathBuf> {
    let data = std::env::var_os("CLAUDE_PLUGIN_DATA")
        .or_else(|| std::env::var_os("CLAUDE_PLUGIN_ROOT"))
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("not running as a plugin"))?;
    let bin = data.join("bin").join(version).join("uxlint");
    if !bin.is_file() {
        crate::update::install_version_at(version, &bin)?;
    }
    Ok(bin)
}

/// How often to look for a plugin update. Cheap (one small file read), and an upgrade only lands
/// between calls anyway.
const CHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(60);
/// The longest a retired child may keep running to finish a call (an audit can take minutes).
const DRAIN_LIMIT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

enum Event {
    Agent(Option<String>),
    Child(u32, Option<String>),
    Upgrade(String, std::path::PathBuf),
}

/// Run the supervisor until the agent closes stdin. `child_args` are this process's own `mcp` args
/// minus `--supervise`, passed to every child.
pub(crate) fn run(child_args: Vec<String>) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve(child_args))
}

async fn serve(child_args: Vec<String>) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    let mut stdins: HashMap<u32, tokio::process::ChildStdin> = HashMap::new();
    let mut procs: HashMap<u32, tokio::process::Child> = HashMap::new();
    let mut router = Router::new();
    let mut running = env!("CARGO_PKG_VERSION").to_string();
    let mut next_gen = 1u32;

    let spawn = |gen: u32,
                 bin: &std::path::Path,
                 tx: tokio::sync::mpsc::UnboundedSender<Event>|
     -> anyhow::Result<(tokio::process::Child, tokio::process::ChildStdin)> {
        let mut child = tokio::process::Command::new(bin)
            .args(&child_args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("child has no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("child has no stdout"))?;
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                let _ = tx.send(Event::Child(gen, Some(l)));
            }
            let _ = tx.send(Event::Child(gen, None));
        });
        Ok((child, stdin))
    };

    let me = std::env::current_exe()?;
    let (c0, s0) = spawn(0, &me, tx.clone())?;
    procs.insert(0, c0);
    stdins.insert(0, s0);

    // The agent's side.
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                let _ = tx.send(Event::Agent(Some(l)));
            }
            let _ = tx.send(Event::Agent(None));
        });
    }
    // Plugin-update watch: a newer installed plugin version → install its binary off the loop.
    let (want_tx, mut want_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut last: Option<String> = None;
            loop {
                tokio::time::sleep(CHECK_EVERY).await;
                while let Ok(v) = want_rx.try_recv() {
                    last = Some(v); // the version now running, fed back after each switch
                }
                let Some(wanted) = tokio::task::spawn_blocking(installed_plugin_version)
                    .await
                    .ok()
                    .flatten()
                else {
                    continue;
                };
                let have = last
                    .clone()
                    .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
                if !crate::update::version_newer(&wanted, &have) {
                    continue;
                }
                let w = wanted.clone();
                match tokio::task::spawn_blocking(move || binary_for(&w)).await {
                    Ok(Ok(bin)) => {
                        last = Some(wanted.clone());
                        let _ = tx.send(Event::Upgrade(wanted, bin));
                    }
                    Ok(Err(e)) => eprintln!("uxlint: couldn't install {wanted} for an in-place upgrade ({e}) — will retry"),
                    Err(_) => {}
                }
            }
        });
    }

    let mut out = tokio::io::stdout();
    let mut agent_open = true;
    while let Some(ev) = rx.recv().await {
        let actions = match ev {
            Event::Agent(Some(l)) => router.on_agent(&l),
            Event::Agent(None) => {
                agent_open = false;
                stdins.clear(); // EOF to every child: the session is over
                vec![]
            }
            Event::Child(g, Some(l)) => router.on_child(g, &l),
            Event::Child(g, None) => {
                procs.remove(&g);
                stdins.remove(&g);
                let mut acts = router.child_exited(g);
                // The CURRENT child died on its own: start a fresh one of the same version in its
                // place, so one crash doesn't end the agent's session.
                if agent_open && g == router.current() {
                    let bin = if running == env!("CARGO_PKG_VERSION") {
                        me.clone()
                    } else {
                        binary_for(&running).unwrap_or(me.clone())
                    };
                    let gen = next_gen;
                    next_gen += 1;
                    if let Ok((c, s)) = spawn(gen, &bin, tx.clone()) {
                        procs.insert(gen, c);
                        stdins.insert(gen, s);
                        acts.extend(router.adopt(gen));
                    }
                }
                if procs.is_empty() {
                    break;
                }
                acts
            }
            Event::Upgrade(version, bin) => {
                let gen = next_gen;
                next_gen += 1;
                match spawn(gen, &bin, tx.clone()) {
                    Ok((c, s)) => {
                        eprintln!("uxlint: plugin updated — switching to {version} without restarting the session");
                        procs.insert(gen, c);
                        stdins.insert(gen, s);
                        running = version.clone();
                        let _ = want_tx.send(version);
                        router.adopt(gen)
                    }
                    Err(e) => {
                        eprintln!("uxlint: couldn't start {version} ({e}); staying on {running}");
                        vec![]
                    }
                }
            }
        };
        for a in actions {
            match a {
                Action::ToAgent(l) => {
                    out.write_all(l.as_bytes()).await?;
                    out.write_all(b"\n").await?;
                    out.flush().await?;
                }
                Action::ToChild(g, l) => {
                    if let Some(s) = stdins.get_mut(&g) {
                        let _ = s.write_all(l.as_bytes()).await;
                        let _ = s.write_all(b"\n").await;
                        let _ = s.flush().await;
                    }
                }
                Action::Retire(g) => {
                    stdins.remove(&g); // EOF: an MCP server exits when its input ends
                    if let Some(mut c) = procs.remove(&g) {
                        // …and if it doesn't within the drain limit, it goes anyway.
                        tokio::spawn(async move {
                            if tokio::time::timeout(DRAIN_LIMIT, c.wait()).await.is_err() {
                                let _ = c.kill().await;
                            }
                        });
                    }
                }
            }
        }
        if !agent_open && procs.is_empty() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(r: &mut Router, v: Value) -> Vec<Action> {
        r.on_agent(&v.to_string())
    }
    fn child(r: &mut Router, g: u32, v: Value) -> Vec<Action> {
        r.on_child(g, &v.to_string())
    }
    fn to_child(a: &[Action]) -> Vec<(u32, Value)> {
        a.iter()
            .filter_map(|x| match x {
                Action::ToChild(g, l) => Some((*g, serde_json::from_str(l).unwrap())),
                _ => None,
            })
            .collect()
    }

    /// A session that started on child 0, then upgraded: the new child is initialized with the agent's
    /// OWN handshake (its reply swallowed), takes new work, and the old one finishes and retires.
    #[test]
    fn an_upgrade_happens_under_a_live_session_without_dropping_a_call() {
        let mut r = Router::new();
        agent(
            &mut r,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"claude"}}}),
        );
        child(&mut r, 0, json!({"jsonrpc":"2.0","id":1,"result":{}}));
        agent(
            &mut r,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        );
        // A long audit is running on child 0 when the upgrade lands.
        agent(
            &mut r,
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"audit_url"}}),
        );

        let adopt = r.adopt(1);
        let replay = to_child(&adopt);
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].0, 1);
        assert_eq!(replay[0].1["method"], "initialize");
        assert_eq!(
            replay[0].1["params"]["clientInfo"]["name"], "claude",
            "the agent's own handshake"
        );
        assert_eq!(
            r.current(),
            0,
            "not switched until the new child has answered"
        );

        // Its initialize reply is ours — never shown to the agent. Then: initialized, list_changed,
        // and child 0 (still busy) is NOT retired yet.
        let acts = child(
            &mut r,
            1,
            json!({"jsonrpc":"2.0","id":"__uxlint_resume_1","result":{}}),
        );
        assert_eq!(r.current(), 1);
        assert!(acts.contains(&Action::ToChild(
            1,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string()
        )));
        assert!(acts
            .iter()
            .any(|a| matches!(a, Action::ToAgent(l) if l.contains("tools/list_changed"))));
        assert!(
            !acts.iter().any(|a| matches!(a, Action::Retire(_))),
            "{acts:?}"
        );

        // New work goes to the new child…
        let a = agent(
            &mut r,
            json!({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"ux_guidance"}}),
        );
        assert_eq!(to_child(&a)[0].0, 1);
        // …and when the old one finishes its audit, the reply reaches the agent and it retires.
        let done = child(
            &mut r,
            0,
            json!({"jsonrpc":"2.0","id":7,"result":{"content":[]}}),
        );
        assert!(matches!(&done[0], Action::ToAgent(l) if l.contains("\"id\":7")));
        assert_eq!(done[1], Action::Retire(0));
    }

    /// Both children number their own requests to the agent from 0; the agent must never see two
    /// requests with one id, and each reply must reach the child that asked.
    #[test]
    fn child_requests_to_the_agent_never_collide() {
        let mut r = Router::new();
        r.adopt(1); // no handshake yet: child 1 becomes current directly
        let a0 = child(
            &mut r,
            0,
            json!({"jsonrpc":"2.0","id":0,"method":"roots/list"}),
        );
        let a1 = child(
            &mut r,
            1,
            json!({"jsonrpc":"2.0","id":0,"method":"roots/list"}),
        );
        let id = |a: &[Action]| match &a[0] {
            Action::ToAgent(l) => serde_json::from_str::<Value>(l).unwrap()["id"].clone(),
            _ => panic!(),
        };
        assert_ne!(id(&a0), id(&a1));
        let back = agent(
            &mut r,
            json!({"jsonrpc":"2.0","id": id(&a0), "result": {"roots": []}}),
        );
        assert_eq!(
            to_child(&back),
            vec![(0, json!({"jsonrpc":"2.0","id":0,"result":{"roots":[]}}))]
        );
    }

    /// A cancel for a call the OLD child is still running must reach the old child.
    #[test]
    fn a_cancel_follows_the_call_it_cancels() {
        let mut r = Router::new();
        agent(
            &mut r,
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call"}),
        );
        r.adopt(1);
        let a = agent(
            &mut r,
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}),
        );
        assert_eq!(to_child(&a)[0].0, 0);
    }

    /// A child that dies mid-call must not leave the agent waiting forever.
    #[test]
    fn a_crashed_childs_calls_are_answered_with_an_error() {
        let mut r = Router::new();
        agent(
            &mut r,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call"}),
        );
        let a = r.child_exited(0);
        assert!(
            matches!(&a[0], Action::ToAgent(l) if l.contains("\"id\":3") && l.contains("retry"))
        );
    }

    #[test]
    fn follows_exactly_the_plugin_version_claude_code_installed() {
        let json = r#"{"version":2,"plugins":{"uxlint@uxlint":[{"installPath":"/h/.claude/plugins/cache/uxlint/uxlint/0.1.38","version":"0.1.38"}],
            "other@x":[{"installPath":"/h/.claude/plugins/cache/x/other/9.9.9","version":"9.9.9"}]}}"#;
        let dir = std::path::Path::new("/h/.claude/plugins/cache/uxlint/uxlint");
        assert_eq!(installed_version_in(json, dir).as_deref(), Some("0.1.38"));
        assert_eq!(
            installed_version_in(json, std::path::Path::new("/elsewhere")),
            None
        );
        assert_eq!(installed_version_in("not json", dir), None);
    }
}
