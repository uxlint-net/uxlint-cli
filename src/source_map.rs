//! Client-side source mapping: turn a finding into a `file:line` hint by grepping the LOCAL
//! project for a distinctive string from it (the rewrite from-text, a quoted phrase, or an
//! element id). Runs only for local audits, entirely on the client — the server never sees your
//! code and neither does this; it's a plain local file search so an agent can jump straight to
//! the spot. Best-effort: a hint is added only when a confident match is found.

use serde_json::Value;
use std::path::Path;

const SRC_EXT: &[&str] = &[
    "svelte", "tsx", "jsx", "ts", "js", "mjs", "cjs", "vue", "astro", "html", "htm", "php", "erb",
    "rb", "hbs", "ejs", "twig", "blade", "md", "mdx",
];
const SKIP_DIR: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "build",
    ".svelte-kit",
    ".next",
    ".nuxt",
    "vendor",
    "out",
    ".cache",
    "coverage",
    ".turbo",
    "__pycache__",
];

/// Collapse runs of whitespace to a single space — source formatting shouldn't defeat a match.
fn squeeze(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A distinctive phrase to grep for: for long copy, a middle slice (interpolation tends to sit at
/// the edges — `{name}` etc.); short strings (link text, an id) are used whole.
fn distinctive(s: &str) -> String {
    let w: Vec<&str> = s.split_whitespace().collect();
    if w.len() > 8 {
        w[2..w.len().min(10)].join(" ")
    } else {
        w.join(" ")
    }
}

/// The best greppable needle for a finding, most-reliable first.
fn needle(f: &Value) -> Option<String> {
    // 1. Exact source copy from a rewrite mark (prose-clarity, jargon, show-dont-tell, …).
    if let Some(marks) = f["marks"].as_array() {
        for m in marks {
            if m["t"].as_str() == Some("rewrite") {
                if let Some(from) = m["from"].as_str() {
                    let d = distinctive(from);
                    if d.chars().filter(|c| c.is_alphanumeric()).count() >= 8 {
                        return Some(d);
                    }
                }
            }
        }
    }
    // 2. A quoted phrase in the message (link text, a quoted sentence).
    if let Some(msg) = f["msg"].as_str() {
        if let Some(start) = msg.find('"') {
            if let Some(len) = msg[start + 1..].find('"') {
                let d = distinctive(&msg[start + 1..start + 1 + len]);
                if d.chars().filter(|c| c.is_alphanumeric()).count() >= 4 {
                    return Some(d);
                }
            }
        }
    }
    // 3. An element id from the selector (`input#devname` → `devname`).
    if let Some(sel) = f["sel"].as_str() {
        if let Some(h) = sel.find('#') {
            let id: String = sel[h + 1..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if id.len() >= 3 {
                return Some(id);
            }
        }
    }
    None
}

/// Walk the project source ONCE → (relpath, squeezed-lines). Bounded so it stays fast on any repo.
fn collect(root: &Path) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if p.is_dir() {
                if !name.starts_with('.') && !SKIP_DIR.contains(&name) {
                    stack.push(p);
                }
            } else if p
                .extension()
                .and_then(|x| x.to_str())
                .map(|x| SRC_EXT.contains(&x))
                .unwrap_or(false)
            {
                if e.metadata().map(|m| m.len() > 512 * 1024).unwrap_or(true) {
                    continue; // skip huge/unstattable files
                }
                if let Ok(content) = std::fs::read_to_string(&p) {
                    let rel = p
                        .strip_prefix(root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string();
                    out.push((rel, content.lines().map(squeeze).collect()));
                }
            }
            if out.len() >= 6000 {
                return out;
            }
        }
    }
    out
}

/// A repeated "box-like" utility-class cluster found in the source — a de-facto component that
/// should be extracted once (see web Panel.svelte) instead of retyped.
pub(crate) struct DrySignal {
    pub cluster: String,
    pub count: usize,
    pub files: usize,
    /// First `relpath:line` the cluster appears at, so an agent can open it straight away.
    pub source: String,
}

/// DRY advisory (LOCAL source only, never leaves the machine): a bordered, filled surface — a
/// card/panel class cluster — repeated across the source is a component waiting to be extracted.
/// This is SOURCE-based on purpose. In the rendered DOM an inlined panel and a `<Panel>` component
/// are byte-identical, so a rendered lint can't tell them apart and would keep firing after the fix;
/// in the source, an extracted component's class string appears ONCE, so adopting it shrinks this to
/// nothing — which is exactly the signal we want.
pub(crate) fn dry_advisory(root: &Path) -> Vec<DrySignal> {
    dry_signals_from(&collect(root))
}

/// Inner text of every STATIC `class="…"` / `className="…"` / `class='…'` on a line (dynamic
/// `class={…}` bindings are skipped — we only reason about literal utility clusters).
fn class_strings(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for pat in ["class=\"", "className=\"", "class='"] {
        let close = pat.chars().last().unwrap(); // the opening quote, " or '
        let mut from = 0;
        while let Some(i) = line[from..].find(pat) {
            let start = from + i + pat.len();
            match line[start..].find(close) {
                Some(j) => {
                    out.push(line[start..start + j].to_string());
                    from = start + j + 1;
                }
                None => break,
            }
        }
    }
    out
}

/// Core of the advisory, split out so it's testable without touching the filesystem. A cluster is
/// reported when it's a bordered + filled surface (looks like a card/panel), has ≥4 classes, and is
/// repeated ≥3× across the source — conservative, so ordinary flex rows and one-off boxes stay quiet.
fn dry_signals_from(sources: &[(String, Vec<String>)]) -> Vec<DrySignal> {
    let mut map: std::collections::HashMap<
        String,
        (String, usize, std::collections::BTreeSet<String>, String),
    > = std::collections::HashMap::new();
    for (rel, lines) in sources {
        for (li, line) in lines.iter().enumerate() {
            for cls in class_strings(line) {
                let toks: Vec<&str> = cls
                    .split(' ')
                    .filter(|t| !t.is_empty() && !t.contains('{') && !t.contains('}'))
                    .collect();
                if toks.len() < 4 {
                    continue;
                }
                // A card/panel: a border AND a fill. This is the "extract a component" shape — not a
                // bare flex/grid row (no box) and not a lone coloured chip (usually < 4 classes).
                let boxed = toks.iter().any(|t| t.starts_with("border"))
                    && toks.iter().any(|t| t.starts_with("bg-"));
                if !boxed {
                    continue;
                }
                let mut sorted = toks.clone();
                sorted.sort_unstable();
                let sig = sorted.join(" ");
                let e = map.entry(sig).or_insert_with(|| {
                    (
                        toks.join(" "),
                        0,
                        std::collections::BTreeSet::new(),
                        format!("{rel}:{}", li + 1),
                    )
                });
                e.1 += 1;
                e.2.insert(rel.clone());
            }
        }
    }
    let mut out: Vec<DrySignal> = map
        .into_values()
        .filter(|(_, count, ..)| *count >= 3)
        .map(|(cluster, count, files, source)| DrySignal {
            cluster,
            count,
            files: files.len(),
            source,
        })
        .collect();
    // Worst offender first, then longest cluster (most to gain), for a stable, useful order.
    out.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(b.cluster.len().cmp(&a.cluster.len()))
    });
    out
}

/// A Markdown doc (README, docs/*.md) — repo documentation, not rendered UI source. A rendered
/// on-page string almost always lives in a component (`.svelte`/`.tsx`/`.html`), so a Markdown match
/// is only a last resort, and a match INSIDE a fenced code block (```) is documentation OF code (a
/// shell snippet, a config sample) that coincidentally shares words with the page — never the source
/// of the finding. (The mtg-deck FP: contrast text mapped to a `npm run …` fence in README.md.)
fn is_markdown(rel: &str) -> bool {
    let low = rel.to_ascii_lowercase();
    low.ends_with(".md") || low.ends_with(".mdx")
}

/// First line index (0-based) in `lines` containing `n` that is NOT inside a fenced code block.
/// Fences toggle on a line whose first non-space run is ``` or ~~~.
fn first_prose_match(lines: &[String], n: &str) -> Option<usize> {
    let mut fenced = false;
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if !fenced && line.contains(n) {
            return Some(i);
        }
    }
    None
}

/// Add a `source: "relpath:line"` hint to each finding whose needle is found in the local tree.
/// Real source/template files are preferred over Markdown docs, and a Markdown-only match is used
/// only when it's in prose (never a code fence). Scanning is in sorted path order so the hint is
/// deterministic run to run — the earlier "first file the OS happened to return" was not.
pub(crate) fn annotate(report: &mut Value, root: &Path) {
    let mut sources = collect(root);
    if sources.is_empty() {
        return;
    }
    sources.sort_by(|a, b| a.0.cmp(&b.0));
    // Real source first, Markdown docs last — so a component match always beats a README coincidence.
    let (code, docs): (Vec<_>, Vec<_>) = sources.iter().partition(|(rel, _)| !is_markdown(rel));
    let Some(pages) = report["pages"].as_array_mut() else {
        return;
    };
    for page in pages {
        let Some(findings) = page["findings"].as_array_mut() else {
            continue;
        };
        for f in findings {
            let Some(n) = needle(f) else { continue };
            // 1. A real source/template file (deterministic: first line of the first sorted file).
            let hit = code.iter().find_map(|(rel, lines)| {
                lines
                    .iter()
                    .position(|line| line.contains(&n))
                    .map(|i| format!("{rel}:{}", i + 1))
            });
            // 2. Fall back to Markdown PROSE only (never a code fence) — better no hint than a wrong one.
            let hit = hit.or_else(|| {
                docs.iter().find_map(|(rel, lines)| {
                    first_prose_match(lines, &n).map(|i| format!("{rel}:{}", i + 1))
                })
            });
            if let Some(src) = hit {
                f["source"] = Value::String(src);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(pairs: &[(&str, &str)]) -> Vec<(String, Vec<String>)> {
        pairs
            .iter()
            .map(|(f, c)| (f.to_string(), c.lines().map(squeeze).collect()))
            .collect()
    }

    #[test]
    fn class_strings_extracts_static_only() {
        let got = class_strings(
            r#"<div class="rounded-lg border p-5"><a className="x y">z</a><b class={dyn}>"#,
        );
        assert_eq!(
            got,
            vec!["rounded-lg border p-5".to_string(), "x y".to_string()]
        );
    }

    #[test]
    fn repeated_panel_cluster_is_flagged() {
        // The panel signature inlined on three pages → one signal, count 3, 3 files.
        let panel = r#"<section class="rounded-lg border border-line bg-surface-2 p-5">"#;
        let out = dry_signals_from(&src(&[
            ("a.svelte", panel),
            ("b.svelte", panel),
            ("c.svelte", panel),
        ]));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].count, 3);
        assert_eq!(out[0].files, 3);
        assert_eq!(out[0].source, "a.svelte:1"); // first occurrence, for jump-to-source
    }

    #[test]
    fn token_order_and_whitespace_do_not_split_a_cluster() {
        // Same classes, different order / extra spaces → still the same cluster (normalised).
        let a = r#"<div class="rounded-lg border border-line bg-surface-2 p-5">"#;
        let b = r#"<div class="bg-surface-2  p-5 rounded-lg border  border-line">"#;
        let c = r#"<div class="p-5 bg-surface-2 border border-line rounded-lg">"#;
        let out = dry_signals_from(&src(&[("a", a), ("b", b), ("c", c)]));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].count, 3);
    }

    #[test]
    fn a_bare_flex_row_is_not_a_panel() {
        // No border+bg box → not the "extract a component" shape, even repeated.
        let row = r#"<div class="flex items-center gap-2 mt-3">"#;
        assert!(dry_signals_from(&src(&[("a", row), ("b", row), ("c", row)])).is_empty());
    }

    #[test]
    fn a_panel_used_twice_is_below_threshold() {
        // Two inlined copies isn't yet worth a component; needs ≥3.
        let panel = r#"<section class="rounded-lg border border-line bg-surface-2 p-5">"#;
        assert!(dry_signals_from(&src(&[("a", panel), ("b", panel)])).is_empty());
    }

    // ---- source attribution (annotate) -----------------------------------------

    // A one-page report with a single finding carrying a quoted needle in its message.
    fn report_with_msg(msg: &str) -> Value {
        serde_json::json!({ "pages": [ { "findings": [ { "msg": msg } ] } ] })
    }
    fn source_of(report: &Value) -> Option<String> {
        report["pages"][0]["findings"][0]["source"]
            .as_str()
            .map(str::to_string)
    }
    // Drive annotate against an in-memory source tree (bypassing the filesystem walk).
    fn annotate_over(report: &mut Value, mut sources: Vec<(String, Vec<String>)>) {
        sources.sort_by(|a, b| a.0.cmp(&b.0));
        let (code, docs): (Vec<_>, Vec<_>) = sources.iter().partition(|(rel, _)| !is_markdown(rel));
        for f in report["pages"][0]["findings"].as_array_mut().unwrap() {
            let Some(n) = needle(f) else { continue };
            let hit = code
                .iter()
                .find_map(|(rel, lines)| {
                    lines
                        .iter()
                        .position(|l| l.contains(&n))
                        .map(|i| format!("{rel}:{}", i + 1))
                })
                .or_else(|| {
                    docs.iter().find_map(|(rel, lines)| {
                        first_prose_match(lines, &n).map(|i| format!("{rel}:{}", i + 1))
                    })
                });
            if let Some(s) = hit {
                f["source"] = Value::String(s);
            }
        }
    }

    #[test]
    fn a_component_match_beats_a_readme_coincidence() {
        // The rendered string lives in a component; README also mentions it — the component wins.
        let mut r = report_with_msg(r#"Low contrast on "double-sided printing" text"#);
        annotate_over(
            &mut r,
            src(&[
                (
                    "README.md",
                    "Supports double-sided printing via the print dialog.",
                ),
                ("src/Print.svelte", "<label>double-sided printing</label>"),
            ]),
        );
        assert_eq!(source_of(&r).as_deref(), Some("src/Print.svelte:1"));
    }

    #[test]
    fn a_readme_code_fence_match_is_rejected() {
        // The mtg-deck FP: the only match is inside a ``` fence in the README (a shell command) —
        // documentation OF code, not the rendered UI. No hint is better than a wrong one.
        let mut r = report_with_msg(r#"Tiny text near "npm run upscaler""#);
        annotate_over(
            &mut r,
            src(&[(
                "README.md",
                "## Setup\n\n```bash\nnpm run upscaler\n```\n\nThat builds the images.",
            )]),
        );
        assert_eq!(
            source_of(&r),
            None,
            "a code-fence-only match must not attribute"
        );
    }

    #[test]
    fn readme_prose_still_attributes_when_nothing_else_matches() {
        // A genuine docs/content match (prose, not a fence) is still useful when there's no code file.
        let mut r = report_with_msg(r#"Unclear phrase "calibrate your printer offset""#);
        annotate_over(
            &mut r,
            src(&[(
                "docs/printing.md",
                "First, calibrate your printer offset carefully.",
            )]),
        );
        assert_eq!(source_of(&r).as_deref(), Some("docs/printing.md:1"));
    }

    #[test]
    fn attribution_is_deterministic_across_file_order() {
        // Same match in two components → the path-sorted-first one always wins, regardless of input order.
        let msg = r#"Label reads "Add to deck""#;
        let files = [
            ("src/z_Late.svelte", "<button>Add to deck</button>"),
            ("src/a_Early.svelte", "<button>Add to deck</button>"),
        ];
        let mut r1 = report_with_msg(msg);
        annotate_over(&mut r1, src(&files));
        let mut r2 = report_with_msg(msg);
        let mut rev = files.to_vec();
        rev.reverse();
        annotate_over(&mut r2, src(&rev));
        assert_eq!(source_of(&r1).as_deref(), Some("src/a_Early.svelte:1"));
        assert_eq!(source_of(&r1), source_of(&r2), "order-independent");
    }
}
