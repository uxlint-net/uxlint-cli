//! Terminal styling for the CLI's two output streams — tiny ANSI helpers, no dependency.
//!
//! Color is a per-STREAM decision: the report goes to stdout, progress to stderr, and either can
//! independently be a pipe (`uxlint audit | tee`, `2>err.log`). Each stream styles itself only
//! when it's a real terminal, and `NO_COLOR` (https://no-color.org) switches everything off.
//! The JSON and MCP paths never come through here, so machine output stays byte-clean.

use std::io::IsTerminal;
use std::sync::OnceLock;

fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

fn stdout_styled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| !no_color() && std::io::stdout().is_terminal())
}

fn stderr_styled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| !no_color() && std::io::stderr().is_terminal())
}

/// A styling target: wraps text in the given SGR codes when that stream is a styled terminal.
#[derive(Clone, Copy)]
pub(crate) enum Stream {
    Out,
    Err,
}

impl Stream {
    fn on(self) -> bool {
        match self {
            Stream::Out => stdout_styled(),
            Stream::Err => stderr_styled(),
        }
    }
    fn paint(self, sgr: &str, s: &str) -> String {
        if self.on() && !s.is_empty() {
            format!("\x1b[{sgr}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub(crate) fn bold(self, s: &str) -> String {
        self.paint("1", s)
    }
    pub(crate) fn dim(self, s: &str) -> String {
        self.paint("2", s)
    }
    pub(crate) fn red(self, s: &str) -> String {
        self.paint("31;1", s)
    }
    pub(crate) fn yellow(self, s: &str) -> String {
        self.paint("33", s)
    }
    pub(crate) fn green(self, s: &str) -> String {
        self.paint("32", s)
    }
    pub(crate) fn cyan(self, s: &str) -> String {
        self.paint("36", s)
    }
    pub(crate) fn link(self, s: &str) -> String {
        self.paint("4;36", s)
    }
    /// A phase banner: bold cyan — the visual anchor each stage of a run hangs from.
    pub(crate) fn header(self, s: &str) -> String {
        self.paint("1;36", s)
    }
}
