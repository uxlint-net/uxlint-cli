//! Where audit progress goes is a POLICY the caller owns, not a hardcoded `println!`.
//!
//! The CLI sends progress to stderr (stdout is reserved for the report / `--json`). The MCP
//! stdio server sends it to `Silent`, because there stdout IS the JSON-RPC channel and any
//! stray print corrupts the protocol — which is exactly the bug a scattered `println!` caused.
//! Routing progress through a sink makes that impossible by construction, and leaves room for
//! a future sink that captures progress (e.g. to return it as MCP notifications).
//!
//! The sink is shared across the scoped crawl workers, so it must be `Sync`.

use std::fmt::Arguments;

pub(crate) trait Progress: Sync {
    fn note(&self, args: Arguments<'_>);
}

/// CLI: human progress on stderr.
pub(crate) struct Stderr;
impl Progress for Stderr {
    fn note(&self, args: Arguments<'_>) {
        eprintln!("{args}");
    }
}

/// MCP stdio server and tests: swallow progress entirely (stdout must stay clean JSON-RPC).
pub(crate) struct Silent;
impl Progress for Silent {
    fn note(&self, _args: Arguments<'_>) {}
}

/// `note!(sink, "crawl: {n} routes")` — the sink decides where (or whether) it goes.
macro_rules! note {
    ($sink:expr, $($arg:tt)*) => {
        $crate::progress::Progress::note($sink, std::format_args!($($arg)*))
    };
}
pub(crate) use note;
