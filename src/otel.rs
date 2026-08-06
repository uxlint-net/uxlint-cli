//! OpenTelemetry for the CLI — TRACES ONLY (the client emits no metrics/logs of its own; its stderr
//! is the user-facing report, and `env_logger` already surfaces CDP trouble). It exists so the crawl
//! stops being an OPAQUE box in a hosted trace: the audit-worker opens `audit_worker.job` and hands us
//! its W3C `traceparent` in the `TRACEPARENT` env var (see audit-worker); we continue that SAME
//! distributed trace, so a long `uxlint audit` shows up as nested spans (capture, probes, tests, post,
//! previews) UNDER the worker's job span. Locally (`just dogfood`/`just e2e` with
//! `OTEL_EXPORTER_OTLP_ENDPOINT` set) there's no parent — the `audit` span is its own root.
//!
//! The audit is a SYNCHRONOUS, blocking crawl with no ambient runtime, but the tonic OTLP exporter
//! needs one. So [`Session::start`] builds a small multi-thread runtime, builds the exporter while
//! that runtime is entered (binding the gRPC channel to it), and keeps the runtime alive for the whole
//! command — the batch processor's export calls ride that channel from their own thread. Everything
//! here is inert when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset (the common case: a plain local audit).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use opentelemetry::trace::{TraceContextExt, Tracer};
use opentelemetry::{global, Context, ContextGuard};
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};

/// Flipped on once the exporter is installed, so [`phase`] is a cheap no-op on the overwhelmingly
/// common untraced path (no allocation, no context churn) instead of minting no-op spans.
static ENABLED: AtomicBool = AtomicBool::new(false);

const TRACER: &str = "uxlint-cli";

/// Owns the exporter runtime + tracer provider for one CLI command. Drop order matters: `_provider`
/// is declared FIRST so it shuts down (flushing batched spans, which needs the runtime) BEFORE
/// `_runtime` is torn down. Both fields are `None` when telemetry is off.
pub struct Session {
    _provider: Option<SdkTracerProvider>,
    _runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for Session {
    fn drop(&mut self) {
        ENABLED.store(false, Ordering::Relaxed);
        if let Some(p) = &self._provider {
            let _ = p.shutdown(); // blocking flush of any batched spans while the runtime is still up
        }
    }
}

/// Parse `OTEL_EXPORTER_OTLP_HEADERS` (`k1=v1,k2=v2`) into tonic gRPC metadata — New Relic auth rides
/// here as `api-key=<license-key>` in prod (the audit-worker forwards this var into our env). Mirrors
/// the server/worker helper so the CLI authenticates to the same collector the same way.
fn otlp_metadata() -> MetadataMap {
    let mut md = MetadataMap::new();
    let Ok(raw) = std::env::var("OTEL_EXPORTER_OTLP_HEADERS") else {
        return md;
    };
    for pair in raw.split(',') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if let (Ok(key), Ok(val)) = (
            MetadataKey::from_bytes(k.trim().as_bytes()),
            MetadataValue::try_from(v.trim()),
        ) {
            md.insert(key, val);
        }
    }
    md
}

impl Session {
    /// Install the OTLP trace exporter for this command when `OTEL_EXPORTER_OTLP_ENDPOINT` is set,
    /// else a no-op session. Call ONCE, early, and keep the returned value alive until the command is
    /// done (its drop flushes). A build failure degrades to no telemetry rather than failing the audit.
    pub fn start() -> Session {
        let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .filter(|e| !e.is_empty());
        let Some(endpoint) = endpoint else {
            return Session {
                _provider: None,
                _runtime: None,
            };
        };

        // A dedicated runtime purely to drive the exporter's gRPC channel; one worker thread is plenty
        // for a trickle of span batches. The blocking audit runs OUTSIDE it, on the main thread.
        let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
        else {
            return Session {
                _provider: None,
                _runtime: None,
            };
        };

        // Build the exporter + provider while the runtime is ENTERED, so the tonic channel binds to it
        // and later export calls (from the batch processor's thread) resolve onto this runtime.
        let provider = {
            let _guard = runtime.enter();
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&endpoint)
                .with_metadata(otlp_metadata())
                .build();
            match exporter {
                Ok(exporter) => Some(
                    SdkTracerProvider::builder()
                        .with_batch_exporter(exporter)
                        .with_resource(Resource::builder().with_service_name(TRACER).build())
                        .build(),
                ),
                Err(_) => None,
            }
        };

        let Some(provider) = provider else {
            return Session {
                _provider: None,
                _runtime: Some(runtime),
            };
        };

        global::set_tracer_provider(provider.clone());
        global::set_text_map_propagator(TraceContextPropagator::new());
        ENABLED.store(true, Ordering::Relaxed);
        Session {
            _provider: Some(provider),
            _runtime: Some(runtime),
        }
    }
}

/// The parent trace context the hosted worker handed us via the `TRACEPARENT` env var, so the root
/// `audit` span continues the worker's distributed trace. Returns the ROOT context (a fresh trace)
/// when the var is absent/empty — i.e. a local `uxlint audit`, where the audit IS the root.
fn parent_from_env() -> Context {
    match std::env::var("TRACEPARENT") {
        Ok(tp) if !tp.trim().is_empty() => {
            let mut carrier = HashMap::new();
            carrier.insert("traceparent".to_string(), tp);
            global::get_text_map_propagator(|prop| prop.extract(&carrier))
        }
        _ => Context::new(),
    }
}

/// The current span's W3C `traceparent`, to set as a header on the outgoing `/v1/audit` request so the
/// SERVER continues THIS trace — its judge spans then nest under our `post` span, closing the last gap
/// (CLI → server → judge worker as one trace). `None` when telemetry is off or no span is active.
pub fn traceparent() -> Option<String> {
    if !ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    let mut carrier = HashMap::<String, String>::new();
    global::get_text_map_propagator(|prop| prop.inject_context(&Context::current(), &mut carrier));
    carrier.remove("traceparent")
}

/// A running span that ends (and detaches from the current context) on drop — the sync sibling of
/// tracing's `span.enter()`. While held, it's the CURRENT context, so any [`phase`] opened inside it
/// nests underneath. `None` fields mean telemetry is off, so it's a zero-cost guard.
pub struct PhaseGuard {
    cx: Option<Context>,
    _attach: Option<ContextGuard>,
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        if let Some(cx) = &self.cx {
            cx.span().end();
        }
        // _attach drops after, detaching the context — order is irrelevant to correctness here.
    }
}

/// Open the ROOT `audit` span, parented on the hosted worker's trace when present. Hold it for the
/// whole audit so every [`phase`] nests under it. No-op when telemetry is off.
pub fn audit_root() -> PhaseGuard {
    start(&parent_from_env(), "audit")
}

/// Open a child span named `name` under whatever span is currently active, and make it current for as
/// long as the returned guard lives. Scope it to a `{ }` block around one crawl phase. No-op when off.
pub fn phase(name: &'static str) -> PhaseGuard {
    if !ENABLED.load(Ordering::Relaxed) {
        return PhaseGuard {
            cx: None,
            _attach: None,
        };
    }
    start(&Context::current(), name)
}

/// Shared span-open: start `name` as a child of `parent`, attach the resulting context as current.
fn start(parent: &Context, name: &'static str) -> PhaseGuard {
    if !ENABLED.load(Ordering::Relaxed) {
        return PhaseGuard {
            cx: None,
            _attach: None,
        };
    }
    let span = global::tracer(TRACER).start_with_context(name, parent);
    let cx = parent.with_span(span);
    let attach = cx.clone().attach();
    PhaseGuard {
        cx: Some(cx),
        _attach: Some(attach),
    }
}
