use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::mpsc;

use anyhow::Result;
use log::trace;

use crate::types::{CallId, Response};

use super::ConnectionClosed;

trait IdentifiableResponse {
    fn call_id(&self) -> CallId;
}

#[derive(Debug)]
pub struct WaitingCallRegistry {
    calls: Mutex<HashMap<CallId, mpsc::Sender<Result<Response>>>>,
}

impl IdentifiableResponse for Response {
    fn call_id(&self) -> CallId {
        self.call_id
    }
}

impl Default for WaitingCallRegistry {
    fn default() -> Self {
        let calls = Mutex::new(HashMap::new());

        Self { calls }
    }
}

impl WaitingCallRegistry {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn resolve_call(&self, response: Response) -> Result<()> {
        trace!("Resolving call");
        // uxlint patch: a response whose waiter already timed out and unregistered itself
        // is NOT an error — return quietly. The old .unwrap() panicked here, which
        // poisoned the shared `calls` mutex and cascaded into every other browser
        // thread's .lock().unwrap(). Under a wide worker pool this took down the run.
        let waiting_call_tx = {
            let mut waiting_calls = match self.calls.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            waiting_calls.remove(&response.call_id())
        };
        if let Some(tx) = waiting_call_tx {
            let _ = tx.send(Ok(response));
        }
        Ok(())
    }

    pub fn register_call(&self, call_id: CallId) -> mpsc::Receiver<Result<Response>> {
        let (tx, rx) = mpsc::channel::<Result<Response>>();
        // uxlint patch: recover a poisoned lock instead of propagating the panic.
        let mut calls = match self.calls.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        calls.insert(call_id, tx);
        trace!("registered {call_id:?}");
        rx
    }

    pub fn unregister_call(&self, call_id: CallId) {
        trace!("Deregistering call");
        // uxlint patch: tolerate an already-removed call (double unregister on a
        // timeout+late-response race) and a poisoned lock — never panic here.
        let mut calls = match self.calls.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        calls.remove(&call_id);
    }

    // TODO: make it so we can pass in whatever error we want here
    // to make it less dependent on browser::transport
    pub fn cancel_outstanding_method_calls(&self) {
        trace!("Cancelling outstanding method calls");
        // uxlint patch: recover a poisoned lock rather than panic during teardown.
        let calls = match self.calls.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        for (call_id, sender) in &*calls {
            trace!("Telling waiting method call {call_id:?} that the connection closed");
            if let Err(e) = sender.send(Err(ConnectionClosed {}.into())) {
                trace!(
                    "Couldn't send ConnectionClosed to waiting method call: {call_id:?} because {e:?}",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn register_and_receive_calls() {
        env_logger::try_init().unwrap_or(());

        let waiting_calls = WaitingCallRegistry::new();

        let call_rx = waiting_calls.register_call(431);
        let resp = Response {
            call_id: 431,
            result: Some(json! {true}),
            error: None,
        };
        let resp_clone = resp.clone();

        let call_rx2 = waiting_calls.register_call(123);
        let resp2 = Response {
            call_id: 123,
            result: Some(json! {false}),
            error: None,
        };
        let cloned_resp = resp2.clone();

        waiting_calls.resolve_call(resp).unwrap();
        waiting_calls.resolve_call(resp2).unwrap();

        // note how they're in reverse order to that in which they were called!
        assert_eq!(cloned_resp, call_rx2.recv().unwrap().unwrap());
        assert_eq!(resp_clone, call_rx.recv().unwrap().unwrap());
    }
}
