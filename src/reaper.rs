//! Kill orphaned Chrome children when the driver dies.
//!
//! `AuditWorker::drop` handles the clean path, but a process that is SIGNALLED — a
//! `timeout`-wrapped e2e run (SIGTERM), Ctrl-C (SIGINT), a closed terminal (SIGHUP) —
//! never runs Drop, so its whole Chrome fleet was orphaned (observed: 112 headless
//! processes from one killed audit). We register each browser's PID and install a
//! signal handler that SIGKILLs the lot, then re-raises the signal with the default
//! disposition so the exit status is still correct.
//!
//! The one case nothing can catch is SIGKILL (-9) of the driver itself — uncatchable
//! by definition. For that, the temp-profile dirs are the only trace and get swept by
//! the OS eventually; there is no in-process remedy.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, Once};

// Fixed-size slot table of live Chrome PIDs. A plain array of atomics is
// async-signal-safe to read from the handler (no allocation, no locking on the signal
// path); registration/removal on the normal path takes the Mutex only to find a slot.
const MAX: usize = 64;
static PIDS: [AtomicI32; MAX] = [const { AtomicI32::new(0) }; MAX];
static SLOT_LOCK: Mutex<()> = Mutex::new(());
static INSTALL: Once = Once::new();

/// Record a spawned browser PID so a fatal signal can kill it. Idempotent-ish; drops
/// silently if the (small) table is full.
pub(crate) fn register(pid: u32) {
    install_handlers();
    let _g = SLOT_LOCK.lock().unwrap();
    for slot in PIDS.iter() {
        if slot
            .compare_exchange(0, pid as i32, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return;
        }
    }
}

/// Forget a PID once its browser has exited cleanly (Drop path).
pub(crate) fn unregister(pid: u32) {
    let _g = SLOT_LOCK.lock().unwrap();
    for slot in PIDS.iter() {
        let _ = slot.compare_exchange(pid as i32, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

extern "C" fn handle_signal(sig: i32) {
    // Async-signal-safe body only: atomic loads + libc::kill (both on the safe list).
    // Killing the Chrome MAIN makes it reap its own renderer children.
    for slot in PIDS.iter() {
        let pid = slot.swap(0, Ordering::SeqCst);
        if pid > 0 {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
    // Restore the default handler and re-raise so our exit status reflects the signal.
    // (Profile tempdirs are left for the OS to sweep — rmdir of a non-empty tree isn't
    // worth doing on the signal path; they hold no live processes.)
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

fn install_handlers() {
    INSTALL.call_once(|| unsafe {
        for &sig in &[libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::signal(sig, handle_signal as *const () as libc::sighandler_t);
        }
    });
}

/// Prefix of the temp profile dirs headless_chrome creates (`/tmp/rust-headless-chrome-profile*`).
const CHROME_PROFILE_PREFIX: &str = "rust-headless-chrome-profile";

/// Sweep orphaned Chrome temp profiles at audit start. Clean exits delete their own tempdir
/// (TempDir drop), but a SIGKILL of the CLI — the one thing nothing can catch — leaves the profile
/// dir behind, and on a tmpfs the OS reclaims it "eventually" (read: never). So before each audit we
/// remove any `rust-headless-chrome-profile*` dir untouched for `max_age`. Age-gated: a FRESH dir
/// (a concurrent audit's live Chrome, which keeps writing to it) has a recent mtime and is left
/// alone — the generous margin stands in for a per-pid liveness check. Prefix-matched so it never
/// touches unrelated temp files. Best-effort; returns how many it removed.
pub(crate) fn sweep_stale_chrome_profiles(max_age: std::time::Duration) -> usize {
    sweep_dir(&std::env::temp_dir(), max_age)
}

/// The sweep against a specific directory — split out so it's unit-testable against a throwaway dir
/// instead of the real `/tmp`.
fn sweep_dir(dir: &std::path::Path, max_age: std::time::Duration) -> usize {
    let mut removed = 0;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let now = std::time::SystemTime::now();
    for entry in rd.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with(CHROME_PROFILE_PREFIX) {
            continue;
        }
        let aged = entry
            .metadata()
            .ok()
            .filter(|m| m.is_dir())
            .and_then(|m| m.modified().ok())
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age >= max_age);
        if aged && std::fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Backdate a path's mtime by `secs` via utimes — so a test can make a dir look "aged" without
    /// actually waiting.
    fn backdate(path: &std::path::Path, secs: i64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let tv = libc::timeval {
            tv_sec: now - secs,
            tv_usec: 0,
        };
        let times = [tv, tv]; // atime, mtime
        let c = std::ffi::CString::new(path.as_os_str().to_str().unwrap()).unwrap();
        unsafe { libc::utimes(c.as_ptr(), times.as_ptr()) };
    }

    #[test]
    fn sweep_removes_aged_profiles_and_spares_fresh_ones() {
        // A private scratch dir so we never touch the real /tmp contents.
        let base = std::env::temp_dir().join(format!("uxlint-sweep-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        let aged = base.join("rust-headless-chrome-profile-aged");
        let fresh = base.join("rust-headless-chrome-profile-fresh");
        let unrelated = base.join("some-other-tempdir"); // wrong prefix — must never be touched
        for d in [&aged, &fresh, &unrelated] {
            std::fs::create_dir_all(d).unwrap();
        }
        backdate(&aged, 3600); // an hour old — past the 30-min gate
                               // `fresh` keeps its just-now mtime.

        let removed = sweep_dir(&base, Duration::from_secs(30 * 60));
        assert_eq!(removed, 1, "exactly the one aged profile dir is swept");
        assert!(!aged.exists(), "the aged profile dir is removed");
        assert!(
            fresh.exists(),
            "a fresh profile dir (a live audit's) survives the age gate"
        );
        assert!(
            unrelated.exists(),
            "a non-matching temp dir is never touched"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
