//! Signals only set a flag; socket shutdown and thread joins run on the main thread.
use std::sync::atomic::{AtomicBool, Ordering};
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
pub(super) fn stopping() -> bool {
    STOP.load(Ordering::Relaxed)
}
pub(super) struct Signals(Vec<(libc::c_int, libc::sigaction)>);
impl Signals {
    pub fn install() -> Result<Self, String> {
        STOP.store(false, Ordering::Relaxed);
        let mut guard = Self(Vec::new());
        for signal in [libc::SIGINT, libc::SIGTERM] {
            // SAFETY: POSIX sigaction structs are initialized before use; the
            // handler is an extern C function that only performs a lock-free
            // atomic store. No allocation, I/O or unwinding occurs in it.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                let mut previous: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = stop as *const () as libc::sighandler_t;
                libc::sigemptyset(&mut action.sa_mask);
                if libc::sigaction(signal, &action, &mut previous) != 0 {
                    return Err("cannot install daemon shutdown handler".into());
                }
                guard.0.push((signal, previous));
            }
        }
        Ok(guard)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, action) in self.0.iter().rev() {
            // SAFETY: restores the exact initialized action returned at install.
            unsafe {
                libc::sigaction(*signal, action, std::ptr::null_mut());
            }
        }
    }
}
