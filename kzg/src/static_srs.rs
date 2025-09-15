use crate::SrsEval;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

// Simple lock-free one-time init for no_std (with atomic available). Not re-entrant safe in panic scenarios.
struct SrsHolder {
    inited: AtomicBool,
    srs: UnsafeCell<Option<SrsEval>>,
}
unsafe impl Sync for SrsHolder {}

static HOLDER: SrsHolder = SrsHolder {
    inited: AtomicBool::new(false),
    srs: UnsafeCell::new(None),
};

pub fn static_srs() -> &'static SrsEval {
    if !HOLDER.inited.load(Ordering::Acquire) {
        // Attempt initialization (benign race: losing thread just overwrites same deterministic value before flag set)
        unsafe {
            *HOLDER.srs.get() = Some(SrsEval::deterministic());
        }
        HOLDER.inited.store(true, Ordering::Release);
    }
    unsafe { (*HOLDER.srs.get()).as_ref().unwrap() }
}
