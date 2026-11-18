//! Allocation counting for benchmarks (`--features count-allocs`); see `bench/run.sh`.

use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
pub static REQUESTS: AtomicU64 = AtomicU64::new(0);

/// Wraps mimalloc and counts every allocation and reallocation.
pub struct Counting(pub mimalloc::MiMalloc);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        unsafe { self.0.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.0.dealloc(ptr, layout) }
    }
}

/// Logs allocations per request over each 5 second window that saw requests.
pub fn report() {
    std::thread::spawn(|| {
        let (mut allocs, mut requests) = (0, 0);
        loop {
            std::thread::sleep(Duration::from_secs(5));
            let (a, r) = (ALLOCS.load(Relaxed), REQUESTS.load(Relaxed));
            if r > requests {
                let per_request = (a - allocs) as f64 / (r - requests) as f64;
                log::info!(
                    "{} requests, {per_request:.2} allocations/request",
                    r - requests
                );
            }
            (allocs, requests) = (a, r);
        }
    });
}
