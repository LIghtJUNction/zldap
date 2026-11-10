//! Measurement-only allocator. It is excluded from the published zldap crate.
#[cfg(feature = "count-allocations")]
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

#[cfg(feature = "count-allocations")]
pub struct CountingAllocator;
static ENABLED: AtomicBool = AtomicBool::new(false);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "count-allocations")]
fn allocated(size: usize) {
    CALLS.fetch_add(1, Relaxed);
    let live = LIVE.fetch_add(size, Relaxed) + size;
    PEAK.fetch_max(live, Relaxed);
}

// SAFETY: All pointers and Layout values are forwarded unchanged to the system
// allocator. Bookkeeping only observes successful allocations; it never reads,
// writes, offsets, or dereferences a user allocation. Each caller obeys the
// GlobalAlloc contract. Benchmark measurements are single-threaded and do not
// free allocations created before begin(), or retain them after end().
#[cfg(feature = "count-allocations")]
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller provides the layout required by GlobalAlloc::alloc.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && ENABLED.load(Relaxed) {
            allocated(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Same delegation contract as alloc, preserving zeroing.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() && ENABLED.load(Relaxed) {
            allocated(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ENABLED.load(Relaxed) {
            LIVE.fetch_sub(layout.size(), Relaxed);
        }
        // SAFETY: Pointer and layout are exactly those supplied by the caller.
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: System performs the original realloc operation unchanged.
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() && ENABLED.load(Relaxed) {
            LIVE.fetch_sub(layout.size(), Relaxed);
            allocated(new_size);
        }
        new_ptr
    }
}

pub fn measure(operation: impl FnOnce()) -> (usize, usize) {
    CALLS.store(0, Relaxed);
    LIVE.store(0, Relaxed);
    PEAK.store(0, Relaxed);
    ENABLED.store(true, Relaxed);
    operation();
    ENABLED.store(false, Relaxed);
    assert_eq!(
        LIVE.load(Relaxed),
        0,
        "measurement retained or freed preexisting heap storage"
    );
    (CALLS.load(Relaxed), PEAK.load(Relaxed))
}
