//! This module provides the `ArcSwap` type, which allows atomic load and swap operations on an `Arc<T>`.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, Ordering};

/// A thread-safe storage for an `Arc<T>` that can be atomically loaded and swapped.
///
/// This type provides atomic operations for loading and swapping an `Arc<T>`.
pub struct ArcSwap<T> {
    ptr: AtomicPtr<T>,
}

impl<T> ArcSwap<T> {
    /// Creates a new `ArcSwap` instance holding the given `Arc<T>`.
    pub fn new(data: Arc<T>) -> Self {
        let ptr = Arc::into_raw(data).cast_mut();
        Self {
            ptr: AtomicPtr::new(ptr),
        }
    }

    /// Atomically loads an `Arc<T>` to the current value.
    ///
    /// This method increments the strong count of the `Arc<T>` and returns a new `Arc<T>`.
    pub fn load(&self) -> Arc<T> {
        let ptr = self.ptr.load(Ordering::Acquire);
        // SAFETY: We increase the strong count before creating a new Arc.
        // The pointer is valid because it was obtained from Arc::into_raw.
        unsafe {
            Arc::increment_strong_count(ptr);
            Arc::from_raw(ptr)
        }
    }

    /// Atomically swaps the current value with a new `Arc<T>`, returning the old `Arc<T>`.
    pub fn swap(&self, new: Arc<T>) -> Arc<T> {
        let new_ptr = Arc::into_raw(new).cast_mut();
        let old_ptr = self.ptr.swap(new_ptr, Ordering::AcqRel);
        // SAFETY: The old pointer was obtained from Arc::into_raw, so it's safe to create an Arc.
        unsafe { Arc::from_raw(old_ptr) }
    }
}

impl<T> Drop for ArcSwap<T> {
    fn drop(&mut self) {
        let ptr = self.ptr.load(Ordering::Acquire);
        if !ptr.is_null() {
            // SAFETY: We have exclusive access to `self`, so we can safely create an `Arc<T>`
            // and allow it to be dropped, which will decrement the strong count.
            unsafe {
                drop(Arc::from_raw(ptr));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// Tests the basic functionality of `ArcSwap` in a single-threaded context.
    #[test]
    fn test_single_thread_load_and_swap() {
        let data1 = Arc::new(5);
        let data2 = Arc::new(10);
        let arc_swap = ArcSwap::new(data1.clone());

        let loaded = arc_swap.load();
        assert_eq!(*loaded, 5);

        let old = arc_swap.swap(data2.clone());
        assert_eq!(*old, 5);

        let loaded = arc_swap.load();
        assert_eq!(*loaded, 10);
    }

    /// Tests concurrent loads from multiple threads.
    #[test]
    fn test_concurrent_loads() {
        let data = Arc::new(42);
        let arc_swap = ArcSwap::new(data.clone());

        thread::scope(|s| {
            for _ in 0..10 {
                s.spawn(|| {
                    let loaded = arc_swap.load();
                    assert_eq!(*loaded, 42);
                });
            }
        });
    }

    /// Tests concurrent swaps from multiple threads.
    #[test]
    fn test_concurrent_swaps() {
        let initial_data = Arc::new(0);
        let arc_swap = ArcSwap::new(initial_data.clone());

        thread::scope(|s| {
            for i in 1..11 {
                let arc_swap = &arc_swap;
                s.spawn(move || {
                    let new_data = Arc::new(i);
                    let old = arc_swap.swap(new_data.clone());
                    assert!((*old >= 0 && *old < 11));
                });
            }
        });

        let loaded = arc_swap.load();
        // After all swaps, the value should be between 1 and 10
        assert!(*loaded >= 1 && *loaded <= 10);
    }

    /// Tests concurrent loads and swaps to ensure thread safety.
    #[test]
    fn test_concurrent_loads_and_swaps() {
        let initial_data = Arc::new(0);
        let arc_swap = ArcSwap::new(initial_data.clone());

        thread::scope(|s| {
            for i in 1..11 {
                let arc_swap = &arc_swap;
                s.spawn(move || {
                    // Swap in a new value
                    let new_data = Arc::new(i);
                    arc_swap.swap(new_data);
                });
                s.spawn(move || {
                    // Load the current value
                    let loaded = arc_swap.load();
                    // Value is between 0 and 10
                    assert!(*loaded >= 0 && *loaded <= 10);
                });
            }
        });

        let loaded = arc_swap.load();
        // After all swaps, the value should be between 1 and 10
        assert!(*loaded >= 1 && *loaded <= 10);
    }

    /// Tests the reference counting to ensure `Arc` counts are managed correctly.
    #[test]
    fn test_arc_counts() {
        let data = Arc::new(0);
        let arc_swap = ArcSwap::new(data.clone());

        // At this point, both `data` and `arc_swap` hold an `Arc`, so the count should be 2
        assert_eq!(Arc::strong_count(&data), 2);

        {
            let loaded = arc_swap.load();
            // Loading should increase the count
            assert_eq!(Arc::strong_count(&data), 3);
            drop(loaded);
        }

        // After dropping `loaded`, the count should go back to 2
        assert_eq!(Arc::strong_count(&data), 2);

        let data2 = Arc::new(1);
        arc_swap.swap(data2.clone());

        // After the swap, `arc_swap` holds `data2`, so `data` count should be 1
        assert_eq!(Arc::strong_count(&data), 1);
        assert_eq!(Arc::strong_count(&data2), 2);

        drop(data2);

        // Only `arc_swap` holds `data2` now
        let loaded = arc_swap.load();
        assert_eq!(Arc::strong_count(&loaded), 2);
        drop(loaded);
    }

    /// Tests that `ArcSwap` properly drops the contained `Arc<T>` on drop.
    #[test]
    fn test_drop() {
        #[allow(dead_code)]
        struct TestDrop(Arc<()>);
        let drop_flag = Arc::new(());
        let data = Arc::new(TestDrop(drop_flag.clone()));
        let arc_swap = ArcSwap::new(data);

        assert_eq!(Arc::strong_count(&drop_flag), 2); // One for `data`, one for `arc_swap`

        drop(arc_swap);

        // After dropping `arc_swap`, the strong count should be 1
        assert_eq!(Arc::strong_count(&drop_flag), 1);
    }

    /// Tests swapping to `ArcSwap` from multiple threads to ensure no data races occur.
    #[test]
    fn test_stress_swapping() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let arc_swap = ArcSwap::new(Arc::new(0));
        let counter = AtomicUsize::new(0);

        thread::scope(|s| {
            for _ in 0..10 {
                s.spawn(|| {
                    for _ in 0..1000 {
                        let new_value = Arc::new(counter.fetch_add(1, Ordering::SeqCst) + 1);
                        arc_swap.swap(new_value);
                    }
                });
            }
        });

        let final_value = arc_swap.load();
        assert_eq!(*final_value, 10000);
    }
}
