use alloc::vec::Vec;
use core::{
    num::NonZeroU32,
    sync::atomic::{AtomicUsize, Ordering},
};
use snafu::ensure;

/// Errors that can occur when freeing a handle from a [`HandleAllocator`].
#[derive(Debug, snafu::Snafu)]
pub enum Error {
    /// The handle was not allocated by this allocator.
    NotAllocated,
    /// The handle was out of the bounds of values used by this allocator.
    OutOfBounds,
}

/// A handle allocator implemented using a fixed-size atomic bit set for concurrent handle allocation.
///
/// This structure allows for lock-free allocation and deallocation of handles,
/// represented as bits in an atomic bit set. Handles are indices into the bit set,
/// and are of type `NonZeroU32`, ie handles range from `1` to `max_handle`.
///
pub struct HandleAllocator {
    /// Vector of atomic words representing the bits.
    bits: Vec<AtomicUsize>,
    /// The total number of bits in the bit set.
    max_handle: NonZeroU32,
}

impl HandleAllocator {
    /// Creates a new `AtomicBitSet` with the given size.
    ///
    /// # Arguments
    ///
    /// * `size` - The total number of bits (handles) in the bit set.
    #[must_use]
    pub fn new(max_handle: NonZeroU32) -> Self {
        // Calculate the number of `usize` words needed to cover `size` bits.
        let num_words = (u32::from(max_handle) + 1).div_ceil(usize::BITS);
        // Initialize the vector with zeroed atomic words.
        let mut bits = Vec::with_capacity(num_words as usize);
        for _ in 0..num_words {
            bits.push(AtomicUsize::new(0));
        }
        Self { bits, max_handle }
    }

    /// Returns the largest possible handle that this allocator could return.
    pub fn max_handle_value(&self) -> NonZeroU32 {
        self.max_handle
    }

    /// Allocates the next available handle.
    ///
    /// Scans the bit set to find the first zero bit, atomically sets it to one,
    /// and returns its index as the allocated handle.
    ///
    /// # Returns
    ///
    /// * `Some(u32)` - The index of the allocated handle.
    /// * `None` - If no handles are available.
    ///
    #[must_use]
    // while this function can panic, it would only do so if `self.bits.len() > u32::MAX`, which is
    // impossible because `max_handle <= u32::MAX`, but unfortunatly the type system can't express that.
    #[allow(clippy::missing_panics_doc)]
    pub fn next_handle(&self) -> Option<NonZeroU32> {
        for word_index in 0..self.bits.len() {
            let word = &self.bits[word_index];
            let mut current = word.load(Ordering::Relaxed);

            loop {
                // If all bits are set, move to the next word.
                if current == usize::MAX {
                    break;
                }

                // Find the first zero bit in the current word.
                let zero_bit = (!current).trailing_zeros();
                let bit_index = u32::try_from(word_index).unwrap() * usize::BITS + zero_bit;

                // Check if the bit index is within bounds.
                if bit_index >= self.max_handle.into() {
                    // Out of bounds, no more handles.
                    break;
                }

                // Create a mask to set the zero bit.
                let mask = 1 << zero_bit;
                let new = current | mask;

                // Attempt to atomically set the bit.
                match word.compare_exchange_weak(current, new, Ordering::AcqRel, Ordering::Relaxed)
                {
                    Ok(_) => {
                        // Successfully set the bit, return the handle.
                        return NonZeroU32::new(bit_index + 1);
                    }
                    Err(prev) => {
                        // Failed to set the bit, update `current` and retry.
                        current = prev;
                        // Note: `compare_exchange_weak` may fail spuriously, so we continue to loop.
                    }
                }
            }
        }

        // No available handles found.
        None
    }

    /// Frees a previously allocated handle.
    ///
    /// Atomically clears the bit corresponding to the given handle index.
    /// Returns an error if the handle was not allocated or is out of bounds.
    ///
    /// # Errors
    /// - [`Error::OutOfBounds`] if the handle is outside of the range of handles managed by this allocator.
    /// - [`Error::NotAllocated`] if the handle was already free.
    pub fn free_handle(&self, handle: NonZeroU32) -> Result<(), Error> {
        let handle: u32 = u32::from(handle) - 1;

        // Check if the handle is within bounds.
        ensure!(handle < self.max_handle.into(), OutOfBoundsSnafu);

        let word_index = handle / usize::BITS;
        let bit_index = handle % usize::BITS;
        let mask = 1 << bit_index;
        let word = &self.bits[word_index as usize];
        let mut current = word.load(Ordering::Relaxed);

        loop {
            // Check if the bit is currently set.
            ensure!(current & mask != 0, NotAllocatedSnafu);

            let new = current & !mask;

            // Attempt to atomically clear the bit.
            match word.compare_exchange_weak(current, new, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => {
                    // Successfully cleared the bit.
                    return Ok(());
                }
                Err(prev) => {
                    // Failed to clear the bit, update `current` and retry.
                    current = prev;
                    // Note: `compare_exchange_weak` may fail spuriously, so we continue to loop.
                }
            }
        }
    }

    /// Frees all allocated handles in the allocator, causing them to all be invalid.
    ///
    /// # Safety
    /// This function is only safe if you have some way to track which handles you have
    /// invalidated, i.e. a generation counter!
    pub unsafe fn reset(&self) {
        for word in &self.bits {
            word.store(0, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use test_case::{test_case, test_matrix};

    #[test_case(1)]
    #[test_case(15)]
    #[test_case(4096)]
    fn test_single_thread_allocation_and_freeing(size: u32) {
        let bitset = HandleAllocator::new(NonZeroU32::new(size).unwrap());
        let mut handles = Vec::new();

        // Allocate all handles
        for _ in 0..size {
            let handle = bitset.next_handle().expect("Should allocate handle");
            handles.push(handle);
        }

        // Should not be able to allocate more handles
        assert!(bitset.next_handle().is_none());

        // Free all handles
        for handle in handles {
            bitset.free_handle(handle).expect("Should free handle");
        }

        // Now we should be able to allocate again
        let handle = bitset.next_handle();
        assert_eq!(handle, NonZeroU32::new(1));
    }

    #[test]
    fn test_freeing_unallocated_handle() {
        let bitset = HandleAllocator::new(NonZeroU32::new(10).unwrap());
        // Freeing without allocation should return error
        assert!(bitset.free_handle(NonZeroU32::new(1).unwrap()).is_err());
    }

    #[test]
    fn test_handle_out_of_bounds() {
        let bitset = HandleAllocator::new(NonZeroU32::new(10).unwrap());
        assert!(bitset.free_handle(NonZeroU32::new(10).unwrap()).is_err());
        assert!(bitset.free_handle(NonZeroU32::new(100).unwrap()).is_err());
    }

    #[test_matrix(
        [1,2,4,8,16],
        [1, 15, 100, 4096]
    )]
    fn test_concurrent_allocation(num_threads: usize, bitset_size: u32) {
        let bitset = Arc::new(HandleAllocator::new(NonZeroU32::new(bitset_size).unwrap()));
        let handles = Arc::new(std::sync::Mutex::new(Vec::new()));
        let barrier = Arc::new(Barrier::new(num_threads));

        let mut threads = Vec::new();

        for _ in 0..num_threads {
            let bitset_clone = Arc::clone(&bitset);
            let handles_clone = Arc::clone(&handles);
            let barrier_clone = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                // Wait for all threads to be ready
                barrier_clone.wait();

                loop {
                    match bitset_clone.next_handle() {
                        Some(handle) => {
                            handles_clone.lock().unwrap().push(handle);
                        }
                        None => {
                            break;
                        }
                    }
                }
            }));
        }

        for thread in threads {
            thread.join().expect("Thread panicked");
        }

        let handles = handles.lock().unwrap();
        assert_eq!(handles.len(), bitset_size as usize);

        // Ensure all handles are unique
        let mut handles_set = std::collections::HashSet::new();
        for &handle in handles.iter() {
            assert!(
                handles_set.insert(handle),
                "Duplicate handle found: {handle}"
            );
        }

        // Now free all handles
        for &handle in handles.iter() {
            bitset.free_handle(handle).expect("Should free handle");
        }

        // Try allocating again
        let handle = bitset.next_handle();
        assert_eq!(handle, NonZeroU32::new(1));
    }

    #[test_matrix(
        [1,2,4,8,16],
        [1, 15, 100, 4096]
    )]
    fn test_concurrent_allocation_and_freeing(num_threads: usize, bitset_size: u32) {
        let bitset = Arc::new(HandleAllocator::new(NonZeroU32::new(bitset_size).unwrap()));

        let iterations = 1000;

        let mut threads = Vec::new();

        for _ in 0..num_threads {
            let bitset_clone = Arc::clone(&bitset);
            threads.push(thread::spawn(move || {
                for _ in 0..iterations {
                    if let Some(handle) = bitset_clone.next_handle() {
                        // Simulate some work with the handle
                        bitset_clone
                            .free_handle(handle)
                            .expect("Should free handle");
                    }
                }
            }));
        }

        for thread in threads {
            thread.join().expect("Thread panicked");
        }

        // Ensure all handles are freed
        for handle in 0..bitset_size {
            assert!(
                bitset
                    .free_handle(NonZeroU32::new(handle + 1).unwrap())
                    .is_err(),
                "Handle {handle} should already be free"
            );
        }
    }

    #[test]
    fn test_all_handles_allocated_once() {
        let bitset_size = 128;
        let bitset = HandleAllocator::new(NonZeroU32::new(bitset_size).unwrap());
        let mut allocated = Vec::new();

        // Allocate all handles
        for _ in 0..bitset_size {
            let handle = bitset.next_handle().expect("Should allocate handle");
            allocated.push(handle);
        }

        // Ensure no duplicates
        let unique_handles: std::collections::HashSet<_> = allocated.iter().copied().collect();
        assert_eq!(unique_handles.len(), bitset_size as usize);

        // No more handles should be available
        assert!(bitset.next_handle().is_none());
    }

    #[test]
    fn test_random_allocation_and_freeing() {
        use rand::seq::SliceRandom;
        use rand::{thread_rng, Rng};

        let bitset_size = 100;
        let bitset = HandleAllocator::new(NonZeroU32::new(bitset_size).unwrap());
        let mut rng = thread_rng();

        // Randomly allocate handles
        let mut allocated = Vec::new();
        for _ in 0..bitset_size {
            if rng.gen_bool(0.5) {
                if let Some(handle) = bitset.next_handle() {
                    allocated.push(handle);
                }
            }
        }

        // Randomly free handles
        allocated.shuffle(&mut rng);
        for handle in allocated {
            bitset.free_handle(handle).expect("Should free handle");
        }

        // All handles should be free now
        for _ in 0..bitset_size {
            assert!(bitset.next_handle().is_some());
        }
    }
}
