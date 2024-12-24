use core::num::{NonZeroU16, NonZeroU32};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::collections::{HandleAllocator, HandleAllocatorError};

/// Represents an Address Space Identifier (ASID).
///
/// ASIDs are 16-bit values used by a system to tag and identify different
/// process address spaces. The value `0` is reserved to indicate an invalid
/// or "no ASID".
pub type AddressSpaceId = NonZeroU16;

/// `AsidPool` manages a pool of ASIDs (16-bit integers) using a `HandleAllocator`
/// and a generation counter. The generation counter ensures that ASIDs can be
/// recycled without confusion. Each time the pool runs out of ASIDs, it resets
/// (frees all allocated ASIDs) and increments the generation counter, making all
/// previously issued ASIDs from prior generations invalid.
///
/// # Behavior
/// - If no ASIDs are available when allocating:
///   1. The allocator is reset (all ASIDs freed).
///   2. The generation counter is incremented.
///   3. The first available ASID in the new generation is returned.
///
/// # Thread Safety
/// This struct is designed to be used in a concurrent environment. The internal
/// `HandleAllocator` is thread-safe, and the generation counter is updated atomically.
pub struct AddressSpaceIdPool {
    /// The current generation count. This value is incremented whenever
    /// the pool runs out of ASIDs and resets.
    generation: AtomicU32,

    /// The underlying handle allocator that manages ASID allocation.
    allocator: HandleAllocator,
}

impl Default for AddressSpaceIdPool {
    fn default() -> Self {
        Self::new(u16::MAX)
    }
}

impl AddressSpaceIdPool {
    /// Creates a new ASID pool.
    #[must_use]
    pub fn new(max_asid: u16) -> Self {
        AddressSpaceIdPool {
            generation: AtomicU32::new(0),
            allocator: HandleAllocator::new(NonZeroU32::new(u32::from(max_asid)).unwrap()),
        }
    }

    /// Allocates a new ASID and returns it along with the current generation count.
    ///
    /// If no ASIDs are available, the pool is reset (all allocated ASIDs are freed),
    /// the generation is incremented, and then the first ASID of the new generation
    /// is returned.
    ///
    /// # Returns
    ///
    /// `(asid, generation)` where:
    /// - `asid` is a 16-bit integer representing the allocated ASID.
    /// - `generation` is the 32-bit integer representing the current generation.
    ///
    /// # Guarantees
    ///
    /// - The returned `asid` will never be `0`.
    /// - Each `asid` is unique until the pool is reset.
    /// - The `generation` value is monotonically increasing each time the pool resets.
    pub fn allocate(&self) -> (AddressSpaceId, u32) {
        // Try to get the next available handle.
        if let Some(handle) = self.allocator.next_handle() {
            // Safe to unwrap since handle comes from the allocator and must be <= max_asids.
            let asid = handle.try_into().unwrap();
            let gen = self.generation.load(Ordering::Relaxed);
            return (asid, gen);
        }

        // No ASIDs available. Reset and increment the generation.
        unsafe {
            // SAFETY: we know this is safe because we are tracking generation counts
            self.allocator.reset();
        }
        let new_gen = self.generation.fetch_add(1, Ordering::Relaxed) + 1;

        // After resetting, the first available handle must succeed unless max_asids = 0,
        // which we disallowed in `new`.
        let handle = self
            .allocator
            .next_handle()
            .expect("allocator should have an available handle after reset");
        let asid = handle.try_into().unwrap();
        (asid, new_gen)
    }

    /// Frees a previously allocated ASID.
    ///
    /// # Arguments
    ///
    /// * `asid` - A 16-bit ASID that was previously returned by `allocate`.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the ASID was successfully freed.
    /// - `Err(Error)` if the ASID was out of bounds or not allocated.
    ///
    /// # Errors
    /// Returns an error if the handle could not be freed.
    ///
    /// # Notes
    ///
    /// This function does not reset the generation. Freed ASIDs can be reused
    /// within the same generation.
    pub fn free(&self, asid: AddressSpaceId) -> Result<(), HandleAllocatorError> {
        self.allocator.free_handle(asid.into())
    }

    /// Returns the current generation count.
    ///
    /// This can be useful to detect when a pool reset (and generation increment) has occurred.
    pub fn current_generation(&self) -> u32 {
        self.generation.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{num::NonZeroU16, vec::Vec};

    // Utility function to convert a u16 to a NonZeroU16 (for tests only).
    fn nz16(val: u16) -> NonZeroU16 {
        NonZeroU16::new(val).expect("Value must not be zero")
    }

    #[test]
    fn test_basic_allocation() {
        let pool = AddressSpaceIdPool::new(10); // max is 10 ASIDs
        let (asid, gen) = pool.allocate();
        assert!(asid.get() > 0 && asid.get() <= 10);
        assert_eq!(gen, 0);

        // Allocating a second one should give a different ASID.
        let (asid2, gen2) = pool.allocate();
        assert_ne!(asid, asid2);
        assert_eq!(gen2, 0);
    }

    #[test]
    fn test_free_allocation() {
        let pool = AddressSpaceIdPool::new(5);
        let (asid, gen) = pool.allocate();
        assert!(pool.free(asid).is_ok());

        // After freeing, we should be able to get the same ASID again.
        let (asid2, gen2) = pool.allocate();
        assert_eq!(gen, gen2); // generation should not have changed
                               // Because we freed the only allocated ASID, it's likely we get the same one.
                               // We can't guarantee the allocator picks the same handle first, but typically
                               // HandleAllocator picks the lowest free bit. Assuming sequential allocation,
                               // we check if we got something valid again.
        assert!(asid2.get() > 0 && asid2.get() <= 5);
    }

    #[test]
    fn test_out_of_bounds_free() {
        let pool = AddressSpaceIdPool::new(5);

        // Attempt to free an out-of-range ASID
        assert!(pool.free(nz16(6)).is_err()); // Out of range
        assert!(pool.free(nz16(0xFFFF)).is_err()); // Way out of range
    }

    #[test]
    fn test_free_unallocated() {
        let pool = AddressSpaceIdPool::new(5);

        // Attempt to free an ASID that was never allocated
        assert!(pool.free(nz16(1)).is_err()); // not allocated yet
    }

    #[test]
    fn test_exhaustion_and_reset() {
        let pool = AddressSpaceIdPool::new(3);

        // Allocate all available ASIDs
        let mut allocated = Vec::new();
        for _ in 0..3 {
            let (asid, gen) = pool.allocate();
            assert!(asid.get() >= 1 && asid.get() <= 3);
            assert_eq!(gen, 0);
            allocated.push(asid);
        }

        // All ASIDs are now allocated; the next allocation should cause reset & gen increment
        let (asid_new, gen_new) = pool.allocate();
        assert!(asid_new.get() >= 1 && asid_new.get() <= 3);
        assert_eq!(gen_new, 1); // generation should have incremented

        // After a reset, all previously allocated ASIDs from old generation are invalid
        // But the new one is valid in the new generation.
    }

    #[test]
    fn test_generation_increments() {
        let pool = AddressSpaceIdPool::new(2);

        let (a1, g1) = pool.allocate();
        let (a2, g2) = pool.allocate();

        // No more ASIDs left at this point
        assert_eq!(g1, 0);
        assert_eq!(g2, 0);

        // Next allocate triggers a reset and increments generation
        let (a3, g3) = pool.allocate();
        assert_eq!(g3, 1);
        assert!(a3.get() >= 1 && a3.get() <= 2);

        // Allocate second one in new gen
        let (a4, g4) = pool.allocate();
        assert_eq!(g4, 1);
        assert!(a4.get() >= 1 && a4.get() <= 2);

        // Exhaust again and re-check generation increment
        let (a5, g5) = pool.allocate();
        assert_eq!(g5, 2);
        assert!(a5.get() >= 1 && a5.get() <= 2);
    }

    #[test]
    fn test_generation_method() {
        let pool = AddressSpaceIdPool::new(3);
        assert_eq!(pool.current_generation(), 0);

        // Allocate all
        for _ in 0..3 {
            pool.allocate();
        }

        // This triggers a reset and increments generation
        pool.allocate();
        assert_eq!(pool.current_generation(), 1);
    }

    #[test]
    fn test_large_allocations() {
        // Test with a larger number to ensure that everything still works.
        let pool = AddressSpaceIdPool::new(1000);

        let mut allocated = Vec::new();
        for _ in 0..1000 {
            let (asid, gen) = pool.allocate();
            assert!(asid.get() > 0 && asid.get() <= 1000);
            assert_eq!(gen, 0);
            allocated.push(asid);
        }

        // Trigger reset
        let (asid_new, gen_new) = pool.allocate();
        assert!(asid_new.get() > 0 && asid_new.get() <= 1000);
        assert_eq!(gen_new, 1);

        // Free some and reallocate
        pool.free(asid_new).unwrap();
        let (asid_re, gen_re) = pool.allocate();
        assert!(asid_re.get() > 0 && asid_re.get() <= 1000);
        assert_eq!(gen_re, 1);
    }
}
