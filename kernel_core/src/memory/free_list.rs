//! A simple free-list allocator for blocks in a virtual address space.
//!
//! This allocator manages abstract "blocks" of a fixed size, which must be a non-zero power of two.
//! Blocks are analogous to pages but can have any size as long as they adhere to the power-of-two constraint.

#![allow(clippy::redundant_else)]
use super::{Error, VirtualAddress};
use alloc::vec::Vec;

/// A contiguous range of memory in the virtual address space,
/// measured in whole blocks.
///
/// - `start` is the virtual address (must be in kernel space).
/// - `blocks` is the number of blocks in this range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub start: VirtualAddress,
    pub blocks: usize,
}

impl Range {
    /// Returns the exclusive-end address of this range,
    /// given the block size in bytes.
    #[inline]
    pub fn end(&self, block_size: usize) -> VirtualAddress {
        let offset_bytes = self.blocks * block_size;
        self.start.byte_add(offset_bytes)
    }
}

/// A simple free-list allocator for blocks in a virtual address space.
///
/// The free list is a sorted `Vec<Range>`, each describing a
/// free region in block counts. When allocating:
///  - We look for the first range with enough blocks.
///  - We remove or shrink that free range.
///
/// When freeing:
///  - We insert a `Range` back in sorted order.
///  - We attempt to merge with neighbors if they are directly adjacent.
///
/// # Usage Notes
///  - All addresses must be block-aligned (i.e., the `start` of a `Range`
///    should be aligned to `block_size`).
///  - `blocks` must be a whole number (≥ 1).
pub struct FreeListAllocator {
    free_list: Vec<Range>,
    block_size: usize,
}

impl FreeListAllocator {
    /// Create a new allocator with a single free range of `[start..start + blocks * block_size)`.
    ///
    /// # Parameters
    /// - `start`: A **block-aligned** virtual address in kernel space.
    /// - `blocks`: The number of blocks that this allocator should initially manage.
    /// - `block_size`: The size of each block in bytes (must be a non-zero power of two).
    ///
    /// # Panics
    /// This constructor panics if `block_size` is not a non-zero power of two.
    /// It does not enforce that `start` is actually block-aligned,
    /// nor does it validate that it's in the kernel range. For a production
    /// kernel, you might add such checks if needed.
    #[must_use]
    pub fn new(start: VirtualAddress, blocks: usize, block_size: usize) -> Self {
        assert!(
            block_size.is_power_of_two() && block_size != 0,
            "block_size must be a non-zero power of two"
        );

        let mut free_list = Vec::new();
        if blocks > 0 {
            free_list.push(Range { start, blocks });
        }
        FreeListAllocator {
            free_list,
            block_size,
        }
    }

    /// Reserve (remove) `[start..start + blocks * block_size)` from the free list.
    ///
    /// This function will remove that entire block from the free list,
    /// splitting or shrinking any free range(s) as needed.
    ///
    /// # Errors
    /// - `InvalidSize` if `blocks` is zero or if the range cannot be
    ///   fully removed (partial overlap, out of bounds, etc.).
    pub fn reserve_range(&mut self, start: VirtualAddress, blocks: usize) -> Result<(), Error> {
        if blocks == 0 {
            return Err(Error::InvalidSize);
        }

        let end = start.byte_add(blocks * self.block_size);

        let mut i = 0;
        let mut blocks_left_to_remove = blocks;

        while i < self.free_list.len() && blocks_left_to_remove > 0 {
            let frange = self.free_list[i];
            let frange_end = frange.end(self.block_size);

            // No overlap
            if end <= frange.start || start >= frange_end {
                i += 1;
                continue;
            }

            // Overlap exists
            if start > frange.start {
                // Split the free range into two parts:
                // [frange.start, start) and [end, frange_end)
                let blocks_before = self.blocks_in_range(frange.start, start);
                self.free_list[i].blocks = blocks_before;

                if end < frange_end {
                    let blocks_after = self.blocks_in_range(end, frange_end);
                    self.free_list.insert(
                        i + 1,
                        Range {
                            start: end,
                            blocks: blocks_after,
                        },
                    );
                }

                // We've handled the overlap
                return Ok(());
            } else {
                // start <= frange.start
                let overlap_end = end.min(frange_end);
                let overlap_blocks = self.blocks_in_range(frange.start, overlap_end);

                if end < frange_end {
                    // Adjust the current range to start from `end`
                    let leftover_blocks = frange.blocks - overlap_blocks;
                    self.free_list[i] = Range {
                        start: end,
                        blocks: leftover_blocks,
                    };
                } else {
                    // Remove the entire range
                    self.free_list.remove(i);
                    i = i.saturating_sub(1);
                }

                if overlap_blocks >= blocks_left_to_remove {
                    // All required blocks have been removed
                    return Ok(());
                } else {
                    // Need to continue removing from the next range
                    blocks_left_to_remove -= overlap_blocks;
                }
            }
            i += 1;
        }

        // Unable to remove the entire requested range
        Err(Error::InvalidSize)
    }

    /// Allocate a contiguous range of `blocks` blocks.
    ///
    /// # Errors
    /// - `InvalidSize` if `blocks == 0`.
    /// - `OutOfMemory` if no free range has enough blocks.
    pub fn alloc(&mut self, blocks: usize) -> Result<Range, Error> {
        if blocks == 0 {
            return Err(Error::InvalidSize);
        }

        // Find the first free range that can satisfy the allocation
        if let Some((i, frange)) = self
            .free_list
            .iter()
            .enumerate()
            .find(|(_, frange)| frange.blocks >= blocks)
        {
            let allocated_start = frange.start;
            let allocated = Range {
                start: allocated_start,
                blocks,
            };

            if frange.blocks > blocks {
                // Shrink the free range
                let new_start = allocated_start.byte_add(blocks * self.block_size);
                self.free_list[i] = Range {
                    start: new_start,
                    blocks: frange.blocks - blocks,
                };
            } else {
                // Remove the entire free range
                self.free_list.remove(i);
            }

            return Ok(allocated);
        }

        // No suitable free range found
        Err(Error::OutOfMemory)
    }

    /// Free a previously allocated `Range` by returning `blocks` blocks at `start`
    /// to the free list, attempting to merge with neighbors.
    ///
    /// # Errors
    /// - `InvalidSize` if `range.blocks == 0`.
    ///
    /// **Note**: This does not check for ownership or overlapping with existing free ranges.
    /// It's the caller's responsibility to ensure that only valid allocated ranges are freed.
    pub fn free(&mut self, range: Range) -> Result<(), Error> {
        if range.blocks == 0 {
            return Err(Error::InvalidSize);
        }

        // Find the insertion position to keep the free list sorted
        let insert_pos = self
            .free_list
            .binary_search_by_key(&usize::from(range.start), |r| usize::from(r.start))
            .unwrap_or_else(|pos| pos);
        self.free_list.insert(insert_pos, range);

        // Attempt to merge with adjacent ranges
        self.merge_with_neighbors(insert_pos);

        Ok(())
    }

    /// Returns the total free space in **blocks**.
    #[must_use]
    pub fn free_blocks(&self) -> usize {
        self.free_list.iter().map(|r| r.blocks).sum()
    }

    /// Merges the range at `idx` with its adjacent neighbors if they are contiguous.
    fn merge_with_neighbors(&mut self, idx: usize) {
        if idx >= self.free_list.len() {
            return;
        }

        // Merge with the previous range if contiguous
        if idx > 0 {
            let prev = self.free_list[idx - 1];
            let current = self.free_list[idx];
            if prev.end(self.block_size) == current.start {
                self.free_list[idx - 1].blocks += current.blocks;
                self.free_list.remove(idx);
                if idx < self.free_list.len() {
                    // Adjust idx after removal
                } else {
                    return;
                }
            }
        }

        // Merge with the next range if contiguous
        if idx < self.free_list.len() - 1 {
            let current = self.free_list[idx];
            let next = self.free_list[idx + 1];
            if current.end(self.block_size) == next.start {
                self.free_list[idx].blocks += next.blocks;
                self.free_list.remove(idx + 1);
            }
        }
    }

    /// Computes the number of whole blocks in the range `[start..end)`.
    ///
    /// Assumes that `start` and `end` are block-aligned and that `end >= start`.
    #[inline]
    fn blocks_in_range(&self, start: VirtualAddress, end: VirtualAddress) -> usize {
        let byte_delta = usize::from(end) - usize::from(start);
        byte_delta / self.block_size // Assuming VirtualAddress has block_size method
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(64)]
    #[test_case(4096)]
    #[test_case(16384)]
    fn test_new_allocator(block_size: usize) {
        let start_addr = VirtualAddress::from(0xffff_8000_0000_0000usize);
        let alloc = FreeListAllocator::new(start_addr, 4, block_size);
        // 4 blocks free
        assert_eq!(alloc.free_blocks(), 4);
    }

    #[test_case(64)]
    #[test_case(4096)]
    #[test_case(16384)]
    fn test_simple_alloc(block_size: usize) {
        let start_addr = VirtualAddress::from(0xffff_8000_0000_0000usize);
        let mut alloc = FreeListAllocator::new(start_addr, 4, block_size);

        // Allocate 2 blocks
        let r1 = alloc.alloc(2).expect("failed to alloc 2 blocks");
        assert_eq!(r1.blocks, 2);

        // We used 2 of the 4 free blocks, so 2 remain
        assert_eq!(alloc.free_blocks(), 2);

        // Allocate 1 page
        let r2 = alloc.alloc(1).expect("failed to alloc 1 page");
        assert_eq!(r2.blocks, 1);

        // 1 page remains free
        assert_eq!(alloc.free_blocks(), 1);
    }

    #[test_case(64)]
    #[test_case(4096)]
    #[test_case(16384)]
    fn test_reserve_range(block_size: usize) {
        let start_addr = VirtualAddress::from(0xffff_8000_0000_0000usize);
        let mut alloc = FreeListAllocator::new(start_addr, 4, block_size);
        assert_eq!(alloc.free_blocks(), 4);

        // We'll reserve 1 page, starting from `start_addr + (1 * page_size)`.
        // So effectively we remove the second page in the range.
        let reserve_start = start_addr.byte_add(block_size);
        alloc.reserve_range(reserve_start, 1).unwrap();

        // Now 3 blocks remain free
        assert_eq!(alloc.free_blocks(), 3);

        // Attempt to reserve partially overlapping region -> should fail
        let overlap_start = start_addr.byte_add(block_size + block_size / 2); // mid-page
        let result = alloc.reserve_range(overlap_start, 1);
        assert!(result.is_err());
    }

    #[test_case(64)]
    #[test_case(4096)]
    #[test_case(16384)]
    fn test_free(block_size: usize) {
        let start_addr = VirtualAddress::from(0xffff_8000_0000_0000usize);
        let mut alloc = FreeListAllocator::new(start_addr, 3, block_size);
        assert_eq!(alloc.free_blocks(), 3);

        // Allocate 2 blocks
        let r1 = alloc.alloc(2).unwrap();
        assert_eq!(r1.blocks, 2);
        assert_eq!(alloc.free_blocks(), 1);

        // Allocate 1 page
        let r2 = alloc.alloc(1).unwrap();
        assert_eq!(r2.blocks, 1);
        assert_eq!(alloc.free_blocks(), 0);

        // Free r2, 1 page is free again
        alloc.free(r2).unwrap();
        assert_eq!(alloc.free_blocks(), 1);

        // Free r1, total free blocks = 3
        alloc.free(r1).unwrap();
        assert_eq!(alloc.free_blocks(), 3);
    }

    #[test_case(64)]
    #[test_case(4096)]
    #[test_case(16384)]
    fn test_merge(block_size: usize) {
        let start_addr = VirtualAddress::from(0xffff_8000_0000_0000usize);
        let mut alloc = FreeListAllocator::new(start_addr, 4, block_size);

        // Allocate 2 blocks
        let r = alloc.alloc(2).unwrap();
        assert_eq!(alloc.free_blocks(), 2);

        // Free it -> the free list merges back to 4 blocks
        alloc.free(r).unwrap();
        assert_eq!(alloc.free_blocks(), 4);
        assert_eq!(alloc.free_list.len(), 1);
    }
}
