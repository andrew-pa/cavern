//! A simple free-list allocator for pages in a virtual address space.
#![allow(clippy::redundant_else)]
use super::{Error, PageSize, VirtualAddress};
use alloc::vec::Vec;

/// A contiguous range of memory in the virtual address space,
/// measured in whole pages.
///
/// - `start` is the virtual address (must be in kernel space).
/// - `pages` is the number of pages in this range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub start: VirtualAddress,
    pub pages: usize,
}

impl Range {
    /// Return the exclusive-end address of this range,
    /// given the page size.
    #[inline]
    pub fn end(&self, page_size: PageSize) -> VirtualAddress {
        let offset_bytes = self.pages * usize::from(page_size);
        self.start.byte_add(offset_bytes)
    }
}

/// A simple free-list allocator for pages in a virtual address space.
///
/// The free list is a sorted `Vec<Range>`, each describing a
/// free region in page counts. When allocating:
///  - We look for the first range with enough pages.
///  - We remove or shrink that free range.
///
/// When freeing:
///  - We insert a `Range` back in sorted order.
///  - We attempt to merge with neighbors if they are directly adjacent.
///
/// Usage notes:
///  - All addresses must be page-aligned (i.e., the `start` of a `Range`
///    should be aligned to `page_size`).
///  - `pages` must be a whole number (≥ 1).
pub struct FreeListAllocator {
    free_list: Vec<Range>,
    page_size: PageSize,
}

impl FreeListAllocator {
    /// Create a new allocator with a single free range of `[start..start + pages * page_size)`.
    ///
    /// # Parameters
    /// - `start`: A **page-aligned** virtual address in kernel space.
    /// - `pages`: The number of pages that this allocator should initially manage.
    /// - `page_size`: The size of a page (e.g., 4KiB or 16KiB).
    ///
    /// # Panics
    /// This constructor does not enforce that `start` is actually page-aligned,
    /// nor does it validate that it's in the kernel range. For a production
    /// kernel, you might add such checks if needed.
    #[must_use]
    pub fn new(start: VirtualAddress, pages: usize, page_size: PageSize) -> Self {
        let mut free_list = Vec::new();
        if pages > 0 {
            free_list.push(Range { start, pages });
        }
        FreeListAllocator {
            free_list,
            page_size,
        }
    }

    /// Reserve (remove) `[start..start + pages * page_size)` from the free list.
    ///
    /// This function will remove that entire block from the free list,
    /// splitting or shrinking any free range(s) as needed.
    ///
    /// # Errors
    /// - `InvalidSize` if `pages` is zero or if the range cannot be
    ///   fully removed (partial overlap, out of bounds, etc.).
    pub fn reserve_range(&mut self, start: VirtualAddress, pages: usize) -> Result<(), Error> {
        if pages == 0 {
            return Err(Error::InvalidSize);
        }

        // Calculate the end address
        let end = start.byte_add(pages * usize::from(self.page_size));

        let mut i = 0;
        let mut pages_left_to_remove = pages;

        // We’ll walk through the free list, removing or splitting segments.
        while i < self.free_list.len() && pages_left_to_remove > 0 {
            let frange = self.free_list[i];
            let frange_end = frange.end(self.page_size);

            // If there's no overlap, skip
            if end <= frange.start || start >= frange_end {
                i += 1;
                continue;
            }

            // Overlap is found. We might split the free range in up to two parts.
            if start > frange.start {
                // Trim the tail of `frange` to end at `start`.
                // The front part remains free.
                // The overlapping portion (from `start`) will be removed.
                let overlap_begin_pages = pages_in_range(frange.start, start, self.page_size);

                // Overlap_end_pages is how many pages remain from `frange` after `start`.
                // We'll keep the front portion as is:
                self.free_list[i] = Range {
                    start: frange.start,
                    pages: overlap_begin_pages,
                };

                // If `end < frange_end`, we need to keep the leftover portion
                // after `end` as well.
                if end < frange_end {
                    let overlap_tail_pages = pages_in_range(end, frange_end, self.page_size);
                    self.free_list.insert(
                        i + 1,
                        Range {
                            start: end,
                            pages: overlap_tail_pages,
                        },
                    );
                }

                // We’ve accounted for this entire overlap out of the free range `frange`.
                // So we’re done removing from this segment.
                return Ok(());
            } else {
                // `start <= frange.start`
                // The overlap might remove all or part of `frange`.
                // Overlap could be partial if `end < frange_end`.
                let overlap_size_in_pages = pages_in_range(
                    frange.start,
                    core::cmp::min(frange_end, end),
                    self.page_size,
                );

                if end < frange_end {
                    // The reservation removes the front part of `frange`.
                    // We keep any leftover pages after `end`.
                    let leftover_pages = frange.pages - overlap_size_in_pages;
                    let leftover_start = end;
                    self.free_list[i] = Range {
                        start: leftover_start,
                        pages: leftover_pages,
                    };
                } else {
                    // The reservation covers the entire frange, remove it completely.
                    self.free_list.remove(i);
                    i = i.saturating_sub(1);
                }

                if overlap_size_in_pages >= pages_left_to_remove {
                    // Done removing
                    return Ok(());
                } else {
                    // Reservation extends beyond this free range
                    pages_left_to_remove -= overlap_size_in_pages;
                }
            }
            i += 1;
        }

        // If we get here, we couldn't fully remove all `pages`.
        if pages_left_to_remove > 0 {
            return Err(Error::InvalidSize);
        }

        Ok(())
    }

    /// Allocate a contiguous range of `pages` pages.
    ///
    /// # Errors
    /// - `InvalidSize` if `pages == 0`.
    /// - `OutOfMemory` if no free range has enough pages.
    pub fn alloc(&mut self, pages: usize) -> Result<Range, Error> {
        if pages == 0 {
            return Err(Error::InvalidSize);
        }

        // Search the free_list for the first range that can fit `pages`.
        for i in 0..self.free_list.len() {
            let frange = self.free_list[i];
            if frange.pages < pages {
                continue;
            }

            // Found a range big enough
            let allocated_start = frange.start;
            let allocated = Range {
                start: allocated_start,
                pages,
            };

            // Remove or shrink the free range
            let leftover_pages = frange.pages - pages;
            if leftover_pages > 0 {
                let leftover_start = frange.start.byte_add(pages * usize::from(self.page_size));
                self.free_list[i] = Range {
                    start: leftover_start,
                    pages: leftover_pages,
                };
            } else {
                // We consumed the entire free range
                self.free_list.remove(i);
            }

            return Ok(allocated);
        }

        // No suitable free range found
        Err(Error::OutOfMemory)
    }

    /// Free a previously allocated `Range` by returning `pages` pages at `start`
    /// to the free list, attempting to merge with neighbors.
    ///
    /// # Errors
    /// - `InvalidSize` if `range.pages == 0`.
    ///
    /// **Note**: This does not check for ownership or overlapping with existing free ranges.
    /// It's the caller's responsibility to ensure that only valid allocated ranges are freed.
    pub fn free(&mut self, range: Range) -> Result<(), Error> {
        if range.pages == 0 {
            return Err(Error::InvalidSize);
        }

        // Insert the freed range in sorted order by start address
        let insert_pos = match self
            .free_list
            .binary_search_by_key(&usize::from(range.start), |r| usize::from(r.start))
        {
            Ok(pos) | Err(pos) => pos,
        };
        self.free_list.insert(insert_pos, range);

        // Merge with neighbors if possible
        self.merge_with_neighbors(insert_pos);

        Ok(())
    }

    /// Returns the total free space in **pages** (not bytes).
    #[must_use]
    pub fn free_pages(&self) -> usize {
        self.free_list.iter().map(|r| r.pages).sum()
    }

    /// Merge adjacent neighbors around the index `idx`.
    fn merge_with_neighbors(&mut self, idx: usize) {
        if idx >= self.free_list.len() {
            return;
        }

        // Merge backward
        if idx > 0 {
            let (prev_idx, curr_idx) = (idx - 1, idx);
            let prev_range = self.free_list[prev_idx];
            let curr_range = self.free_list[curr_idx];

            // They are adjacent if `prev_range.end(page_size) == curr_range.start`
            if prev_range.end(self.page_size) == curr_range.start {
                // Merge them
                self.free_list[prev_idx] = Range {
                    start: prev_range.start,
                    pages: prev_range.pages + curr_range.pages,
                };
                self.free_list.remove(curr_idx);
            }
        }

        // Merge forward
        if idx < self.free_list.len() {
            let curr_idx = idx.min(self.free_list.len() - 1);
            if curr_idx + 1 < self.free_list.len() {
                let curr_range = self.free_list[curr_idx];
                let next_range = self.free_list[curr_idx + 1];
                if curr_range.end(self.page_size) == next_range.start {
                    self.free_list[curr_idx] = Range {
                        start: curr_range.start,
                        pages: curr_range.pages + next_range.pages,
                    };
                    self.free_list.remove(curr_idx + 1);
                }
            }
        }
    }
}

/// A helper to compute how many whole pages lie in `[start..end)`,
/// assuming `start` and `end` are page-aligned (or that the caller
/// at least ensures `end >= start`).
///
/// `pages_in_range( start, end, page_size ) = (end - start) / page_size`.
fn pages_in_range(start: VirtualAddress, end: VirtualAddress, page_size: PageSize) -> usize {
    let start_val = usize::from(start);
    let end_val = usize::from(end);
    let byte_delta = end_val.saturating_sub(start_val);
    byte_delta / usize::from(page_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_allocator() {
        let start_addr = VirtualAddress::from(0xffff_8000_0000_0000usize);
        let alloc = FreeListAllocator::new(start_addr, 4, PageSize::FourKiB);
        // 4 pages free
        assert_eq!(alloc.free_pages(), 4);
    }

    #[test]
    fn test_simple_alloc() {
        let start_addr = VirtualAddress::from(0xffff_8000_0000_0000usize);
        let mut alloc = FreeListAllocator::new(start_addr, 4, PageSize::FourKiB);

        // Allocate 2 pages
        let r1 = alloc.alloc(2).expect("failed to alloc 2 pages");
        assert_eq!(r1.pages, 2);

        // We used 2 of the 4 free pages, so 2 remain
        assert_eq!(alloc.free_pages(), 2);

        // Allocate 1 page
        let r2 = alloc.alloc(1).expect("failed to alloc 1 page");
        assert_eq!(r2.pages, 1);

        // 1 page remains free
        assert_eq!(alloc.free_pages(), 1);
    }

    #[test]
    fn test_reserve_range() {
        let start_addr = VirtualAddress::from(0xffff_8000_0000_0000usize);
        let mut alloc = FreeListAllocator::new(start_addr, 4, PageSize::FourKiB);
        assert_eq!(alloc.free_pages(), 4);

        // We'll reserve 1 page, starting from `start_addr + (1 * page_size)`.
        // So effectively we remove the second page in the range.
        let reserve_start = start_addr.byte_add(0x1000);
        alloc.reserve_range(reserve_start, 1).unwrap();

        // Now 3 pages remain free
        assert_eq!(alloc.free_pages(), 3);

        // Attempt to reserve partially overlapping region -> should fail
        let overlap_start = start_addr.byte_add(0x1800); // mid-page
        let result = alloc.reserve_range(overlap_start, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_free() {
        let start_addr = VirtualAddress::from(0xffff_8000_0000_0000usize);
        let mut alloc = FreeListAllocator::new(start_addr, 3, PageSize::FourKiB);
        assert_eq!(alloc.free_pages(), 3);

        // Allocate 2 pages
        let r1 = alloc.alloc(2).unwrap();
        assert_eq!(r1.pages, 2);
        assert_eq!(alloc.free_pages(), 1);

        // Allocate 1 page
        let r2 = alloc.alloc(1).unwrap();
        assert_eq!(r2.pages, 1);
        assert_eq!(alloc.free_pages(), 0);

        // Free r2, 1 page is free again
        alloc.free(r2).unwrap();
        assert_eq!(alloc.free_pages(), 1);

        // Free r1, total free pages = 3
        alloc.free(r1).unwrap();
        assert_eq!(alloc.free_pages(), 3);
    }

    #[test]
    fn test_merge() {
        let start_addr = VirtualAddress::from(0xffff_8000_0000_0000usize);
        let mut alloc = FreeListAllocator::new(start_addr, 4, PageSize::FourKiB);

        // Allocate 2 pages
        let r = alloc.alloc(2).unwrap();
        assert_eq!(alloc.free_pages(), 2);

        // Free it -> the free list merges back to 4 pages
        alloc.free(r).unwrap();
        assert_eq!(alloc.free_pages(), 4);
        assert_eq!(alloc.free_list.len(), 1);
    }
}
