//! Buddy allocator for pages.

use core::{
    ptr::{null, null_mut, NonNull},
    sync::atomic::{AtomicPtr, Ordering},
};

use snafu::{ensure, OptionExt as _};

use crate::memory::{subtract_ranges, InvalidSizeSnafu, OutOfMemorySnafu, UnknownPtrSnafu};

use super::{Error, PageAllocator, PageSize, PhysicalAddress};

#[repr(C)]
struct FreeHeader {
    next_block: AtomicPtr<FreeHeader>,
}

/// Page allocator that uses the buddy memory allocation algorithm to allocate pages of physical
/// memory.
///
/// `MAX_ORDER` is the largest power of two block of pages that will be managed by the allocator.
#[allow(clippy::module_name_repetitions)]
pub struct BuddyPageAllocator<const MAX_ORDER: usize = 16> {
    base_addr: *mut u8,
    end_addr: *mut u8,
    page_size: PageSize,
    free_blocks: [AtomicPtr<FreeHeader>; MAX_ORDER],
}

unsafe impl Send for BuddyPageAllocator {}
unsafe impl Sync for BuddyPageAllocator {}

impl<const MAX_ORDER: usize> BuddyPageAllocator<MAX_ORDER> {
    /// Create a new allocator that will allocate memory from the region at `memory_start` of length `memory_length` bytes.
    /// The memory start address must be page aligned, and must contain a whole number of pages.
    /// The allocator will start with no actual memory in the free pool, memory must be added with [`Self::add_memory_region`].
    ///
    /// # Panics
    ///
    /// This function panics if the aformentioned invarients are not met.
    ///
    /// # Safety
    ///
    /// The memory region provided must be entirely valid memory that is safe to dereference,
    /// live for the lifetime of the allocator and not be shared outside of the allocator.
    pub unsafe fn new(page_size: PageSize, memory_start: *mut u8, memory_length: usize) -> Self {
        let page_len = usize::from(page_size);
        assert!(memory_start.is_aligned_to(page_len));
        assert_eq!(memory_length % page_len, 0);

        Self {
            base_addr: memory_start,
            end_addr: unsafe { memory_start.add(memory_length) },
            page_size,
            free_blocks: [const { AtomicPtr::new(null_mut()) }; MAX_ORDER],
        }
    }

    /// Adds a region of memory to the pool of memory managed by the allocator.
    /// The region does not need to be aligned, this function will add the necessary padding.
    /// The region must be within the range that is managed by the allocator.
    /// Returns `false` if the region is too small to be used.
    ///
    /// # Arguments
    /// - `region_start`: a pointer to the beginning of the region in the kernel address space.
    /// - `region_length`: the length of the region in bytes.
    pub unsafe fn add_memory_region(&self, region_start: *mut u8, region_length: usize) -> bool {
        assert!(region_length > 0);
        assert!(!region_start.is_null());
        assert!(region_start >= self.base_addr && region_start < self.end_addr);
        assert!(region_start.add(region_length) <= self.end_addr);
        let page_len = usize::from(self.page_size);
        let start_alignment_padding = region_start.align_offset(page_len);
        if region_length < page_len || region_length - start_alignment_padding < page_len {
            return false;
        }
        let mut block_start = NonNull::new(region_start.add(start_alignment_padding)).unwrap();
        let mut remaining_bytes = region_length;
        let mut order = MAX_ORDER - 1;
        while remaining_bytes > 0 {
            let block_len = (1 << order) * page_len;
            if remaining_bytes >= block_len {
                let block = block_start.cast();
                unsafe {
                    block.write(FreeHeader {
                        next_block: AtomicPtr::default(),
                    });
                }
                self.push_free(order, block);
                remaining_bytes -= block_len;
                block_start = block_start.add(block_len);
            } else {
                match order.checked_sub(1) {
                    Some(new_order) => order = new_order,
                    None => break,
                }
            }
        }
        true
    }

    /// Pop the next free block of order `order` if one exists.
    fn pop_free(&self, order: usize) -> Option<NonNull<FreeHeader>> {
        let mut head = NonNull::new(self.free_blocks[order].load(Ordering::Acquire))?;
        loop {
            let new_head = unsafe {
                // SAFETY: to become the head, this block must be correctly initialized
                head.as_ref().next_block.load(Ordering::Relaxed)
            };
            match self.free_blocks[order].compare_exchange(
                head.as_ptr(),
                new_head,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    #[cfg(test)]
                    std::println!("pop_free {order} {head:x?}");
                    return Some(head);
                }
                Err(h) => head = NonNull::new(h)?,
            }
        }
    }

    /// Push the newly freed block of order `order` into the free list.
    /// Automatically updates the `next_block` field of the header of the new block.
    ///
    /// # Safety
    ///
    /// We assume that `block` is *not* shared between threads, and that the header is initialized
    /// and reference-convertable.
    unsafe fn push_free(&self, order: usize, mut block: NonNull<FreeHeader>) {
        #[cfg(test)]
        std::println!("push_free {order} {block:x?}");
        assert!(block.is_aligned_to(usize::from(self.page_size)));
        let mut head = self.free_blocks[order].load(Ordering::Acquire);
        let mut i = 0;
        loop {
            block.as_mut().next_block.store(head, Ordering::Relaxed);
            match self.free_blocks[order].compare_exchange(
                head,
                block.as_ptr(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(h) => head = h,
            }
            i += 1;
            assert!(i < 1000);
        }
    }

    fn try_remove_buddy(&self, order: usize, buddy: NonNull<FreeHeader>) -> bool {
        let free_list = &self.free_blocks[order];
        // keep trying until successful or not found
        'retry: loop {
            let mut prev_ptr: Option<NonNull<FreeHeader>> = None;
            let mut current_ptr = NonNull::new(free_list.load(Ordering::Acquire));

            // step through the list
            while let Some(current) = current_ptr {
                let next_ptr = unsafe { current.as_ref().next_block.load(Ordering::Relaxed) };

                if current == buddy {
                    // Attempt to remove the buddy from the free list.
                    let success = if let Some(prev_ptr) = prev_ptr {
                        unsafe {
                            prev_ptr
                                .as_ref()
                                .next_block
                                .compare_exchange(
                                    current.as_ptr(),
                                    next_ptr,
                                    Ordering::AcqRel,
                                    Ordering::Acquire,
                                )
                                .is_ok()
                        }
                    } else {
                        // Removing from head
                        free_list
                            .compare_exchange(
                                current.as_ptr(),
                                next_ptr,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                    };

                    if success {
                        return true;
                    }

                    // Failed to remove; retry from the beginning of the list.
                    continue 'retry;
                }

                prev_ptr = current_ptr;
                current_ptr = NonNull::new(next_ptr);
            }

            // Buddy not found in the free list.
            return false;
        }
    }

    fn block_in_free_list(&self, order: usize, block: NonNull<FreeHeader>) -> bool {
        let mut cur = NonNull::new(self.free_blocks[order].load(Ordering::Acquire));
        while let Some(n) = cur {
            if n == block {
                return true;
            }
            cur = unsafe { NonNull::new(n.as_ref().next_block.load(Ordering::Relaxed)) };
        }
        false
    }

    #[cfg(test)]
    fn count_in_free_list(&self, order: usize) -> usize {
        let mut count = 0;
        let mut cur = NonNull::new(self.free_blocks[order].load(Ordering::Acquire));
        while let Some(n) = cur {
            count += 1;
            cur = unsafe { NonNull::new(n.as_ref().next_block.load(Ordering::Relaxed)) };
        }
        count
    }

    #[cfg(test)]
    fn total_pages_free(&self) -> usize {
        (0..MAX_ORDER)
            .map(|order| self.count_in_free_list(order) * (1 << order))
            .sum()
    }

    fn split_block_to_size(
        &self,
        block: NonNull<FreeHeader>,
        mut current_order: usize,
        desired_order: usize,
    ) -> NonNull<FreeHeader> {
        while current_order > desired_order {
            current_order -= 1;
            let new_size = 1 << current_order;
            unsafe {
                let new_block = block.cast::<u8>().add(new_size * self.page_size).cast();
                self.push_free(current_order, new_block);
            }
        }
        block
    }

    unsafe fn buddy_of(&self, block: NonNull<FreeHeader>, order: usize) -> NonNull<FreeHeader> {
        let offset: usize = unsafe { block.cast::<u8>().as_ptr().offset_from(self.base_addr) }
            .try_into()
            .unwrap();
        let buddy_offset = offset ^ (self.page_size * (1 << order));
        let ptr = unsafe { self.base_addr.add(buddy_offset) };
        NonNull::new(ptr).unwrap().cast()
    }
}

impl<const MAX_ORDER: usize> PageAllocator for BuddyPageAllocator<MAX_ORDER> {
    fn page_size(&self) -> PageSize {
        self.page_size
    }

    fn allocate(&self, num_pages: usize) -> Result<PhysicalAddress, Error> {
        ensure!(num_pages > 0, InvalidSizeSnafu);

        let block_size = num_pages
            .checked_next_power_of_two()
            .context(OutOfMemorySnafu)?;
        let order = block_size.ilog2() as usize;

        let mut actual_order = order;
        let free_block = loop {
            ensure!(actual_order < MAX_ORDER, OutOfMemorySnafu);
            if let Some(free) = self.pop_free(actual_order) {
                break free;
            }
            actual_order += 1;
        };

        let block = self.split_block_to_size(free_block, actual_order, order);

        Ok(PhysicalAddress::from(block.as_ptr().cast()))
    }

    fn free(&self, pages: PhysicalAddress, num_pages: usize) -> Result<(), Error> {
        let pages_ptr: *mut () = pages.into();
        let block = NonNull::new(pages_ptr.cast()).context(UnknownPtrSnafu)?;
        ensure!(num_pages > 0, InvalidSizeSnafu);
        ensure!(
            pages_ptr.cast() >= self.base_addr && pages_ptr.cast() < self.end_addr,
            UnknownPtrSnafu
        );

        let block_size = num_pages
            .checked_next_power_of_two()
            .context(InvalidSizeSnafu)?;
        let order = block_size.ilog2() as usize;
        ensure!(order < MAX_ORDER, InvalidSizeSnafu);

        let buddy = unsafe { self.buddy_of(block, order) };

        #[cfg(test)]
        std::println!("free block={block:x?} order={order} buddy={buddy:x?}");

        if self.try_remove_buddy(order, buddy) {
            #[cfg(test)]
            std::println!("removed buddy");
            unsafe {
                self.push_free(order + 1, block);
            }
        } else {
            // prevent double frees
            ensure!(!self.block_in_free_list(order, block), UnknownPtrSnafu);
            ensure!(!self.block_in_free_list(order + 1, block), UnknownPtrSnafu);
            ensure!(!self.block_in_free_list(order + 1, buddy), UnknownPtrSnafu);
            #[cfg(test)]
            std::println!("buddy is allocated");
            unsafe {
                self.push_free(order, block);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::alloc::Layout;

    use super::*;
    use crate::test_page_allocator;

    struct TestContext {
        memory: *mut u8,
        layout: Layout,
        num_pages_free_at_end: usize,
    }

    fn setup_allocator() -> (TestContext, BuddyPageAllocator) {
        let page_size = PageSize::FourKiB;
        let total_pages = 512;
        let total_size = total_pages * page_size;
        let layout = Layout::from_size_align(total_size, usize::from(page_size)).unwrap();
        let memory = unsafe { std::alloc::alloc(layout) };
        assert!(!memory.is_null());

        let allocator = unsafe {
            let a = BuddyPageAllocator::new(page_size, memory, total_size);
            assert!(a.add_memory_region(memory, total_size));
            a
        };

        (
            TestContext {
                memory,
                layout,
                num_pages_free_at_end: total_pages,
            },
            allocator,
        )
    }

    fn setup_allocator_with_gap() -> (TestContext, BuddyPageAllocator) {
        let page_size = PageSize::FourKiB;
        let total_pages = 513;
        let total_size = total_pages * page_size;
        let layout = Layout::from_size_align(total_size, usize::from(page_size)).unwrap();
        let memory = unsafe { std::alloc::alloc(layout) };
        assert!(!memory.is_null());

        let allocator = unsafe {
            let a = BuddyPageAllocator::new(page_size, memory, total_size);
            assert!(a.add_memory_region(memory, 256 * page_size));
            assert!(a.add_memory_region(memory.add(page_size * 257), 256 * page_size));
            a
        };

        (
            TestContext {
                memory,
                layout,
                // since one page will be reserved, it will remain unfree
                num_pages_free_at_end: total_pages - 1,
            },
            allocator,
        )
    }

    fn cleanup_allocator(cx: TestContext, allocator: BuddyPageAllocator) {
        // every page should be free at the end
        assert_eq!(allocator.total_pages_free(), cx.num_pages_free_at_end);
        unsafe {
            std::alloc::dealloc(cx.memory, cx.layout);
        }
    }

    test_page_allocator!(BuddyPageAllocator, setup_allocator, cleanup_allocator);
    test_page_allocator!(
        BuddyPageAllocatorWithGap,
        setup_allocator_with_gap,
        cleanup_allocator
    );

    #[test]
    fn real_world_4gib() {
        let page_size = PageSize::FourKiB;
        let four_gb = 0x1_0000_0000;
        let layout = Layout::from_size_align(four_gb, usize::from(page_size)).unwrap();
        let memory = unsafe { std::alloc::alloc(layout) };
        assert!(!memory.is_null());

        let reserved_regions = unsafe {
            [
                (memory.add(0x100_0000), 0x41bb90),
                (memory.add(0xbeef_c000), 0x2000),
            ]
        };

        let allocator = unsafe { BuddyPageAllocator::<16>::new(page_size, memory, four_gb) };

        for (start, len) in subtract_ranges((memory, four_gb), reserved_regions.into_iter()) {
            unsafe {
                assert!(
                    allocator.add_memory_region(start, len),
                    "add memory region {start:x?} : {len}"
                );
            }
        }
    }
}
