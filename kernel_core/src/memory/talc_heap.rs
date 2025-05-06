//! Definitions for using Talc as the kernel Rust heap implementation.

use core::alloc::Layout;

use log::{error, trace};
use spin::once::Once;
use talc::{OomHandler, Span};

use super::PageAllocator;

/// Talc OOM handler that uses a page allocator to allocate more pages for the heap.
pub struct PageAllocOnOom<'pa, PA: PageAllocator> {
    page_allocator: &'pa Once<PA>,
}

const MIN_PAGES_ALLOCATED: usize = 16;

impl<PA: PageAllocator> OomHandler for PageAllocOnOom<'_, PA> {
    fn handle_oom(talc: &mut talc::Talc<Self>, layout: Layout) -> Result<(), ()> {
        let pa = talc.oom_handler.page_allocator.get().ok_or(())?;
        let num_pages = layout
            .size()
            .div_ceil(pa.page_size().into())
            .max(MIN_PAGES_ALLOCATED);
        match pa.allocate(num_pages) {
            Ok(mem) => {
                trace!("expanding Rust heap {num_pages} @ {mem:?}");
                let base = mem.cast().into();
                unsafe {
                    talc.claim(Span::new(base, base.byte_add(pa.page_size() * num_pages)))?;
                }
                Ok(())
            }
            Err(err) => {
                error!(
                    "failed to allocate new memory for kernel Rust heap: {}",
                    snafu::Report::from_error(err)
                );
                Err(())
            }
        }
    }
}

/// The global allocator type.
pub type GlobalAllocator<PA> = talc::Talck<spin::Mutex<()>, PageAllocOnOom<'static, PA>>;

/// Create a new global allocator that provides a heap backed by memory allocated by the kernel.
#[must_use]
pub const fn init_allocator<PA: PageAllocator>(
    page_allocator: &'static Once<PA>,
) -> GlobalAllocator<PA> {
    talc::Talc::new(PageAllocOnOom { page_allocator }).lock()
}
