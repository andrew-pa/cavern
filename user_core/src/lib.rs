//! This crate contains useful definitions for user space services without the standard library.
#![no_std]
#![no_main]
#![deny(missing_docs)]

extern crate alloc;

use kernel_api::{EnvironmentValue, allocate_heap_pages, read_env_value, write_log};
use talc::{OomHandler, Span};

/// Talc OOM handler that expands the heap by allocating a new segment using system calls.
pub struct KernelAllocOnOom {
    next_alloc_page_count: usize,
    page_size: spin::once::Once<usize>,
}

impl KernelAllocOnOom {
    const fn new() -> Self {
        Self {
            next_alloc_page_count: 8,
            page_size: spin::once::Once::new(),
        }
    }
}

impl OomHandler for KernelAllocOnOom {
    fn handle_oom(talc: &mut talc::Talc<Self>, layout: core::alloc::Layout) -> Result<(), ()> {
        let page_size = talc
            .oom_handler
            .page_size
            .call_once(|| read_env_value(EnvironmentValue::PageSizeInBytes));
        let layout_pages_req = layout.size().div_ceil(*page_size);
        let num_pages = if talc.oom_handler.next_alloc_page_count > layout_pages_req {
            let s = talc.oom_handler.next_alloc_page_count;
            talc.oom_handler.next_alloc_page_count *= 2;
            s
        } else {
            layout_pages_req + 2
        };
        match allocate_heap_pages(num_pages) {
            Ok(mem) => {
                unsafe {
                    talc.claim(Span::new(mem, mem.byte_add(page_size * num_pages)))?;
                }
                Ok(())
            }
            Err(_) => {
                let _ = write_log(1, "failed to allocate memory");
                Err(())
            }
        }
    }
}

/// Allocator type.
pub type GlobalAllocator = talc::Talck<spin::Mutex<()>, KernelAllocOnOom>;

/// Create a new allocator.
pub const fn init_allocator() -> GlobalAllocator {
    talc::Talc::new(KernelAllocOnOom::new()).lock()
}
