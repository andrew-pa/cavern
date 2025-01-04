//! Processes (and threads).
use alloc::{sync::Arc, vec::Vec};

use kernel_api::{ExitReason, ImageSection, ImageSectionKind, ProcessCreateInfo};
use log::trace;
use snafu::{OptionExt, ResultExt, Snafu};
use spin::{Mutex, RwLock};
pub use thread::{Id as ThreadId, Thread};

pub mod system_calls;
pub mod thread;

use crate::memory::{
    page_table::{MapBlockSize, MemoryProperties},
    AddressSpaceId, AddressSpaceIdPool, FreeListAllocator, PageAllocator, PageTables,
    VirtualAddress,
};

/// A unique id for a process.
pub type Id = crate::collections::Handle;

/// The largest possible process ID in the system.
pub const MAX_PROCESS_ID: Id = Id::new(0xffff).unwrap();

/// Convert an image section kind into the necessary memory properties to map the pages of that section.
#[must_use]
pub fn image_section_kind_as_properties(this: &ImageSectionKind) -> MemoryProperties {
    match this {
        ImageSectionKind::ReadOnly => MemoryProperties {
            user_space_access: true,
            writable: false,
            executable: false,
            ..MemoryProperties::default()
        },
        ImageSectionKind::ReadWrite => MemoryProperties {
            user_space_access: true,
            writable: true,
            executable: false,
            ..MemoryProperties::default()
        },
        ImageSectionKind::Executable => MemoryProperties {
            user_space_access: true,
            writable: false,
            executable: true,
            ..MemoryProperties::default()
        },
    }
}

/// Properties describing a process
pub struct Properties {
    /// The supervisor process for this process.
    pub supervisor: Option<Arc<Process>>,
    /// The parent process that spawned this process.
    pub parent: Option<Arc<Process>>,
    /// True if this process has driver-level access to the kernel.
    pub is_driver: bool,
    /// True if this process is privileged (can send messages outside of its supervisor).
    pub is_privileged: bool,
    /// Enable parent notification when this process exits.
    pub notify_parent_on_exit: bool,
}

/// A user-space process.
pub struct Process {
    /// The id of this process.
    pub id: Id,

    /// Immutable properties for this process.
    pub props: Properties,

    /// The threads running in this process.
    pub threads: RwLock<Vec<Arc<Thread>>>,

    /// The page tables that map this process' virtual address space.
    pub page_tables: RwLock<PageTables<'static>>,

    /// Allocator for pages in the process' virtual address space.
    pub address_space_allocator: Mutex<FreeListAllocator>,

    /// The current address space ID and its generation.
    pub address_space_id: RwLock<(Option<AddressSpaceId>, u32)>,
}

impl Process {
    /// Create a new process object and sets up the process' virtual memory space using the `image`.
    ///
    /// # Errors
    /// Returns an error if allocating physical memory for the process fails, or if a page table
    /// mapping operation is invalid.
    pub fn new(
        allocator: &'static impl PageAllocator,
        id: Id,
        props: Properties,
        image: &[ImageSection],
    ) -> Result<Self, ProcessManagerError> {
        trace!("creating new process object #{id}");

        // setup the process' memory space
        let mut page_tables = PageTables::empty(allocator).context(MemorySnafu)?;
        let page_size = allocator.page_size();
        // Allocate memory for the process from the entire virtual memory address space.
        let mut virt_alloc = FreeListAllocator::new(
            VirtualAddress::null(),
            0x0000_ffff_ffff_ffff / page_size,
            page_size,
        );

        for section in image {
            // compute the size of the section
            let size_in_pages = section.total_size.div_ceil(page_size.into());
            // allocate memory
            let memory = allocator.allocate(size_in_pages).context(MemorySnafu)?;
            // copy the data / zero the remainder
            let ptr: *mut u8 = memory.cast().into();
            unsafe {
                if section.data_offset > 0 {
                    core::ptr::write_bytes(ptr, 0, section.data_offset);
                }
                core::ptr::copy_nonoverlapping(
                    section.data,
                    ptr.byte_add(section.data_offset),
                    section.data_size,
                );
                if section.data_size < section.total_size {
                    core::ptr::write_bytes(
                        ptr.byte_add(section.data_offset + section.data_size),
                        0,
                        section.total_size - section.data_size,
                    );
                }
            }
            // map it into the process
            let props = image_section_kind_as_properties(&section.kind);
            trace!("mapping setion {section:?} to {memory:?}, # pages = {size_in_pages}, properties = {props:?}");
            page_tables
                .map(
                    section.base_address.into(),
                    memory,
                    size_in_pages,
                    crate::memory::page_table::MapBlockSize::Page,
                    &props,
                )
                .context(PageTablesSnafu)?;
            // reserve the range with the allocator as well
            virt_alloc
                .reserve_range(section.base_address.into(), size_in_pages)
                .context(MemorySnafu)?;
        }

        trace!("process page tables: {page_tables:?}");

        Ok(Self {
            id,
            props,
            threads: RwLock::default(),
            page_tables: RwLock::new(page_tables),
            address_space_allocator: Mutex::new(virt_alloc),
            address_space_id: RwLock::default(),
        })
    }

    /// Get or allocate an address space ID for this process.
    /// Returns true if a new generation has occured.
    pub fn get_address_space_id(&self, pool: &AddressSpaceIdPool) -> (AddressSpaceId, bool) {
        loop {
            let (asid, generation) = *self.address_space_id.read();
            if generation == pool.current_generation() {
                if let Some(i) = asid {
                    // current ASID is valid
                    return (i, false);
                }
            }
            // ASID is invalid so we need to allocate and store a new one. However only one thread
            // needs to do this, so if we don't get the lock, we'll wait for the write to finish.
            if let Some(mut asid_writer) = self.address_space_id.try_write() {
                // we can write, so allocate a new ASID
                let new = pool.allocate();
                *asid_writer = (Some(new.0), new.1);
                return (new.0, new.1 != generation);
            }
        }
    }

    /// Allocate new memory in the process' virtual memory space, and back it with physical pages.
    ///
    /// # Errors
    /// Returns an error if the physical memory cannot be allocated, the virtual addresses in the
    /// process' address space cannot be allocated, or if a page mapping operation fails.
    pub fn allocate_memory(
        &self,
        page_allocator: &'static impl PageAllocator,
        size_in_pages: usize,
        properties: &MemoryProperties,
    ) -> Result<VirtualAddress, ProcessManagerError> {
        let phys_addr = page_allocator
            .allocate(size_in_pages)
            .context(MemorySnafu)?;
        let virt_addr = self
            .address_space_allocator
            .lock()
            .alloc(size_in_pages)
            .context(MemorySnafu)?
            .start;
        self.page_tables
            .write()
            .map(
                virt_addr,
                phys_addr,
                size_in_pages,
                MapBlockSize::Page,
                properties,
            )
            .context(PageTablesSnafu)?;
        Ok(virt_addr)
    }

    /// Free previously allocated memory in the process' virtual memory space, including the
    /// backing physical pages. The `base_address` must have been returned by a call to
    /// `allocate_memory` with exactly `size_in_pages`.
    ///
    /// # Errors
    /// Returns an error if the physical pages or virtual addresses cannot be freed, or if a page
    /// mapping operation fails.
    pub fn free_memory(
        &self,
        page_allocator: &'static impl PageAllocator,
        base_address: VirtualAddress,
        size_in_pages: usize,
    ) -> Result<(), ProcessManagerError> {
        let paddr = self
            .page_tables
            .read()
            .physical_address_of(base_address)
            .context(MissingSnafu {
                cause: "virtual address does not map to a physical address",
            })?;
        page_allocator
            .free(paddr, size_in_pages)
            .context(MemorySnafu)?;
        self.page_tables
            .write()
            .unmap(base_address, size_in_pages, MapBlockSize::Page)
            .context(PageTablesSnafu)?;

        Ok(())
    }
}

/// Errors arising from [`ProcessManager`] operations.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ProcessManagerError {
    /// An error occurred during a memory operation.
    Memory {
        /// Underlying error.
        source: crate::memory::Error,
    },

    /// An error occurred during a page table operation.
    PageTables {
        /// Underlying error.
        source: crate::memory::page_table::Error,
    },

    /// The kernel has run out of handles.
    OutOfHandles,

    /// An `Option` was `None`.
    Missing {
        /// The source of the `None` option.
        cause: &'static str,
    },
}

/// An interface for managing processes and threads.
#[cfg_attr(test, mockall::automock)]
pub trait ProcessManager {
    /// Spawn a new process.
    ///
    /// # Errors
    /// Returns an error if the process could not be spawned due to resource requirements or
    /// invalid inputs.
    fn spawn_process(
        &self,
        parent: Option<Arc<Process>>,
        info: &ProcessCreateInfo,
    ) -> Result<Arc<Process>, ProcessManagerError>;

    /// Spawn a new thread with the given parent process.
    /// The `stack_size` is in pages.
    ///
    /// # Errors
    /// Returns an error if the thread could not be spawned due to resource requirements or
    /// invalid inputs.
    fn spawn_thread(
        &self,
        parent_process: Arc<Process>,
        entry_point: VirtualAddress,
        stack_size: usize,
        user_data: usize,
    ) -> Result<Arc<Thread>, ProcessManagerError>;

    /// Kill a process.
    ///
    /// # Errors
    /// TODO
    fn kill_process(&self, process: &Arc<Process>) -> Result<(), ProcessManagerError>;

    /// Cause a thread to exit, with a given `reason`.
    ///
    /// # Errors
    /// Returns an error if the thread could not be cleaned up (which should be rare).
    fn exit_thread(
        &self,
        thread: &Arc<Thread>,
        reason: ExitReason,
    ) -> Result<(), ProcessManagerError>;

    /// Get the thread associated with a thread ID.
    fn thread_for_id(&self, thread_id: ThreadId) -> Option<Arc<Thread>>;

    /// Get the process associated with a process ID.
    fn process_for_id(&self, process_id: Id) -> Option<Arc<Process>>;
}
