//! Processes (and threads).
use alloc::{sync::Arc, vec::Vec};

pub mod thread;
use snafu::{ResultExt, Snafu};
use spin::RwLock;
pub use thread::{Id as ThreadId, Thread};

use crate::memory::{
    page_table::MemoryProperties, AddressSpaceId, AddressSpaceIdPool, PageAllocator, PageTables,
    VirtualAddress,
};

/// A unique id for a process.
pub type Id = crate::collections::Handle;

/// The largest possible process ID in the system.
pub const MAX_PROCESS_ID: Id = Id::new(0xffff).unwrap();

/// The type of a image section.
pub enum ImageSectionKind {
    /// Immutable data.
    ReadOnly,
    /// Mutable data.
    ReadWrite,
    /// Executable program code.
    Executable,
}

impl ImageSectionKind {
    /// Convert an image section kind into the necessary memory properties to map the pages of that section.
    pub fn as_properties(&self) -> MemoryProperties {
        match self {
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
}

/// A section of memory in a process image.
pub struct ImageSection<'d> {
    /// The base address in the process' address space.
    pub base_address: VirtualAddress,
    /// The total size of the section in bytes. Any bytes past the size of `data` will be zeroed.
    pub total_size: usize,
    /// The data that will be copied into the beginning of this section.
    pub data: &'d [u8],
    /// The type of section this is.
    pub kind: ImageSectionKind,
}

/// A description of a process executable image.
pub struct Image<'d> {
    /// The main entry point of the executable.
    pub entry_point: VirtualAddress,
    /// The memory sections in this executable.
    pub sections: &'d [ImageSection<'d>],
}

/// Properties describing a process
pub struct Properties {
    /// The supervisor process for this process.
    pub supervisor: Arc<Process>,
    /// The parent process that spawned this process.
    pub parent: Arc<Process>,
    /// True if this process has driver-level access to the kernel.
    pub is_driver: bool,
    /// True if this process is privileged (can send messages outside of its supervisor).
    pub is_privileged: bool,
    /// True if this process is a supervisor.
    /// Child processes spawned by this process will have it as their supervisor, rather than inheriting this process' supervisor.
    pub is_supervisor: bool,
}

/// A user-space process.
pub struct Process {
    /// The id of this process.
    pub id: Id,

    /// Immutable properties for this process.
    pub props: Properties,

    /// The threads running in this process.
    pub threads: RwLock<Vec<Arc<Thread>>>,

    /// The page tables that map this process' virtual memory space.
    pub page_tables: RwLock<PageTables<'static>>,

    /// The current address space ID and its generation.
    pub address_space_id: RwLock<(Option<AddressSpaceId>, u32)>,
}

impl Process {
    /// Create a new process object.
    pub fn new(
        allocator: &'static dyn PageAllocator,
        id: Id,
        props: Properties,
        image: &[ImageSection],
    ) -> Result<Self, ProcessManagerError> {
        // setup the process' memory space
        let mut page_tables = PageTables::empty(allocator).context(MemorySnafu)?;

        for section in image {
            // compute the size of the section
            let size_in_pages = section.total_size.div_ceil(allocator.page_size().into());
            // allocate memory
            let memory = allocator.allocate(size_in_pages).context(MemorySnafu)?;
            // copy the data / zero the remainder
            let ptr: *mut u8 = memory.cast().into();
            unsafe {
                core::ptr::copy_nonoverlapping(section.data.as_ptr(), ptr, section.data.len());
                if section.data.len() < section.total_size {
                    core::ptr::write_bytes(
                        ptr.add(section.data.len()),
                        0,
                        section.total_size - section.data.len(),
                    );
                }
            }
            // map it into the process
            page_tables
                .map(
                    section.base_address,
                    memory,
                    size_in_pages,
                    crate::memory::page_table::MapBlockSize::Page,
                    &section.kind.as_properties(),
                )
                .context(PageTablesSnafu)?;
        }

        Ok(Self {
            id,
            props,
            threads: RwLock::default(),
            page_tables: RwLock::new(page_tables),
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
}

/// An interface for managing processes and threads.
pub trait ProcessManager {
    /// Spawn a new process.
    fn spawn_process(
        &self,
        image: &Image,
        properties: Properties,
    ) -> Result<Arc<Process>, ProcessManagerError>;

    /// Spawn a new thread with the given parent process.
    fn spawn_thread(
        &self,
        parent_process: Arc<Process>,
        entry_point: VirtualAddress,
    ) -> Result<Arc<Thread>, ProcessManagerError>;

    /// Kill a process.
    fn kill_process(&self, process: Arc<Process>) -> Result<(), ProcessManagerError>;

    /// Kill a thread.
    fn kill_thread(&self, thread: Arc<Thread>) -> Result<(), ProcessManagerError>;

    /// Get the thread associated with a thread ID.
    fn thread_for_id(
        &self,
        thread_id: ThreadId,
    ) -> Result<Option<Arc<Thread>>, ProcessManagerError>;

    /// Get the process associated with a process ID.
    fn process_for_id(&self, process_id: Id) -> Result<Option<Arc<Process>>, ProcessManagerError>;
}
