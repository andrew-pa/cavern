//! Processes (and threads).

use core::fmt::Debug;

use alloc::{string::String, sync::Arc, vec::Vec};

use kernel_api::{
    flags::SharedBufferFlags, ExitReason, ImageSectionKind, MessageHeader, PrivilegeLevel,
    SharedBufferInfo, MESSAGE_BLOCK_SIZE,
};
use log::trace;
use queue::{PendingMessage, QueueManager};
use snafu::{ensure, OptionExt, ResultExt, Snafu};
use spin::{Mutex, RwLock};

pub mod system_calls;
pub mod thread;
use thread::ThreadManager;
pub use thread::{Id as ThreadId, Thread};
pub mod queue;
pub use queue::{Id as QueueId, MessageQueue};

use crate::{
    collections::HandleMap,
    memory::{
        page_table::{MapBlockSize, MemoryProperties},
        AddressSpaceId, AddressSpaceIdPool, FreeListAllocator, PageAllocator, PageSize, PageTables,
        PhysicalAddress, VirtualAddress,
    },
};

/// A unique id for a process.
pub type Id = crate::collections::Handle;

/// The largest possible process ID in the system.
pub const MAX_PROCESS_ID: Id = Id::new(0xffff).unwrap();

/// A unique id for a shared buffer (scoped to a single process).
pub type SharedBufferId = crate::collections::Handle;

/// The largest possible shared buffer ID in the system.
pub const MAX_SHARED_BUFFER_ID: Id = Id::new(0xffff).unwrap();

/// A section of memory in a process image.
#[derive(Clone)]
pub struct ImageSection<'a> {
    /// The base address in the process' address space. This must be page aligned.
    pub base_address: VirtualAddress,
    /// Offset from the base address where the `data` will be copied to. Any bytes between the
    /// start and the offset will be zeroed.
    pub data_offset: usize,
    /// The total size of the section in bytes (including the `data_offset` bytes).
    /// Any bytes past the size of `data` will be zeroed.
    pub total_size: usize,
    /// The data that will be copied into the section.
    pub data: &'a [u8],
    /// The type of section this is.
    pub kind: ImageSectionKind,
}

impl Debug for ImageSection<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ImageSection")
            .field("base_address", &self.base_address)
            .field("data_offset", &self.data_offset)
            .field("total_size", &self.total_size)
            .field("data.len()", &self.data.len())
            .field("kind", &self.kind)
            .finish()
    }
}

/// Parameters for creating a new process.
#[derive(Debug, Clone)]
pub struct ProcessCreateInfo<'a> {
    /// The process image sections that will be loaded into the new process.
    pub sections: &'a [ImageSection<'a>],
    /// The new process' supervisor queue, or None to inherit.
    pub supervisor: Option<QueueId>,
    /// The new process' registry queue, or None to inherit.
    pub registry: Option<QueueId>,
    /// The new process' privilege level (must be less than or equal to the current privilege level).
    pub privilege_level: PrivilegeLevel,
    /// The size of this process' message inbox, in message blocks.
    pub inbox_size: usize,
}

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

/// Copy the data for an image section into memory allocated for the process, with the correct offset.
/// Any leftover bytes in the section (before/after the data) will be zeroed.
///
/// # Safety
/// - `memory` must point to writable memory of size `section.total_size.div_ceil(page_size)` pages.
/// - `section` must be valid, with `section.data` pointing to `section.data_size` bytes.
unsafe fn copy_image_section_data_to_process_memory(
    section: &ImageSection,
    memory: PhysicalAddress,
) {
    let dest_ptr: *mut u8 = memory.cast().into();
    if section.data_offset > 0 {
        core::ptr::write_bytes(dest_ptr, 0, section.data_offset);
    }
    core::ptr::copy_nonoverlapping(
        section.data.as_ptr(),
        dest_ptr.byte_add(section.data_offset),
        section.data.len(),
    );
    if section.data.len() + section.data_offset < section.total_size {
        core::ptr::write_bytes(
            dest_ptr.byte_add(section.data_offset + section.data.len()),
            0,
            section.total_size - (section.data.len() + section.data_offset),
        );
    }
}

/// Properties describing a process
pub struct Properties {
    /// The inherited queue ID for communicating with this process' assigned supervisor.
    ///
    /// None means that this process is the root process (of which there should only be one).
    pub supervisor_queue: Option<QueueId>,

    /// The inherited queue ID for communicating with this process' assigned registry.
    ///
    /// None means that this process is the root process (of which there should only be one).
    pub registry_queue: Option<QueueId>,

    /// Level of privilege this process has.
    pub privilege: PrivilegeLevel,
}

/// A buffer shared from an owner process to a borrower process.
#[derive(Debug)]
pub struct SharedBuffer {
    /// The source process that this buffer's memory is owned by.
    pub owner: Arc<Process>,
    /// Flags defining the properties of this buffer.
    pub flags: SharedBufferFlags,
    /// The base address of the buffer in the owner process' address space.
    pub base_address: VirtualAddress,
    /// Length of the buffer in bytes.
    pub length: usize,
}

/// Errors that can arise during shared buffer operations.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum TransferError {
    /// The transfer is outside the bounds of the buffer.
    OutOfBounds,
    /// The buffer was not shared with the correct permissions for the transfer.
    InsufficentPermissions,
    /// An error occured making the copy into the owner's address space.
    PageTables {
        /// Underlying cause of the error.
        source: crate::memory::page_table::Error,
    },
}

impl SharedBuffer {
    /// Copies the bytes in `src` into this buffer, starting at `offset`.
    /// The buffer must have the [`SharedBufferFlags::WRITE`] flag set.
    ///
    /// # Errors
    /// Returns an error if the copy would go out of bounds or forbidden by the sender.
    pub fn transfer_to(&self, offset: usize, src: &[u8]) -> Result<(), TransferError> {
        // Check that the shared buffer permits writes.
        ensure!(
            self.flags.contains(SharedBufferFlags::WRITE),
            transfer_error::InsufficentPermissionsSnafu
        );

        // Check that the transfer lies within the buffer bounds.
        ensure!(
            offset
                .checked_add(src.len())
                .is_some_and(|end| end <= self.length),
            transfer_error::OutOfBoundsSnafu
        );

        // Compute the destination virtual address in the owner’s address space.
        let dest = self.base_address.byte_add(offset);

        // Use the owner's page tables to copy the data.
        let pt = self.owner.page_tables.read();
        unsafe { pt.copy_to_while_unmapped(dest, src) }.context(transfer_error::PageTablesSnafu)
    }

    /// Copies bytes from the buffer starting at `offset` into `dst`.
    /// The buffer must have the [`SharedBufferFlags::READ`] flag set.
    ///
    /// # Errors
    /// Returns an error if the copy would go out of bounds or forbidden by the sender.
    pub fn transfer_from(&self, offset: usize, dst: &mut [u8]) -> Result<(), TransferError> {
        // Check that the shared buffer permits reads.
        ensure!(
            self.flags.contains(SharedBufferFlags::READ),
            transfer_error::InsufficentPermissionsSnafu
        );

        // Check that the requested transfer is within the bounds of the buffer.
        ensure!(
            offset
                .checked_add(dst.len())
                .is_some_and(|end| end <= self.length),
            transfer_error::OutOfBoundsSnafu
        );

        // Compute the source virtual address in the owner’s address space.
        let src_addr = self.base_address.byte_add(offset);

        // Use the owner's page tables to copy the data.
        let pt = self.owner.page_tables.read();
        unsafe { pt.copy_from_while_unmapped(src_addr, dst) }
            .context(transfer_error::PageTablesSnafu)
    }
}

/// A user-space process.
pub struct Process {
    /// The id of this process.
    pub id: Id,

    /// Immutable properties for this process.
    pub props: Properties,

    /// The threads running in this process.
    /// The first thread is the designated receiver thread.
    pub threads: RwLock<Vec<Arc<Thread>>>,

    /// The page tables that map this process' virtual address space.
    pub page_tables: RwLock<PageTables<'static>>,

    /// Allocator for pages in the process' virtual address space.
    pub address_space_allocator: Mutex<FreeListAllocator>,

    /// The current address space ID and its generation.
    pub address_space_id: RwLock<(Option<AddressSpaceId>, u32)>,

    /// Allocator for message blocks in this process' inbox.
    pub inbox_allocator: Mutex<FreeListAllocator>,

    /// Message queues that are owned by this process.
    pub owned_queues: Mutex<Vec<Arc<MessageQueue>>>,

    /// Buffers that have been shared with this process from other processes.
    pub shared_buffers: HandleMap<SharedBuffer>,

    /// Threads/processes that will be notified when this process exits.
    pub exit_subscribers: Mutex<Vec<Arc<MessageQueue>>>,
}

impl Process {
    /// Create a new process object and sets up the process' virtual memory space using the `image`.
    ///
    /// The `inbox_size` is in units of message blocks.
    ///
    /// # Errors
    /// Returns an error if allocating physical memory for the process fails, or if a page table
    /// mapping operation is invalid.
    pub fn new(
        allocator: &'static impl PageAllocator,
        id: Id,
        props: Properties,
        image: &[ImageSection],
        inbox_size: usize,
    ) -> Result<Self, ManagerError> {
        trace!("creating new process object #{id}");

        let mut page_tables = PageTables::empty(allocator).context(MemorySnafu {
            cause: "create new page tables for process",
        })?;
        let page_size = allocator.page_size();
        let mut virt_alloc = Self::init_address_space_allocator(page_size);

        Self::map_image_sections(
            allocator,
            &mut page_tables,
            &mut virt_alloc,
            image,
            page_size,
        )?;
        let (inbox_start, inbox_alloc) = Self::setup_inbox(
            allocator,
            &mut page_tables,
            &mut virt_alloc,
            inbox_size,
            page_size,
        )?;

        trace!("process page tables: {page_tables:?}");

        Ok(Self {
            id,
            props,
            threads: RwLock::default(),
            page_tables: RwLock::new(page_tables),
            address_space_allocator: Mutex::new(virt_alloc),
            address_space_id: RwLock::default(),
            inbox_allocator: Mutex::new(inbox_alloc),
            owned_queues: Mutex::default(),
            shared_buffers: HandleMap::new(MAX_SHARED_BUFFER_ID),
            exit_subscribers: Mutex::default(),
        })
    }

    fn init_address_space_allocator(page_size: PageSize) -> FreeListAllocator {
        FreeListAllocator::new(
            VirtualAddress::null().byte_add(page_size.into()),
            0x0000_ffff_ffff_ffff / page_size,
            page_size.into(),
        )
    }

    fn map_image_sections(
        allocator: &impl PageAllocator,
        page_tables: &mut PageTables<'static>,
        virt_alloc: &mut FreeListAllocator,
        image: &[ImageSection],
        page_size: PageSize,
    ) -> Result<(), ManagerError> {
        for section in image {
            let size_in_pages = section.total_size.div_ceil(page_size.into());
            let memory = allocator
                .allocate(size_in_pages)
                .with_context(|_| MemorySnafu {
                    cause: alloc::format!(
                        "allocate memory for image section {section:?} ({size_in_pages} pages)"
                    ),
                })?;
            unsafe {
                copy_image_section_data_to_process_memory(section, memory);
            }
            let props = image_section_kind_as_properties(&section.kind);
            trace!(
                "mapping setion {section:x?} to {memory:?}, # pages = {size_in_pages}, properties = {props:?}"
            );
            page_tables
                .map(
                    section.base_address,
                    memory,
                    size_in_pages,
                    MapBlockSize::Page,
                    &props,
                )
                .context(PageTablesSnafu)?;
            virt_alloc
                .reserve_range(section.base_address, size_in_pages)
                .context(MemorySnafu {
                    cause: "reserve image section in process virtual address space allocator",
                })?;
        }
        Ok(())
    }

    fn setup_inbox(
        allocator: &impl PageAllocator,
        page_tables: &mut PageTables<'static>,
        virt_alloc: &mut FreeListAllocator,
        inbox_size: usize,
        page_size: PageSize,
    ) -> Result<(VirtualAddress, FreeListAllocator), ManagerError> {
        let inbox_size_in_pages = (inbox_size * MESSAGE_BLOCK_SIZE).div_ceil(page_size.into());
        let inbox_start = virt_alloc
            .alloc(inbox_size_in_pages)
            .with_context(|_| MemorySnafu {
                cause: alloc::format!(
                    "allocate virtual addresses for process inbox, size {inbox_size_in_pages}"
                ),
            })?
            .start;
        let inbox_memory = allocator
            .allocate(inbox_size_in_pages)
            .context(MemorySnafu {
                cause: "allocate physical pages for process inbox",
            })?;
        trace!(
            "process inbox at {inbox_start:?}, {inbox_size_in_pages} pages; at {inbox_memory:?}"
        );
        page_tables
            .map(
                inbox_start,
                inbox_memory,
                inbox_size_in_pages,
                MapBlockSize::Page,
                &MemoryProperties {
                    user_space_access: true,
                    writable: true,
                    ..Default::default()
                },
            )
            .context(PageTablesSnafu)?;
        Ok((
            inbox_start,
            FreeListAllocator::new(inbox_start, inbox_size, MESSAGE_BLOCK_SIZE),
        ))
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

    /// Map physical memory into the process' address space, returning the new virtual address of the memory.
    ///
    /// # Errors
    /// Returns an error if the virtual addresses in the process' address space cannot be allocated, or if a page mapping operation fails.
    fn map_arbitrary(
        &self,
        base_addr: PhysicalAddress,
        size_in_pages: usize,
        props: &MemoryProperties,
    ) -> Result<VirtualAddress, ManagerError> {
        let virt_addr = self
            .address_space_allocator
            .lock()
            .alloc(size_in_pages)
            .context(MemorySnafu {
                cause: "allocate virtual addresses",
            })?
            .start;
        self.page_tables
            .write()
            .map(
                virt_addr,
                base_addr,
                size_in_pages,
                MapBlockSize::Page,
                props,
            )
            .context(PageTablesSnafu)?;
        Ok(virt_addr)
    }

    /// Allocate new memory in the process' virtual memory space, and back it with physical pages.
    ///
    /// Warning! The `page_allocator` must be the same as the one used to create the process, but
    /// this is currently not enforced!
    ///
    /// # Errors
    /// Returns an error if the physical memory cannot be allocated, the virtual addresses in the
    /// process' address space cannot be allocated, or if a page mapping operation fails.
    pub fn allocate_memory(
        &self,
        page_allocator: &impl PageAllocator,
        size_in_pages: usize,
        mut properties: MemoryProperties,
    ) -> Result<VirtualAddress, ManagerError> {
        let phys_addr = page_allocator
            .allocate(size_in_pages)
            .context(MemorySnafu {
                cause: "allocate physical pages",
            })?;
        // let the page tables own this memory so that it is freed when the process is dropped.
        properties.owned = true;
        self.map_arbitrary(phys_addr, size_in_pages, &properties)
    }

    /// Map a region of physical memory into this process' address space without transferring
    /// ownership to the process.
    ///
    /// # Safety
    /// This is only safe if the physical memory will remain valid for the process to access (ie allocated) until
    /// it is unmapped or the process exits.
    /// This is mostly important if the memory is RAM allocated by the kernel, otherwise it is less
    /// of an issue (ie device memory should be fine).
    ///
    /// # Errors
    /// Returns an error if the virtual addresses in the process' address space cannot be allocated, or if a page mapping operation fails.
    pub fn map_borrowed_memory(
        &self,
        base_addr: PhysicalAddress,
        size_in_pages: usize,
        props: &MemoryProperties,
    ) -> Result<VirtualAddress, ManagerError> {
        assert!(!props.owned);
        self.map_arbitrary(base_addr, size_in_pages, props)
    }

    /// Free previously allocated memory in the process' virtual memory space, including the
    /// backing physical pages. The `base_address` must have been returned by a call to
    /// `allocate_memory` with exactly `size_in_pages`.
    ///
    /// Warning! The `page_allocator` must be the same as the one used to create the process, but
    /// this is currently not enforced!
    ///
    /// # Errors
    /// Returns an error if the physical pages or virtual addresses cannot be freed, or if a page
    /// mapping operation fails.
    pub fn free_memory(
        &self,
        page_allocator: &impl PageAllocator,
        base_address: VirtualAddress,
        size_in_pages: usize,
    ) -> Result<(), ManagerError> {
        let paddr = self
            .page_tables
            .read()
            .physical_address_of(base_address)
            .ok_or(crate::memory::page_table::Error::NotMapped {
                address: base_address,
            })
            .context(PageTablesSnafu)?;
        trace!("freeing {base_address:?} = {paddr:?}, {size_in_pages} pages");
        self.page_tables
            .write()
            .unmap(base_address, size_in_pages, MapBlockSize::Page)
            .context(PageTablesSnafu)?;
        page_allocator
            .free(paddr, size_in_pages)
            .context(MemorySnafu {
                cause: "free physical pages",
            })?;
        self.address_space_allocator
            .lock()
            .free(base_address, size_in_pages)
            .context(MemorySnafu {
                cause: "free virtual addresses",
            })?;
        Ok(())
    }

    /// Insert a message into this process' inbox, returning the [`PendingMessage`] that can be
    /// enqueued.
    ///
    /// The message will never be received unless the [`PendingMessage`] is added to some
    /// [`MessageQueue`]. See [`MessageQueue::send_message`].
    ///
    /// # Errors
    /// Returns an error if the message could not be delivered, or something goes wrong with memory
    /// or page tables.
    pub fn deliver_message(
        &self,
        message: &[u8],
        buffers: impl ExactSizeIterator<Item = Arc<SharedBuffer>>,
    ) -> Result<PendingMessage, ManagerError> {
        let payload_start =
            size_of::<MessageHeader>() + size_of::<SharedBufferInfo>() * buffers.len();
        let actual_message_size_in_bytes = message.len() + payload_start;
        // trace!("delivering message of size {actual_message_size_in_bytes} to {self:?}");

        // allocate new memory for the message in the inbox
        let ptr = {
            match self
                .inbox_allocator
                .lock()
                .alloc(actual_message_size_in_bytes.div_ceil(MESSAGE_BLOCK_SIZE))
            {
                Ok(r) => r.start,
                Err(crate::memory::Error::OutOfMemory) => {
                    return Err(ManagerError::InboxFull)
                }
                Err(e) => {
                    return Err(ManagerError::Memory {
                        cause: alloc::format!("allocate message memory in inbox, message size {actual_message_size_in_bytes}"),
                        source: e
                    })
                },
            }
        };

        // encode and write the message header to the inbox
        let mut header_enc: Vec<usize> = Vec::with_capacity(payload_start / size_of::<usize>());

        // start with the number of shared buffers
        header_enc.push(buffers.len());

        // create `SharedBufferInfo` in the header for each shared buffer
        for b in buffers {
            let flags = b.flags;
            let len = b.length;
            let handle = self
                .shared_buffers
                .insert(b)
                .context(OutOfHandlesSnafu)?
                .get() as usize;
            // encode a `SharedBufferInfo`
            // TODO: this is messy/brittle
            header_enc.push(handle << 32 | flags.bits() as usize);
            header_enc.push(len);
        }

        unsafe {
            // SAFETY: Since we just allocated this memory using the inbox_allocator we know it is safe to copy to.
            let pt = self.page_tables.read();
            // copy the header into the inbox
            pt.copy_to_while_unmapped(ptr, bytemuck::cast_slice(header_enc.as_slice()))
                .context(PageTablesSnafu)?;
            // copy the message into the inbox
            pt.copy_to_while_unmapped(ptr.byte_add(payload_start), message)
                .context(PageTablesSnafu)?;
        }

        Ok(PendingMessage {
            data_address: ptr,
            data_length: actual_message_size_in_bytes,
        })
    }

    /// Frees a message from the inbox.
    ///
    /// # Errors
    /// Returns an error if the memory could not be freed.
    pub fn free_message(&self, ptr: VirtualAddress, len: usize) -> Result<(), ManagerError> {
        self.inbox_allocator
            .lock()
            .free(ptr, len.div_ceil(MESSAGE_BLOCK_SIZE))
            .context(MemorySnafu {
                cause: "free inbox memory",
            })
    }

    /// Free a group of shared buffers by id. After calling this method, all ids passed to it
    /// are invalid. All ids will be processed even if one is already freed.
    ///
    /// # Errors
    /// - `Missing` if one or more buffers was already freed.
    pub fn free_shared_buffers(
        &self,
        buffers: impl Iterator<Item = SharedBufferId>,
    ) -> Result<(), ManagerError> {
        let mut not_found = false;

        for buffer in buffers {
            not_found = self.shared_buffers.remove(buffer).is_none() || not_found;
        }

        ensure!(
            !not_found,
            MissingSnafu {
                cause: "a buffer handle was not found"
            }
        );

        Ok(())
    }
}

impl core::fmt::Debug for Process {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "<Process #{}>", self.id)
    }
}

/// Errors arising from [`ProcessManager`], [`ThreadManager`] or [`QueueManager`] operations.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ManagerError {
    /// An error occurred during a memory operation.
    #[snafu(display("Memory error: {cause}"))]
    Memory {
        /// A string containing more information about what caused the error.
        cause: String,
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

    /// The process' inbox is full.
    InboxFull,

    /// An `Option` was `None`.
    #[snafu(display("Encountered `None` value: {cause}"))]
    Missing {
        /// The source of the `None` option.
        cause: &'static str,
    },
}

/// An interface for managing processes.
#[cfg_attr(test, mockall::automock)]
pub trait ProcessManager {
    /// Spawn a new process. This does *not* create a main thread!
    ///
    /// # Errors
    /// Returns an error if the process could not be spawned due to resource requirements or
    /// invalid inputs.
    #[allow(clippy::elidable_lifetime_names)]
    fn spawn_process<'a>(
        &self,
        parent: Option<Arc<Process>>,
        info: &ProcessCreateInfo<'a>,
    ) -> Result<Arc<Process>, ManagerError>;

    /// Kill a process.
    /// The process must not have any threads or owned queues, ie the caller must exit them first.
    ///
    /// Killing a process must be infailable.
    fn kill_process(&self, process: &Arc<Process>, reason: ExitReason);

    /// Get the process associated with a process ID.
    fn process_for_id(&self, process_id: Id) -> Option<Arc<Process>>;
}

/// Helper to entirely kill a thread, making sure to clean up the rest of the process if it was the last
/// one, cascading the exit.
pub fn kill_thread_entirely(
    pm: &impl ProcessManager,
    tm: &impl ThreadManager,
    qm: &impl QueueManager,
    thread: &Arc<Thread>,
    reason: ExitReason,
) {
    // that was the last thread, so we need to kill the entire process
    let parent = thread.parent.clone();
    if tm.exit_thread(thread, reason) {
        if let Some(parent) = parent {
            // Make a copy of the queues in the process. Freeing the queue will remove it from the parent process.
            let queues = parent.owned_queues.lock().clone();
            for qu in queues {
                qm.free_queue(&qu);
            }
            pm.kill_process(&parent, reason);
        }
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use core::ptr;
    use kernel_api::{ImageSectionKind, MessageHeader, ProcessId};
    use std::{
        sync::{Arc, LazyLock},
        vec::Vec,
    };

    use test_case::test_case;

    use crate::{
        memory::{tests::MockPageAllocator, PageAllocator as _, PageSize, VirtualAddress},
        process::{ImageSection, MessageQueue, QueueId},
    };

    use super::{
        thread::{ProcessorState, State},
        ManagerError, Process, Properties, Thread, ThreadId,
    };

    /// "Global" page allocator.
    pub static PAGE_ALLOCATOR: LazyLock<MockPageAllocator> =
        LazyLock::new(|| MockPageAllocator::new(PageSize::FourKiB, 2048));

    /// Create a new test process using the "global" allocator.
    pub fn create_test_process(
        pid: ProcessId,
        props: Properties,
        tid: ThreadId,
    ) -> Result<Arc<Process>, ManagerError> {
        let proc = Arc::new(Process::new(&*PAGE_ALLOCATOR, pid, props, &[], 8)?);
        let thread = Arc::new(Thread::new(
            tid,
            Some(proc.clone()),
            State::Running,
            ProcessorState::new_for_user_thread(VirtualAddress::null(), VirtualAddress::null(), 0),
            (VirtualAddress::null(), 0),
        ));
        proc.threads.write().push(thread);
        Ok(proc)
    }

    #[test]
    fn create_process() {
        let proc = create_test_process(
            ProcessId::new(1).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Driver,
            },
            ThreadId::new(1).unwrap(),
        )
        .map_err(|e| snafu::Report::from_error(e))
        .unwrap();
        assert_eq!(proc.threads.read().len(), 1);
    }

    #[test]
    fn send_message() {
        let proc = create_test_process(
            ProcessId::new(1).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Driver,
            },
            ThreadId::new(1).unwrap(),
        )
        .expect("create process");

        let qu = MessageQueue::new(QueueId::new(1).unwrap(), &proc);

        let message = b"Hello, world!!";

        qu.send(message, core::iter::empty()).expect("send message");

        let msg = qu.receive().unwrap();
        assert_eq!(msg.data_length, message.len() + size_of::<MessageHeader>());

        let mut message_data_check = [0u8; 14];
        unsafe {
            proc.page_tables
                .read()
                .copy_from_while_unmapped(
                    msg.data_address.byte_add(size_of::<MessageHeader>()),
                    &mut message_data_check,
                )
                .unwrap();
        }
        assert_eq!(&message_data_check, message);
    }

    // Parameterized tests covering a mix of offsets and sizes.
    #[test_case(0, 10, 10; "Exact copy with no padding")]
    #[test_case(4, 6, 10; "Leading zeros only (offset > 0, no trailing)")]
    #[test_case(0, 6, 10; "Trailing zeros only (data_size < total_size)")]
    #[test_case(2, 3, 10; "Both leading and trailing padding")]
    #[test_case(10, 0, 10; "Offset equal to total_size, no data copied")]
    #[test_case(0, 0, 10; "No offset and no data: entire region zeroed")]
    #[test_case(5, 0, 8; "Nonzero offset, no data, trailing zeros")]
    #[test_case(3, 4, 8; "Data in the middle with trailing zeros")]
    fn test_copy_image_section(data_offset: usize, data_size: usize, total_size: usize) {
        // For simplicity, restrict total_size to one page.
        let page_size: usize = PageSize::FourKiB.into();
        assert!(
            total_size <= page_size,
            "For these tests total_size must be <= one page ({} bytes)",
            page_size
        );

        // Create test data of length `data_size` with a simple pattern.
        let test_data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();

        // Allocate one page using our mock allocator.
        let memory = PAGE_ALLOCATOR.allocate(1).expect("Allocation failed");

        // Fill the destination region with a known nonzero value.
        unsafe {
            let dest_ptr: *mut u8 = memory.cast().into();
            ptr::write_bytes(dest_ptr, 0xAA, total_size);
        }

        // Construct an ImageSection for testing.
        let section = ImageSection {
            base_address: VirtualAddress::null(), // Not used in the copy function.
            data_offset,
            total_size,
            data: &test_data,
            kind: ImageSectionKind::ReadOnly,
        };

        // Perform the copy. SAFETY: We have allocated a region that is large enough and writable.
        unsafe {
            crate::process::copy_image_section_data_to_process_memory(&section, memory);
        }

        // Read back the destination memory.
        let mut result = vec![0u8; total_size];
        unsafe {
            let dest_ptr: *mut u8 = memory.cast().into();
            ptr::copy_nonoverlapping(dest_ptr, result.as_mut_ptr(), total_size);
        }

        // Verify that the region before the data offset is zero.
        for i in 0..data_offset.min(total_size) {
            assert_eq!(result[i], 0, "Byte {} (before data copy) should be zero", i);
        }

        // Verify that the copied region contains the expected data.
        let copy_end = (data_offset + data_size).min(total_size);
        for i in data_offset..copy_end {
            let expected = test_data[i - data_offset];
            assert_eq!(result[i], expected, "Byte {} in copied region mismatch", i);
        }

        // Verify that any trailing bytes are zero.
        if data_offset + data_size < total_size {
            for i in (data_offset + data_size)..total_size {
                assert_eq!(result[i], 0, "Byte {} after copied data should be zero", i);
            }
        }

        // Free the allocated memory.
        PAGE_ALLOCATOR.free(memory, 1).expect("Free failed");
    }

    /// A dedicated test that uses a full page.
    #[test]
    fn test_copy_image_section_full_page() {
        let page_size: usize = PageSize::FourKiB.into();
        let total_size = page_size;
        let data_offset = 100;
        let data_size = total_size - data_offset;
        let test_data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();

        let memory = PAGE_ALLOCATOR.allocate(1).expect("Allocation failed");

        // Initialize destination memory with a distinct pattern.
        unsafe {
            let dest_ptr: *mut u8 = memory.cast().into();
            ptr::write_bytes(dest_ptr, 0xBB, total_size);
        }

        let section = ImageSection {
            base_address: VirtualAddress::null(),
            data_offset,
            total_size,
            data: &test_data,
            kind: ImageSectionKind::ReadOnly,
        };

        unsafe {
            crate::process::copy_image_section_data_to_process_memory(&section, memory);
        }

        let mut result = vec![0u8; total_size];
        unsafe {
            let dest_ptr: *mut u8 = memory.cast().into();
            ptr::copy_nonoverlapping(dest_ptr, result.as_mut_ptr(), total_size);
        }

        // Verify that the first `data_offset` bytes are zero.
        for i in 0..data_offset {
            assert_eq!(result[i], 0, "Byte {} (before data copy) should be zero", i);
        }
        // Verify that the remaining bytes match the test data.
        for i in data_offset..total_size {
            let expected = test_data[i - data_offset];
            assert_eq!(result[i], expected, "Byte {} in copied region mismatch", i);
        }

        PAGE_ALLOCATOR.free(memory, 1).expect("Free failed");
    }
}
