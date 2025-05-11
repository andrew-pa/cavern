//! Policy for spawning the `init` process at boot.

use alloc::vec::Vec;
use bytemuck::{Pod, Zeroable};
use kernel_api::{ImageSection, ImageSectionKind, PrivilegeLevel, ProcessCreateInfo};
use log::{debug, trace};
use snafu::{ResultExt, Snafu};
use tar_no_std::TarArchiveRef;

use crate::{
    memory::{page_table::MemoryProperties, PageSize, PhysicalAddress, PhysicalPointer},
    process::{queue::QueueManager, thread::ThreadManager, ManagerError, ProcessManager},
};

/// Errors that can occur while spawning the `init` process.
#[derive(Debug, Snafu)]
pub enum SpawnInitError {
    /// Error occurred trying to parse `tar` archive.
    InitrdArchive {
        /// Underlying cause.
        reason: tar_no_std::CorruptDataError,
    },
    /// Error occurred spawning the process.
    Process {
        /// Underlying cause.
        source: ManagerError,
    },
    /// Error occurred parsing the init process binary file.
    Binary {
        /// Underlying cause.
        source: elf::ParseError,
    },
}

/// Message sent to init process to communicate location of initrd and device tree blob memory.
#[derive(Debug, Pod, Zeroable, Clone, Copy)]
#[repr(C)]
struct InitMessage {
    initramfs_address: usize,
    initramfs_length: usize,
    device_tree_address: usize,
    device_tree_length: usize,
}

/// Spawn the `init` process by loading it from the initial ramdisk, parsing the binary and
/// spawning a new process with the loaded image.
///
/// # Errors
/// Returns an error if the init process is invalid or missing, or if spawning the process fails.
pub fn spawn_init_process(
    (init_ramdisk_ptr, init_ramdisk_len): (PhysicalPointer<u8>, usize),
    init_exec_name: &str,
    proc_man: &impl ProcessManager,
    thread_man: &impl ThreadManager,
    qu_man: &impl QueueManager,
    page_size: PageSize,
    (devicetree_ptr, devicetree_len): (PhysicalAddress, usize),
) -> Result<(), SpawnInitError> {
    let init_ramdisk_data =
        unsafe { core::slice::from_raw_parts(init_ramdisk_ptr.into(), init_ramdisk_len) };

    let archive = TarArchiveRef::new(init_ramdisk_data)
        .map_err(|reason| SpawnInitError::InitrdArchive { reason })?;

    let Some(e) = archive
        .entries()
        .inspect(|e| trace!("initrd entry: {e:?}"))
        .find(|e| e.filename().as_str().is_ok_and(|f| f == init_exec_name))
    else {
        panic!("could not find init binary \"{init_exec_name}\" in ram disk");
    };

    trace!("got init executable entry of size {} bytes", e.size());
    let bin: elf::ElfBytes<'_, elf::endian::LittleEndian> =
        elf::ElfBytes::minimal_parse(e.data()).context(BinarySnafu)?;

    let sections = bin
        .segments()
        .expect("init binary has segments")
        .iter()
        // only consider PT_LOAD=1 segments
        .filter(|segment| segment.p_type == 1)
        .map(|segment| {
            let (base_address, data_offset) = page_size.split(segment.p_vaddr as usize);
            let data = bin.segment_data(&segment).context(BinarySnafu)?;
            Ok(ImageSection {
                kind: match segment.p_flags {
                    0b100 => ImageSectionKind::ReadOnly,
                    0b110 => ImageSectionKind::ReadWrite,
                    0b101 | 0b001 => ImageSectionKind::Executable,
                    x => panic!("unexpected flags for program header: {x}"),
                },
                base_address,
                data_offset,
                total_size: data_offset + segment.p_memsz as usize,
                data: data.as_ptr(),
                data_size: data.len(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let info = ProcessCreateInfo {
        entry_point: bin.ehdr.e_entry as usize,
        num_sections: sections.len(),
        sections: sections.as_ptr(),
        supervisor: None,
        registry: None,
        privilege_level: PrivilegeLevel::Driver,
        notify_on_exit: false,
        inbox_size: 256,
    };
    debug!("init image = {info:?}");

    let init_process = proc_man.spawn_process(None, &info).context(ProcessSnafu)?;
    let init_queue = qu_man.create_queue(&init_process).context(ProcessSnafu)?;
    debug!(
        "spawned init process #{}, init queue #{}",
        init_process.id, init_queue.id
    );

    // setup mapping for initrd and device tree and send it to the init process
    let init_shared_memprops = MemoryProperties {
        user_space_access: true,
        writable: false,
        executable: false,
        ..Default::default()
    };
    let virt_initrd_addr = init_process
        .map_borrowed_memory(
            init_ramdisk_ptr.cast(),
            init_ramdisk_len.div_ceil(page_size.into()),
            &init_shared_memprops,
        )
        .context(ProcessSnafu)?;
    trace!("mapped init ramdisk to {virt_initrd_addr:?} in init process");
    let virt_dtb_addr = init_process
        .map_borrowed_memory(
            devicetree_ptr,
            devicetree_len.div_ceil(page_size.into()),
            &init_shared_memprops,
        )
        .context(ProcessSnafu)?;
    trace!("mapped device tree blob to {virt_dtb_addr:?} in init process");
    let init_msg = InitMessage {
        initramfs_address: virt_initrd_addr.into(),
        initramfs_length: init_ramdisk_len,
        device_tree_address: virt_dtb_addr.into(),
        device_tree_length: devicetree_len,
    };
    init_queue
        .send(bytemuck::bytes_of(&init_msg), core::iter::empty())
        .context(ProcessSnafu)?;

    // spawn the main init thread
    thread_man
        .spawn_thread(
            init_process.clone(),
            info.entry_point.into(),
            8 * 1024 * 1024 / page_size,
            init_queue.id.get() as usize,
        )
        .context(ProcessSnafu)?;

    Ok(())
}
