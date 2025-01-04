//! Policy for spawning the `init` process at boot.

use alloc::vec::Vec;
use kernel_api::{ImageSection, ImageSectionKind, PrivilegeLevel, ProcessCreateInfo};
use log::{debug, trace};
use snafu::{ResultExt, Snafu};
use tar_no_std::TarArchiveRef;

use crate::{
    memory::{PageSize, PhysicalPointer},
    process::{ProcessManager, ProcessManagerError},
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
        source: ProcessManagerError,
    },
    /// Error occurred parsing the init process binary file.
    Binary {
        /// Underlying cause.
        source: elf::ParseError,
    },
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
    page_size: PageSize,
) -> Result<(), SpawnInitError> {
    let init_ramdisk_data =
        unsafe { core::slice::from_raw_parts(init_ramdisk_ptr.into(), init_ramdisk_len) };

    let archive = TarArchiveRef::new(init_ramdisk_data)
        .map_err(|reason| SpawnInitError::InitrdArchive { reason })?;

    match archive
        .entries()
        .inspect(|e| trace!("initrd entry: {:?}", e))
        .find(|e| e.filename().as_str().is_ok_and(|f| f == init_exec_name))
    {
        Some(e) => {
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
                privilege_level: PrivilegeLevel::Driver,
            };
            debug!("init image = {info:?}");
            let init_process = proc_man.spawn_process(None, &info).context(ProcessSnafu)?;
            debug!("spawned init process #{}", init_process.id);
            Ok(())
        }
        None => {
            panic!("could not find init binary \"{init_exec_name}\" in ram disk");
        }
    }
}
