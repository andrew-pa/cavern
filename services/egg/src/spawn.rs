use alloc::{string::String, vec::Vec};
use kernel_api::{
    ErrorCode, ImageSection, ImageSectionKind, PrivilegeLevel, ProcessCreateInfo, ProcessId,
    QueueId, read_env_value, spawn_process,
};
use snafu::{OptionExt, ResultExt, Snafu};
use tar_no_std::TarArchiveRef;

#[derive(Debug, Snafu)]
pub enum Error {
    /// File could not be found in initramfs.
    #[snafu(display("Failed to find \"{name}\" in initramfs"))]
    FileNotFound {
        /// Name of file searched for.
        name: String,
    },
    /// Failed to parse ELF binary
    ElfParse {
        /// Underlying error
        source: elf::ParseError,
    },
    /// System call returned an error.
    #[snafu(display("System call failed: {cause}"))]
    SysCall {
        /// Message
        cause: String,
        /// Underlying error code
        source: ErrorCode,
    },
}

/// Returns the page base and offset for an address.
/// For example, if the page size was 0x1000 then an address `0xaaaa_abbb` would
/// become `(0xaaaa_a000, 0xbbb)`
pub fn split(page_size: usize, addr: impl Into<usize>) -> (usize, usize) {
    let addr: usize = addr.into();
    let mask = page_size - 1;
    (addr & !mask, addr & mask)
}

pub fn spawn_root_process(
    initramfs: &TarArchiveRef,
    name: &str,
) -> Result<(ProcessId, QueueId), Error> {
    let entry = initramfs
        .entries()
        .find(|e| e.filename().as_str().is_ok_and(|n| n == name))
        .context(FileNotFoundSnafu { name })?;

    let bin = elf::ElfBytes::<'_, elf::endian::LittleEndian>::minimal_parse(entry.data())
        .context(ElfParseSnafu)?;

    let page_size = read_env_value(kernel_api::EnvironmentValue::PageSizeInBytes);

    let sections = bin
        .segments()
        .expect("binary has segments")
        .iter()
        // only consider PT_LOAD=1 segments
        .filter(|segment| segment.p_type == 1)
        .map(|segment| {
            let (base_address, data_offset) = split(page_size, segment.p_vaddr as usize);
            let data = bin.segment_data(&segment).context(ElfParseSnafu)?;
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

    let self_pid =
        ProcessId::new(read_env_value(kernel_api::EnvironmentValue::CurrentProcessId) as u32)
            .unwrap();

    let info = ProcessCreateInfo {
        entry_point: bin.ehdr.e_entry as usize,
        num_sections: sections.len(),
        sections: sections.as_ptr(),
        supervisor: Some(self_pid),
        privilege_level: PrivilegeLevel::Driver,
        notify_on_exit: false,
        inbox_size: 256,
    };

    spawn_process(&info).context(SysCallSnafu {
        cause: "spawn process",
    })
}
