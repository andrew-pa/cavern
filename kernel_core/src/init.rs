//! Policy for spawning the `init` process at boot.

use log::{debug, trace};
use tar_no_std::{TarArchiveRef, TarFormatString};

use crate::{memory::PhysicalPointer, process::ProcessManager};

/// Spawn the `init` process.
pub fn spawn_init_process(
    (init_ramdisk_ptr, init_ramdisk_len): (PhysicalPointer<u8>, usize),
    init_exec_name: &str,
    proc_man: &impl ProcessManager,
) {
    let init_ramdisk_data =
        unsafe { core::slice::from_raw_parts(init_ramdisk_ptr.into(), init_ramdisk_len) };

    let archive = TarArchiveRef::new(init_ramdisk_data).expect("parse ram disk archive");

    match archive
        .entries()
        .inspect(|e| trace!("initrd entry: {:?}", e))
        .find(|e| {
            e.filename()
                .as_str()
                .expect("init ramdisk must have UTF-8 valid names")
                == init_exec_name
        }) {
        Some(e) => {
            trace!("got init executable entry of size {} bytes", e.size());
            proc_man
                .spawn_process(todo!(), todo!())
                .expect("spawn init process");
        }
        None => {
            panic!("could not find init binary \"{init_exec_name}\" in ram disk");
        }
    }
}
