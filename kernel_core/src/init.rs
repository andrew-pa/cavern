//! Policy for spawning the `init` process at boot.

use log::{debug, trace};
use tar_no_std::TarArchiveRef;

/// Spawn the `init` process.
pub fn spawn_init_process(init_ramdisk: &[u8]) {
    let archive = TarArchiveRef::new(init_ramdisk).expect("parse ram disk archive");
    for entry in archive.entries() {
        debug!("{entry:?}");
        trace!("{}", entry.data_as_str().unwrap());
    }
}
