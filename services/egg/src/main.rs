//! The "egg" bootstrap service is the first spawned process and starts the rest of the system.
//! This requires it to have a few somewhat disjoint responsibilities:
//! - providing a service to interact with the initial RAM disk passed from the kernel as a file system
//! - spawning the root resource registry process, root supervisor process and log redistributor
//! - starting various core drivers based on the device tree blob passed from the kernel
//! - spawning the supervisors for the rest of user space
#![no_std]
#![no_main]
#![deny(missing_docs)]
#![allow(clippy::cast_possible_truncation)]

use bytemuck::{Contiguous, Pod, Zeroable};
use kernel_api::{
    ErrorCode, KERNEL_FAKE_PID, exit_current_thread, flags::ReceiveFlags, receive, write_log,
};

// heap
// async?
// RPC
// initramfs parse
// config
// spawn processes from initramfs directly (parse elf)
// device tree

#[derive(Debug, Pod, Zeroable, Clone, Copy)]
#[repr(C)]
struct InitMessage {
    initramfs_address: usize,
    initramfs_length: usize,
    device_tree_address: usize,
    device_tree_length: usize,
}

fn main() -> Result<(), ErrorCode> {
    write_log(3, "egg boot start")?;
    let init_msg = receive(ReceiveFlags::empty())?;
    assert_eq!(init_msg.header().sender_pid, KERNEL_FAKE_PID);
    let init: &InitMessage = bytemuck::from_bytes(init_msg.payload());
    assert!(init.initramfs_address > 0);
    assert!(init.initramfs_length > 0);
    assert!(init.device_tree_address > 0);
    assert!(init.device_tree_length > 0);
    Ok(())
}

/// The main entry point.
///
/// # Panics
/// Right now we panic if any errors happen.
#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    match main() {
        Ok(()) => exit_current_thread(0),
        Err(e) => {
            exit_current_thread(e.into_integer() as u32);
        }
    }
}

/// The panic handler.
#[panic_handler]
pub fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    let _ = write_log(1, "panic!");
    exit_current_thread(1);
}
