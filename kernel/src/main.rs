//! The Cavern microkernel. See `spec/kernel.md` for the specification.
//!
//! This binary is the actual kernel, containing the entry point and implementing the mechanisms
//! necessary for executing the policies defined in [`kernel_core`].
#![no_std]
#![no_main]
#![deny(missing_docs)]

extern crate alloc;

core::arch::global_asm!(core::include_str!("./start.S"));

mod exceptions;
mod logging;
mod memory;
mod psci;
mod running_image;
mod thread;
mod timer;
mod uart;

use kernel_core::{
    memory::{PhysicalAddress, PhysicalPointer},
    platform::{cpu::boot_all_cores, device_tree::DeviceTree},
};
use log::{debug, info};
use memory::page_allocator;

/// The main entry point for the kernel.
///
/// This function is called by `start.S` after it sets up virtual memory, the stack, etc.
/// The device tree blob is provided by U-Boot, see `u-boot/arch/arm/lib/bootm.c:boot_jump_linux(...)`.
///
/// # Panics
///
/// If something goes wrong during the boot process that is unrecoverable, a panic will occur.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn kmain(device_tree_blob: PhysicalPointer<u8>) -> ! {
    unsafe {
        running_image::zero_bss_section();
        exceptions::install_exception_vector();
    }

    let device_tree = unsafe { DeviceTree::from_memory(device_tree_blob.into()) };

    logging::init_logging(&device_tree);

    memory::init(&device_tree);
    thread::init();
    exceptions::init_interrupts(&device_tree);

    init_smp(&device_tree);

    info!("Boot succesful!");

    unsafe {
        exceptions::CpuExceptionMask::all_enabled().write();
    }

    loop {
        exceptions::wait_for_interrupt();
    }
}

extern "C" {
    /// The true entry point for non-boot cores. Defined in `start.S`.
    pub fn _secondary_core_start();
}

/// Initialize power control interface and boot the rest of the cores in the system.
fn init_smp(device_tree: &DeviceTree) {
    let power = psci::Psci::in_device_tree(device_tree).expect("get PSCI info from device tree");

    let entry_point_address = PhysicalAddress::from(_secondary_core_start as *mut ());

    boot_all_cores(device_tree, &power, entry_point_address, page_allocator())
        .expect("boot all cores on board");
}

/// The main entry point for secondary cores in an SMP system.
///
/// This function is called by `start.S:_secondary_core_start` after it sets up virtual memory, the stack, etc.
#[no_mangle]
pub extern "C" fn secondary_core_kmain() -> ! {
    unsafe {
        exceptions::install_exception_vector();
    }

    debug!("Secondary core init");

    exceptions::init_interrupts_for_core();

    unsafe {
        exceptions::CpuExceptionMask::all_enabled().write();
    }

    loop {
        exceptions::wait_for_interrupt();
    }
}

/// The kernel-wide panic handler.
///
/// Code here should not assume anything about the state of the kernel.
/// Currently this only writes to the platform defined debug UART.
#[panic_handler]
#[cfg(not(test))]
pub fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    // TODO: somehow make sure that if one core panics, they all halt. Probably via SGI?

    log::error!("{info}");

    /*use core::fmt::Write;
    unsafe {
        let mut uart = uart::PL011::from_platform_debug_best_guess();

        writeln!(&mut uart, "\x1b[31mpanic!\x1b[0m {info}").unwrap();
    }*/

    #[allow(clippy::empty_loop)]
    loop {}
}
