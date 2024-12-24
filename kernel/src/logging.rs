//! Kernel logging mechanism.
use log::{debug, info};
use spin::once::Once;

use kernel_core::{
    logger::{GlobalValueReader, Logger},
    platform::device_tree::{DeviceTree, Value},
};

use crate::uart;

/// Implementation of [`GlobalValueReader`] that reads the real system registers.
struct SystemGlobalValueReader;

impl GlobalValueReader for SystemGlobalValueReader {
    fn read() -> kernel_core::logger::GlobalValues {
        let mut r = kernel_core::logger::GlobalValues::default();
        unsafe {
            core::arch::asm!(
                "mrs {counter}, CNTPCT_EL0",
                "mrs {core_id}, MPIDR_EL1",
                counter = out(reg) r.timer_counter,
                core_id = out(reg) r.core_id
            );
        }
        // clear multiprocessor flag bit in MPIDR register
        r.core_id &= !0x8000_0000;
        r
    }
}

/// The global kernel logger instance.
static LOGGER: Once<Logger<uart::PL011, SystemGlobalValueReader>> = Once::new();

/// Initialize the kernel global logger.
pub fn init_logging(device_tree: &DeviceTree, max_log_level: log::LevelFilter) {
    let stdout_device_path = device_tree
        .find_property(b"/chosen/stdout-path")
        .and_then(Value::into_bytes)
        // the string is null terminated in the device tree
        // TODO: default to QEMU virt board UART for now, should be platform default
        .map_or(b"/pl011@9000000" as &[u8], |p| &p[0..p.len() - 1]);

    let uart = uart::PL011::from_device_tree(device_tree, stdout_device_path).expect("init UART");

    log::set_max_level(max_log_level);
    log::set_logger(LOGGER.call_once(|| Logger::new(uart, max_log_level)) as _).unwrap();

    info!(
        "\x1b[1mCavern 🕳️\x1b[0m v{} (git: {}@{})",
        env!("CARGO_PKG_VERSION"),
        env!("VERGEN_GIT_BRANCH"),
        env!("VERGEN_GIT_SHA"),
    );

    if let Some(board_model) = device_tree
        .find_property(b"/model")
        .and_then(Value::into_string)
    {
        info!("Board model: {board_model:?}");
    }

    debug!("Build timestamp: {}", env!("VERGEN_BUILD_TIMESTAMP"));
    debug!(
        "Stdout device path: {:?}",
        core::str::from_utf8(stdout_device_path)
    );
    debug!("Kernel memory region: {:x?}", unsafe {
        crate::running_image::memory_region()
    },);
}
