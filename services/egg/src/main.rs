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

extern crate alloc;
mod config;
mod initramfs;
mod setup;
mod spawn;

use alloc::{boxed::Box, string::String};
use bytemuck::{Contiguous, Pod, Zeroable};
use config::Config;
use kernel_api::{
    ErrorCode, KERNEL_FAKE_PID, ThreadId, exit_current_thread, flags::ReceiveFlags, read_env_value,
    receive, write_log,
};
use setup::Setup;
use snafu::{OptionExt, ResultExt, Snafu};
use spawn::spawn_root_process;
use tar_no_std::TarArchiveRef;
use user_core::interfaces::{registry::RegistryClient, supervisor::SupervisorClient};

#[global_allocator]
static ALLOCATOR: user_core::heap::GlobalAllocator = user_core::heap::init_allocator();

// heap
// async?
// RPC
// initramfs parse
// config
// spawn processes from initramfs directly (parse elf)
// device tree

/// The initial message sent to the service from the kernel.
#[derive(Debug, Pod, Zeroable, Clone, Copy)]
#[repr(C)]
pub struct InitMessage {
    /// Pointer to initramfs blob in service address space.
    initramfs_address: usize,
    /// Length of initramfs blob in bytes.
    initramfs_length: usize,
    /// Pointer to device tree blob in service address space.
    device_tree_address: usize,
    /// Length of device tree blob in bytes.
    device_tree_length: usize,
}

/// Errors
#[derive(Debug, Snafu)]
pub enum Error {
    /// System call returned an error.
    #[snafu(display("System call failed: {cause}"))]
    SysCall {
        /// Message
        cause: String,
        /// Underlying error code
        source: ErrorCode,
    },
    /// Initramfs failed to parse.
    #[snafu(display("Initramfs archive corrupt: {cause}"))]
    InitramfsArchive {
        /// Underlying `tar` error
        cause: tar_no_std::CorruptDataError,
    },
    /// File not found in initramfs.
    #[snafu(display("File in initramfs not found: {name}"))]
    FileNotFound {
        /// Name of file not found
        name: String,
    },
    /// Failed to parse configuration file
    ParseConfig {
        /// Underlying error
        source: serde_json_core::de::Error,
    },
    /// Failed to spawn a root process.
    #[snafu(display("Failed to spawn {name} process"))]
    SpawnRootProcess {
        /// Conceptual name of process
        name: String,
        /// Underlying error
        source: spawn::Error,
    },
    /// Registry RPC call failed.
    #[snafu(display("Registry operation {what} failed"))]
    Registry {
        /// What operation was being performed.
        what: String,
        /// The underlying error.
        source: user_core::interfaces::registry::Error,
    },
    /// Supervisor RPC call failed.
    #[snafu(display("Supervisor operation {what} failed"))]
    Supervisor {
        /// What operation was being performed.
        what: String,
        /// The underlying error.
        source: user_core::interfaces::supervisor::Error,
    },
}

fn load_config<'a>(initramfs: &'a TarArchiveRef<'_>) -> Result<Config<'a>, Error> {
    let config_file = initramfs
        .entries()
        .find(|e| e.filename().as_str().is_ok_and(|n| n == "config.json"))
        .context(FileNotFoundSnafu {
            name: "config.json",
        })?;
    serde_json_core::from_slice(config_file.data())
        .context(ParseConfigSnafu)
        .map(|(c, _)| c)
}

fn main() -> Result<(), Error> {
    write_log(3, "egg boot start").context(SysCallSnafu { cause: "write log" })?;
    let init_msg = receive(ReceiveFlags::empty()).context(SysCallSnafu {
        cause: "receive init msg",
    })?;
    assert_eq!(init_msg.header().sender_pid, KERNEL_FAKE_PID);
    let init: &InitMessage = bytemuck::from_bytes(init_msg.payload());
    assert!(init.initramfs_address > 0);
    assert!(init.initramfs_length > 0);
    assert!(init.device_tree_address > 0);
    assert!(init.device_tree_length > 0);

    let initramfs_slice =
        unsafe { core::slice::from_raw_parts(init.initramfs_address as _, init.initramfs_length) };
    // just leak this box so we can have refs from the async task to the config (the box would have only dropped in a panic anyways)
    let initramfs = Box::leak(Box::new(
        TarArchiveRef::new(initramfs_slice).map_err(|cause| Error::InitramfsArchive { cause })?,
    ));

    let device_tree_blob = unsafe {
        device_tree::DeviceTree::from_bytes(core::slice::from_raw_parts(
            init.device_tree_address as _,
            init.device_tree_length,
        ))
    };

    // Read configuration from initramfs
    let config = load_config(initramfs)?;

    // Spawn the root resource registry directly using the initramfs
    let registry_pid = spawn_root_process(initramfs, config.binaries.resource_registry).context(
        SpawnRootProcessSnafu {
            name: "root resource registry",
        },
    )?;

    // Spawn the root supervisor directly using the initramfs
    let supervisor_pid = spawn_root_process(initramfs, config.binaries.supervisor).context(
        SpawnRootProcessSnafu {
            name: "root supervisor",
        },
    )?;

    // Create the Initramfs service object
    let initramfs_service = initramfs::InitramfsService::new(initramfs.clone());

    // this is implied because `tasks::run` always runs the service on the designated receiver thread.
    let initramfs_service_thread = ThreadId::new(read_env_value(
        kernel_api::EnvironmentValue::DesignatedReceiverThreadId,
    ) as u32)
    .unwrap();

    // start the async executor, then finish setting things up
    let s = Setup {
        registry: RegistryClient::new(registry_pid, None),
        supervisor: SupervisorClient::new(supervisor_pid, None),
        config,
        device_tree_blob,
        initramfs_service_thread,
    };
    user_core::tasks::run(initramfs_service, async move {
        match s.setup().await {
            Ok(()) => {
                write_log(3, "system setup complete!").unwrap();
            }
            Err(e) => {
                panic!("system setup failed: {}", snafu::Report::from_error(e))
            }
        }
    })
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
            let s = alloc::format!("{}", snafu::Report::from_error(&e));
            let _ = write_log(1, &s);
            exit_current_thread(match e {
                Error::SysCall { source, .. } => source.into_integer() as u32 + 0x1000,
                _ => 1,
            });
        }
    }
}

/// The panic handler.
#[panic_handler]
pub fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    let _ = write_log(1, "panic!");
    if let Some(s) = info.message().as_str() {
        let _ = write_log(1, s);
    }
    exit_current_thread(1);
}
