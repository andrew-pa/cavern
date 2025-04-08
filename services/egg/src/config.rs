use alloc::vec::Vec;
use hashbrown::HashSet;
use serde::Deserialize;

/// Paths in initramfs that contain important binaries.
#[derive(Debug, Deserialize)]
pub struct BinariesPaths<'a> {
    /// The path of the resource registry service.
    pub resource_registry: &'a str,
    /// The path of the supervisor service.
    pub supervisor: &'a str,
    /// The path of the log redistributor service.
    pub log_redistributor: &'a str,
}

/// Configuration for a device driver.
#[derive(Debug, Deserialize)]
pub struct DriverConfig<'a> {
    /// The binary path of the driver service.
    pub binary: &'a str,
    /// The set of device tree "compatible" tags that this driver is compatible with, in order of
    /// most to least specific.
    pub compatible: Vec<&'a str>,
}

/// Configuration for a system supervisors.
#[derive(Debug, Deserialize)]
pub struct SupervisorConfig<'a> {
    /// The name of the supervisor.
    pub name: &'a str,
    /// The path (in the registry) for the configuration file directing this supervisor.
    pub config_path: &'a str,
}

/// Configuration for the `egg` service.
#[derive(Debug, Deserialize)]
pub struct Config<'a> {
    /// Path to mount initramfs at (like `/volume/init`).
    #[serde(borrow)]
    pub initramfs_root: &'a str,
    /// Paths for locating necessary binaries in initramfs.
    #[serde(borrow)]
    pub binaries: BinariesPaths<'a>,
    /// List of known drivers for Device Tree devices.
    #[serde(borrow)]
    pub drivers: Vec<DriverConfig<'a>>,
    /// List of supervisors to spawn once devices are configured.
    #[serde(borrow)]
    pub supervisors: Vec<SupervisorConfig<'a>>,
}
