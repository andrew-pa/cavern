//! Kernel configuration in `bootargs`.
use serde::Deserialize;

/// Kernel configuration in `bootargs`.
#[derive(Deserialize, Debug)]
pub struct Config<'a> {
    /// Maximum level to output in logs.
    pub log_level: log::LevelFilter,

    /// Filename in the init ramdisk of the `init` process.
    pub init_exec_name: &'a str,
}

impl Default for Config<'_> {
    fn default() -> Self {
        Self {
            log_level: log::LevelFilter::Trace,
            init_exec_name: "egg",
        }
    }
}
