use crate::{
    Error, RegistrySnafu, SupervisorSnafu,
    config::{Config, DriverConfig},
};
use alloc::vec::Vec;
use hashbrown::HashMap;
use kernel_api::ThreadId;
use snafu::ResultExt;
use user_core::interfaces::{
    registry::{Path, RegistryClient},
    supervisor::{ExitPolicy, ProcessSpec, SupervisorClient, SupervisorConfig},
};

async fn spawn_drivers_for_devices_in_dtb(
    supervisor: &SupervisorClient,
    drivers: &[DriverConfig<'_>],
) -> Result<(), Error> {
    let compat_index: HashMap<&str, (&Path, usize)> = drivers
        .iter()
        .flat_map(|d| {
            d.compatible
                .iter()
                .enumerate()
                .map(|(i, c)| (*c, d.binary, i))
        })
        // retain only the most specific driver for any particular compatible string
        .fold(HashMap::new(), |mut m, (compat, bin_path, i)| {
            m.entry(compat)
                .and_modify(|v| {
                    if i < v.1 {
                        *v = (bin_path, i);
                    }
                })
                .or_insert((bin_path, i));
            m
        });
    todo!()
}

/// Spawn and configure the root system services and drivers.
pub async fn setup(
    registry: RegistryClient,
    supervisor: SupervisorClient,
    config: &Config<'_>,
    initramfs_service_thread: ThreadId,
) -> Result<(), Error> {
    // Configure the root supervisor default exit policy
    supervisor
        .configure(&SupervisorConfig {
            default_exit_policy: ExitPolicy::Restart {
                max_attempts: None,
                delay_ms: 0,
            },
            children: Vec::new(),
        })
        .await
        .context(SupervisorSnafu {
            what: "configure root supervisor with default exit policy",
        })?;

    // Register the initramfs service with the registry
    registry
        .register_provider(config.initramfs_root, initramfs_service_thread)
        .await
        .context(RegistrySnafu {
            what: "register initramfs provider with root registry",
        })?;

    // Spawn log redistributor via root supervisor
    supervisor
        .spawn(&ProcessSpec {
            bin_path: config.binaries.log_redistributor,
            exit_policy: None,
            init_parameter: None,
        })
        .await
        .context(SupervisorSnafu {
            what: "spawn log redistributor in root supervisor",
        })?;

    // Spawn drivers
    spawn_drivers_for_devices_in_dtb(&supervisor, &config.drivers).await?;

    // Spawn sub-supervisors

    // Watch root registry, supervisor and do something if they exit (probably crash)

    Ok(())
}
