use crate::{Error, RegistrySnafu, SupervisorSnafu, config::Config};
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use device_tree::{DeviceTree, fdt::Token};
use hashbrown::HashMap;
use kernel_api::{ThreadId, write_log};
use snafu::ResultExt;
use user_core::interfaces::{
    registry::{Path, RegistryClient},
    supervisor::{ExitPolicy, ProcessSpec, SupervisorClient, SupervisorConfig},
};

/// The setup worker state.
pub struct Setup<'c, 'dt> {
    pub registry: RegistryClient,
    pub supervisor: SupervisorClient,
    pub config: Config<'c>,
    pub device_tree_blob: DeviceTree<'dt>,
    pub initramfs_service_thread: ThreadId,
}

impl Setup<'_, '_> {
    async fn spawn_drivers_for_devices_in_dtb(&self) -> Result<(), Error> {
        let compat_index: HashMap<&[u8], (&Path, usize)> = self
            .config
            .drivers
            .iter()
            .flat_map(|d| {
                d.compatible
                    .iter()
                    .enumerate()
                    .map(|(i, c)| (*c, d.binary, i))
            })
            // retain only the most specific driver for any particular compatible string
            .fold(HashMap::new(), |mut m, (compat, bin_path, i)| {
                m.entry(compat.as_bytes())
                    .and_modify(|v| {
                        if i < v.1 {
                            *v = (bin_path, i);
                        }
                    })
                    .or_insert((bin_path, i));
                m
            });

        let results = process_root_children(
            &self.device_tree_blob,
            |name, compat| {
                if compat.split(|b| *b == b',').any(|c| compat_index.contains_key(c)) {
                    true
                } else {
                    write_log(2, &format!("no compatible driver for device {} (compatible: {})!", String::from_utf8_lossy(name), String::from_utf8_lossy(compat))).unwrap();
                    false
                }
            },
            |name, tokens, compat| {
                let (driver_path, driver_compat) =
                    compat.split(|b| *b == b',').find_map(|c| compat_index.get(c).map(|(p,_)| (*p, c)))
                    .expect("node was checked");
                let name_str = String::from_utf8_lossy(name).to_string();
                write_log(3, &format!("using driver {driver_path} for device {} (device compatible: {}, driver compatible: {})", name_str, String::from_utf8_lossy(compat), String::from_utf8_lossy(driver_compat))).unwrap();
                // encode tokens into init parameter
                let init_param = postcard::to_allocvec(&tokens).unwrap();
                async move {
                    self.supervisor
                        .spawn(&ProcessSpec {
                            bin_path: driver_path,
                            exit_policy: None,
                            init_parameter: Some(&init_param),
                        })
                    .await
                        .with_context(|_| SupervisorSnafu {
                            what: format!("spawn driver process {driver_path} for device {name_str}"),
                        })
                }
            },
        )
        .await;

        for res in results {
            if let Err(e) = res {
                write_log(
                    1,
                    &format!("driver launch failed: {}", snafu::Report::from_error(e)),
                )
                .unwrap();
            }
        }

        Ok(())
    }

    /// Spawn and configure the root system services and drivers.
    pub async fn setup(self) -> Result<(), Error> {
        // Configure the root supervisor default exit policy
        self.supervisor
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
        self.registry
            .register_provider(self.config.initramfs_root, self.initramfs_service_thread)
            .await
            .context(RegistrySnafu {
                what: "register initramfs provider with root registry",
            })?;

        // Spawn log redistributor via root supervisor
        self.supervisor
            .spawn(&ProcessSpec {
                bin_path: self.config.binaries.log_redistributor,
                exit_policy: None,
                init_parameter: None,
            })
            .await
            .context(SupervisorSnafu {
                what: "spawn log redistributor in root supervisor",
            })?;

        // Spawn drivers
        self.spawn_drivers_for_devices_in_dtb().await?;

        // Spawn sub-supervisors
        for sup in self.config.supervisors.iter() {
            self.supervisor
                .spawn(&ProcessSpec {
                    bin_path: self.config.binaries.supervisor,
                    exit_policy: None,
                    init_parameter: todo!(),
                })
                .await
                .with_context(|_| SupervisorSnafu {
                    what: alloc::format!("spawn supervisor {} in root supervisor", sup.name),
                })?;
        }

        // Watch root registry, supervisor and do something if they exit (probably crash)

        Ok(())
    }
}

/// Collects all tokens (including nested ones) for a child node starting from its initial StartNode token.
/// It tracks the first encountered "compatible" property and calls the `check` closure on its value.
/// If `check` returns false, the remainder of the subtree is drained and `None` is returned,
/// signaling that the child should be skipped.
///
/// # Parameters
///
/// - `iter`: The mutable iterator over device tree tokens.
/// - `child_name`: The name of the child node (from its StartNode token).
/// - `check`: A closure to validate the "compatible" property. If it returns false, the child is not further processed.
///
/// # Returns
///
/// If processing is allowed, returns `Some((tokens, compatible))`, where:
/// - `tokens` is the vector of all tokens belonging to the child (including the initial StartNode)
/// - `compatible` is the a byte slice for the "compatible" property.
///   If `check` fails the first time the "compatible" property is encountered,
///   the function drains the rest of the subtree and returns `None`.
fn collect_child_tokens<'dt, I, F>(
    iter: &mut I,
    child_name: &'dt [u8],
    check: &mut F,
) -> Option<(Vec<Token<'dt>>, &'dt [u8])>
where
    I: Iterator<Item = Token<'dt>>,
    F: FnMut(&[u8], &[u8]) -> bool,
{
    let mut tokens = Vec::new();
    // Record the initial StartNode token for this child.
    tokens.push(Token::StartNode(child_name));

    let mut compatible = None;
    // We are within the child's scope; depth = 1 (child StartNode already seen).
    let mut depth = 1;

    while depth > 0 {
        // If the iterator unexpectedly ends, bail out.
        let token = iter.next()?;
        match token {
            Token::StartNode(_) => {
                depth += 1;
                tokens.push(token);
            }
            Token::EndNode => {
                depth -= 1;
                tokens.push(token);
            }
            Token::Property { name, data } => {
                // Look for the "compatible" property only once.
                if name == b"compatible" && compatible.is_none() {
                    compatible = Some(data);
                    // If the check function signals to skip this child, drain the rest of the subtree.
                    if !check(child_name, data) {
                        while depth > 0 {
                            if let Some(tok) = iter.next() {
                                match tok {
                                    Token::StartNode(_) => depth += 1,
                                    Token::EndNode => depth -= 1,
                                    _ => {}
                                }
                            } else {
                                break;
                            }
                        }
                        return None;
                    }
                }
                tokens.push(Token::Property { name, data });
            }
        }
    }
    Some((tokens, compatible?))
}

/// Iterates over each direct child of the device tree root node. For every child node,
/// this function collects its entire token subtree (using the helper above), while also
/// tracking the "compatible" property. When the "compatible" property is first seen, the
/// `check` closure is called; if it returns false, processing is stopped for that child.
///
/// If the child’s tokens are successfully collected, the `process` closure is called with:
///   - the child's name,
///   - the vector of collected tokens,
///   - and the optional "compatible" property value.
///
/// # Parameters
///
/// - `dt`: A reference to the device tree.
/// - `check`: A closure that is given the "compatible" property's value and returns `true` if processing should continue for that node or `false` to skip it.
/// - `process`: A closure called for each child node that is not skipped. It is passed: the child’s name, the collected tokens, and the "compatible" property.
pub async fn process_root_children<F, G, R, FR>(
    dt: &DeviceTree<'_>,
    mut check: G,
    mut process: F,
) -> Vec<R>
where
    FR: Future<Output = R>,
    F: FnMut(&[u8], Vec<Token>, &[u8]) -> FR,
    G: FnMut(&[u8], &[u8]) -> bool,
{
    let mut iter = dt.iter_structure();

    // Consume the root StartNode token.
    if let Some(Token::StartNode(_)) = iter.next() {
        // Continue processing inside the root.
    } else {
        return Vec::new();
    }

    let mut process_tasks = Vec::new();
    // Iterate over direct children of the root.
    while let Some(token) = iter.next() {
        match token {
            Token::StartNode(child_name) => {
                if let Some((child_tokens, child_compat)) =
                    collect_child_tokens(&mut iter, child_name, &mut check)
                {
                    process_tasks.push(process(child_name, child_tokens, child_compat));
                }
            }
            Token::EndNode => break,
            _ => {}
        }
    }

    futures::future::join_all(process_tasks.into_iter()).await
}
