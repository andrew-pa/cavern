//! Client interface for the ARM Power State Coordination Interface (PSCI).
//!
//! API Reference: <https://developer.arm.com/documentation/den0022>
//!
//! Device Tree Reference: <https://www.kernel.org/doc/Documentation/devicetree/bindings/arm/psci.txt>

use byteorder::{BigEndian, ByteOrder};
use kernel_core::memory::PhysicalAddress;
use kernel_core::platform::cpu::{Id as CpuId, PowerManager, PowerManagerError};
use kernel_core::platform::device_tree::{
    DeviceTree, NodeNotFoundSnafu, ParseError, PropertyNotFoundSnafu,
};
use log::{error, trace, warn};
use snafu::OptionExt;

/// Convert a PSCI return value to a Rust [`Result`].
fn psci_error_code_to_result(result: i32) -> Result<(), PowerManagerError> {
    // Error codes as defined by §5.2.2.
    match result {
        0 => Ok(()),
        // InvalidParameters
        -2 => Err(PowerManagerError::InvalidCoreId),
        // AlreadyOn
        -4 => Err(PowerManagerError::AlreadyOn),
        // OnPending
        -5 => Err(PowerManagerError::Pending),
        // InvalidAddress
        -9 => Err(PowerManagerError::InvalidAddress),
        _ => {
            error!("PSCI error {result}");
            Err(PowerManagerError::Internal)
        }
    }
}

/// Method for invoking a PSCI firmware function.
#[derive(Debug)]
enum CallingMethod {
    /// Use the SMC instruction.
    Smc,
    /// Use the HVC instruction.
    Hvc,
}

/// Function ID for `CPU_ON` PSCI function.
const FUNC_ID_CPU_ON: u32 = 0xC400_0003;

/// The PSCI driver.
#[derive(Debug)]
pub struct Psci {
    /// The calling method reported by the firmware.
    calling_method: CallingMethod,
    /// The current function ID for `CPU_ON` PSCI function reported by the firmware.
    func_id_cpu_on: u32,
}

impl Psci {
    /// Create a new client using device tree information for portability.
    ///
    /// # Errors
    /// Returns an error if the device tree does not contain a `/psci` node with the correct values.
    pub fn in_device_tree<'a>(dt: &'a DeviceTree) -> Result<Self, ParseError<'a>> {
        let mut calling_method = None;
        let mut func_id_cpu_on = None;

        for (name, value) in dt
            .iter_node_properties(b"/psci")
            .context(NodeNotFoundSnafu { path: "/psci" })?
        {
            match name {
                b"method" => {
                    calling_method = match value.as_bytes(name)? {
                        b"smc\0" => Some(CallingMethod::Smc),
                        b"hvc\0" => Some(CallingMethod::Hvc),
                        _ => None,
                    };
                }
                b"cpu_on" => {
                    func_id_cpu_on = Some(BigEndian::read_u32(value.as_bytes(name)?));
                }
                _ => {}
            }
        }

        let calling_method = calling_method.context(PropertyNotFoundSnafu { name: "method" })?;

        if func_id_cpu_on.is_none() {
            warn!("PSCI device tree node did not provide CPU_ON function id");
        }

        Ok(Self {
            calling_method,
            func_id_cpu_on: func_id_cpu_on.unwrap_or(FUNC_ID_CPU_ON),
        })
    }
}

impl PowerManager for Psci {
    unsafe fn start_core(
        &self,
        target_cpu: CpuId,
        entry_point_address: PhysicalAddress,
        arg: usize,
    ) -> Result<(), PowerManagerError> {
        trace!(
            "turning CPU #{target_cpu} on! entry point = {entry_point_address:?}, arg  = 0x{arg:x}"
        );

        let entry_point: usize = entry_point_address.into();

        let result: i32;

        match self.calling_method {
            CallingMethod::Smc => core::arch::asm!(
                "mov w0, {func_id:w}",
                "mov x1, {target_cpu}",
                "mov x2, {entry_point_address}",
                "mov x3, {context_id}",
                "smc #0",
                "mov {result:w}, w0",
                func_id = in(reg) self.func_id_cpu_on,
                entry_point_address = in(reg) entry_point,
                target_cpu = in(reg) target_cpu,
                context_id = in(reg) arg,
                result = out(reg) result
            ),
            CallingMethod::Hvc => core::arch::asm!(
                "mov w0, {func_id:w}",
                "mov x1, {target_cpu}",
                "mov x2, {entry_point_address}",
                "mov x3, {context_id}",
                "hvc #0",
                "mov {result:w}, w0",
                func_id = in(reg) self.func_id_cpu_on,
                entry_point_address = in(reg) entry_point,
                target_cpu = in(reg) target_cpu,
                context_id = in(reg) arg,
                result = out(reg) result
            ),
        }

        psci_error_code_to_result(result)
    }

    fn enable_method_name() -> &'static [u8] {
        b"psci\0"
    }
}
