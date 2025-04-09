//! Driver for ARM Generic Interrupt Controller version 2.
//!
//! # Reference Documentation
//! - `GICv2` specification: <https://developer.arm.com/documentation/ihi0048>
//! - Device tree node: [Linux Kernel Documentation](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/devicetree/bindings/interrupt-controller/arm,gic.yaml)

use byteorder::{BigEndian, ByteOrder};
use kernel_core::{
    exceptions::interrupt::{Config, Controller, Id, TriggerMode},
    memory::PhysicalAddress,
    platform::device_tree::{
        iter::NodePropertyIter, ParseError, PropertyNotFoundSnafu, UnexpectedValueSnafu,
    },
};
use log::{debug, trace};
use snafu::{ensure, OptionExt as _};
use spin::Mutex;

pub struct GenericV2 {
    distributor_base: Mutex<*mut u32>,
    cpu_base: *mut u32,
}

/// SAFETY: The GIC CPU registers which are unprotected are actually unique for each core, so they
/// do not need to be synchronized.
unsafe impl Send for GenericV2 {}
unsafe impl Sync for GenericV2 {}

/// A list of device tree `compatible` strings (see section 2.3.1 of the spec) that this driver is compatible with.
const COMPATIBLE: &[&[u8]] = &[
    b"arm,arm11mp-gic" as &[u8],
    b"arm,cortex-a15-gic",
    b"arm,cortex-a7-gic",
    b"arm,cortex-a5-gic",
    b"arm,cortex-a9-gic",
    b"arm,eb11mp-gic",
    b"arm,gic-400",
    b"arm,pl390",
    b"arm,tc11mp-gic",
    b"qcom,msm-8660-qgic",
    b"qcom,msm-qgic2",
];

impl GenericV2 {
    /// Create the GIC driver from configuration found in the device tree.
    pub fn in_device_tree(node: NodePropertyIter) -> Result<Self, ParseError> {
        let mut found_marker_property = false;
        let mut dist_base = PhysicalAddress::null();
        let mut cpu_base = PhysicalAddress::null();

        for (name, value) in node {
            match name {
                b"compatible" => {
                    let strings = value.as_strings(name)?;
                    // make sure that the driver is compatible with the device
                    ensure!(
                        strings.iter().any(|model_name| COMPATIBLE
                            .iter()
                            .any(|supported_model_name| model_name.to_bytes()
                                == *supported_model_name)),
                        UnexpectedValueSnafu {
                            name,
                            value,
                            reason: "incompatible"
                        }
                    );
                    debug!("GICv2 compatible device: {strings:?}");
                }
                b"#interrupt-cells" => {
                    let n = value.as_bytes(name)?;
                    ensure!(
                        n.len() == 4 && n[3] == 3,
                        UnexpectedValueSnafu {
                            name,
                            value,
                            reason: "driver supports GICv2 with #interrupt-cells=3 only"
                        }
                    );
                }
                b"interrupt-controller" => {
                    found_marker_property = true;
                }
                b"reg" => {
                    let registers = value.as_reg(name)?;
                    let mut regs = registers.iter();
                    let (dist_base_raw, _) = regs.next().with_context(|| UnexpectedValueSnafu {
                        name,
                        value: value.clone(),
                        reason: "distributor register region to be present",
                    })?;
                    dist_base = dist_base_raw.into();
                    let (cpu_base_raw, _) = regs.next().with_context(|| UnexpectedValueSnafu {
                        name,
                        value: value.clone(),
                        reason: "cpu register region to be present",
                    })?;
                    cpu_base = cpu_base_raw.into();
                }
                _ => {}
            }
        }

        // per spec this property must be present, check for sanity
        ensure!(
            found_marker_property,
            PropertyNotFoundSnafu {
                name: "interrupt-controller"
            }
        );

        // make sure we found the register base addresses
        ensure!(
            !dist_base.is_null(),
            PropertyNotFoundSnafu {
                name: "distributor base address"
            }
        );
        ensure!(
            !cpu_base.is_null(),
            PropertyNotFoundSnafu {
                name: "CPU base address"
            }
        );

        Ok(Self {
            distributor_base: Mutex::new(dist_base.cast().into()),
            cpu_base: cpu_base.cast().into(),
        })
    }
}

fn id_to_bit_offset(id: Id) -> (usize, u32) {
    ((id / 32) as usize, (id % 32))
}

/// Set the bit flag of `register` for the interrupt `id` high.
unsafe fn write_bit_for_id(interface: *mut u32, register: usize, id: Id) {
    let (word_offset, bit_offset) = id_to_bit_offset(id);
    let ptr = interface.add(register).add(word_offset);
    trace!(
        "writing GIC register bit 0x{:x} for id={id} (byte=0x{word_offset:x}, bit={bit_offset})",
        ptr as usize
    );
    ptr.write_volatile(1 << bit_offset);
}

/// Set the byte of `register` for interrupt `id`.
unsafe fn write_byte_for_id(interface: *mut u32, register: usize, id: Id, value: u8) {
    trace!("writing GIC register byte {interface:x?}+{register:x} for id={id}, value={value:x}");
    interface
        .add(register)
        .cast::<u8>()
        .add(id as usize)
        .write_volatile(value);
}

impl Controller for GenericV2 {
    /// Prepare the controller for handling interrupts generally.
    fn global_initialize(&self) {
        let dist_base = self.distributor_base.lock();
        debug!("Initializing GICv2 Distributor @ {dist_base:x?}");
        unsafe {
            dist_base.add(dist_regs::CTLR).write_volatile(0b11);
        }
    }

    /// Prepare the controller for handling interrupts for the current core.
    fn initialize_for_core(&self) {
        debug!("Initializing GICv2 CPU interface @ {:x?}", self.cpu_base);
        unsafe {
            // bit 0: enable group 1 interrupts
            self.cpu_base
                .add(cpu_regs::CTLR)
                .write_volatile(0b0000_0000_0000_0011);

            // Set minimum priority to lowest possible.
            self.cpu_base.add(cpu_regs::PMR).write_volatile(0xff);

            // Disable group priority bits.
            // TODO: Why was this necessary?
            // self.cpu_base.add(cpu_regs::BPR).write_volatile(0x00);
        }
    }

    fn interrupt_in_device_tree(&self, data: &[u8], index: usize) -> Option<(Id, TriggerMode)> {
        if (index + 1) * 12 > data.len() {
            return None;
        }

        let d = &data[index * 12..(index + 1) * 12];
        let first_cell = BigEndian::read_u32(&d[0..4]);
        let second_cell = BigEndian::read_u32(&d[4..8]);
        let flags = d[11];

        let id = match first_cell {
            0 => {
                // SPI interrupt
                // defined in device tree as 0-987, mapped to interrupt ids 32-1019
                32 + second_cell
            }
            1 => {
                // PPI interrupt
                // defined in device tree as 0-15, mapped to interrupt ids 16-31
                16 + second_cell
            }
            _ => return None,
        };

        let trigger_mode = match flags {
            0b0001 | 0b0010 => TriggerMode::Edge,
            0b0100 | 0b1000 => TriggerMode::Level,
            _ => return None,
        };

        Some((id, trigger_mode))
    }

    fn configure(&self, id: Id, config: &Config) {
        debug!("configuring interrupt {id} {config:?}");
        let distributor_base = self.distributor_base.lock();
        unsafe {
            write_byte_for_id(
                *distributor_base,
                dist_regs::IPRIORITYR_N,
                id,
                config.priority,
            );

            // for now, make sure that all CPUs recieve this interrupt.
            write_byte_for_id(*distributor_base, dist_regs::ITARGETSR_N, id, 0xff);
        }
    }

    fn enable(&self, id: Id) {
        debug!("enable interrupt {id}");
        let distributor_base = self.distributor_base.lock();
        unsafe {
            write_bit_for_id(*distributor_base, dist_regs::ISENABLER_N, id);
        }
    }

    fn disable(&self, id: Id) {
        debug!("disable interrupt {id}");
        let distributor_base = self.distributor_base.lock();
        unsafe {
            write_bit_for_id(*distributor_base, dist_regs::ICENABLER_N, id);
        }
    }

    fn clear_pending(&self, id: Id) {
        let distributor_base = self.distributor_base.lock();
        unsafe {
            write_bit_for_id(*distributor_base, dist_regs::ICPENDR_N, id);
        }
    }

    fn ack_interrupt(&self) -> Option<Id> {
        let id = unsafe { self.cpu_base.add(cpu_regs::IAR).read_volatile() };
        if id == INTID_NONE_PENDING {
            None
        } else {
            Some(id)
        }
    }

    fn finish_interrupt(&self, id: Id) {
        unsafe {
            self.cpu_base.add(cpu_regs::EOIR).write_volatile(id);
        }
    }

    fn broadcast_sgi(&self, sgi_id: u8) {
        // 0b01 = Forward to all but the requester.
        let v = SoftwareGeneratedInterruptRegister::new(0b01, 0, sgi_id);
        let dist = self.distributor_base.lock();
        unsafe {
            dist.add(dist_regs::SGIR).write_volatile(v.0);
        }
    }
}

bitfield::bitfield! {
    struct SoftwareGeneratedInterruptRegister(u32);
    impl Debug;
    impl new;
    u8, target_list_filter, set_target_list_filter: 25, 24;
    u8, cpu_target_list, set_cpu_target_list: 23, 16;
    u8, sgi_id, set_sgi_id: 3, 0;
}

/// Register offsets for the GIC distributor (relative to its base address, by u32s).
///
/// In the specification, these are named `GICD_*`.
#[allow(unused, missing_docs)]
mod dist_regs {
    pub const CTLR: usize = 0x0000 >> 2;
    pub const TYPER: usize = 0x0004 >> 2;
    pub const STATUSR: usize = 0x0010 >> 2;
    pub const SETSPI_NSR: usize = 0x0040 >> 2;
    pub const CLRSPI_NSR: usize = 0x0048 >> 2;
    pub const SETSPI_SR: usize = 0x0050 >> 2;
    pub const CLRSPI_SR: usize = 0x0058 >> 2;
    pub const IGROUPR_N: usize = 0x0080 >> 2;
    pub const ISENABLER_N: usize = 0x0100 >> 2;
    pub const ICENABLER_N: usize = 0x0180 >> 2;
    pub const ISPENDR_N: usize = 0x0200 >> 2;
    pub const ICPENDR_N: usize = 0x0280 >> 2;
    pub const ISACTIVER_N: usize = 0x0300 >> 2;
    pub const ICACTIVER_N: usize = 0x0380 >> 2;
    pub const IPRIORITYR_N: usize = 0x0400 >> 2;
    pub const ITARGETSR_N: usize = 0x0800 >> 2;
    pub const ICFGR_N: usize = 0x0c00 >> 2;
    pub const IGRPMOD_N: usize = 0x0d00 >> 2;
    pub const SGIR: usize = 0x0f00 >> 2;
    pub const CPENDSGIR_N: usize = 0x0f10 >> 2;
    pub const SPENDSGIR_N: usize = 0x0f20 >> 2;
    pub const INMIR: usize = 0x0f80 >> 2;
}

/// Register offsets for the GIC CPU interface (relative to its base address, by u32s).
///
/// In the specification, these are named `GICC_*`.
#[allow(unused, missing_docs)]
mod cpu_regs {
    pub const CTLR: usize = 0x000 >> 2;
    pub const PMR: usize = 0x0004 >> 2;
    pub const BPR: usize = 0x008 >> 2;
    pub const IAR: usize = 0x000c >> 2;
    pub const EOIR: usize = 0x0010 >> 2;
    pub const RPR: usize = 0x0014 >> 2;
    pub const HPPIR: usize = 0x0018 >> 2;
    pub const ABPR: usize = 0x001c >> 2;
    pub const AIAR: usize = 0x0020 >> 2;
    pub const AEOIR: usize = 0x0024 >> 2;
    pub const AHPPIR: usize = 0x0028 >> 2;
    pub const STATUSR: usize = 0x002c >> 2;
    pub const APR_N: usize = 0x00d0 >> 2;
    pub const NSAPR_N: usize = 0x00e0 >> 2;
    pub const IIDR: usize = 0x00fc >> 2;
    pub const DIR: usize = 0x1000 >> 2;
}

/// Interupt ID that represents no interrupt pending.
const INTID_NONE_PENDING: Id = 1023;
