//! Standard system timer driver.

use bitfield::bitfield;
use core::arch::asm;
use kernel_core::{
    exceptions::{interrupt, InterruptController, InterruptId},
    platform::{
        device_tree::{
            iter::NodePropertyIter, ParseError, PropertyNotFoundSnafu, UnexpectedValueSnafu,
        },
        timer::SystemTimer,
    },
};
use log::{debug, trace};
use snafu::{ensure, OptionExt};

/// Write timer value register (`CNTP_TVAL_EL0`).
///
/// # Safety
/// This will change the system register that stores the current timer value.
/// This may cause the timer interrupt to be triggered if it is enabled, and is globally visible.
unsafe fn write_timer_value(timer_value: u32) {
    asm!("msr CNTP_TVAL_EL0, {cv:x}", cv = in(reg) timer_value);
}

/// Read timer counter frequency register (`CNTFRQ_EL0`).
fn frequency() -> u32 {
    let mut freq: u32;
    unsafe {
        asm!("mrs {val:x}, CNTFRQ_EL0", val = out(reg) freq);
    }
    freq
}

bitfield! {
    struct TimerControlRegister(u64);
    impl Debug;
    u8;
    istatus, _: 2;
    imask, set_imask: 1;
    enable, set_enable: 0;
}

impl TimerControlRegister {
    /// Read the timer control register (`CNTP_CTL_EL0`).
    fn read() -> TimerControlRegister {
        let mut ctrl: u64;
        unsafe {
            asm!("mrs {ctrl}, CNTP_CTL_EL0", ctrl = out(reg) ctrl);
        }
        TimerControlRegister(ctrl)
    }

    /// Write the timer control register (`CNTP_CTL_EL0`) with this value.
    ///
    /// # Safety
    /// This function will write the system register that controls the timer, which could have
    /// unintended consequences if the kernel is not ready for timer interrupts.
    unsafe fn write(&self) {
        asm!("msr CNTP_CTL_EL0, {ctrl}", ctrl = in(reg) self.0);
    }
}

/// A list of device tree `compatible` strings (see section 2.3.1 of the spec) that this driver is compatible with.
const COMPATIBLE: &[&[u8]] = &[b"arm,armv7-timer", b"arm,armv8-timer"];

/// The system timer interface.
///
/// This interface is implicitly per-CPU, so it does not need to be synchronized.
#[derive(Debug)]
pub struct Timer {
    int_id: InterruptId,
    int_config: interrupt::Config,
    reset_value: u32,
}

impl Timer {
    /// Create a timer instance using the properties found in the device tree node, and configure
    /// its interrupt with the interrupt controller.
    /// The timer will trigger every `1 / interval` seconds.
    ///
    /// # Errors
    /// Returns an error if the device tree node does not contain the correct properties to
    /// describe a timer.
    pub fn in_device_tree<'dt>(
        node: NodePropertyIter<'dt>,
        intc: &impl InterruptController,
        interval: u32,
    ) -> Result<Self, ParseError<'dt>> {
        let mut int = None;

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
                    debug!("Timer compatible device: {strings:?}");
                }
                b"interrupts" => {
                    let interrupts_blob = value.as_bytes(name)?;
                    let i = intc.interrupt_in_device_tree(interrupts_blob, 1).context(
                        UnexpectedValueSnafu {
                            name,
                            value,
                            reason: "expected interrupt #1 to exist",
                        },
                    )?;
                    int = Some(i);
                }
                _ => {}
            }
        }

        let (id, trigger_mode) = int.context(PropertyNotFoundSnafu { name: "interrupts" })?;

        let s = Self {
            int_id: id,
            int_config: interrupt::Config {
                priority: 0,
                mode: trigger_mode,
            },
            reset_value: frequency() / interval,
        };

        debug!("configured system timer: {s:?}");

        intc.configure(id, &s.int_config);

        Ok(s)
    }

    /// Initialize the system timer for the current core.
    // NOTE: you've gotta call this for every CPU because the timer itself is per-CPU
    // this is kinda strange, b/c it should really be in the mech trait
    pub fn start_for_core(&self, intc: &impl InterruptController) {
        let mut ctl = TimerControlRegister::read();
        ctl.set_enable(true);
        ctl.set_imask(false);
        unsafe {
            ctl.write();
            write_timer_value(0);
        }
        intc.enable(self.int_id);
        trace!("system timer started");
    }
}

impl SystemTimer for Timer {
    fn interrupt_id(&self) -> kernel_core::exceptions::InterruptId {
        self.int_id
    }

    fn reset(&self) {
        unsafe {
            write_timer_value(self.reset_value);
        }
    }
}
