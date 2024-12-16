//! Mechanisms for exception handling

mod handlers;
pub use handlers::install_exception_vector;

mod interrupt;

pub use interrupt::init as init_interrupts;
pub use interrupt::init_for_core as init_interrupts_for_core;
pub use interrupt::wait_for_interrupt;
pub use interrupt::CONTROLLER as INTERRUPT_CONTROLLER;

use bitfield::bitfield;

bitfield! {
    /// A system CPU exception mask (DAIF register) value.
    ///
    /// In this register, 0 is enabled and 1 is disabled.
    pub struct CpuExceptionMask(u64);
    u8;
    debug, set_debug: 9;
    sys_error, set_sys_error: 8;
    irq, set_irq: 7;
    frq, set_frq: 6;
}

#[allow(unused)]
impl CpuExceptionMask {
    /// A mask to enable all exceptions.
    pub fn all_enabled() -> CpuExceptionMask {
        CpuExceptionMask(0)
    }

    /// A mask to disable all exceptions.
    pub fn all_disabled() -> CpuExceptionMask {
        let mut s = CpuExceptionMask(0);
        s.set_debug(true);
        s.set_frq(true);
        s.set_irq(true);
        s.set_sys_error(true);
        s
    }

    /// Read the CPU exception mask register (DAIF).
    #[inline]
    pub fn read() -> CpuExceptionMask {
        let mut v: u64;
        unsafe {
            core::arch::asm!("mrs {v}, DAIF", v = out(reg) v);
        }
        CpuExceptionMask(v)
    }

    /// Write the CPU exception mask register (DAIF).
    ///
    /// # Safety
    /// The system must be ready to accept interrupts as soon as the next instruction if they are
    /// enabled.
    #[inline]
    pub unsafe fn write(self: CpuExceptionMask) {
        core::arch::asm!("msr DAIF, {v}", v = in(reg) self.0);
    }
}
