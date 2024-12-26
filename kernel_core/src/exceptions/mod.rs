//! Policies and definitions for processing hardware exceptions.
//! This includes interrupts, synchronous exceptions, etc.

pub mod interrupt;
pub use interrupt::Controller as InterruptController;
pub use interrupt::Id as InterruptId;

bitfield::bitfield! {
    /// A value in the ESR (Exception Syndrome Register), which indicates the cause of an
    /// exception.
    pub struct ExceptionSyndromeRegister(u64);
    u8;
    iss2, _: 36, 32;
    /// The class of exception that occurred.
    pub u8, into ExceptionClass, ec, _: 31, 26;
    il, _: 25, 25;
    u32, iss, _: 24, 0;
}

/// An exception class, indicating what kind of synchronous exception occurred.
pub struct ExceptionClass(u8);

impl From<u8> for ExceptionClass {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

#[allow(unused)]
impl ExceptionClass {
    /// Determines if the exception is a system call.
    #[inline]
    #[must_use]
    pub fn is_system_call(&self) -> bool {
        self.0 == 0b01_0101
    }

    /// Checks if the exception is a user space data page fault.
    #[inline]
    #[must_use]
    pub fn is_user_space_data_page_fault(&self) -> bool {
        self.0 == 0b10_0100
    }

    /// Checks if the exception is a kernel data page fault.
    #[inline]
    #[must_use]
    pub fn is_kernel_data_page_fault(&self) -> bool {
        self.0 == 0b10_0101
    }

    /// Checks if the exception is a data abort in user or kernel space.
    #[inline]
    #[must_use]
    pub fn is_data_abort(&self) -> bool {
        self.is_user_space_data_page_fault() || self.is_kernel_data_page_fault()
    }

    /// Checks if the exception is a user space code page fault.
    #[inline]
    #[must_use]
    pub fn is_user_space_code_page_fault(&self) -> bool {
        self.0 == 0b10_0000
    }
}
impl core::fmt::Debug for ExceptionClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0b{:b}=", self.0)?;
        match self.0 {
            0b00_0000 => write!(f, "[Misc]"),
            0b00_0001 => write!(f, "[Trapped WF* instruction]"),
            0b00_0111 => write!(f, "[Access to SME, SVE, Advanced SIMD or floating-point functionality trapped by CPACR_EL1.FPEN, CPTR_EL2.FPEN, CPTR_EL2.TFP, or CPTR_EL3.TFP control]"),
            0b00_1010 => write!(f, "[Trapped execution of an LD64B or ST64B* instruction.]"),
            0b00_1101 => write!(f, "[Branch Target Exception]"),
            0b00_1110 => write!(f, "[Illegal Execution state]"),
            0b01_0101 => write!(f, "[SVC instruction]"),
            0b01_1000 => write!(f, "[Trapped MSR, MRS or System instruction execution in AArch64 state, that is not reported using EC 0b00_0000, 0b00_0001, or 0b00_0111]"),
            0b10_0000 => write!(f, "[Instruction Abort from a lower Exception level]"),
            0b10_0001 => write!(f, "[Instruction Abort taken without a change in Exception level]"),
            0b10_0010 => write!(f, "[PC alignment fault exception]"),
            0b10_0100 => write!(f, "[Data Abort exception from a lower Exception level]"),
            0b10_0101 => write!(f, "[Data Abort exception taken without a change in Exception level]"),
            0b10_0110 => write!(f, "[SP alignment fault exception]"),
            _ => write!(f, "[Unknown]")
        }
    }
}

fn data_abort_dfsc_description(code: u8) -> &'static str {
    match code {
        0b00_0000 => "Address size fault, level 0 of translation or translation table base register",
        0b00_0001 => "Address size fault, level 1",
        0b00_0010 => "Address size fault, level 2",
        0b00_0011 => "Address size fault, level 3",
        0b00_0100 => "Translation fault, level 0",
        0b00_0101 => "Translation fault, level 1",
        0b00_0110 => "Translation fault, level 2",
        0b00_0111 => "Translation fault, level 3",
        0b00_1000 => "Access flag fault, level 0",
        0b00_1001 => "Access flag fault, level 1",
        0b00_1010 => "Access flag fault, level 2",
        0b00_1011 => "Access flag fault, level 3",
        0b00_1100 => "Permission fault, level 0",
        0b00_1101 => "Permission fault, level 1",
        0b00_1110 => "Permission fault, level 2",
        0b00_1111 => "Permission fault, level 3",
        0b01_0000 => "Synchronous External abort, not on translation table walk or hardware update of translation table",
        0b01_0001 => "Synchronous Tag Check Fault",
        0b01_0011 => "Synchronous External abort on translation table walk or hardware update of translation table, level -1",
        0b01_0100 => "Synchronous External abort on translation table walk or hardware update of translation table, level 0",
        0b01_0101 => "Synchronous External abort on translation table walk or hardware update of translation table, level 1",
        0b01_0110 => "Synchronous External abort on translation table walk or hardware update of translation table, level 2",
        0b01_0111 => "Synchronous External abort on translation table walk or hardware update of translation table, level 3",
        0b01_1000 => "Synchronous parity or ECC error on memory access, not on translation table walk",
        0b01_1011 => "Synchronous parity or ECC error on memory access on translation table walk or hardware update of translation table, level -1",
        0b01_1100 => "Synchronous parity or ECC error on memory access on translation table walk or hardware update of translation table, level 0",
        0b01_1101 => "Synchronous parity or ECC error on memory access on translation table walk or hardware update of translation table, level 1",
        0b01_1110 => "Synchronous parity or ECC error on memory access on translation table walk or hardware update of translation table, level 2",
        0b01_1111 => "Synchronous parity or ECC error on memory access on translation table walk or hardware update of translation table, level 3",
        0b10_0001 => "Alignment fault",
        0b10_0011 => "Granule Protection Fault on translation table walk or hardware update of translation table, level -1",
        0b10_0100 => "Granule Protection Fault on translation table walk or hardware update of translation table, level 0",
        0b10_0101 => "Granule Protection Fault on translation table walk or hardware update of translation table, level 1",
        0b10_0110 => "Granule Protection Fault on translation table walk or hardware update of translation table, level 2",
        0b10_0111 => "Granule Protection Fault on translation table walk or hardware update of translation table, level 3",
        0b10_1000 => "Granule Protection Fault, not on translation table walk or hardware update of translation table",
        0b10_1001 => "Address size fault, level -1",
        0b10_1011 => "Translation fault, level -1",
        0b11_0000 => "TLB conflict abort",
        0b11_0001 => "Unsupported atomic hardware update fault",
        0b11_0100 => "IMPLEMENTATION DEFINED fault (Lockdown)",
        0b11_0101 => "IMPLEMENTATION DEFINED fault (Unsupported Exclusive or Atomic access)",
        _ => "?",
    }
}

impl core::fmt::Display for ExceptionSyndromeRegister {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ESR")
            .field("ISS2", &format_args!("0x{:x}", self.iss2()))
            .field("EC", &self.ec())
            .field("IL", &self.il())
            // TODO: the ISS field could be decoded further
            .field(
                "ISS",
                &format_args!(
                    "0x{:x}=0b{:b}=[{}]",
                    self.iss(),
                    self.iss(),
                    if self.ec().is_data_abort() {
                        data_abort_dfsc_description((self.iss() & 0b11_1111) as u8)
                    } else {
                        ""
                    }
                ),
            )
            .finish()
    }
}
