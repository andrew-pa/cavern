//! PL011 UART driver.
//!
//! Documentation for the interface can be found [on ARM's website](https://developer.arm.com/documentation/ddi0183/latest/).

use core::fmt::Write;

use kernel_core::{
    logger::LogSink,
    memory::PhysicalPointer,
    platform::device_tree::{DeviceTree, Value},
};

/// The PL011 UART object.
pub struct PL011 {
    base_address: *mut u8,
}

// SAFETY: It's fine to move the pointer as long as it doesn't get duplicated!
unsafe impl Send for PL011 {}

impl PL011 {
    /// Configure the driver using information from a device tree node.
    /// The node must follow the spec at [].
    #[must_use]
    pub fn from_device_tree(dt: &DeviceTree, path: &[u8]) -> Option<Self> {
        let mut base_address = None;
        for (name, value) in dt.iter_node_properties(path)? {
            if let (b"reg", Value::Reg(r)) = (name, value) {
                base_address = r.iter().next().map(|(r, _)| PhysicalPointer::from(r));
            }
        }
        base_address.map(|r| PL011 {
            base_address: r.into(),
        })
    }
}

impl Write for PL011 {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for ch in s.bytes() {
            unsafe {
                self.base_address.write_volatile(ch);
            }
        }
        Ok(())
    }
}

impl LogSink for PL011 {
    fn accept(&mut self, chunk: &[u8]) {
        for byte in chunk {
            unsafe {
                self.base_address.write_volatile(*byte);
            }
        }
    }
}
