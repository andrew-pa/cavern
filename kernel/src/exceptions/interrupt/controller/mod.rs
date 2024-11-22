//! Interrupt controllers. (Implementations of [`kernel_core::exceptions::InterruptController`])

pub mod gic2;

pub type PlatformController = gic2::GenericV2;
