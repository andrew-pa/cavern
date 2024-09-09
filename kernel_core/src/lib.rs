//! The Endless Hole microkernel. See `spec/kernel.md` for the specification.
//!
//! This crate contains definitions for data structures, algorithms and policies that are used in the kernel proper.
//! This crate is broken out primarily so that these definitions can be unit tested using
//! `std` for convenience while building the kernel without it.
//! The actual kernel entry point is in the `kernel` crate.
#![no_std]
#![deny(missing_docs)]

#[cfg(all(test, not(target_os = "none")))]
#[macro_use]
extern crate std;

pub mod platform;

#[cfg(test)]
mod tests {
    use std::prelude::rust_2021::*;

    #[test]
    fn it_works() {
        println!("hello");
        assert_eq!(2 + 2, 4);
    }
}