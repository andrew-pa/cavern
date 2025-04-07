//! This crate contains useful definitions for user space services without the standard library.
#![no_std]
#![no_main]
#![deny(missing_docs)]

extern crate alloc;

pub mod heap;
pub mod interfaces;
pub mod rpc;
pub mod tasks;
