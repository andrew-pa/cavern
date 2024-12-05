//! Generic data structures for kernel usage.

mod handle_allocator;
pub use handle_allocator::HandleAllocator;

mod handle_map;
pub use handle_map::{Handle, HandleMap};

mod arc_swap;
pub use arc_swap::ArcSwap;
