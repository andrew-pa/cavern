//! Memory managment algorithms and policies.
//!
//! # Pointers and Memory Addresses
//! The kernel has a plethora of different types of things that are memory addresses.
//! This table details each of these types in order of safety/abstraction.
//! Using the type-system to keep these straight helps improve code readability and helps prevent subtle
//! errors from assuming the address space of pointers.
//!
//! | Type                  | Dereference | Description |
//! |-----------------------|-------------|-------------|
//! | `&T`, `&mut T`        | Safe, trivial | Garden-variety Rust borrow, has the strongest safety gurantees. All of Rust's normal rules apply. References are always kernel-space addresses, since they can be dereferenced via the MMU while in EL1. |
//! | `*const T`, `*mut T`  | Unsafe | Raw pointer with fewer safety gurantees from Rust. Still should be a kernel-space address that is dereferenceable via the MMU while in EL1. |
//! | [`VirtualPointer<T>`], [`VirtualPointerMut<T>`] | If kernel-space: unsafe but trivial. Otherwise requires a manual page table lookup. | A virtual address in some address space. If the address space is the kernel's, then this is trivially convertable into a raw pointer. Otherwise a [`PageTables`] instance must be consulted to lookup the actual physical address that it is mapped to. |
//! | [`VirtualAddress`]    | Same as `VirtualPointer` but must assume type. | An address in a virtual memory address space that is not associated with a type, but indicates some location. Assumed mutable for convenience. |
//! | [`PhysicalPointer<T>`]| With conversion to kernel-space, unsafe. | A pointer to something in physical memory, i.e. the untranslated address space. Because the kernel virtual address space is identity mapped, these are trivially convertable to a [`VirtualPointer<T>`] or `*mut T`. All physical addresses are assumed to be mutable from the kernel's perspective. |
//! | [`PhysicalAddress`]   | Same as `PhysicalPointer` but must assume type. | An address in the physical memory address space that is not associated with a type, but indicates some location.

#![allow(clippy::manual_is_multiple_of)]

use core::{marker::PhantomData, num::NonZeroUsize};
use snafu::Snafu;

#[cfg(test)]
use mockall::automock;

mod buddy;
pub use buddy::BuddyPageAllocator;

mod heap;
pub use heap::HeapAllocator;

pub mod talc_heap;

mod subtract_ranges;
pub use subtract_ranges::*;

pub mod page_table;
pub use page_table::PageTables;

pub mod active_user_space_tables;

mod asid_pool;
pub use asid_pool::{AddressSpaceId, AddressSpaceIdPool};

mod free_list;
pub use free_list::FreeListAllocator;

/// A 48-bit physical address pointer that is not part of a virtual address space.
///
/// Although in the kernel the virtual addresses are identity mapped, the high bits of the address
/// must be `0xffff` to select the kernel page tables, so a `*mut T` is not quite but very close to
/// the physical address of the `T`.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysicalPointer<T>(usize, PhantomData<*mut T>);
unsafe impl<T: Send> Send for PhysicalPointer<T> {}

/// A physical 48-bit address that does not dereference to any particular type of value.
pub type PhysicalAddress = PhysicalPointer<()>;

impl<T> Clone for PhysicalPointer<T> {
    fn clone(&self) -> Self {
        Self(self.0, PhantomData)
    }
}

impl<T> PhysicalPointer<T> {
    /// Offset this pointer forward by `count` number of `T`s.
    #[inline]
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub const fn add(self, count: usize) -> Self {
        self.byte_add(count * size_of::<T>())
    }

    /// Offset this pointer forward by `count` bytes.
    #[inline]
    #[must_use]
    pub const fn byte_add(self, count: usize) -> Self {
        Self(self.0 + count, PhantomData)
    }

    /// Cast this pointer from type `T` to type `U`.
    #[inline]
    #[must_use]
    pub const fn cast<U>(self) -> PhysicalPointer<U> {
        PhysicalPointer(self.0, PhantomData)
    }

    /// A null physical pointer (address 0).
    #[must_use]
    pub const fn null() -> Self {
        Self(0, PhantomData)
    }

    /// Check to see if this pointer is null.
    #[inline]
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Returns whether the pointer is aligned to `alignment`.
    #[inline]
    #[must_use]
    pub const fn is_aligned_to(self, alignment: usize) -> bool {
        self.0.is_multiple_of(alignment)
    }
}

impl PhysicalAddress {
    /// Convert a pointer of any type into a virtual address with no type.
    #[inline]
    #[must_use]
    pub fn from_ptr<T>(ptr: *mut T) -> Self {
        Self(ptr as usize, PhantomData)
    }
}

impl<T> core::fmt::Debug for PhysicalPointer<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "p:0x{:016x}", self.0)
    }
}

impl<T> From<usize> for PhysicalPointer<T> {
    fn from(value: usize) -> Self {
        assert!(value < 0xffff_0000_0000_0000);
        PhysicalPointer(value, PhantomData)
    }
}

impl<T> From<PhysicalPointer<T>> for usize {
    fn from(val: PhysicalPointer<T>) -> Self {
        val.0
    }
}

impl<T> From<*const T> for PhysicalPointer<T> {
    fn from(value: *const T) -> Self {
        PhysicalPointer(value as usize & 0x0000_ffff_ffff_ffff, PhantomData)
    }
}

impl<T> From<PhysicalPointer<T>> for *const T {
    fn from(val: PhysicalPointer<T>) -> Self {
        #[cfg(not(test))]
        {
            (val.0 | 0xffff_0000_0000_0000) as _
        }
        #[cfg(test)]
        {
            // HACK: Because the test environment is in user-space, we assume that physical pointers are actually untagged, but fit in the 48-bit space.
            val.0 as _
        }
    }
}

impl<T> From<*mut T> for PhysicalPointer<T> {
    fn from(value: *mut T) -> Self {
        PhysicalPointer(value as usize & 0x0000_ffff_ffff_ffff, PhantomData)
    }
}

impl<T> From<PhysicalPointer<T>> for *mut T {
    fn from(val: PhysicalPointer<T>) -> Self {
        #[cfg(not(test))]
        {
            (val.0 | 0xffff_0000_0000_0000) as _
        }
        #[cfg(test)]
        {
            // HACK: Because the test environment is in user-space, we assume that physical pointers are actually untagged, but fit in the 48-bit space.
            val.0 as _
        }
    }
}

/// A 48-bit virtual address space pointer to a `T` in some address space.
/// Analogous to a `*const T`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct VirtualPointer<T>(usize, PhantomData<*const T>);
// TODO: this is techinically wrong, but convenient
unsafe impl<T: Send> Send for VirtualPointer<T> {}
unsafe impl<T: Send> Sync for VirtualPointer<T> {}

/// A 48-bit virtual address space pointer to a mutable `T` in some address space.
/// Analogous to a `*mut T`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct VirtualPointerMut<T>(usize, PhantomData<*mut T>);
unsafe impl<T: Send> Send for VirtualPointerMut<T> {}
unsafe impl<T: Send> Sync for VirtualPointerMut<T> {}

/// A virtual 48-bit address that does not dereference to any particular type of value.
pub type VirtualAddress = VirtualPointerMut<()>;

/// The error returned from `TryFrom` implementations if the `value` pointer is not in the kernel address space.
pub struct NotInKernelAddressSpaceError;

macro_rules! virtual_pointer_impl {
    ($vpt:ident) => {
        impl<T> $vpt<T> {
            /// Returns true if this pointer is in the kernel address space.
            #[inline]
            #[must_use]
            pub fn is_in_kernel_space(&self) -> bool {
                self.0 & 0xffff_0000_0000_0000 == 0xffff_0000_0000_0000
            }

            /// Offset this pointer forward by `count` number of `T`s.
            #[inline]
            #[must_use]
            #[allow(clippy::should_implement_trait)]
            pub fn add(self, count: usize) -> Self {
                self.byte_add(count * size_of::<T>())
            }

            /// Offset this pointer forward by `count` bytes.
            #[inline]
            #[must_use]
            pub fn byte_add(self, count: usize) -> Self {
                Self(self.0 + count, PhantomData)
            }

            /// Cast this pointer from type `T` to type `U`.
            #[inline]
            #[must_use]
            pub fn cast<U>(self) -> $vpt<U> {
                $vpt(self.0, PhantomData)
            }

            /// Returns whether the pointer is aligned to `alignment`.
            #[inline]
            #[must_use]
            pub const fn is_aligned_to(self, alignment: usize) -> bool {
                self.0 % alignment == 0
            }

            /// A null virtual pointer.
            #[must_use]
            pub const fn null() -> Self {
                Self(0, PhantomData)
            }

            /// Returns whether the pointer is null.
            #[inline]
            #[must_use]
            pub const fn is_null(self) -> bool {
                self.0 == 0
            }
        }

        impl<T> core::fmt::Debug for $vpt<T> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "v:0x{:x}", self.0)
            }
        }

        impl<T> From<usize> for $vpt<T> {
            fn from(value: usize) -> Self {
                $vpt(value, PhantomData)
            }
        }

        impl<T> From<$vpt<T>> for usize {
            fn from(val: $vpt<T>) -> Self {
                val.0
            }
        }

        impl<T> From<*const T> for $vpt<T> {
            fn from(value: *const T) -> Self {
                $vpt(value as usize, PhantomData)
            }
        }

        impl<T> TryFrom<$vpt<T>> for *const T {
            type Error = NotInKernelAddressSpaceError;

            fn try_from(value: $vpt<T>) -> Result<Self, Self::Error> {
                value
                    .is_in_kernel_space()
                    .then_some(value.0 as _)
                    .ok_or(NotInKernelAddressSpaceError)
            }
        }

        impl<T> From<PhysicalPointer<T>> for $vpt<T> {
            fn from(value: PhysicalPointer<T>) -> Self {
                Self(value.0 | 0xffff_0000_0000_0000, PhantomData)
            }
        }

        impl<T> TryFrom<$vpt<T>> for PhysicalPointer<T> {
            type Error = NotInKernelAddressSpaceError;

            fn try_from(value: $vpt<T>) -> Result<Self, Self::Error> {
                value
                    .is_in_kernel_space()
                    .then_some(PhysicalPointer::from(value.0 & 0x0000_ffff_ffff_ffff))
                    .ok_or(NotInKernelAddressSpaceError)
            }
        }
    };
}
virtual_pointer_impl!(VirtualPointer);
virtual_pointer_impl!(VirtualPointerMut);

impl<T> VirtualPointerMut<T> {
    /// Convert this virtual address directly to a Rust pointer.
    ///
    /// # Safety
    /// It is up to the caller to ensure that this pointer is valid for the lifetime of the value.
    #[must_use]
    pub unsafe fn as_ptr(self) -> *mut T {
        self.0 as _
    }
}

impl<T> From<*mut T> for VirtualPointerMut<T> {
    fn from(value: *mut T) -> Self {
        VirtualPointerMut(value as usize, PhantomData)
    }
}

impl<T> TryFrom<VirtualPointerMut<T>> for *mut T {
    type Error = NotInKernelAddressSpaceError;

    fn try_from(value: VirtualPointerMut<T>) -> Result<Self, Self::Error> {
        value
            .is_in_kernel_space()
            .then_some(value.0 as _)
            .ok_or(NotInKernelAddressSpaceError)
    }
}

impl<T> From<VirtualPointerMut<T>> for VirtualPointer<T> {
    fn from(value: VirtualPointerMut<T>) -> Self {
        Self(value.0, PhantomData)
    }
}

/// Errors that arise due to memory related operations.
#[derive(Debug, Snafu)]
pub enum Error {
    /// The system has run out of free memory.
    OutOfMemory,
    /// A size was provided that is not valid (i.e. is zero, or is too large).
    InvalidSize,
    /// A pointer was provided that is not known to the allocator.
    UnknownPtr,
}

/// The size of a single memory page.
/// Defined to be equal to the size in bytes of the page.
///
/// There are only a fixed number of supported values because the hardware only supports a few configurations.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum PageSize {
    /// A page is 4 kibibytes (2^12 bytes).
    FourKiB,
    /// A page is 16 kibibytes (2^14 bytes).
    SixteenKiB,
}

impl PageSize {
    /// Returns the page base and offset for an address.
    /// For example, if the page size was [`Self::FourKiB`] then an address `0xaaaa_abbb` would
    /// become `(0xaaaa_a000, 0xbbb)`
    pub fn split(self, addr: impl Into<usize>) -> (usize, usize) {
        let addr: usize = addr.into();
        let mask = usize::from(self) - 1;
        (addr & !mask, addr & mask)
    }

    /// Return the minimum number of bits necessary to represent a page offset.
    #[must_use]
    pub fn ilog2(self) -> usize {
        match self {
            PageSize::FourKiB => 12,
            PageSize::SixteenKiB => 14,
        }
    }
}

impl From<usize> for PageSize {
    fn from(value: usize) -> Self {
        match value {
            0x1000 => PageSize::FourKiB,
            0x4000 => PageSize::SixteenKiB,
            _ => panic!("unsupported page size {value}"),
        }
    }
}

impl From<PageSize> for usize {
    fn from(value: PageSize) -> Self {
        match value {
            PageSize::FourKiB => 0x1000,
            PageSize::SixteenKiB => 0x4000,
        }
    }
}

impl From<PageSize> for NonZeroUsize {
    fn from(value: PageSize) -> Self {
        unsafe { NonZeroUsize::new_unchecked(usize::from(value)) }
    }
}

impl core::ops::Mul<usize> for PageSize {
    type Output = usize;

    fn mul(self, rhs: usize) -> Self::Output {
        usize::from(self) * rhs
    }
}

impl core::ops::Mul<PageSize> for usize {
    type Output = usize;

    fn mul(self, rhs: PageSize) -> Self::Output {
        self * usize::from(rhs)
    }
}

impl core::ops::Div<PageSize> for usize {
    type Output = usize;

    fn div(self, rhs: PageSize) -> Self::Output {
        self / usize::from(rhs)
    }
}

/// A memory allocator that provides pages of physical memory.
///
/// Implementers of this trait must provide internal synchronization and each associated function
/// should be re-entrant.
#[cfg_attr(test, automock)]
pub trait PageAllocator {
    /// The size of one page in this allocator.
    ///
    /// This value must remain the same throughout the lifetime of the allocator.
    fn page_size(&self) -> PageSize;

    /// Allocate `num_pages` of memory, returning a pointer to the beginning which will be page-aligned.
    ///
    /// # Errors
    /// - [`Error::OutOfMemory`] if there is not enough memory to allocate `num_pages`.
    /// - [`Error::InvalidSize`] if `num_pages` is zero.
    fn allocate(&self, num_pages: usize) -> Result<PhysicalAddress, Error>;

    /// Allocate `num_pages` of memory, returning a pointer to the beginning which will be page-aligned.
    /// Every byte of the pages will be set to zero.
    ///
    /// # Errors
    /// - [`Error::OutOfMemory`] if there is not enough memory to allocate `num_pages`.
    /// - [`Error::InvalidSize`] if `num_pages` is zero.
    fn allocate_zeroed(&self, num_pages: usize) -> Result<PhysicalAddress, Error> {
        let pages = self.allocate(num_pages)?;
        unsafe {
            core::ptr::write_bytes(pages.cast::<u8>().into(), 0, num_pages * self.page_size());
        }
        Ok(pages)
    }

    /// Free the pages pointed to by `pages` that points to a region of `num_pages`.
    /// This pointer must have been returned at some point from a call to [`PageAllocator::allocate`] that allocated exactly `num_pages`.
    ///
    /// # Errors
    /// - [`Error::UnknownPtr`] if `pages` is null or was not allocated by this allocator.
    fn free(&self, pages: PhysicalAddress, num_pages: usize) -> Result<(), Error>;
}

#[cfg(test)]
/// Tests for memory module.
pub mod tests {
    use snafu::{ensure, OptionExt};

    use crate::memory::{InvalidSizeSnafu, OutOfMemorySnafu, PhysicalPointer, UnknownPtrSnafu};

    use super::{Error, PageAllocator, PageSize, PhysicalAddress};

    /// Generate tests to ensure correct implementation of the [`PageAllocator`] trait.
    ///
    /// `$allocator_name` is the name of the allocator, and `$create_allocator` is an expression that evaluates to a new allocator.
    #[macro_export]
    macro_rules! test_page_allocator {
        ($allocator_name:ident, $setup_allocator:ident, $cleanup_allocator:ident) => {
            paste::paste!{
                mod [<$allocator_name:snake:lower _implements_page_allocator>] {
                    use test_case::test_case;
                    use $crate::memory::{PageAllocator, Error};
                    use super::*;
                    // Test the page size is consistent
                    #[test]
                    fn page_size_consistency() {
                        let (cx, allocator) = $setup_allocator();
                        let page_size = allocator.page_size();
                        // Allocating multiple times should return the same page size
                        for _ in 0..10 {
                            assert_eq!(allocator.page_size(), page_size, "Page size should remain constant");
                        }
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test allocating multiple pages and freeing them
                    #[test_case(1 ; "one")]
                    #[test_case(2 ; "two")]
                    #[test_case(3 ; "three")]
                    #[test_case(7 ; "seven")]
                    #[test_case(8 ; "eight")]
                    #[test_case(16 ; "sixteen")]
                    #[test_case(128 ; "huge")]
                    fn allocate_pages_once(num_pages: usize) {
                        let (cx, allocator) = $setup_allocator();
                        let page_size = allocator.page_size();
                        let pages = allocator.allocate(num_pages).expect("Failed to allocate multiple pages");
                        let ptr: *mut () = pages.into();
                        // Ensure the memory address is aligned to the page size
                        assert!(!ptr.is_null());
                        assert!(ptr.is_aligned_to(page_size.into()),  "Pointer should be page-aligned");
                        allocator.free(pages, num_pages).expect("Failed to free allocated pages");
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test allocating zero pages (should fail)
                    #[test]
                    fn allocate_zero_pages() {
                        let (cx, allocator) = $setup_allocator();
                        let result = allocator.allocate(0);
                        assert!(matches!(result, Err(Error::InvalidSize)), "Allocating 0 pages should fail");
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test double free (should fail)
                    #[test]
                    fn double_free_trivial() {
                        let (cx, allocator) = $setup_allocator();
                        let ptr = allocator.allocate(1).expect("Failed to allocate a page");
                        assert!(!ptr.is_null());
                        allocator.free(ptr, 1).expect("Failed to free allocated page");
                        let result = allocator.free(ptr, 1);
                        assert!(matches!(result, Err(Error::UnknownPtr)), "Double free should fail");
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test double free (should fail)
                    #[test]
                    fn double_free_tricky() {
                        let _ = env_logger::try_init();
                        let (cx, allocator) = $setup_allocator();
                        log::info!("first allocation");
                        let ptr = allocator.allocate(2).expect("Failed to allocate a page");
                        log::info!("second allocation");
                        let ptr2 = allocator.allocate(2).expect("Failed to allocate a page");
                        log::info!("free ptr2 {ptr2:?}");
                        allocator.free(ptr2, 2).expect("Failed to free allocated page");
                        log::info!("free ptr {ptr:?}");
                        allocator.free(ptr, 2).expect("Failed to free allocated page");
                        log::info!("do double free");
                        let result = allocator.free(ptr2, 2);
                        assert!(matches!(result, Err(Error::UnknownPtr)), "Double free should fail");
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test allocating more pages than available (simulated out-of-memory condition)
                    #[test]
                    fn out_of_memory() {
                        let (cx, allocator) = $setup_allocator();
                        // Simulate by attempting to allocate a large number of pages
                        let result = allocator.allocate(usize::MAX);
                        assert!(matches!(result, Err(Error::OutOfMemory)), "Allocator should return an error when out of memory");
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test allocating more pages than available (simulated out-of-memory condition), but do so slowly, and then free everything
                    #[test]
                    fn out_of_memory_slow() {
                        let _ = env_logger::try_init();
                        let (cx, allocator) = $setup_allocator();
                        let mut ptrs = std::vec::Vec::new();
                        while ptrs.len() < 1_000_000 {
                            match allocator.allocate(1) {
                                Ok(p) => ptrs.push(p),
                                Err(Error::OutOfMemory) => {
                                    for p in ptrs {
                                        allocator.free(p, 1).expect("free page");
                                    }
                                    $cleanup_allocator(cx, allocator);
                                    return
                                },
                                Err(e) => panic!("unexpected error allocating: {e}")
                            }
                        }
                        panic!("should have reached out-of-memory by now");
                    }

                    // Test stress: allocate and free multiple pages in a loop
                    #[test]
                    fn stress_allocation() {
                        let (cx, allocator) = $setup_allocator();
                        let num_pages = 8;
                        for _ in 0..64 {
                            let ptr = allocator.allocate(num_pages).expect("Failed to allocate pages");
                            assert!(!ptr.is_null());
                            allocator.free(ptr, num_pages).expect("Failed to free allocated pages");
                        }
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test sequential allocate and free
                    #[test]
                    fn sequential_alloc_free() {
                        let (cx, allocator) = $setup_allocator();
                        let num_pages = 4;

                        let ptr1 = allocator.allocate(num_pages).expect("Failed to allocate pages");
                        allocator.free(ptr1, num_pages).expect("Failed to free pointer 1");

                        let ptr2 = allocator.allocate(num_pages).expect("Failed to allocate pages");
                        allocator.free(ptr2, num_pages).expect("Failed to free pointer 2");
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test interleaved allocate/free pattern
                    #[test]
                    fn interleaved_alloc_free() {
                        let _ = env_logger::try_init();
                        let (cx, allocator) = $setup_allocator();

                        let ptr1 = allocator.allocate(2).expect("Failed to allocate pages");
                        let ptr2 = allocator.allocate(3).expect("Failed to allocate pages");
                        let ptr3 = allocator.allocate(1).expect("Failed to allocate pages");

                        // Free ptr2 first
                        allocator.free(ptr2, 3).expect("Failed to free pointer 2");

                        // Now free ptr1 and ptr3
                        allocator.free(ptr1, 2).expect("Failed to free pointer 1");
                        allocator.free(ptr3, 1).expect("Failed to free pointer 3");
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test allocation, freeing some, then reallocating more
                    #[test]
                    fn partial_free_then_allocate() {
                        let (cx, allocator) = $setup_allocator();

                        let ptr1 = allocator.allocate(4).expect("Failed to allocate 4 pages");
                        let ptr2 = allocator.allocate(2).expect("Failed to allocate 2 pages");

                        // Free the first allocation
                        allocator.free(ptr1, 4).expect("Failed to free pointer 1");

                        // Allocate a new set of pages after freeing
                        let ptr3 = allocator.allocate(3).expect("Failed to allocate 3 pages");

                        // Free remaining pointers
                        allocator.free(ptr2, 2).expect("Failed to free pointer 2");
                        allocator.free(ptr3, 3).expect("Failed to free pointer 3");
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test allocating multiple regions and freeing in reverse order
                    #[test]
                    fn free_in_reverse_order() {
                        let (cx, allocator) = $setup_allocator();

                        let ptr1 = allocator.allocate(2).expect("Failed to allocate 2 pages");
                        let ptr2 = allocator.allocate(3).expect("Failed to allocate 3 pages");
                        let ptr3 = allocator.allocate(1).expect("Failed to allocate 1 page");

                        // Free in reverse order of allocation
                        allocator.free(ptr3, 1).expect("Failed to free pointer 3");
                        allocator.free(ptr2, 3).expect("Failed to free pointer 2");
                        allocator.free(ptr1, 2).expect("Failed to free pointer 1");
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test mixed small and large allocations
                    #[test]
                    fn mixed_small_and_large_allocations() {
                        let (cx, allocator) = $setup_allocator();

                        let small_ptr = allocator.allocate(1).expect("Failed to allocate 1 page");
                        let large_ptr = allocator.allocate(64).expect("Failed to allocate 16 pages");

                        // Free in reverse order of allocation
                        allocator.free(large_ptr, 64).expect("Failed to free large pointer");
                        allocator.free(small_ptr, 1).expect("Failed to free small pointer");
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test allocate/free in a loop to simulate reuse of pages
                    #[test_case(1 ; "one page")]
                    #[test_case(2 ; "two pages")]
                    #[test_case(3 ; "three pages")]
                    #[test_case(7 ; "seven pages")]
                    #[test_case(8 ; "eight pages")]
                    fn allocate_free_loop(num_pages: usize) {
                        let (cx, allocator) = $setup_allocator();

                        for _ in 0..128 {
                            let ptr = allocator.allocate(num_pages).expect("Failed to allocate pages");
                            assert!(!ptr.is_null());
                            allocator.free(ptr, num_pages).expect("Failed to free allocated pages");
                        }
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test multiple allocations without freeing, then freeing all at once
                    #[test_case(1 ; "one page")]
                    #[test_case(2 ; "two pages")]
                    #[test_case(3 ; "three pages")]
                    #[test_case(7 ; "seven pages")]
                    #[test_case(8 ; "eight pages")]
                    fn allocate_without_freeing_then_free_all(num_pages: usize) {
                        let (cx, allocator) = $setup_allocator();

                        let mut ptrs = std::vec::Vec::new();
                        for _ in 0..32 {
                            let ptr = allocator.allocate(num_pages).expect("Failed to allocate pages");
                            assert!(!ptr.is_null());
                            ptrs.push(ptr);
                        }

                        // Now free all allocations
                        for ptr in ptrs {
                            allocator.free(ptr, num_pages).expect("Failed to free allocated pages");
                        }
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test multiple allocations without freeing, then freeing all at once in reverse
                    #[test_case(1 ; "one page")]
                    #[test_case(2 ; "two pages")]
                    #[test_case(3 ; "three pages")]
                    #[test_case(7 ; "seven pages")]
                    #[test_case(8 ; "eight pages")]
                    fn allocate_without_freeing_then_free_all_rev(num_pages: usize) {
                        let (cx, allocator) = $setup_allocator();

                        let mut ptrs = std::vec::Vec::new();
                        for _ in 0..32 {
                            let ptr = allocator.allocate(num_pages).expect("Failed to allocate pages");
                            assert!(!ptr.is_null());
                            ptrs.push(ptr);
                        }

                        // Now free all allocations
                        for ptr in ptrs.into_iter().rev() {
                            allocator.free(ptr, num_pages).expect("Failed to free allocated pages");
                        }
                        $cleanup_allocator(cx, allocator);
                    }

                    // Test multiple allocations without freeing, then freeing first the odd
                    // indices, then the even indices in reverse
                    #[test_case(1 ; "one page")]
                    #[test_case(2 ; "two pages")]
                    #[test_case(3 ; "three pages")]
                    #[test_case(7 ; "seven pages")]
                    #[test_case(8 ; "eight pages")]
                    fn allocate_without_freeing_then_free_all_mixed(num_pages: usize) {
                        let (cx, allocator) = $setup_allocator();

                        let mut ptrs = std::vec::Vec::new();
                        for _ in 0..32 {
                            let ptr = allocator.allocate(num_pages).expect("Failed to allocate pages");
                            assert!(!ptr.is_null());
                            ptrs.push(ptr);
                        }

                        // Now free all allocations
                        for ptr in ptrs.iter().skip(1).step_by(2) {
                            allocator.free(*ptr, num_pages).expect("Failed to free allocated pages");
                        }
                        for ptr in ptrs.iter().step_by(2).rev() {
                            allocator.free(*ptr, num_pages).expect("Failed to free allocated pages");
                        }
                        $cleanup_allocator(cx, allocator);
                    }

                    // TODO: interleaved batch tests
                    // TODO: concurrent tests
                }
            }
        };
    }

    use core::alloc::Layout;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Mock implementation of the [`PageAllocator`] trait with page limits.
    ///
    /// This allocator uses the system allocator to allocate the underlying memory.
    pub struct MockPageAllocator {
        page_size: PageSize,
        max_pages: usize,
        allocated_pages: Arc<Mutex<HashMap<*mut u8, (usize, usize)>>>, // Map from pointer to number of pages total and number of pages still allocated
        total_allocated: Arc<Mutex<usize>>, // Tracks total allocated pages
    }

    unsafe impl Send for MockPageAllocator {}
    unsafe impl Sync for MockPageAllocator {}

    impl MockPageAllocator {
        /// Create a new `MockAllocator` with the given page size and maximum number of pages.
        #[must_use]
        pub fn new(page_size: PageSize, max_pages: usize) -> Self {
            assert!(max_pages > 0);
            MockPageAllocator {
                page_size,
                max_pages,
                allocated_pages: Default::default(),
                total_allocated: Arc::new(Mutex::new(0)),
            }
        }

        /// Check to make sure everything was freed at the end of a test.
        pub fn end_check(self) {
            assert!(self.allocated_pages.lock().unwrap().is_empty());
            assert_eq!(*self.total_allocated.lock().unwrap(), 0);
        }
    }

    impl PageAllocator for MockPageAllocator {
        fn page_size(&self) -> PageSize {
            self.page_size
        }

        fn allocate(&self, num_pages: usize) -> Result<PhysicalAddress, Error> {
            ensure!(num_pages > 0, InvalidSizeSnafu);

            let mut total_allocated = self.total_allocated.lock().unwrap();

            std::println!(
                "allocate check for space: total:{total_allocated} + query:{num_pages} <= max:{}",
                self.max_pages
            );

            // Check if there's enough space to allocate the requested number of pages
            ensure!(
                *total_allocated + num_pages <= self.max_pages,
                OutOfMemorySnafu
            );

            // Calculate the total size in bytes for the allocation
            let total_size = usize::from(self.page_size)
                .checked_mul(num_pages)
                .context(OutOfMemorySnafu)?;
            let layout = Layout::from_size_align(total_size, self.page_size.into()).unwrap();

            unsafe {
                // Allocate the memory
                let ptr = std::alloc::alloc_zeroed(layout);
                ensure!(!ptr.is_null(), OutOfMemorySnafu);

                // Add the pointer and its allocated size to the map of allocated pages
                let mut allocated_pages = self.allocated_pages.lock().unwrap();
                allocated_pages.insert(ptr, (num_pages, num_pages));

                // Update the total allocated pages count
                *total_allocated += num_pages;

                Ok(PhysicalPointer::from(ptr.cast()))
            }
        }

        fn free(&self, pages: PhysicalAddress, num_pages: usize) -> Result<(), Error> {
            let pages_ptr: *mut u8 = pages.cast().into();
            ensure!(!pages_ptr.is_null(), UnknownPtrSnafu);

            let mut allocated_pages = self.allocated_pages.lock().unwrap();

            // find the actual allocation these pages are in
            let (actual_ptr, (actual_num_pages, current_allocated_pages)) = allocated_pages
                .iter_mut()
                .find(|(addr, (size, _))| unsafe {
                    **addr <= pages_ptr && pages_ptr < addr.byte_add(*size * self.page_size)
                })
                .context(UnknownPtrSnafu)?;

            #[cfg(test)]
            std::println!("freeing {pages:?}/{num_pages}, actually in {actual_ptr:x?}/{actual_num_pages} ({current_allocated_pages} currently allocated)");

            ensure!(*current_allocated_pages > 0, UnknownPtrSnafu);
            ensure!(num_pages <= *actual_num_pages, InvalidSizeSnafu);
            ensure!(num_pages <= *current_allocated_pages, InvalidSizeSnafu);
            ensure!(
                unsafe {
                    pages_ptr.byte_add(num_pages * self.page_size)
                        <= actual_ptr.byte_add(*actual_num_pages * self.page_size)
                },
                InvalidSizeSnafu
            );
            *current_allocated_pages -= num_pages;

            if *current_allocated_pages == 0 {
                let actual_ptr = *actual_ptr;
                let actual_num_pages = *actual_num_pages;

                allocated_pages
                    .remove(&actual_ptr)
                    .context(UnknownPtrSnafu)?;
                drop(allocated_pages);

                // Deallocate the memory
                let total_size = usize::from(self.page_size) * actual_num_pages;
                let layout = Layout::from_size_align(total_size, self.page_size.into()).unwrap();

                unsafe {
                    std::alloc::dealloc(actual_ptr, layout);
                }
            } else {
                drop(allocated_pages);
            }

            // Update the total allocated pages count
            let mut total_allocated = self.total_allocated.lock().unwrap();
            *total_allocated -= num_pages;

            Ok(())
        }
    }

    fn setup_allocator() -> ((), MockPageAllocator) {
        ((), MockPageAllocator::new(PageSize::FourKiB, 1024))
    }

    fn cleanup_allocator(_cx: (), allocator: MockPageAllocator) {
        allocator.end_check();
    }

    test_page_allocator!(MockPageAllocator, setup_allocator, cleanup_allocator);
}
