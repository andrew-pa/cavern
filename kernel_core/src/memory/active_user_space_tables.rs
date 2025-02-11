//! Active user space page table translation interface.
//!
//! The hardware provides an interface to accelerate page table lookups outside of memory accesses
//! via the `AT` instruction. This is an abstraction over that interface and others like it,
//! allowing the actual mechanism to be isolated.
use log::trace;

use super::{
    page_table::Error, PageSize, PhysicalAddress, VirtualAddress, VirtualPointer, VirtualPointerMut,
};

/// Mechanisms for interacting with the currently active EL0 page tables.
/// The lifetime of this object must be tied to the lifetime in which a single set of tables is
/// mapped for EL0.
#[cfg_attr(test, mockall::automock)]
pub trait ActiveUserSpaceTables {
    /// Get the size of pages.
    fn page_size(&self) -> PageSize;

    /// Translate a virtual address into a physical one using the current EL0 page tables
    /// and also look up the memory properties for the mapping.
    /// If `for_write` is true, the translation will occur as if it was a write to the address,
    /// and if it is false, then the translation will occur as if it was a read.
    ///
    /// # Errors
    /// Returns an error if the address is not actually mapped.
    fn translate(&self, addr: VirtualAddress, for_write: bool) -> Result<PhysicalAddress, Error>;
}

/// Policy for checking references into active user space, wrapping an [`ActiveUserSpaceTables`] instance's translation mechanism.
#[derive(Copy, Clone)]
pub struct ActiveUserSpaceTablesChecker<'a, T: ActiveUserSpaceTables>(&'a T);

impl<'a, A: ActiveUserSpaceTables> From<&'a A> for ActiveUserSpaceTablesChecker<'a, A> {
    fn from(value: &'a A) -> Self {
        Self(value)
    }
}

#[allow(clippy::needless_pass_by_value)]
impl<'a, A: ActiveUserSpaceTables> ActiveUserSpaceTablesChecker<'a, A> {
    /// Helper to check that every page in `[start, start + length_in_bytes - 1]`
    /// is mapped in EL0 space, and (if `must_write` is true) that it is writable.
    ///
    /// # Errors
    /// Returns an error if the range is not actually mapped at some address, or if it is mapped
    /// with insufficient permissions.
    fn check_user_pages_in_range(
        &self,
        start: VirtualAddress,
        length_in_bytes: usize,
        for_write: bool,
    ) -> Result<(), Error> {
        assert!(length_in_bytes > 0);

        let page_sz = usize::from(self.0.page_size());
        let start_usize = usize::from(start);
        let end_usize = start_usize
            .checked_add(length_in_bytes - 1)
            .ok_or(Error::WouldFault {
                code: 0xff,
                address: start.byte_add(length_in_bytes),
            })?;

        // Round each address down to its page base
        let first_page_base = start_usize & !(page_sz - 1);
        let last_page_base = end_usize & !(page_sz - 1);

        let mut cur_page = first_page_base;
        while cur_page <= last_page_base {
            let va = VirtualAddress::from(cur_page);
            let _ = self.0.translate(va, for_write)?;
            cur_page = cur_page.checked_add(page_sz).ok_or(Error::WouldFault {
                code: 0xff,
                address: va,
            })?;
        }
        Ok(())
    }

    /// Check to see if a user-space address `ptr` is valid to convert to a reference given that
    /// the current EL0 page tables remain active. If so, the reference is returned.
    ///
    /// # Errors
    /// If dereferencing the pointer would result in a fault, [`Error::WouldFault`] is returned.
    pub fn check_ref<T>(&self, ptr: VirtualPointer<T>) -> Result<&'a T, Error> {
        trace!("checking user space ref, ptr={ptr:?}");
        let size = core::mem::size_of::<T>();
        // If T is zero-sized, still force checking at least 1 byte of coverage
        self.check_user_pages_in_range(ptr.0.into(), size.max(1), false)?;
        // Now that we've validated all pages, do the actual pointer cast
        unsafe {
            (ptr.0 as *const T).as_ref().ok_or(Error::WouldFault {
                code: 0b100,
                address: usize::from(ptr).into(),
            })
        }
    }

    /// Check to see if a user-space address `ptr` is valid to convert to a mutable reference
    /// given that the current EL0 page tables remain active. If so, the reference is returned.
    ///
    /// # Errors
    /// If dereferencing the pointer would result in a fault, [`Error::WouldFault`] is returned.
    /// This includes if the memory is mapped as read-only.
    pub fn check_mut_ref<T>(&self, ptr: VirtualPointerMut<T>) -> Result<&'a mut T, Error> {
        let size = core::mem::size_of::<T>();
        self.check_user_pages_in_range(ptr.0.into(), size.max(1), true)?;
        unsafe {
            (ptr.0 as *mut T).as_mut().ok_or(Error::WouldFault {
                code: 0b100,
                address: ptr.cast(),
            })
        }
    }

    /// Check to see if a user-space slice starting at `ptr` with a length of `len` measured in `T`s
    /// is valid to convert to a regular slice of `T`s, given that the current EL0 page tables
    /// remain active. If so, the slice is returned.
    ///
    /// # Errors
    /// If dereferencing any index in the slice would result in a fault,
    /// [`Error::WouldFault`] is returned.
    pub fn check_slice<T>(&self, ptr: VirtualPointer<T>, len: usize) -> Result<&'a [T], Error> {
        use core::slice;
        let size = core::mem::size_of::<T>()
            .checked_mul(len)
            .ok_or(Error::WouldFault {
                code: 0xee,
                address: VirtualAddress::null(),
            })?;
        self.check_user_pages_in_range(ptr.0.into(), size.max(1), false)?;
        Ok(unsafe { slice::from_raw_parts(ptr.0 as *const T, len) })
    }

    /// Check to see if a user-space mutable slice starting at `ptr` with a length of `len`
    /// measured in `T`s is valid to convert to a regular slice of `T`s,
    /// given that the current EL0 page tables remain active. If so, the slice is returned.
    ///
    /// # Errors
    /// If dereferencing () any index in the slice would result in a fault,
    /// [`Error::WouldFault`] is returned.
    /// This includes mutating at an index.
    pub fn check_slice_mut<T>(
        &self,
        ptr: VirtualPointerMut<T>,
        len: usize,
    ) -> Result<&'a mut [T], Error> {
        use core::slice;
        let size = core::mem::size_of::<T>()
            .checked_mul(len)
            .ok_or(Error::WouldFault {
                code: 0xee,
                address: VirtualAddress::null(),
            })?;
        self.check_user_pages_in_range(ptr.0.into(), size.max(1), true)?;
        Ok(unsafe { slice::from_raw_parts_mut(ptr.0 as *mut T, len) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::eq;

    // helper to compute the page base for a given address and page size
    fn page_base(addr: usize, page_size: usize) -> usize {
        addr & !(page_size - 1)
    }

    #[derive(Debug, PartialEq)]
    struct Dummy(u32);

    #[test]
    fn test_check_ref_success() {
        // Create a dummy value and obtain its pointer.
        let dummy = Dummy(42);
        let dummy_ptr: *const Dummy = &dummy as *const _;
        let virt_ptr: VirtualPointer<Dummy> = VirtualPointer::from(dummy_ptr);

        // Set up the mock ActiveUserSpaceTables.
        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);
        let page_sz = usize::from(PageSize::FourKiB);
        let addr_usize = dummy_ptr as usize;
        let expected_page = page_base(addr_usize, page_sz);

        // Expect one translate call (for_write=false) for the page covering dummy.
        mock.expect_translate()
            .withf(move |va, write| *write == false && (va.0 as usize) == expected_page)
            .returning(move |va, _| Ok(PhysicalAddress::from(va.0)));

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        let result = checker.check_ref(virt_ptr);
        assert!(result.is_ok());
        assert_eq!(*result.unwrap(), Dummy(42));
    }

    #[test]
    fn test_check_ref_failure_due_to_unmapped_page() {
        let dummy = Dummy(100);
        let dummy_ptr: *const Dummy = &dummy as *const _;
        let virt_ptr: VirtualPointer<Dummy> = VirtualPointer::from(dummy_ptr);

        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);
        let page_sz = usize::from(PageSize::FourKiB);
        let expected_page = page_base(dummy_ptr as usize, page_sz);

        // Simulate an unmapped page by returning an error.
        mock.expect_translate()
            .withf(move |va, write| *write == false && (va.0 as usize) == expected_page)
            .returning(|_, _| {
                Err(Error::WouldFault {
                    code: 0b100,
                    address: VirtualAddress::null(),
                })
            });

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        let result = checker.check_ref(virt_ptr);
        assert!(result.is_err());
        if let Err(Error::WouldFault { code, .. }) = result {
            assert_eq!(code, 0b100);
        } else {
            panic!("Expected a WouldFault error");
        }
    }

    #[test]
    fn test_check_mut_ref_success() {
        let mut dummy = Dummy(10);
        let dummy_ptr: *mut Dummy = &mut dummy as *mut _;
        let virt_ptr: VirtualPointerMut<Dummy> = VirtualPointerMut::from(dummy_ptr);

        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);
        let page_sz = usize::from(PageSize::FourKiB);
        let expected_page = page_base(dummy_ptr as usize, page_sz);

        mock.expect_translate()
            .withf(move |va, write| *write == true && (va.0 as usize) == expected_page)
            .returning(move |va, _| Ok(PhysicalAddress::from(va.0)));

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        let result = checker.check_mut_ref(virt_ptr);
        assert!(result.is_ok());
        *result.unwrap() = Dummy(20);
        assert_eq!(dummy, Dummy(20));
    }

    #[test]
    fn test_check_mut_ref_failure_due_to_unwritable_page() {
        let mut dummy = Dummy(30);
        let dummy_ptr: *mut Dummy = &mut dummy as *mut _;
        let virt_ptr: VirtualPointerMut<Dummy> = VirtualPointerMut::from(dummy_ptr);

        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);
        let page_sz = usize::from(PageSize::FourKiB);
        let expected_page = page_base(dummy_ptr as usize, page_sz);

        mock.expect_translate()
            .withf(move |va, write| *write == true && (va.0 as usize) == expected_page)
            .returning(|_, _| {
                Err(Error::WouldFault {
                    code: 0b100,
                    address: VirtualAddress::null(),
                })
            });

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        let result = checker.check_mut_ref(virt_ptr);
        assert!(result.is_err());
        if let Err(Error::WouldFault { code, .. }) = result {
            assert_eq!(code, 0b100);
        } else {
            panic!("Expected a WouldFault error");
        }
    }

    #[test]
    fn test_check_slice_success_single_page() {
        let vec = vec![Dummy(1), Dummy(2), Dummy(3)];
        let slice_ptr = vec.as_ptr();
        let virt_ptr: VirtualPointer<Dummy> = VirtualPointer::from(slice_ptr);

        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);
        let page_sz = usize::from(PageSize::FourKiB);
        let expected_page = page_base(slice_ptr as usize, page_sz);

        // Expect translate for the one page covering the slice.
        mock.expect_translate()
            .withf(move |va, write| *write == false && (va.0 as usize) == expected_page)
            .returning(move |va, _| Ok(PhysicalAddress::from(va.0)));

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        let result = checker.check_slice(virt_ptr, vec.len());
        assert!(result.is_ok());
        let slice = result.unwrap();
        assert_eq!(slice, &vec[..]);
    }

    #[test]
    fn test_check_slice_mut_success_single_page() {
        let mut vec = vec![Dummy(5), Dummy(6), Dummy(7)];
        let slice_ptr = vec.as_mut_ptr();
        let virt_ptr: VirtualPointerMut<Dummy> = VirtualPointerMut::from(slice_ptr);

        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);
        let page_sz = usize::from(PageSize::FourKiB);
        let expected_page = page_base(slice_ptr as usize, page_sz);

        mock.expect_translate()
            .withf(move |va, write| *write == true && (va.0 as usize) == expected_page)
            .returning(move |va, _| Ok(PhysicalAddress::from(va.0)));

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        let result = checker.check_slice_mut(virt_ptr, vec.len());
        assert!(result.is_ok());
        let slice = result.unwrap();
        for elem in slice.iter_mut() {
            elem.0 += 1;
        }
        assert_eq!(vec, vec![Dummy(6), Dummy(7), Dummy(8)]);
    }

    #[test]
    fn test_check_slice_mut_failure_due_to_unmapped_page() {
        let mut vec = vec![Dummy(8), Dummy(9)];
        let slice_ptr = vec.as_mut_ptr();
        let virt_ptr: VirtualPointerMut<Dummy> = VirtualPointerMut::from(slice_ptr);

        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);
        let page_sz = usize::from(PageSize::FourKiB);
        let expected_page = page_base(slice_ptr as usize, page_sz);

        mock.expect_translate()
            .withf(move |va, write| *write == true && (va.0 as usize) == expected_page)
            .returning(|_, _| {
                Err(Error::WouldFault {
                    code: 0b100,
                    address: VirtualAddress::null(),
                })
            });

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        let result = checker.check_slice_mut(virt_ptr, vec.len());
        assert!(result.is_err());
        if let Err(Error::WouldFault { code, .. }) = result {
            assert_eq!(code, 0b100);
        } else {
            panic!("Expected a WouldFault error");
        }
    }

    #[test]
    fn test_check_user_pages_in_range_single_page_aligned() {
        // When the start is page-aligned and the length is less than a full page,
        // only one page should be checked.
        let start_addr = 0x2000; // page-aligned for 4KiB pages.
        let length = 0x800; // less than 4KiB.

        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);
        // Only one page at 0x2000 should be queried.
        mock.expect_translate()
            .with(eq(VirtualAddress::from(start_addr)), eq(false))
            .returning(move |_, _| Ok(PhysicalAddress::from(start_addr)));

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        assert!(checker
            .check_user_pages_in_range(VirtualAddress::from(start_addr), length, false)
            .is_ok());
    }

    #[test]
    fn test_check_user_pages_in_range_unaligned_start() {
        // When the start is not aligned, the check rounds down to the page boundary.
        let start_addr = 0x2010; // not aligned (page starts at 0x2000).
        let length = 0x100; // small length.
        let page_size = usize::from(PageSize::FourKiB);
        let first_page = start_addr & !(page_size - 1); // should be 0x2000.

        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);
        // Only the page starting at 0x2000 is checked.
        mock.expect_translate()
            .with(eq(VirtualAddress::from(first_page)), eq(false))
            .returning(move |_, _| Ok(PhysicalAddress::from(first_page)));

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        assert!(checker
            .check_user_pages_in_range(VirtualAddress::from(start_addr), length, false)
            .is_ok());
    }

    #[test]
    fn test_check_user_pages_in_range_multiple_pages() {
        // When the range spans multiple pages, every page in the interval should be translated.
        let start_addr = 0x3000; // aligned start.
        let page_size = usize::from(PageSize::FourKiB);
        // Span 3 pages: 0x3000, 0x4000, 0x5000.
        let length = page_size * 3;

        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);
        let mut seq = mockall::Sequence::new();
        for page in [0x3000, 0x4000, 0x5000].iter() {
            mock.expect_translate()
                .times(1)
                .in_sequence(&mut seq)
                .with(eq(VirtualAddress::from(*page)), eq(false))
                .returning(move |_, _| Ok(PhysicalAddress::from(*page)));
        }

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        assert!(checker
            .check_user_pages_in_range(VirtualAddress::from(start_addr), length, false)
            .is_ok());
    }

    #[test]
    fn test_check_user_pages_in_range_exact_boundary() {
        // The range exactly covers one page (from start to the end of that page).
        let start_addr = 0x4000;
        let page_size = usize::from(PageSize::FourKiB);
        let length = page_size; // exactly one full page.

        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);
        mock.expect_translate()
            .with(eq(VirtualAddress::from(0x4000)), eq(false))
            .returning(move |_, _| Ok(PhysicalAddress::from(0x4000)));

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        assert!(checker
            .check_user_pages_in_range(VirtualAddress::from(start_addr), length, false)
            .is_ok());
    }

    #[test]
    #[should_panic]
    fn test_check_user_pages_in_range_zero_length() {
        // Passing a zero length should panic (per the assert!(length_in_bytes > 0)).
        let start_addr = 0x5000;
        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        let _ = checker.check_user_pages_in_range(VirtualAddress::from(start_addr), 0, false);
    }

    #[test]
    fn test_check_user_pages_in_range_failure_on_middle_page() {
        // When one page in a multi‐page range fails translation, the method returns an error.
        let start_addr = 0x6000;
        let page_size = usize::from(PageSize::FourKiB);
        // Span two pages: 0x6000 and 0x7000.
        let length = page_size + 0x10; // ensures that the second page (0x7000) is touched.

        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);
        let mut seq = mockall::Sequence::new();

        // First page translates successfully.
        mock.expect_translate()
            .once()
            .in_sequence(&mut seq)
            .with(eq(VirtualAddress::from(0x6000)), eq(false))
            .returning(move |_, _| Ok(PhysicalAddress::from(0x6000)));

        // Second page translation fails.
        mock.expect_translate()
            .once()
            .in_sequence(&mut seq)
            .with(eq(VirtualAddress::from(0x7000)), eq(false))
            .returning(|_, _| {
                Err(Error::WouldFault {
                    code: 0b101,
                    address: VirtualAddress::null(),
                })
            });

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        let res =
            checker.check_user_pages_in_range(VirtualAddress::from(start_addr), length, false);
        assert!(res.is_err());
        if let Err(Error::WouldFault { code, .. }) = res {
            assert_eq!(code, 0b101);
        } else {
            panic!("Expected a WouldFault error");
        }
    }

    #[test]
    fn test_check_user_pages_in_range_odd_length_spanning_pages() {
        // When the start is unaligned and length is odd, the method must check both the rounded-down start page
        // and the additional page covering the tail of the range.
        let start_addr = 0x803; // unaligned (page starts at 0x800)
        let page_size = usize::from(PageSize::FourKiB); // 0x1000 = 4096
                                                        // Choose a length that spans from 0x803 to 100 bytes into the second page.
        let length = (page_size - 0x803) + 100;

        let first_page = 0x803 & !(page_size - 1); // should be 0x800.
        let second_page = first_page + page_size; // 0x1800.

        let mut mock = MockActiveUserSpaceTables::new();
        mock.expect_page_size().return_const(PageSize::FourKiB);

        let mut seq = mockall::Sequence::new();
        mock.expect_translate()
            .once()
            .in_sequence(&mut seq)
            .with(eq(VirtualAddress::from(first_page)), eq(false))
            .returning(move |_, _| Ok(PhysicalAddress::from(first_page)));

        mock.expect_translate()
            .once()
            .in_sequence(&mut seq)
            .with(eq(VirtualAddress::from(second_page)), eq(false))
            .returning(move |_, _| Ok(PhysicalAddress::from(second_page)));

        let checker = ActiveUserSpaceTablesChecker::from(&mock);
        assert!(checker
            .check_user_pages_in_range(VirtualAddress::from(start_addr), length, false)
            .is_ok());
    }
}
