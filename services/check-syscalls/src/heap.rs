use crate::Testable;
use kernel_api::{ErrorCode, allocate_heap_pages, free_heap_pages};

// Test #1: allocate a small region, write/read every byte, then free it.
fn test_allocate_and_write() {
    let size = 4096;
    // should succeed
    let ptr = allocate_heap_pages(size).expect("allocation failed");
    unsafe {
        // turn it into a mutable slice
        let buf = core::slice::from_raw_parts_mut(ptr, size);
        // write
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        // verify
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, (i % 256) as u8);
        }
    }
    free_heap_pages(ptr, size).expect("free failed");
}

// Test #2: allocating zero bytes must error out with InvalidLength.
fn test_allocate_zero_length() {
    match allocate_heap_pages(0) {
        Err(ErrorCode::InvalidLength) => {}
        other => panic!("expected Err(InvalidLength), got {:?}", other),
    }
}

// Test #3: freeing a null pointer must error out with InvalidPointer.
fn test_free_null_pointer() {
    let ptr = core::ptr::null_mut();
    match free_heap_pages(ptr, 4096) {
        Err(ErrorCode::InvalidPointer) => {}
        other => panic!("expected Err(InvalidPointer), got {:?}", other),
    }
}

// Test #4: freeing with a zero size must error out with InvalidLength.
fn test_free_zero_length() {
    let size = 4096;
    let ptr = allocate_heap_pages(size).expect("allocation failed");
    match free_heap_pages(ptr, 0) {
        Err(ErrorCode::InvalidLength) => {}
        other => panic!("expected Err(InvalidLength), got {:?}", other),
    }
    // clean up so subsequent tests aren’t affected
    free_heap_pages(ptr, size).expect("cleanup free failed");
}

// Test #5: double‐free must produce an error (InvalidPointer).
fn test_double_free() {
    let size = 4096;
    let ptr = allocate_heap_pages(size).expect("allocation failed");
    free_heap_pages(ptr, size).expect("first free failed");
    match free_heap_pages(ptr, size) {
        Err(ErrorCode::InvalidPointer) => {}
        other => panic!(
            "expected Err(InvalidPointer) on double free, got {:?}",
            other
        ),
    }
}

// Test #6: many small allocations and frees must all succeed.
fn test_multiple_allocations() {
    const COUNT: usize = 8;
    let size = 1024;
    let mut ptrs = [core::ptr::null_mut(); COUNT];
    for p in &mut ptrs {
        *p = allocate_heap_pages(size).expect("alloc failed");
    }
    for &p in &ptrs {
        free_heap_pages(p, size).expect("free failed");
    }
}

// Test #7: allocating an absurdly large region must fail (OutOfMemory or InvalidLength).
fn test_allocate_out_of_memory() {
    let huge = usize::MAX;
    match allocate_heap_pages(huge) {
        Err(ErrorCode::OutOfMemory | ErrorCode::InvalidLength) => {}
        other => panic!(
            "expected Err(OutOfMemory)|Err(InvalidLength), got {:?}",
            other
        ),
    }
}

pub const TESTS: (&str, &[&dyn Testable]) = (
    "heap",
    &[
        &test_allocate_and_write,
        &test_allocate_zero_length,
        &test_free_null_pointer,
        &test_free_zero_length,
        &test_double_free,
        &test_multiple_allocations,
        &test_allocate_out_of_memory,
    ],
);
