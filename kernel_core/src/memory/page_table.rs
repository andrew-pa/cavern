//! Page tables data structure.

use bitfield::BitRange;
use log::trace;
use snafu::{ensure, ResultExt as _, Snafu};

use super::{PageAllocator, PageSize, PhysicalAddress, VirtualAddress};
use PageSize::{FourKiB, SixteenKiB};

/// Defines required cache coherence for memory shared across different cores.
#[derive(Clone, Default, Debug)]
pub enum Shareability {
    /// The memory is not shared, each core can have its own cache.
    Local,
    /// The memory is shared between cores in the same cluster, so inner caches must stay coherent.
    Cluster,
    #[default]
    /// The memory is shared between all cores in the system, so all (inner and outer) caches must stay coherent.
    Global,
}

impl Shareability {
    #[inline]
    const fn encode(&self) -> u64 {
        match self {
            Shareability::Local => 0b00,
            Shareability::Global => 0b10,
            Shareability::Cluster => 0b11,
        }
    }
}

impl From<u64> for Shareability {
    fn from(value: u64) -> Self {
        match value {
            0b00 => Shareability::Local,
            0b10 => Shareability::Global,
            0b11 => Shareability::Cluster,
            _ => panic!("unknown shareability flag: 0b{value:b}"),
        }
    }
}

/// Types of caching available for memory operations.
#[derive(Clone, Default, Debug)]
pub enum MemoryKind {
    /// "Normal" cached memory.
    #[default]
    Normal,
    /// Device memory that is uncached with strict access order (no gathering, reordering or early
    /// write acknowledgement). Ideal for memory mapped I/O.
    Device,
}

/// The correct value that must be written to the Memory Attribute Indirection Register (`MAIR_EL1`) for [`MemoryProperties`] to correctly encode the meaning of [`MemoryKind`].
///
/// Each byte in the MAIR maps to a [`MemoryKind`].
/// See `D17.2.97` of the `ARMv8` reference for details.
///
/// | Index (LE) | [`MemoryKind`] | Byte Value | Description |
/// |-------|----------------|------------|-------------|
/// |  `0`  | [`MemoryKind::Device`] |  `0b0000_0000`   | Device-nGnRE memory |
/// |  `1`  | [`MemoryKind::Normal`] |  `0b1111_1111`   | Normal memory, write back, read/write allocate, non-transient cache for inner and outer sharing. |
#[allow(clippy::unusual_byte_groupings)]
pub const MAIR_VALUE: u64 = 0x00_00_00_00__00_00_ff_00;

impl MemoryKind {
    /// See [`MAIR_VALUE`] for more details.
    #[inline]
    const fn encode(&self) -> u64 {
        match self {
            MemoryKind::Device => 0b000,
            MemoryKind::Normal => 0b001,
        }
    }
}

impl From<u64> for MemoryKind {
    fn from(value: u64) -> Self {
        match value {
            0b000 => MemoryKind::Device,
            0b001 => MemoryKind::Normal,
            _ => panic!("unknown memory kind: 0b{value:b}"),
        }
    }
}

/// The properties given to a particular memory mapping.
#[derive(Clone, Default)]
pub struct MemoryProperties {
    /// Determines cachability and load/store requirements.
    pub kind: MemoryKind,
    /// Enables access to this memory from user space (EL0).
    pub user_space_access: bool,
    /// Enable writes to this memory.
    pub writable: bool,
    /// Instructions can be fetched from this memory.
    pub executable: bool,
    /// Required cache coherence across cores for this memory.
    pub shareability: Shareability,
}

impl MemoryProperties {
    fn encode(&self) -> u64 {
        (u64::from(!self.executable) << 54)
            | (u64::from(!self.executable) << 53)
            | (self.shareability.encode() << 8)
            | (u64::from(!self.writable) << 7)
            | (u64::from(self.user_space_access) << 6)
            | (self.kind.encode() << 2)
    }

    fn decode(raw_entry: u64) -> Self {
        Self {
            executable: ((raw_entry >> 54) & 0x1) == 0,
            shareability: Shareability::from((raw_entry >> 8) & 0b11),
            writable: ((raw_entry >> 7) & 0x1) == 0,
            user_space_access: ((raw_entry >> 6) & 0x1) == 1,
            kind: MemoryKind::from((raw_entry >> 2) & 0b111),
        }
    }
}

impl core::fmt::Debug for MemoryProperties {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "MemProps<{:?} {:?} {}{} {}>",
            self.shareability,
            self.kind,
            if self.writable { "RW" } else { "R" },
            if self.executable { "X" } else { "" },
            if self.user_space_access { "*" } else { "K" }
        )
    }
}

/// The size of the granule used in a mapping operation.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum MapBlockSize {
    /// Maps by single pages.
    Page,
    /// Maps by small blocks in the Level 2 table.
    /// (2MiB with 4KiB pages, 32MiB with 16KiB pages, 512MiB with 64KiB pages)
    SmallBlock,
    /// Maps by big blocks in the Level 1 table.
    /// (1GiB with 4KiB pages, not available with 16KiB or 64KiB pages)
    LargeBlock,
}

impl MapBlockSize {
    /// Returns the largest block size supported by the hardware for a given page size.
    #[must_use]
    pub fn largest_supported_block_size(page_size: PageSize) -> Self {
        match page_size {
            FourKiB => MapBlockSize::LargeBlock,
            SixteenKiB => MapBlockSize::SmallBlock,
        }
    }

    /// Returns the length in pages of this block size.
    /// Returns None if the block size is not supported in the current page size.
    #[must_use]
    pub fn length_in_pages(&self, page_size: PageSize) -> Option<usize> {
        let entries_per_page = usize::from(page_size) / size_of::<Entry>();
        match self {
            MapBlockSize::Page => Some(1),
            MapBlockSize::SmallBlock => Some(entries_per_page),
            MapBlockSize::LargeBlock if page_size == FourKiB => {
                Some(entries_per_page * entries_per_page)
            }
            MapBlockSize::LargeBlock => None,
        }
    }

    /// Returns the length in bytes of this block size.
    /// Returns None if the block size is not supported in the current page size.
    #[must_use]
    pub fn length_in_bytes(&self, page_size: PageSize) -> Option<usize> {
        self.length_in_pages(page_size).map(|s| s * page_size)
    }
}

/// Errors that could arise in page table operations.
#[derive(Debug, Snafu)]
pub enum Error {
    /// Address was expected to be mapped, but was not.
    #[snafu(display("Expected address {address:?} to be mapped"))]
    NotMapped {
        /// Address that was not mapped in the region.
        address: VirtualAddress,
    },
    /// Address was mapped and cannot be remapped, for example because it was previously mapped with a larger block size.
    #[snafu(display("Address {address:?} is already incompatibly mapped"))]
    AlreadyMapped {
        /// Address that was already mapped in the region.
        address: VirtualAddress,
    },
    /// Error occurred in page allocator.
    Allocator {
        /// Cause of the error.
        source: super::Error,
    },
    /// A mapping was requested that is too small or too large for the system.
    InvalidCount,
    /// Virtual address has the wrong tag value for the table.
    InvalidTag {
        /// Address that was invalid.
        value: VirtualAddress,
    },
    /// Address is improperally aligned for the requested block size.
    InvalidAlignment {
        /// Address that was unaligned (physical or virtual).
        value: usize,
    },
}

#[derive(Eq, PartialEq, Debug, Default, Clone, Copy)]
#[repr(transparent)]
struct Entry(u64);

enum DecodedEntry {
    Empty,
    Table(PhysicalAddress),
    Block(PhysicalAddress),
    Page(PhysicalAddress),
}

impl Entry {
    /// Constructs a page table entry that is unoccupied.
    fn empty() -> Self {
        Self(0)
    }

    /// Construct a page table entry pointing to a lower table.
    fn for_table(table_address: PhysicalAddress) -> Self {
        let address = usize::from(table_address);
        assert_eq!(address & 0xfff, 0);
        Self(0b11 | (address as u64 & 0x0000_ffff_ffff_f000))
    }

    /// Construct a page table entry pointing to a memory block.
    fn for_block(base_address: PhysicalAddress, properties: &MemoryProperties) -> Self {
        let address = usize::from(base_address);
        assert_eq!(address & 0xfff, 0);
        Self(0b01 | (address as u64) | properties.encode() | (1 << 10/*access flag*/))
    }

    /// Construct a page table entry pointing to a memory page.
    fn for_page(base_address: PhysicalAddress, properties: &MemoryProperties) -> Self {
        let address = usize::from(base_address);
        assert_eq!(address & 0xfff, 0);
        Self(0b11 | (address as u64) | properties.encode() | (1 << 10/*access flag*/))
    }

    fn decode(self, occuring_at_level: u8) -> DecodedEntry {
        let address = PhysicalAddress::from((self.0 & 0x0000_ffff_ffff_f000) as usize);
        match (occuring_at_level, self.0 & 0b11) {
            (_, 0b00) => DecodedEntry::Empty,
            (3, 0b11) => DecodedEntry::Page(address),
            (_, 0b11) => DecodedEntry::Table(address),
            (0..=2, 0b01) => DecodedEntry::Block(address),
            (lvl, bits) => {
                panic!("invalid page table entry type/valid: level={lvl}, entry={bits:b}")
            }
        }
    }
}

/// Returns the index into the page table at `level` for `address` given the current `page_size`.
#[inline]
fn index_for_level(address: VirtualAddress, level: u8, page_size: PageSize) -> usize {
    let (msb, lsb) = match (level, page_size) {
        (4, FourKiB) => (11, 0),
        (3, FourKiB) => (20, 12),
        (2, FourKiB) => (29, 21),
        (1, FourKiB) => (38, 30),
        (0, FourKiB) => (47, 39),
        (4, SixteenKiB) => (13, 0),
        (3, SixteenKiB) => (24, 14),
        (2, SixteenKiB) => (35, 25),
        (1, SixteenKiB) => (46, 36),
        (0, SixteenKiB) => (47, 47),
        _ => panic!("unsupported page size"),
    };
    let addr = usize::from(address) as u64;
    let ix: u64 = addr.bit_range(msb, lsb);
    usize::try_from(ix).unwrap()
}

/// Returns the number of pages represented by a single page table entry at `level` given `page_size`.
fn pages_per_entry(level: u8, page_size: PageSize) -> usize {
    match page_size {
        FourKiB => match level {
            0 => 512 * 512 * 512,
            1 => 512 * 512,
            2 => 512,
            3 => 1,
            _ => panic!("invalid level {level}"),
        },
        // the level 0 table only has two entries
        SixteenKiB => match level {
            0 => 2 * 2048 * 2048,
            1 => 2048 * 2048,
            2 => 2048,
            3 => 1,
            _ => panic!("invalid level {level}"),
        },
    }
}

/// Page table traversal closure (recursive).
struct Walker<'a, 's, 'pa, F> {
    parent: &'s PageTables<'pa>,
    /// Level where entries will be passed to `f`.
    end_level: u8,
    block_size_in_bytes: usize,
    block_size_in_pages: usize,
    /// If true, the walker will create new tables for empty entries in the range. Otherwise an
    /// error will be returned when they are encountered.
    create_on_empty: bool,
    f: &'a mut F,
}

impl<F> Walker<'_, '_, '_, F>
where
    F: FnMut(*mut Entry, PhysicalAddress) -> Result<(), Error>,
{
    fn next_table_for_entry(
        &self,
        level: u8,
        address: VirtualAddress,
        entry: &mut Entry,
    ) -> Result<*mut Entry, Error> {
        match entry.decode(level) {
            DecodedEntry::Empty => {
                if self.create_on_empty {
                    let next_table = self
                        .parent
                        .page_allocator
                        .allocate_zeroed(1)
                        .context(AllocatorSnafu)?;
                    *entry = Entry::for_table(next_table);
                    Ok(next_table.cast().into())
                } else {
                    Err(Error::NotMapped { address })
                }
            }
            DecodedEntry::Table(table_pointer) => Ok(table_pointer.cast().into()),
            DecodedEntry::Block(_) | DecodedEntry::Page(_) => Err(Error::AlreadyMapped { address }),
        }
    }

    /// Recursively steps through the page tables to apply the callback function `f` to the entries in the range.
    ///
    /// # Arguments
    ///
    /// * `level` - The current level in the page table hierarchy.
    /// * `table_root` - Pointer to the current page table.
    /// * `virtual_start` - Starting virtual address for this step.
    /// * `physical_start` - Starting physical address for this step.
    /// * `count` - Number of blocks (of size `self.block_size*`) to process.
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Ok if successful, or an error if mapping fails.
    fn step(
        &mut self,
        level: u8,
        table_root: *mut Entry,
        virtual_start: VirtualAddress,
        physical_start: PhysicalAddress,
        count: usize,
    ) -> Result<(), Error> {
        assert!(count > 0);
        let start_index = index_for_level(virtual_start, level, self.parent.page_size);
        if level < self.end_level {
            let number_of_blocks_per_entry_at_this_level =
                pages_per_entry(level, self.parent.page_size) / self.block_size_in_pages;
            // iterate over entries, distributing the `count` blocks across entries
            let mut index = start_index;
            let mut num_blocks = 0;
            while num_blocks < count {
                assert!(index < self.parent.entries_per_page);
                let entry = unsafe { table_root.add(index).as_mut().expect("table is non-null") };
                let byte_offset = num_blocks * self.block_size_in_bytes;
                let next_vs = virtual_start.byte_add(byte_offset);
                let next_table: *mut Entry = self.next_table_for_entry(level, next_vs, entry)?;
                let start_at_next_level =
                    index_for_level(next_vs, level + 1, self.parent.page_size);
                let actual_blocks_in_next_level = (count - num_blocks)
                    .min(number_of_blocks_per_entry_at_this_level - start_at_next_level);
                #[cfg(test)]
                std::println!("L{level}.{index}/{num_blocks}; count={count}, #b/e={number_of_blocks_per_entry_at_this_level}, next_vs={next_vs:?}, next_table={next_table:?}, next_start={start_at_next_level} #b={actual_blocks_in_next_level}, (entry = {entry:x?}), {:?}", self.parent.page_size);
                self.step(
                    level + 1,
                    next_table,
                    next_vs,
                    physical_start.byte_add(byte_offset),
                    actual_blocks_in_next_level,
                )?;
                index += 1;
                num_blocks += actual_blocks_in_next_level;
            }
            Ok(())
        } else {
            let entry_count = self.parent.entries_per_page;
            let end_index = start_index + count;
            #[cfg(test)]
            std::println!("L{level}.{start_index}..{end_index}; count={count}, vs={virtual_start:?}, ps={physical_start:?}");
            assert!(end_index <= entry_count, "start_index({start_index}) + count({count}) = end_index({end_index}) > entries_per_table({entry_count})");
            for i in 0..count {
                let addr = physical_start.byte_add(i * self.block_size_in_bytes);
                let entry_ptr = unsafe { table_root.add(start_index + i) };
                (self.f)(entry_ptr, addr)?;
            }
            Ok(())
        }
    }
}

/// A page table data structure in memory.
///
/// This structure manages the entire tree of tables.
pub struct PageTables<'pa> {
    page_allocator: &'pa dyn PageAllocator,
    /// this is also the number of entries in one table (because a table takes exactly one page).
    entries_per_page: usize,
    root: *mut Entry,
    page_size: PageSize,
    /// true => pointers must have `0xffff` tag, false => must have `0x0000` tag.
    high_tag: bool,
}

// SAFETY: this is safe because each `PageTables` owns the memory it points to exclusively.
unsafe impl Send for PageTables<'_> {}
// SAFETY: this is safe because each `PageTables` owns the memory it points to exclusively, and
// mutation must happen via `&mut PageTables`.
unsafe impl Sync for PageTables<'_> {}

impl<'pa> PageTables<'pa> {
    /// Create a new page tables structure that has no mappings.
    ///
    /// # Errors
    /// - Returns an error if the page allocator fails to allocate the root table.
    pub fn empty(page_allocator: &'pa dyn PageAllocator) -> Result<Self, super::Error> {
        let root = page_allocator.allocate_zeroed(1)?;
        unsafe { Ok(Self::from_existing(page_allocator, root, false)) }
    }

    /// Convert existing page tables in memory into a [`PageTables`] instance.
    /// If `high_tag` is true, these tables will be for mapping addresses starting with `0xffff`, i.e. the TTBR1 table.
    ///
    /// # Safety
    /// - The `root_table_address` must point to a valid root page table in memory.
    /// - Any pages already in the tables must have come from `page_allocator`.
    /// - The pages already in the tables must not be shared with any other instance of `PageTables`.
    ///
    /// # Panics
    /// - If the root table address is null or not aligned to the size of a page.
    pub unsafe fn from_existing(
        page_allocator: &'pa dyn PageAllocator,
        root_table_address: PhysicalAddress,
        high_tag: bool,
    ) -> Self {
        let root: *mut Entry = root_table_address.cast().into();
        assert!(!root.is_null());
        assert!(root.is_aligned_to(usize::from(page_allocator.page_size())));
        Self {
            page_allocator,
            page_size: page_allocator.page_size(),
            entries_per_page: usize::from(page_allocator.page_size()) / size_of::<Entry>(),
            root,
            high_tag,
        }
    }

    /// Get the physical address of the root table.
    #[must_use]
    pub fn physical_address(&self) -> PhysicalAddress {
        PhysicalAddress::from(self.root.cast())
    }

    /// Returns true if this kernel is for "high tag" pointers, i.e. pointers where the top 16 bits are `0xffff`.
    #[must_use]
    pub fn high_tag(&self) -> bool {
        self.high_tag
    }

    fn for_each_entry_of_size<F: FnMut(*mut Entry, PhysicalAddress) -> Result<(), Error>>(
        &self,
        virtual_start: VirtualAddress,
        physical_start: PhysicalAddress,
        count: usize,
        size: MapBlockSize,
        create_on_empty: bool,
        mut f: F,
    ) -> Result<(), Error> {
        let end_level = match size {
            MapBlockSize::Page => 3,
            MapBlockSize::SmallBlock => 2,
            MapBlockSize::LargeBlock => {
                if self.page_size == FourKiB {
                    1
                } else {
                    panic!("large blocks not supported for >4KiB pages")
                }
            }
        };

        let block_size_in_pages = size.length_in_pages(self.page_size).unwrap();
        let block_size_in_bytes = self.page_size * block_size_in_pages;
        // ensure that the size of the mapping is within range
        // TODO: make this bound tighter
        ensure!(
            count > 0
                && count
                    .checked_mul(block_size_in_pages)
                    .is_some_and(|x| x < (1 << 48)),
            InvalidCountSnafu
        );
        ensure!(
            virtual_start.is_aligned_to(block_size_in_bytes),
            InvalidAlignmentSnafu {
                value: virtual_start
            }
        );
        ensure!(
            physical_start.is_aligned_to(block_size_in_bytes),
            InvalidAlignmentSnafu {
                value: physical_start
            }
        );

        Walker {
            parent: self,
            end_level,
            block_size_in_bytes,
            block_size_in_pages,
            create_on_empty,
            f: &mut f,
        }
        .step(0, self.root, virtual_start, physical_start, count)
    }

    /// Map a region of virtual addresses to a region of physical addresses in these page tables with
    /// the given `properties`.
    ///
    /// Both start pointers must be aligned to the `size` required alignment.
    /// The region will be of `count * block_length_in_pages(size) * page_size` bytes.
    ///
    /// # Errors
    /// - [`Error::InvalidTag`] if the virtual pointer has the wrong tag for this table.
    ///
    /// If one of these errors occurs, the region may be partially mapped in the table:
    /// - [`Error::AlreadyMapped`] if part of the region has already been mapped with a different block size.
    /// - [`Error::Allocator`] if an error occurs trying to allocate new tables.
    pub fn map(
        &mut self,
        virtual_start: VirtualAddress,
        physical_start: PhysicalAddress,
        count: usize,
        size: MapBlockSize,
        properties: &MemoryProperties,
    ) -> Result<(), Error> {
        ensure!(
            virtual_start.is_in_kernel_space() == self.high_tag,
            InvalidTagSnafu {
                value: virtual_start
            }
        );
        self.for_each_entry_of_size(
            virtual_start,
            physical_start,
            count,
            size,
            true,
            |entry_ptr, addr| {
                let entry = match size {
                    MapBlockSize::Page => Entry::for_page(addr, properties),
                    _ => Entry::for_block(addr, properties),
                };
                unsafe {
                    entry_ptr.write(entry);
                }
                Ok(())
            },
        )
    }

    /// Unmap a region of virtual addresses to a region of physical addresses in these page tables.
    ///
    /// # Errors
    /// - [`Error::InvalidTag`] if the virtual pointer has the wrong tag for this table.
    ///
    /// If one of these errors occurs, the region may be partially unmapped in the table:
    /// - [`Error::NotMapped`] if the region contains unmapped pages.
    pub fn unmap(
        &mut self,
        virtual_start: VirtualAddress,
        count: usize,
        size: MapBlockSize,
    ) -> Result<(), Error> {
        ensure!(
            virtual_start.is_in_kernel_space() == self.high_tag,
            InvalidTagSnafu {
                value: virtual_start
            }
        );
        self.for_each_entry_of_size(
            virtual_start,
            0.into(),
            count,
            size,
            false,
            |entry_ptr, _| {
                unsafe {
                    entry_ptr.write(Entry::empty());
                }
                Ok(())
            },
        )
    }

    /// Compute the physical address that these page tables map the virtual address `p` to.
    /// Returns `None` if there is no mapping for this address.
    #[must_use]
    pub fn physical_address_of(&self, p: VirtualAddress) -> Option<PhysicalAddress> {
        if p.is_in_kernel_space() != self.high_tag {
            return None;
        }

        let mut level = 0;
        let mut table = self.root;
        while level <= 3 {
            let index = index_for_level(p, level, self.page_size);
            unsafe {
                let entry_ptr = table.add(index);
                match (*entry_ptr).decode(level) {
                    DecodedEntry::Empty => return None,
                    DecodedEntry::Table(table_ptr) => {
                        table = table_ptr.cast().into();
                        level += 1;
                    }
                    DecodedEntry::Block(block_base_ptr) | DecodedEntry::Page(block_base_ptr) => {
                        let offset_mask = match (self.page_size, level) {
                            (FourKiB, 3) => 0xfff,
                            (FourKiB, 2) => 0x1f_ffff,
                            (FourKiB, 1) => 0x3fff_ffff,
                            (SixteenKiB, 3) => 0x3fff,
                            (SixteenKiB, 2) => 0x1ff_ffff,
                            (ps, level) => {
                                unreachable!("invalid level {level} at page size {ps:?}")
                            }
                        };
                        let offset = usize::from(p) & offset_mask;
                        #[cfg(test)]
                        std::println!("p={p:?} block_base={block_base_ptr:?}, offset={offset:x?} (mask={offset_mask:x})");
                        return Some(block_base_ptr.byte_add(offset));
                    }
                }
            }
        }
        None
    }

    fn write_table(
        &self,
        f: &mut core::fmt::Formatter<'_>,
        level: u8,
        table: *mut Entry,
    ) -> core::fmt::Result {
        writeln!(f, "table{level}@{table:x?}: [")?;
        for i in 0..self.entries_per_page {
            unsafe {
                let entry = table.add(i).as_ref().unwrap();
                if entry.0 == 0 {
                    continue;
                }
                for _ in 0..=level {
                    write!(f, "\t")?;
                }
                write!(f, "{i} R{:016x} ", entry.0)?;
                match entry.decode(level) {
                    DecodedEntry::Empty => {}
                    DecodedEntry::Table(physical_pointer) => {
                        self.write_table(f, level + 1, physical_pointer.cast().into())?;
                    }
                    DecodedEntry::Block(physical_pointer) => writeln!(
                        f,
                        "block@{physical_pointer:?} {:?}",
                        MemoryProperties::decode(entry.0)
                    )?,
                    DecodedEntry::Page(physical_pointer) => writeln!(
                        f,
                        "page@{physical_pointer:?} {:?}",
                        MemoryProperties::decode(entry.0)
                    )?,
                }
            }
        }
        for _ in 0..level {
            write!(f, "\t")?;
        }
        writeln!(f, "]")
    }

    fn drop_table(&mut self, level: u8, table: *mut Entry) {
        for i in 0..self.entries_per_page {
            let entry = unsafe { table.add(i).read() };
            if let DecodedEntry::Table(next_table) = entry.decode(level) {
                self.drop_table(level + 1, next_table.cast().into());
            }
        }
        self.page_allocator
            .free(PhysicalAddress::from(table.cast()), 1)
            .unwrap();
    }
}

impl core::fmt::Debug for PageTables<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(
            f,
            "PageTables (tag={}, entries/page={})",
            self.high_tag, self.entries_per_page
        )?;
        self.write_table(f, 0, self.root)
    }
}

impl Drop for PageTables<'_> {
    fn drop(&mut self) {
        trace!("dropping page tables @ {:x?}", self.root);
        self.drop_table(0, self.root);
    }
}

#[cfg(test)]
mod tests {
    use std::boxed::Box;

    use test_case::test_matrix;

    use crate::memory::{
        tests::MockPageAllocator, PageAllocator, PageSize, PhysicalAddress, VirtualAddress,
    };

    use super::*;

    use MapBlockSize::*;

    fn check_mapping(
        pt: &PageTables<'_>,
        physical_start: PhysicalAddress,
        virtual_start: VirtualAddress,
        count: usize,
        block_size: MapBlockSize,
        mapped_or_unmapped: bool,
    ) {
        let page_size = pt.page_allocator.page_size();
        let page_count = count * block_size.length_in_pages(page_size).unwrap();
        let pages_to_check: Box<dyn Iterator<Item = usize>> = if page_count > 2048 {
            // there are too many pages to check them all
            // we know the math is safe because page_count > 2
            Box::new(
                [
                    0,
                    1,
                    page_count / 2 - 1,
                    page_count / 2,
                    page_count / 2 + 1,
                    page_count - 2,
                    page_count - 1,
                ]
                .into_iter(),
            ) as _
        } else {
            Box::new(0..page_count) as _
        };
        for page_offset in pages_to_check {
            let offset = page_size * page_offset;
            let va = virtual_start.byte_add(offset);
            let expected_phy = physical_start.byte_add(offset);
            match (pt.physical_address_of(va), mapped_or_unmapped) {
                (None, true) => {
                    panic!("{va:?} should have been mapped to {expected_phy:?} but was unmapped")
                }
                (None, false) => {}
                (Some(p), true) => assert_eq!(
                    p, expected_phy,
                    "{va:?} mapped to {p:?} expected {expected_phy:?}"
                ),
                (Some(p), false) => panic!("{va:?} mapped to {p:?} but should have been unmapped"),
            }
        }
    }

    #[test_matrix(
        FourKiB,
        Page,
        [1, 2, 7, 64, 67, 512, 521, 1024, 1031],
        [0x0, 0xab00000000, 0xab00001000, 0xab00100000, 0xab001ff000, 0xab00200000]
    )]
    #[test_matrix(
        FourKiB,
        SmallBlock,
        [1, 2, 7, 64, 67, 512, 521, 1024, 1031],
        [0x0, 0xab00000000, 0xab00200000, 0xab20000000, 0xab3fe00000, 0xab40000000]
    )]
    #[test_matrix(
        FourKiB,
        LargeBlock,
        [1, 2, 7, 64, 67/*, 512, 521, 1024, 1031*/],
        [0x0, 0x40000000, 0x4000000000, 0x7fc0000000, 0x8000000000]
    )]
    #[test_matrix(
        SixteenKiB,
        Page,
        [1, 2, 7, 64, 67, 512, 521, 1024, 1031, 2048, 2053],
        [0x0, 0xfa00000000, 0xfa00004000, 0xfa01000000, 0xfa01ffc000, 0xfa02000000]
    )]
    #[test_matrix(
        SixteenKiB,
        SmallBlock,
        [1, 2, 7, 64, 67, 512, 521, 1024, 1031, 2048, 2053],
        [0x0, 0xfa00_0000_0000, 0xfa00_0200_0000, 0xfa08_0000_0000, 0xfa0f_fe00_0000, 0xfa10_0000_0000]
    )]
    fn basic_map_unmap(
        page_size: PageSize,
        block_size: MapBlockSize,
        count: usize,
        start_address: usize,
    ) {
        let pa = MockPageAllocator::new(page_size, 128);
        {
            let mut pt = PageTables::empty(&pa).unwrap();
            let start_address = VirtualAddress::from(start_address);
            pt.map(
                start_address,
                0.into(),
                count,
                block_size,
                &MemoryProperties::default(),
            )
            .expect("map range");
            check_mapping(&pt, 0.into(), start_address, count, block_size, true);
            pt.unmap(start_address, count, block_size)
                .expect("unmap range");
            check_mapping(&pt, 0.into(), start_address, count, block_size, false);
            drop(pt);
        }
        pa.end_check();
    }

    #[test_matrix([FourKiB, SixteenKiB])]
    fn offset_physical_address_of(page_size: PageSize) {
        let pa = MockPageAllocator::new(page_size, 8);
        {
            let mut pt = PageTables::empty(&pa).unwrap();
            pt.map(
                0xff_0000.into(),
                0xaaaa_0000.into(),
                1,
                Page,
                &MemoryProperties::default(),
            )
            .expect("map page");
            assert_eq!(
                pt.physical_address_of(0xff_0033.into()),
                Some(PhysicalAddress::from(0xaaaa_0033))
            );
        }
        pa.end_check();
    }

    #[test_matrix(FourKiB, [Page, SmallBlock, LargeBlock])]
    #[test_matrix(SixteenKiB, [Page, SmallBlock])]
    fn overlapping_map(page_size: PageSize, block_size: MapBlockSize) {
        let pa = MockPageAllocator::new(page_size, 128);
        {
            let mut pt = PageTables::empty(&pa).unwrap();
            let block_len = block_size.length_in_pages(page_size).unwrap() * pa.page_size();
            pt.map(
                0xeeee_0000_0000.into(),
                0xaaaa_0000_0000.into(),
                2,
                block_size,
                &MemoryProperties::default(),
            )
            .expect("map range");
            pt.map(
                (0xeeee_0000_0000 + block_len).into(),
                0xbbbb_0000_0000.into(),
                2,
                block_size,
                &MemoryProperties::default(),
            )
            .expect("map range");
            check_mapping(
                &pt,
                0xaaaa_0000_0000.into(),
                0xeeee_0000_0000.into(),
                1,
                block_size,
                true,
            );
            check_mapping(
                &pt,
                0xbbbb_0000_0000.into(),
                (0xeeee_0000_0000 + block_len).into(),
                2,
                block_size,
                true,
            );
            drop(pt);
        }
        pa.end_check();
    }

    //TODO: map-unmap-map again

    #[test_matrix(FourKiB, [Page, SmallBlock, LargeBlock])]
    #[test_matrix(SixteenKiB, [Page, SmallBlock])]
    fn partial_unmap_whole(page_size: PageSize, block_size: MapBlockSize) {
        let pa = MockPageAllocator::new(page_size, 128);
        {
            let mut pt = PageTables::empty(&pa).unwrap();
            let block_len = block_size.length_in_pages(page_size).unwrap() * pa.page_size();
            pt.map(
                0xeeee_0000_0000.into(),
                0xaaaa_0000_0000.into(),
                3,
                block_size,
                &MemoryProperties::default(),
            )
            .expect("map range");
            pt.unmap((0xeeee_0000_0000 + block_len).into(), 1, block_size)
                .expect("unmap middle");
            check_mapping(
                &pt,
                0xaaaa_0000_0000.into(),
                0xeeee_0000_0000.into(),
                1,
                block_size,
                true,
            );
            check_mapping(
                &pt,
                0.into(),
                (0xeeee_0000_0000 + block_len).into(),
                1,
                block_size,
                false,
            );
            check_mapping(
                &pt,
                (0xaaaa_0000_0000 + 2 * block_len).into(),
                (0xeeee_0000_0000 + 2 * block_len).into(),
                1,
                block_size,
                true,
            );
            drop(pt);
        }
        pa.end_check();
    }
    //TODO: if you map a block and then try to unmap a page in the block or try to remap a page in
    //the block, what should happen? implementing this the obvious way is complex, but returning an
    //error seems leaky.
}
