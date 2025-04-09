//! Flatted Device Tree format definitions.

use byteorder::{BigEndian, ByteOrder as _};
use serde::{Deserialize, Serialize};

/// Values used to delimit structure in the flattened device tree.
///
/// Defined in Section 5.4.1 of the specification.
#[repr(u32)]
pub enum TokenType {
    /// Beginning of a node's representation.
    BeginNode = 0x01,
    /// End of a node's representation.
    EndNode = 0x02,
    /// A node property.
    Prop = 0x03,
    /// Ignored during parsing.
    Nop = 0x04,
    /// Marks the end of the tree structure.
    End = 0x09,
    /// Any encoutered tokens that are undefined by the specification.
    Unknown(u32),
}

impl From<u32> for TokenType {
    fn from(value: u32) -> Self {
        match value {
            0x01 => TokenType::BeginNode,
            0x02 => TokenType::EndNode,
            0x03 => TokenType::Prop,
            0x04 => TokenType::Nop,
            0x09 => TokenType::End,
            _ => TokenType::Unknown(value),
        }
    }
}

/// Device tree blob header.
#[derive(Copy, Clone)]
pub struct BlobHeader<'a> {
    /// Raw bytes that make up the header.
    pub buf: &'a [u8],
}

/// Total size of a header in bytes.
pub const HEADER_SIZE: usize = 10 * 4;
/// The magic value expected in the device tree header.
pub const HEADER_EXPECTED_MAGIC: u32 = 0xd00d_feed;

impl BlobHeader<'_> {
    /// Magic number. Should equal [`HEADER_EXPECTED_MAGIC`].
    #[must_use]
    pub fn magic(&self) -> u32 {
        BigEndian::read_u32(&self.buf[0..])
    }
    /// Total size of the blob.
    #[must_use]
    pub fn total_size(&self) -> u32 {
        BigEndian::read_u32(&self.buf[4..])
    }
    /// Offset to the structs region of the blob.
    #[must_use]
    pub fn off_dt_struct(&self) -> u32 {
        BigEndian::read_u32(&self.buf[8..])
    }
    /// Offset to the strings region of the blob.
    #[must_use]
    pub fn off_dt_strings(&self) -> u32 {
        BigEndian::read_u32(&self.buf[12..])
    }
    /// Offset to the memory reservation block.
    #[must_use]
    pub fn off_mem_rsvmap(&self) -> u32 {
        BigEndian::read_u32(&self.buf[16..])
    }
    /// Blob version code.
    #[must_use]
    pub fn version(&self) -> u32 {
        BigEndian::read_u32(&self.buf[20..])
    }
    /// Last compatible version this device tree is compatible with.
    #[must_use]
    pub fn last_comp_version(&self) -> u32 {
        BigEndian::read_u32(&self.buf[24..])
    }
    /// Physical ID of the boot CPU.
    #[must_use]
    pub fn boot_cpuid_phys(&self) -> u32 {
        BigEndian::read_u32(&self.buf[28..])
    }
    /// Size of the strings region of the blob.
    #[must_use]
    pub fn size_dt_strings(&self) -> u32 {
        BigEndian::read_u32(&self.buf[32..])
    }
    /// Size of the structs region of the blob.
    #[must_use]
    pub fn size_dt_structs(&self) -> u32 {
        BigEndian::read_u32(&self.buf[36..])
    }
}

impl core::fmt::Debug for BlobHeader<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlobHeader")
            .field("magic", &self.magic())
            .field("total_size", &self.total_size())
            .field("off_dt_struct", &self.off_dt_struct())
            .field("off_dt_strings", &self.off_dt_strings())
            .field("off_mem_rsvmap", &self.off_mem_rsvmap())
            .field("version", &self.version())
            .field("last_comp_version", &self.last_comp_version())
            .field("boot_cpuid_phys", &self.boot_cpuid_phys())
            .field("size_dt_strings", &self.size_dt_strings())
            .field("size_dt_structs", &self.size_dt_structs())
            .finish()
    }
}

/// A tree structural item.
#[derive(Debug, Serialize, Deserialize)]
pub enum Token<'dt> {
    /// The beginning of a node in the tree, with a particular name.
    StartNode(&'dt [u8]),
    /// The end of a node in the tree.
    EndNode,
    /// A property attached to some node.
    Property {
        /// The name of the property.
        name: &'dt [u8],
        /// The value associated with this property.
        data: &'dt [u8],
    },
}
