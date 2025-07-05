//! Devicetree blob parser.
//!
//! Parser/search routines for the
//! [Devicetree Specification](https://github.com/devicetree-org/devicetree-specification)
//! to obtain hardware/boot parameters.
//!
//! This is designed to require no allocation/copying so that it can be used as soon as possible
//! during the boot process.
//! Individual device drivers are expected to make sense of the exact structure of the information
//! in their respective portion of the tree, but this module contains common structures and
//! iterators to make that easier.
#![no_std]
extern crate alloc;

use core::{ffi::CStr, fmt::Debug};

use byteorder::{BigEndian, ByteOrder};
use itertools::Itertools;
use snafu::Snafu;

pub mod fdt;
pub mod iter;

/// A list of strings given as the value of a property.
#[derive(Clone)]
pub struct StringList<'dt> {
    /// The raw bytes of the list of strings.
    pub data: &'dt [u8],
}

impl StringList<'_> {
    /// Determine if the byte sequence `s` is in the list of strings.
    #[must_use]
    pub fn contains(&self, s: &[u8]) -> bool {
        self.data.windows(s.len()).any(|w| w == s)
    }

    /// Iterate over the strings present in the list as C strings.
    #[must_use]
    pub fn iter(&self) -> iter::StringListIter<'_> {
        iter::StringListIter {
            data: self.data,
            current_offset: 0,
        }
    }
}

impl<'a: 'dt, 'dt> IntoIterator for &'a StringList<'dt> {
    type IntoIter = iter::StringListIter<'dt>;
    type Item = &'dt core::ffi::CStr;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl core::fmt::Debug for StringList<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// An array of (address, length) pairs representing the address space regions of a device's resources.
#[derive(Clone)]
pub struct Registers<'dt> {
    /// Raw bytes that make up the array.
    pub data: &'dt [u8],
    /// Number of u32 cells that make up an address.
    pub address_cells: u32,
    /// Number of u32 cells that make up a size.
    pub size_cells: u32,
}

impl Registers<'_> {
    /// Iterate over the (address, length) pairs contained in this array.
    ///
    /// These are yielded as `usize`.
    #[must_use]
    pub fn iter(&self) -> iter::RegistersIter<'_, '_> {
        iter::RegistersIter {
            regs: self,
            offset: 0,
        }
    }
}

impl<'a: 'dt, 'dt> IntoIterator for &'a Registers<'dt> {
    type IntoIter = iter::RegistersIter<'a, 'dt>;
    type Item = (usize, usize);
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl core::fmt::Debug for Registers<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// A property value in a device tree.
#[derive(Debug, Clone)]
pub enum Value<'dt> {
    /// A 32-bit integer.
    U32(u32),
    #[allow(unused)]
    /// A 64-bit integer.
    U64(u64),
    /// A `phandle` value that references another node.
    Phandle(u32),
    /// A single printable string.
    String(&'dt CStr),
    /// A list of strings.
    StringList(StringList<'dt>),
    /// A blob of bytes. This means the property has a device specific format.
    Bytes(&'dt [u8]),
    /// An array of (address, length) pairs representing the address space regions of a device's resources.
    Reg(Registers<'dt>),
}

impl<'dt> Value<'dt> {
    /// Parse bytes into a value based on the name and expected type.
    fn parse(name: &[u8], bytes: &'dt [u8], address_cells: u32, size_cells: u32) -> Value<'dt> {
        // See Devicetree Specification section 2.3
        match name {
            b"compatible" => Value::StringList(StringList { data: bytes }),
            b"model" | b"status" | b"device_type" => match CStr::from_bytes_until_nul(bytes) {
                Ok(s) => Value::String(s),
                Err(_) => Value::Bytes(bytes),
            },
            b"phandle" => Value::Phandle(BigEndian::read_u32(bytes)),
            b"#address-cells" | b"#size-cells" | b"virtual-reg" => {
                Value::U32(BigEndian::read_u32(bytes))
            }
            b"reg" => Value::Reg(Registers {
                data: bytes,
                address_cells,
                size_cells,
            }),
            _ => Value::Bytes(bytes),
        }
    }

    /// Try to extract the value as a Rust `u32` if it is of type `u32`.
    ///
    /// # Errors
    ///
    /// Returns a `ParseError::UnexpectedType` if the value is not of type `u32`.
    pub fn as_u32(&self, name: &'dt [u8]) -> Result<&u32, ParseError<'dt>> {
        if let Self::U32(ref v) = *self {
            Ok(v)
        } else {
            Err(ParseError::UnexpectedType {
                name,
                value: self.clone(),
                expected_type: "u32",
            })
        }
    }

    /// Try to extract the value as a Rust `u64` if it is of type `u64`.
    ///
    /// # Errors
    ///
    /// Returns a `ParseError::UnexpectedType` if the value is not of type `u64`.
    pub fn as_u64(&self, name: &'dt [u8]) -> Result<&u64, ParseError<'dt>> {
        if let Self::U64(ref v) = *self {
            Ok(v)
        } else {
            Err(ParseError::UnexpectedType {
                name,
                value: self.clone(),
                expected_type: "u64",
            })
        }
    }

    /// Try to extract the value as a Rust `u32` if it is of type `phandle`.
    ///
    /// # Errors
    ///
    /// Returns a `ParseError::UnexpectedType` if the value is not of type `phandle`.
    pub fn as_phandle(&self, name: &'dt [u8]) -> Result<&u32, ParseError<'dt>> {
        if let Self::Phandle(ref v) = *self {
            Ok(v)
        } else {
            Err(ParseError::UnexpectedType {
                name,
                value: self.clone(),
                expected_type: "phandle",
            })
        }
    }

    /// Try to extract the value as a Rust [`CStr`] if it is of type `string`.
    ///
    /// # Errors
    ///
    /// Returns a `ParseError::UnexpectedType` if the value is not of type `string`.
    pub fn as_string(&self, name: &'dt [u8]) -> Result<&'dt CStr, ParseError<'dt>> {
        if let Self::String(v) = *self {
            Ok(v)
        } else {
            Err(ParseError::UnexpectedType {
                name,
                value: self.clone(),
                expected_type: "string",
            })
        }
    }

    /// Try to extract the value as [`StringList`] if it is of type `stringlist`.
    ///
    /// # Errors
    ///
    /// Returns a `ParseError::UnexpectedType` if the value is not of type `stringlist`.
    pub fn as_strings(&self, name: &'dt [u8]) -> Result<&StringList<'dt>, ParseError<'dt>> {
        if let Self::StringList(ref v) = *self {
            Ok(v)
        } else {
            Err(ParseError::UnexpectedType {
                name,
                value: self.clone(),
                expected_type: "stringlist",
            })
        }
    }

    /// Try to extract the value as a Rust `&[u8]` if it is unparsed, returning the raw bytes.
    ///
    /// # Errors
    ///
    /// Returns a `ParseError::UnexpectedType` if the value is not of type `bytes`.
    pub fn as_bytes(&self, name: &'dt [u8]) -> Result<&'dt [u8], ParseError<'dt>> {
        if let Self::Bytes(v) = *self {
            Ok(v)
        } else {
            Err(ParseError::UnexpectedType {
                name,
                value: self.clone(),
                expected_type: "bytes",
            })
        }
    }

    /// Try to extract the value as [`Registers`] if it is of type `reg`.
    ///
    /// # Errors
    ///
    /// Returns a `ParseError::UnexpectedType` if the value is not of type `reg`.
    pub fn as_reg(&self, name: &'dt [u8]) -> Result<&Registers<'dt>, ParseError<'dt>> {
        if let Self::Reg(ref v) = *self {
            Ok(v)
        } else {
            Err(ParseError::UnexpectedType {
                name,
                value: self.clone(),
                expected_type: "reg",
            })
        }
    }

    /// If the value is of type `u32`, extract the value as a Rust `u32`.
    #[must_use]
    pub fn into_u32(self) -> Option<u32> {
        if let Self::U32(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// If the value is of type `u64`, extract the value as a Rust `u64`.
    #[must_use]
    pub fn into_u64(self) -> Option<u64> {
        if let Self::U64(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// If the value is of type `phandle`, extract the value as a Rust `u32`.
    #[must_use]
    pub fn into_phandle(self) -> Option<u32> {
        if let Self::Phandle(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// If the value is of type `string`, extract the value as a Rust [`CStr`].
    #[must_use]
    pub fn into_string(self) -> Option<&'dt CStr> {
        if let Self::String(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// If the value is of type `stringlist`, extract the value as [`StringList`].
    #[must_use]
    pub fn into_strings(self) -> Option<StringList<'dt>> {
        if let Self::StringList(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// If the value is unparsed, extract the value as a Rust `&[u8]`, returning the raw bytes.
    #[must_use]
    pub fn into_bytes(self) -> Option<&'dt [u8]> {
        if let Self::Bytes(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// If the value is of type `reg`, extract the value as [`Registers`].
    #[must_use]
    pub fn into_reg(self) -> Option<Registers<'dt>> {
        if let Self::Reg(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

/// A device tree blob in memory.
pub struct DeviceTree<'a> {
    header: fdt::BlobHeader<'a>,
    strings: &'a [u8],
    structure: &'a [u8],
    mem_map: &'a [u8],
}

impl DeviceTree<'_> {
    /// Create a [`DeviceTree`] struct that represents a device tree blob resident in memory of an
    /// unknown size, like one provided by U-boot.
    ///
    /// # Panics
    ///
    /// This function panics if the header present in `buf` is incorrect, in particular if:
    /// - the magic value is incorrect.
    /// - the total length reported in the header does not match the length of the slice.
    ///
    /// # Safety
    /// It is up to the caller to make sure that `ptr` actually points to a valid, mapped device
    /// tree blob, and that it will live for the `'a` lifetime at this address.
    ///
    pub unsafe fn from_memory<'a>(ptr: *mut u8) -> DeviceTree<'a> {
        use core::slice;
        unsafe {
            // discover the actual size of the tree from the header
            let header = fdt::BlobHeader {
                buf: slice::from_raw_parts(ptr, fdt::HEADER_SIZE),
            };
            let buf = slice::from_raw_parts(ptr, header.total_size() as usize);
            Self::from_bytes_and_header(buf, header)
        }
    }

    /// Returns the (start, length in bytes) memory region that is occupied by the device tree blob.
    #[must_use]
    pub fn memory_region(&self) -> (*mut u8, usize) {
        (
            self.header.buf.as_ptr().cast_mut(),
            self.header.total_size() as usize,
        )
    }

    /// Create a [`DeviceTree`] that parses the blob present in `buf`.
    ///
    ///
    /// # Panics
    ///
    /// This function panics if the header present in `buf` is incorrect, in particular if:
    /// - the magic value is incorrect.
    /// - the total length reported in the header does not match the length of the slice.
    #[must_use]
    pub fn from_bytes(buf: &[u8]) -> DeviceTree<'_> {
        let header = fdt::BlobHeader { buf };
        Self::from_bytes_and_header(buf, header)
    }

    fn from_bytes_and_header<'a>(buf: &'a [u8], header: fdt::BlobHeader<'a>) -> DeviceTree<'a> {
        assert_eq!(
            header.magic(),
            fdt::HEADER_EXPECTED_MAGIC,
            "buffer header has incorrect magic value"
        );
        assert_eq!(
            header.total_size() as usize,
            buf.len(),
            "buffer incorrect size according to header"
        );

        let str_start = header.off_dt_strings() as usize;
        let str_end = str_start + header.size_dt_strings() as usize;
        let structs_start = header.off_dt_struct() as usize;
        let structs_end = structs_start + header.size_dt_structs() as usize;

        DeviceTree {
            header,
            strings: &buf[str_start..str_end],
            structure: &buf[structs_start..structs_end],
            mem_map: &buf[header.off_mem_rsvmap() as usize..header.off_dt_struct() as usize],
        }
    }

    /// Get the header for the blob.
    #[must_use]
    pub fn header(&self) -> fdt::BlobHeader<'_> {
        self.header
    }

    /// Iterate over the raw flattened tree blob structure.
    #[must_use]
    pub fn iter_structure(&self) -> iter::FlattenedTreeIter<'_> {
        iter::FlattenedTreeIter {
            current_offset: 0,
            dt: self,
        }
    }

    /// Iterate over the properties of a node in the tree given the path, if present.
    ///
    /// # Arguments
    /// * `path` - the path of the node to find
    ///
    /// # Returns
    /// An iterator over the properties of the node in the tree, if present.
    #[must_use]
    pub fn iter_node_properties(&self, path: &[u8]) -> Option<iter::NodePropertyIter<'_>> {
        let mut segments = path.split(|p| *p == b'/');
        let mut looking_for = segments.next()?;
        let mut tokens = self.iter_structure();
        let mut current_address_cells: Option<u32> = None;
        let mut current_size_cells: Option<u32> = None;
        while let Some(token) = tokens.next() {
            match token {
                fdt::Token::StartNode(name) => {
                    if name == looking_for {
                        // enter the node
                        match segments.next() {
                            None | Some(&[]) => {
                                return Some(iter::NodePropertyIter {
                                    cur: tokens,
                                    depth: 1,
                                    // defaults from the spec in section 2.3.5
                                    parent_address_cells: current_address_cells.unwrap_or(2),
                                    parent_size_cells: current_size_cells.unwrap_or(1),
                                });
                            }
                            Some(next_segment) => {
                                looking_for = next_segment;
                            }
                        }
                    } else {
                        // skip this node and all of its children
                        tokens.skip_node();
                    }
                }
                // because we skip everything that is not on the path, these will only be
                // encountered in parents of the node we are searching for
                fdt::Token::EndNode => return None,
                fdt::Token::Property { name, data } => match name {
                    b"#address-cells" => current_address_cells = Some(BigEndian::read_u32(data)),
                    b"#size-cells" => current_size_cells = Some(BigEndian::read_u32(data)),
                    _ => {}
                },
            }
        }
        None
    }

    /// Iterate over the nodes under `path` whose node-name is `node_name`, where nodes per the
    /// spec are given names of form `<node-name>@<unit-address>`.
    /// Each yielded item contains the `unit-address` and an iterator over the properties of that node.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the parent node under which to search for nodes.
    /// * `node_name` - The node-name to match against the nodes under the given path.
    ///
    /// # Returns
    ///
    /// An iterator over `NodeItem`, each containing the `unit-address` and properties iterator.
    /// Returns None if the `path` was not even found in the tree.
    #[must_use]
    pub fn iter_nodes_named<'q>(
        &self,
        path: &[u8],
        node_name: &'q [u8],
    ) -> Option<iter::NodesNamedIter<'_, 'q>> {
        let mut segments = path.split(|p| *p == b'/');
        let mut looking_for = segments.next()?;
        let mut tokens = self.iter_structure();
        let mut current_address_cells: Option<u32> = None;
        let mut current_size_cells: Option<u32> = None;
        while let Some(token) = tokens.next() {
            match token {
                fdt::Token::StartNode(name) => {
                    if name == looking_for {
                        // Enter the node.
                        match segments.next() {
                            None | Some(&[]) => {
                                // Found the node at `path`, create the iterator.
                                return Some(iter::NodesNamedIter {
                                    cur: tokens,
                                    depth: 1,
                                    node_name,
                                    parent_address_cells: current_address_cells.unwrap_or(2),
                                    parent_size_cells: current_size_cells.unwrap_or(1),
                                });
                            }
                            Some(next_segment) => {
                                looking_for = next_segment;
                            }
                        }
                    } else {
                        // Skip this node and its children.
                        tokens.skip_node();
                    }
                }
                fdt::Token::EndNode => return None,
                fdt::Token::Property { name, data } => match name {
                    b"#address-cells" => current_address_cells = Some(BigEndian::read_u32(data)),
                    b"#size-cells" => current_size_cells = Some(BigEndian::read_u32(data)),
                    _ => {}
                },
            }
        }
        None
    }

    /// Find a property in the tree by path, if it is present.
    ///
    /// # Arguments
    /// * `path` - the path to the property to find
    ///
    /// # Returns
    /// The value of the property if found.
    #[must_use]
    pub fn find_property(&self, path: &[u8]) -> Option<Value<'_>> {
        let split = path.iter().rev().find_position(|p| **p == b'/')?.0;
        let (node_path, property_name) = path.split_at(path.len() - split);

        self.iter_node_properties(node_path)?
            .find(|(name, _)| *name == property_name)
            .map(|(_, value)| value)
    }

    /// Iterate over the system reserved memory regions.
    #[must_use]
    pub fn iter_reserved_memory_regions(&self) -> iter::MemRegionIter<'_> {
        iter::MemRegionIter::for_data(self.mem_map)
    }
}

/// Errors that might arise while processing ("parsing") a node in the device tree.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ParseError<'dt> {
    /// The property was not found in the node.
    #[snafu(display("Property \"{name}\" not found"))]
    PropertyNotFound {
        /// The name of the desired property.
        name: &'static str,
    },

    /// The node was not found.
    #[snafu(display("Node \"{path}\" not found"))]
    NodeNotFound {
        /// The path of the desired node.
        path: &'static str,
    },

    /// A property was found to have an unexpected type.
    #[snafu(display("Expected value of type {expected_type} for property \"{}\", got: {value:?}", core::str::from_utf8(name).unwrap_or("<property name is invalid UTF-8>")))]
    UnexpectedType {
        /// The name of the property.
        name: &'dt [u8],
        /// The actual value of the property.
        value: Value<'dt>,
        /// A description of the type of value expected to be associated with this property.
        expected_type: &'static str,
    },

    /// A property was found to have an unexpected value.
    #[snafu(display("Unexpected value for property \"{}\", got: {value:?} ({reason})", core::str::from_utf8(name).unwrap_or("<property name is invalid UTF-8>")))]
    UnexpectedValue {
        /// The name of the property.
        name: &'dt [u8],
        /// The actual value of the property.
        value: Value<'dt>,
        /// A description further explaining why the value was unexpected.
        reason: &'static str,
    },
}

use alloc::string::String;

/// A [`ParseError`] that has owned values instead of borrowing them from the device tree.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum OwnedParseError {
    /// The property was not found in the node.
    #[snafu(display("Property \"{name}\" not found"))]
    PropertyNotFound {
        /// Name of the desired property.
        name: &'static str,
    },
    /// The node was not found.
    #[snafu(display("Node \"{path}\" not found"))]
    NodeNotFound {
        /// Path of the desired node.
        path: &'static str,
    },
    /// A property was found to have an unexpected type.
    #[snafu(display(
        "Expected value of type {expected_type} for property \"{name}\", got: {value:?}"
    ))]
    UnexpectedType {
        /// The name of the property.
        name: String,
        /// Formatted actual value of the property.
        value: String,
        /// Expected type of the property.
        expected_type: &'static str,
    },
    /// A property was found to have an unexpected value.
    #[snafu(display("Unexpected value for property \"{name}\", got: {value:?} ({reason})"))]
    UnexpectedValue {
        /// The name of the property.
        name: String,
        /// Formatted actual value of the property.
        value: String,
        /// A description further explaining why the value was unexpected.
        reason: &'static str,
    },
}

impl ParseError<'_> {
    /// Copy a [`ParseError`] onto the heap so it no longer references the device tree.
    #[must_use]
    pub fn to_owned(self) -> OwnedParseError {
        match self {
            ParseError::PropertyNotFound { name } => OwnedParseError::PropertyNotFound { name },
            ParseError::NodeNotFound { path } => OwnedParseError::NodeNotFound { path },
            ParseError::UnexpectedType {
                name,
                value,
                expected_type,
            } => OwnedParseError::UnexpectedType {
                name: String::from_utf8_lossy(name).into_owned(),
                value: alloc::format!("{value:?}"),
                expected_type,
            },
            ParseError::UnexpectedValue {
                name,
                value,
                reason,
            } => OwnedParseError::UnexpectedValue {
                name: String::from_utf8_lossy(name).into_owned(),
                value: alloc::format!("{value:?}"),
                reason,
            },
        }
    }
}

#[cfg(all(test, not(target_os = "none")))]
#[macro_use]
extern crate std;

#[cfg(test)]
mod tests {
    use std::{string::ToString as _, vec::Vec};

    use super::*;

    /// This test tree blob was generated using QEMU:
    ///
    /// ```bash
    /// $ qemu-system-aarch64 -machine virt,dumpdtb=kernel_core/src/platform/device_tree/test-tree.fdt
    /// ```
    const TEST_TREE_BLOB: &[u8] = include_bytes!("../test-tree.fdt");

    fn test_tree() -> DeviceTree<'static> {
        DeviceTree::from_bytes(TEST_TREE_BLOB)
    }

    #[test]
    fn find_property_at_root() {
        let tree = test_tree();
        match tree.find_property(b"/compatible") {
            Some(Value::StringList(ss)) => {
                assert!(ss.contains(b"linux,dummy-virt"));
            }
            c => panic!("unexpected value for /compatible: {c:?}"),
        }
    }

    #[test]
    fn find_property_in_child_of_root() {
        let tree = test_tree();
        match tree.find_property(b"/timer/compatible") {
            Some(Value::StringList(ss)) => {
                assert!(ss.contains(b"arm,armv7-timer"));
            }
            c => panic!("unexpected value for /compatible: {c:?}"),
        }
    }

    #[test]
    fn find_property_in_nested_child() {
        let tree = test_tree();
        match tree.find_property(b"/intc@8000000/v2m@8020000/phandle") {
            Some(Value::Phandle(v)) => {
                assert_eq!(v, 0x8003);
            }
            c => panic!("unexpected value for /intc@8000000/v2m@8020000/phandle: {c:?}"),
        }
    }

    #[test]
    fn cannot_find_nonexistent_property() {
        let tree = test_tree();
        let r = tree.find_property(b"/cpus/this/property/does/not/exist");
        assert!(r.is_none());
    }

    #[test]
    fn node_properties_exact() {
        let tree = test_tree();
        let mut properties = std::collections::HashSet::from([
            "clock-names",
            "clocks",
            "interrupts",
            "reg",
            "compatible",
        ]);

        for (name, _) in tree.iter_node_properties(b"/pl011@9000000").unwrap() {
            let name_str = core::str::from_utf8(name).unwrap();
            assert!(properties.remove(name_str));
        }

        assert!(
            properties.is_empty(),
            "did not find all properties: {properties:?}"
        );
    }

    #[test]
    fn reg_property() {
        let tree = test_tree();
        match tree.find_property(b"/intc@8000000/reg") {
            Some(Value::Reg(regs)) => {
                let mut i = regs.iter();
                assert_eq!(i.next(), Some((0x0800_0000, 0x1_0000)));
                assert_eq!(i.next(), Some((0x0801_0000, 0x1_0000)));
                assert_eq!(i.next(), None);
            }
            c => panic!("unexpected value for /intc@8000000/reg: {c:?}"),
        }
    }

    #[test]
    fn reg_property_nested() {
        let tree = test_tree();
        match tree.find_property(b"/cpus/cpu@0/reg") {
            Some(Value::Reg(regs)) => {
                assert_eq!(regs.address_cells, 1);
                assert_eq!(regs.size_cells, 0);
                let mut i = regs.iter();
                assert_eq!(i.next(), Some((0, 0)));
                assert_eq!(i.next(), None);
            }
            c => panic!("unexpected value for /cpus/cpu@0/reg: {c:?}"),
        }
    }

    #[test]
    fn test_iter_nodes_named_nonexistent() {
        let tree = test_tree();
        let nodes = tree.iter_nodes_named(b"/", b"nonexistent");
        assert!(
            nodes.is_some(),
            "Expected an iterator even if no nodes are found under '/'"
        );
        let mut nodes = nodes.unwrap();

        assert!(
            nodes.next().is_none(),
            "Expected no nodes named 'nonexistent' under '/'"
        );
    }

    #[test]
    fn test_iter_nodes_named_invalid_path() {
        let tree = test_tree();
        let nodes = tree.iter_nodes_named(b"/invalid/path", b"anynode");
        assert!(
            nodes.is_none(),
            "Expected 'None' for an invalid path '/invalid/path'"
        );
    }

    #[test]
    fn test_iter_nodes_named_memory() {
        let tree = test_tree();
        let nodes = tree.iter_nodes_named(b"/", b"memory");
        assert!(nodes.is_some(), "Expected to find 'memory' nodes under '/'");
        let mut nodes = nodes.unwrap();

        let node_item = nodes.next();
        assert!(
            node_item.is_some(),
            "Expected at least one 'memory' node under '/'"
        );

        let node_item = node_item.unwrap();

        if let Some(unit_addr) = node_item.unit_address {
            assert_eq!(
                unit_addr, b"40000000",
                "Unexpected unit address for 'memory' node"
            );

            // Check properties
            let mut found_device_type = false;
            for (name, value) in node_item.properties {
                println!(
                    "found property {}={:?}",
                    std::str::from_utf8(name).unwrap(),
                    value
                );
                if name == b"device_type" {
                    if let Value::String(s) = value {
                        assert_eq!(
                            s.to_str().unwrap(),
                            "memory",
                            "Unexpected 'device_type' value"
                        );
                        found_device_type = true;
                    }
                }
            }
            assert!(
                found_device_type,
                "Expected to find 'device_type' property in 'memory' node"
            );
        } else {
            panic!("Expected 'memory' node to have a unit address");
        }

        // Ensure there are no additional 'memory' nodes under '/'
        assert!(
            nodes.next().is_none(),
            "Expected only one 'memory' node under '/'"
        );
    }

    #[test]
    fn test_iter_nodes_named_virtio_mmio() {
        let tree = test_tree();
        let nodes = tree.iter_nodes_named(b"/", b"virtio_mmio");
        assert!(
            nodes.is_some(),
            "Expected to find 'virtio_mmio' nodes under '/'"
        );
        let nodes = nodes.unwrap();

        let mut unit_addresses = Vec::new();

        for node_item in nodes {
            if let Some(unit_addr) = node_item.unit_address {
                let unit_addr_str = std::str::from_utf8(unit_addr).unwrap();
                unit_addresses.push(unit_addr_str.to_string());

                // Check properties
                let mut found_compatible = false;
                for (name, value) in node_item.properties {
                    if name == b"compatible" {
                        if let Value::StringList(ss) = value {
                            assert!(
                                ss.contains(b"virtio,mmio"),
                                "Expected 'compatible' to contain 'virtio,mmio'"
                            );
                            found_compatible = true;
                        }
                    }
                }
                assert!(
                    found_compatible,
                    "Expected to find 'compatible' property in 'virtio_mmio' node"
                );
            } else {
                panic!("Expected 'virtio_mmio' node to have a unit address");
            }
        }

        // Check the number of 'virtio_mmio' nodes
        assert_eq!(
            unit_addresses.len(),
            32,
            "Expected 32 'virtio_mmio' nodes under '/'"
        );

        // Check that unit addresses increment correctly
        let expected_unit_addresses = (0..32)
            .map(|i| format!("a{:06x}", i * 0x200))
            .collect::<Vec<_>>();

        assert_eq!(
            unit_addresses, expected_unit_addresses,
            "Unit addresses do not match expected values"
        );
    }

    #[test]
    fn test_iter_nodes_named_v2m() {
        let tree = test_tree();
        let nodes = tree.iter_nodes_named(b"/intc@8000000", b"v2m");
        assert!(
            nodes.is_some(),
            "Expected to find 'v2m' nodes under '/intc@8000000'"
        );
        let mut nodes = nodes.unwrap();

        let node_item = nodes.next();
        assert!(
            node_item.is_some(),
            "Expected at least one 'v2m' node under '/intc@8000000'"
        );

        let node_item = node_item.unwrap();

        if let Some(unit_addr) = node_item.unit_address {
            let unit_addr_str = std::str::from_utf8(unit_addr).unwrap();
            assert_eq!(
                unit_addr_str, "8020000",
                "Unexpected unit address for 'v2m' node"
            );

            // Check properties
            let mut found_compatible = false;
            for (name, value) in node_item.properties {
                if name == b"compatible" {
                    if let Value::StringList(ss) = value {
                        assert!(
                            ss.contains(b"arm,gic-v2m-frame"),
                            "Expected 'compatible' to contain 'arm,gic-v2m-frame'"
                        );
                        found_compatible = true;
                    }
                }
            }
            assert!(
                found_compatible,
                "Expected to find 'compatible' property in 'v2m' node"
            );
        } else {
            panic!("Expected 'v2m' node to have a unit address");
        }

        // Ensure there are no additional 'v2m' nodes under '/intc@8000000'
        assert!(
            nodes.next().is_none(),
            "Expected only one 'v2m' node under '/intc@8000000'"
        );
    }
}
