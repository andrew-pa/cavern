//! Device Tree iterators.
#![allow(clippy::module_name_repetitions)]
use core::ffi::CStr;

use byteorder::{BigEndian, ByteOrder as _};

use super::{Registers, Value, fdt};

fn pad_end_4b(num_bytes: usize) -> usize {
    num_bytes
        + if num_bytes % 4 == 0 {
            0
        } else {
            4 - (num_bytes % 4)
        }
}

/// Iterator over tree tokens in a device tree blob.
#[derive(Clone)]
pub struct FlattenedTreeIter<'dt> {
    pub(super) dt: &'dt super::DeviceTree<'dt>,
    pub(super) current_offset: usize,
}

impl core::fmt::Debug for FlattenedTreeIter<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FlattenedTreeIter")
            .field("current_offset", &self.current_offset)
            .finish()
    }
}

impl FlattenedTreeIter<'_> {
    /// Skips over a node and all its children in the flattened tree iterator.
    /// Assumes that the iterator has just yielded a [`fdt::Token::StartNode`] for the node to be skiped.
    pub fn skip_node(&mut self) {
        let mut depth = 1;
        for token in self {
            match token {
                fdt::Token::StartNode(_) => depth += 1,
                fdt::Token::EndNode => {
                    depth -= 1;
                    if depth == 0 {
                        return;
                    }
                }
                fdt::Token::Property { .. } => {}
            }
        }
    }
}

impl<'dt> Iterator for FlattenedTreeIter<'dt> {
    type Item = super::fdt::Token<'dt>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.current_offset += 4;
            match fdt::TokenType::from(BigEndian::read_u32(
                &self.dt.structure[(self.current_offset - 4)..],
            )) {
                fdt::TokenType::BeginNode => {
                    let mut name_end = self.current_offset;
                    while self.dt.structure.get(name_end).is_some_and(|b| *b != 0) {
                        name_end += 1;
                    }
                    let name = &self.dt.structure[self.current_offset..name_end];
                    self.current_offset = pad_end_4b(name_end + 1);
                    return Some(fdt::Token::StartNode(name));
                }
                fdt::TokenType::EndNode => return Some(fdt::Token::EndNode),
                fdt::TokenType::Prop => {
                    let length =
                        BigEndian::read_u32(&self.dt.structure[self.current_offset..]) as usize;
                    self.current_offset += 4;
                    let name_offset =
                        BigEndian::read_u32(&self.dt.structure[self.current_offset..]) as usize;
                    self.current_offset += 4;
                    let mut name_end = name_offset;
                    while self.dt.strings.get(name_end).is_some_and(|b| *b != 0) {
                        name_end += 1;
                    }
                    let name = &self.dt.strings[name_offset..name_end];
                    let data =
                        &self.dt.structure[self.current_offset..(self.current_offset + length)];
                    self.current_offset += pad_end_4b(length);
                    return Some(fdt::Token::Property { name, data });
                }
                fdt::TokenType::Nop => {}
                fdt::TokenType::End => return None,
                fdt::TokenType::Unknown(x) => panic!("unknown device tree token: {x}"),
            }
        }
    }
}

/// An iterator over reserved regions of memory.
#[derive(Clone, Debug)]
pub struct MemRegionIter<'dt> {
    data: &'dt [u8],
    current_offset: usize,
}

impl<'dt> MemRegionIter<'dt> {
    /// Creates a memory region iterator for the data of an arbitrary property.
    #[must_use]
    pub fn for_data(data: &'dt [u8]) -> Self {
        Self {
            data,
            current_offset: 0,
        }
    }
}

impl Iterator for MemRegionIter<'_> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let addr = BigEndian::read_u64(&self.data[self.current_offset..]);
        self.current_offset += 8;
        let size = BigEndian::read_u64(&self.data[self.current_offset..]);
        self.current_offset += 8;
        if addr == 0 && size == 0 {
            None
        } else {
            Some((addr, size))
        }
    }
}

/// Iterator over strings in a [`super::StringList`].
#[derive(Clone, Debug)]
pub struct StringListIter<'dt> {
    pub(super) data: &'dt [u8],
    pub(super) current_offset: usize,
}

impl<'dt> Iterator for StringListIter<'dt> {
    type Item = &'dt CStr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_offset >= self.data.len() {
            None
        } else {
            match CStr::from_bytes_until_nul(&self.data[self.current_offset..]) {
                Ok(s) => {
                    self.current_offset += s.to_bytes_with_nul().len();
                    Some(s)
                }
                Err(_) => None,
            }
        }
    }
}

/// Iterator over properties of a single node in the tree.
#[derive(Clone, Debug)]
pub struct NodePropertyIter<'a> {
    pub(super) cur: FlattenedTreeIter<'a>,
    pub(super) depth: usize,
    pub(super) parent_address_cells: u32,
    pub(super) parent_size_cells: u32,
}

impl NodePropertyIter<'_> {
    /// Get the `#address-cells` property defined by the parent of this node.
    #[must_use]
    pub fn parent_address_cells(&self) -> u32 {
        self.parent_address_cells
    }

    /// Get the `#size-cells` property defined by the parent of this node.
    #[must_use]
    pub fn parent_size_cells(&self) -> u32 {
        self.parent_size_cells
    }
}

impl<'a> Iterator for NodePropertyIter<'a> {
    type Item = (&'a [u8], Value<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.depth == 0 {
            return None;
        }
        for item in self.cur.by_ref() {
            match item {
                fdt::Token::StartNode(_) => {
                    // Increment depth if we enter another node
                    self.depth += 1;
                }
                fdt::Token::EndNode => {
                    // Decrement depth and stop if we've left the target node
                    self.depth -= 1;
                    if self.depth == 0 {
                        return None; // We're done once we exit the target node
                    }
                }
                fdt::Token::Property { name, data } => {
                    if self.depth == 1 {
                        // We're in the target node; yield the property
                        return Some((
                            name,
                            Value::parse(
                                name,
                                data,
                                self.parent_address_cells,
                                self.parent_size_cells,
                            ),
                        ));
                    }
                }
            }
        }
        None
    }
}

/// An iterator over the (address, length) pairs contained in this array of device register regions.
/// Constructed by a [`super::Registers`].
#[derive(Clone, Debug)]
pub struct RegistersIter<'a, 'dt> {
    pub(super) regs: &'a Registers<'dt>,
    pub(super) offset: usize,
}

impl Iterator for RegistersIter<'_, '_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.regs.data.len() {
            return None;
        }

        let mut address = 0usize;
        for _ in 0..self.regs.address_cells {
            address =
                (address << 32) | (BigEndian::read_u32(&self.regs.data[self.offset..]) as usize);
            self.offset += 4;

            if self.offset > self.regs.data.len() {
                return None;
            }
        }

        let mut size = 0usize;
        for _ in 0..self.regs.size_cells {
            size = (size << 32) | (BigEndian::read_u32(&self.regs.data[self.offset..]) as usize);
            self.offset += 4;

            if self.offset > self.regs.data.len() {
                return None;
            }
        }

        Some((address, size))
    }
}

/// An iterator over nodes with a specific name under a given path.
#[derive(Clone, Debug)]
pub struct NodesNamedIter<'dt, 'query> {
    pub(super) cur: FlattenedTreeIter<'dt>,
    pub(super) depth: usize,
    pub(super) node_name: &'query [u8],
    pub(super) parent_address_cells: u32,
    pub(super) parent_size_cells: u32,
}

/// Represents a node with its unit address and properties iterator.
#[derive(Clone, Debug)]
pub struct NodeItem<'dt> {
    /// The unit address of the node (the part after '@' in the node name), if any.
    pub unit_address: Option<&'dt [u8]>,
    /// An iterator over the properties of the node.
    pub properties: NodePropertyIter<'dt>,
}

impl<'dt> Iterator for NodesNamedIter<'dt, '_> {
    type Item = NodeItem<'dt>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(token) = self.cur.next() {
            match token {
                fdt::Token::StartNode(full_name) => {
                    self.depth += 1;

                    let (name, unit_address) = split_node_name(full_name);
                    if name == self.node_name {
                        // Clone the iterator at this point for the properties iterator.
                        let props_cur = self.cur.clone();
                        let parent_address_cells = self.parent_address_cells;
                        let parent_size_cells = self.parent_size_cells;
                        // Skip this node and its children in the main iterator.
                        self.cur.skip_node();
                        self.depth -= 1;
                        // Create the properties iterator.
                        let props_iter = NodePropertyIter {
                            cur: props_cur,
                            depth: 1,
                            parent_address_cells,
                            parent_size_cells,
                        };
                        // Return the node item.
                        return Some(NodeItem {
                            unit_address,
                            properties: props_iter,
                        });
                    }

                    // Skip this node and its children.
                    self.cur.skip_node();
                    self.depth -= 1;
                }
                fdt::Token::EndNode => {
                    self.depth -= 1;
                    if self.depth == 0 {
                        return None;
                    }
                }
                fdt::Token::Property { name, data } => {
                    // Update address and size cells if necessary.
                    match name {
                        b"#address-cells" => self.parent_address_cells = BigEndian::read_u32(data),
                        b"#size-cells" => self.parent_size_cells = BigEndian::read_u32(data),
                        _ => {}
                    }
                }
            }
        }
        None
    }
}

/// Splits a node's full name into the node name and unit address.
fn split_node_name(full_name: &[u8]) -> (&[u8], Option<&[u8]>) {
    if let Some(pos) = full_name.iter().position(|&c| c == b'@') {
        let name = &full_name[..pos];
        let unit_address = Some(&full_name[pos + 1..]);
        (name, unit_address)
    } else {
        (full_name, None)
    }
}
