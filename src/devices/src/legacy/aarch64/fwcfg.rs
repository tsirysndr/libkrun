// Copyright 2026, the libkrun contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! QEMU fw_cfg (MMIO flavor), just enough of it to hand ACPI tables to EDK2.
//!
//! The EDK2 build libkrun boots (`ArmVirtKrun`) carries OvmfPkg's
//! `AcpiPlatformDxe` + `QemuFwCfgLibMmio`: it discovers a fw_cfg device through
//! the `qemu,fw-cfg-mmio` DTB node, reads QEMU's ACPI "table loader" script
//! from it, and installs the tables it describes. Without a fw_cfg device the
//! firmware publishes **no ACPI at all** — which strands ACPI-only guests
//! (e.g. Nanos, whose GIC/timer/device discovery is MADT/GTDT/DSDT-based).
//!
//! Register layout (per the QEMU spec, and what `QemuFwCfgLibMmio` expects):
//!
//!   base + 0  data register, up to 8 bytes wide. Reading N bytes pops the
//!             next N bytes of the selected item as a stream, packed
//!             big-endian into the register value (the guest byte-swaps).
//!   base + 8  selector, 16-bit, written big-endian. Selecting rewinds.
//!
//! The DMA interface is deliberately not implemented; the DTB node advertises
//! a 16-byte region, which makes the guest fall back to MMIO reads.

use std::collections::BTreeMap;

use crate::bus::BusDevice;

/// Well-known selector keys (from the fw_cfg spec).
const FW_CFG_SIGNATURE: u16 = 0x0000;
const FW_CFG_ID: u16 = 0x0001;
const FW_CFG_FILE_DIR: u16 = 0x0019;
/// First selector handed out to named files.
const FW_CFG_FILE_FIRST: u16 = 0x0020;

/// Size of a file name in a directory entry, including the NUL.
const FW_CFG_FNAME_SIZE: usize = 56;

const DATA_OFFSET: u64 = 0;
const SELECTOR_OFFSET: u64 = 8;

pub struct FwCfg {
    /// Item content by selector key.
    items: BTreeMap<u16, Vec<u8>>,
    /// Named files in insertion order: (name, selector).
    files: Vec<(String, u16)>,
    selector: u16,
    offset: usize,
}

impl Default for FwCfg {
    fn default() -> Self {
        Self::new()
    }
}

impl FwCfg {
    pub fn new() -> Self {
        let mut items = BTreeMap::new();
        items.insert(FW_CFG_SIGNATURE, b"QEMU".to_vec());
        // Feature bitmap: bit 0 = traditional interface, bit 1 = DMA (absent).
        items.insert(FW_CFG_ID, 1u32.to_le_bytes().to_vec());
        items.insert(FW_CFG_FILE_DIR, 0u32.to_be_bytes().to_vec());
        Self {
            items,
            files: Vec::new(),
            selector: 0,
            offset: 0,
        }
    }

    /// Add (or replace) a named file and rebuild the directory listing.
    pub fn add_file(&mut self, name: &str, content: Vec<u8>) {
        assert!(name.len() < FW_CFG_FNAME_SIZE, "fw_cfg name too long");
        let select = match self.files.iter().find(|(n, _)| n == name) {
            Some((_, s)) => *s,
            None => {
                let s = FW_CFG_FILE_FIRST + self.files.len() as u16;
                self.files.push((name.to_string(), s));
                s
            }
        };
        self.items.insert(select, content);
        self.rebuild_dir();
    }

    /// The FILE_DIR item: a big-endian count, then one entry per file
    /// (size u32 BE, select u16 BE, reserved u16, NUL-padded name).
    fn rebuild_dir(&mut self) {
        let mut dir = (self.files.len() as u32).to_be_bytes().to_vec();
        for (name, select) in &self.files {
            let size = self.items.get(select).map(|c| c.len()).unwrap_or(0) as u32;
            dir.extend_from_slice(&size.to_be_bytes());
            dir.extend_from_slice(&select.to_be_bytes());
            dir.extend_from_slice(&0u16.to_be_bytes());
            let mut fname = [0u8; FW_CFG_FNAME_SIZE];
            fname[..name.len()].copy_from_slice(name.as_bytes());
            dir.extend_from_slice(&fname);
        }
        self.items.insert(FW_CFG_FILE_DIR, dir);
    }
}

impl BusDevice for FwCfg {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        log::debug!(
            "fwcfg read: offset={offset} len={} selector={:#06x} item_offset={}",
            data.len(),
            self.selector,
            self.offset
        );
        data.fill(0);
        if offset != DATA_OFFSET {
            return;
        }
        // Pop the next data.len() stream bytes, in stream order. EDK2's
        // MmioReadBytes stores the register value to its buffer verbatim
        // (no byte swap — see OvmfPkg QemuFwCfgLibMmio.c), so the value must
        // be little-endian-packed: first stream byte in the LSB, which on
        // this bus means the slice carries the stream bytes in order.
        let n = data.len();
        if let Some(item) = self.items.get(&self.selector) {
            for (i, slot) in data.iter_mut().enumerate() {
                *slot = item.get(self.offset + i).copied().unwrap_or(0);
            }
            self.offset += n;
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        log::debug!("fwcfg write: offset={offset} data={data:02x?}");
        // Selector writes are big-endian on the bus; a 16-bit store of the
        // byte-swapped selector arrives here as [hi, lo].
        if offset == SELECTOR_OFFSET && data.len() == 2 {
            self.selector = u16::from_be_bytes([data[0], data[1]]);
            self.offset = 0;
        }
        // Data-register writes (legacy) are ignored.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select(dev: &mut FwCfg, key: u16) {
        dev.write(0, SELECTOR_OFFSET, &key.to_be_bytes());
    }

    /// The bus slice must carry the item's bytes in stream order: EDK2's
    /// MmioReadBytes stores the register value to its buffer verbatim, so the
    /// value must be little-endian-packed — first stream byte in the LSB.
    #[test]
    fn data_reads_preserve_stream_order() {
        let mut dev = FwCfg::new();
        select(&mut dev, FW_CFG_SIGNATURE);
        let mut buf = [0u8; 4];
        dev.read(0, DATA_OFFSET, &mut buf);
        assert_eq!(buf, *b"QEMU");
        let value = u32::from_le_bytes(buf);
        assert_eq!(value, u32::from_le_bytes(*b"QEMU")); // SIGNATURE_32('Q','E','M','U')
    }

    #[test]
    fn selecting_rewinds_and_reads_advance() {
        let mut dev = FwCfg::new();
        dev.add_file("etc/x", vec![1, 2, 3]);
        let sel = dev.files[0].1;
        select(&mut dev, sel);
        let mut b = [0u8; 1];
        dev.read(0, DATA_OFFSET, &mut b);
        assert_eq!(b[0], 1);
        dev.read(0, DATA_OFFSET, &mut b);
        assert_eq!(b[0], 2);
        select(&mut dev, sel);
        dev.read(0, DATA_OFFSET, &mut b);
        assert_eq!(b[0], 1);
        // Reads past the end return zeros.
        select(&mut dev, sel);
        let mut b8 = [0xffu8; 8];
        dev.read(0, DATA_OFFSET, &mut b8);
        assert_eq!(&b8[..3], &[1, 2, 3]); // stream order in the slice
        assert_eq!(&b8[3..], &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn file_dir_lists_files_big_endian() {
        let mut dev = FwCfg::new();
        dev.add_file("etc/table-loader", vec![0; 128]);
        dev.add_file("etc/acpi/tables", vec![0; 512]);
        let dir = dev.items.get(&FW_CFG_FILE_DIR).unwrap();
        assert_eq!(u32::from_be_bytes(dir[..4].try_into().unwrap()), 2);
        // First entry: size 128, selector 0x20, name.
        assert_eq!(u32::from_be_bytes(dir[4..8].try_into().unwrap()), 128);
        assert_eq!(u16::from_be_bytes(dir[8..10].try_into().unwrap()), 0x20);
        let name = &dir[12..12 + 16];
        assert_eq!(&name[..16], b"etc/table-loader");
    }
}
