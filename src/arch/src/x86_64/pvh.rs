// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

//! PVH boot (the x86/HVM direct boot ABI): builds the `hvm_start_info` structure
//! and its E820-style memory map in guest RAM, so an external kernel that
//! advertises a PVH `PHYS32_ENTRY` note (e.g. NetBSD's MICROVM kernel) can be
//! entered directly — instead of the Linux 64-bit boot protocol (zero page).
//!
//! The kernel is entered in 32-bit protected mode with paging off, `%ebx`
//! pointing at the `hvm_start_info` at [`layout::PVH_INFO_START`] (see
//! `regs::setup_regs_pvh` / `regs::setup_sregs_pvh`).

use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use super::layout::{CMDLINE_START, PVH_INFO_START, PVH_MEMMAP_START};

/// `hvm_start_info.magic` — "xEn3" little-endian.
const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336e_c578;
/// E820 usable RAM.
const E820_RAM: u32 = 1;

/// The boot info the guest receives, per the x86/HVM direct boot ABI
/// (Xen `arch-x86/hvm/start_info.h`). Layout is a stable ABI.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct hvm_start_info {
    pub magic: u32,
    pub version: u32,
    pub flags: u32,
    pub nr_modules: u32,
    pub modlist_paddr: u64,
    pub cmdline_paddr: u64,
    pub rsdp_paddr: u64,
    pub memmap_paddr: u64,
    pub memmap_entries: u32,
    pub reserved: u32,
}
// Safe: `hvm_start_info` is a `#[repr(C)]` POD of integers.
unsafe impl ByteValued for hvm_start_info {}

/// One entry of the PVH memory map (`hvm_memmap_table_entry`).
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct hvm_memmap_table_entry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,
    pub reserved: u32,
}
// Safe: POD of integers.
unsafe impl ByteValued for hvm_memmap_table_entry {}

#[derive(Debug)]
pub enum Error {
    /// Writing the hvm_start_info / memmap to guest memory failed.
    WriteStartInfo,
}

/// Write the E820-style memory map (from the guest RAM regions) followed by the
/// `hvm_start_info` at the fixed layout addresses. The kernel cmdline is expected
/// to already be at [`CMDLINE_START`] (libkrun's `load_cmdline` writes it there).
///
/// The start_info always lands at [`PVH_INFO_START`], so the vcpu setup can load
/// that constant into `%ebx` without threading the address around.
pub fn configure_pvh(guest_mem: &GuestMemoryMmap) -> Result<(), Error> {
    // 1. Memory map: mark every guest RAM region usable. libkrun has no ACPI
    //    tables to reserve here, and NetBSD's MICROVM only needs the RAM ranges.
    let mut addr = GuestAddress(PVH_MEMMAP_START);
    let mut entries: u32 = 0;
    for region in guest_mem.iter() {
        let entry = hvm_memmap_table_entry {
            addr: region.start_addr().raw_value(),
            size: region.len(),
            type_: E820_RAM,
            reserved: 0,
        };
        guest_mem
            .write_obj(entry, addr)
            .map_err(|_| Error::WriteStartInfo)?;
        addr =
            GuestAddress(addr.raw_value() + std::mem::size_of::<hvm_memmap_table_entry>() as u64);
        entries += 1;
    }

    // 2. The start_info itself. rsdp_paddr = 0: no ACPI (MICROVM doesn't need it).
    let info = hvm_start_info {
        magic: XEN_HVM_START_MAGIC_VALUE,
        version: 1,
        cmdline_paddr: CMDLINE_START,
        memmap_paddr: PVH_MEMMAP_START,
        memmap_entries: entries,
        rsdp_paddr: 0,
        ..Default::default()
    };
    guest_mem
        .write_obj(info, GuestAddress(PVH_INFO_START))
        .map_err(|_| Error::WriteStartInfo)?;

    Ok(())
}
