# libkrun PVH boot patch (sketch)

Goal: boot an external x86_64 ELF kernel that advertises the **x86/HVM direct
boot ABI** (the Xen `PHYS32_ENTRY` note) via **PVH** instead of the Linux 64-bit
boot protocol — so NetBSD's `MICROVM` kernel (and any PVH kernel) boots under
libkrun/KVM.

Today (`v1.19.4`) `load_external_kernel` takes `load_result.kernel_load`
(the ELF `e_entry`, a 64-bit VA), ignores `load_result.pvh_boot_cap`, and the
vcpu is set up for the Linux protocol (long mode, `%rsi` → zero page). NetBSD's
entry doesn't speak that → instant `KVM_EXIT_SHUTDOWN`.

`linux-loader 0.13.2` already parses the note:
`KernelLoaderResult { kernel_load, pvh_boot_cap: elf::PvhBootCapability, .. }`.
So the loader work is done — we only add the *entry selection* + the *PVH vcpu
state* + the *`hvm_start_info`* in guest memory.

All file paths below are relative to the libkrun repo root.

## Status on this branch (`feat/pvh-boot`)

**Implemented** (the self-contained PVH primitives — §1–3 below):
- `src/arch/src/x86_64/layout.rs` — `PVH_INFO_START`, `PVH_MEMMAP_START`.
- `src/arch/src/x86_64/pvh.rs` (new) — `hvm_start_info` / `hvm_memmap_table_entry`
  + `configure_pvh(guest_mem)`; registered as `pub mod pvh;` in `mod.rs`.
- `src/arch/src/x86_64/regs.rs` — `setup_regs_pvh` + `setup_sregs_pvh`.

**Remaining** (mechanical wiring — §4–5; do this on Linux where it compiles):
thread an `is_pvh: bool` from `load_external_kernel` out through `load_payload`
(builder.rs:1283) → `PayloadConfig` (builder.rs:1425, add the field; set it at
the construction site builder.rs:1528) → `Vmm::configure_system` (lib.rs:271)
and `create_vcpus_x86_64` (builder.rs:1730) → `Vcpu::configure_x86_64`
(vstate.rs:1167). The exact edits are in §4–5.

---

## 1. `src/arch/src/x86_64/layout.rs` — reserve low-RAM addresses

The Linux path puts the zero page at `ZERO_PAGE_START = 0x7000`. For PVH we put
the `hvm_start_info` + its E820-style memmap in the same low region (below the
kernel at `HIMEM_START = 0x100000`). The cmdline already lives at
`CMDLINE_START = 0x20000` — we reuse it.

```rust
/// PVH boot: hvm_start_info + its memory-map table (below the kernel).
pub const PVH_INFO_START: u64 = 0x6000;
pub const PVH_MEMMAP_START: u64 = 0x7000; // reuses the (unused-in-PVH) zero-page slot
```

---

## 2. `src/arch/src/x86_64/pvh.rs` (new) — start_info structs + writer

The Xen ABI structs (stable). Make them `ByteValued` so `write_obj` works.

```rust
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};
use super::layout::{CMDLINE_START, PVH_INFO_START, PVH_MEMMAP_START};

const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336e_c578;
const E820_RAM: u32 = 1;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct hvm_start_info {
    pub magic: u32,          // XEN_HVM_START_MAGIC_VALUE
    pub version: u32,        // 1
    pub flags: u32,
    pub nr_modules: u32,
    pub modlist_paddr: u64,
    pub cmdline_paddr: u64,
    pub rsdp_paddr: u64,     // 0 — NetBSD MICROVM needs no ACPI
    pub memmap_paddr: u64,
    pub memmap_entries: u32,
    pub reserved: u32,
}
unsafe impl ByteValued for hvm_start_info {}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct hvm_memmap_table_entry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,          // E820_RAM, etc.
    pub reserved: u32,
}
unsafe impl ByteValued for hvm_memmap_table_entry {}

/// Write the memmap + hvm_start_info into guest RAM. `ram_regions` is the list of
/// (start, len) RAM ranges (from the GuestMemoryMmap regions). Returns the guest
/// address of the start_info, to be loaded into %ebx.
pub fn configure_pvh(
    guest_mem: &GuestMemoryMmap,
    ram_regions: &[(u64, u64)],
) -> Result<GuestAddress, vm_memory::GuestMemoryError> {
    // 1. memmap table (E820-style). Mark all RAM as usable; libkrun has no ACPI
    //    tables to reserve, and NetBSD only needs the RAM ranges here.
    let mut addr = GuestAddress(PVH_MEMMAP_START);
    let mut n = 0u32;
    for (start, len) in ram_regions {
        let e = hvm_memmap_table_entry {
            addr: *start,
            size: *len,
            type_: E820_RAM,
            reserved: 0,
        };
        guest_mem.write_obj(e, addr)?;
        addr = addr.unchecked_add(std::mem::size_of::<hvm_memmap_table_entry>() as u64);
        n += 1;
    }

    // 2. start_info
    let info = hvm_start_info {
        magic: XEN_HVM_START_MAGIC_VALUE,
        version: 1,
        cmdline_paddr: CMDLINE_START,
        memmap_paddr: PVH_MEMMAP_START,
        memmap_entries: n,
        rsdp_paddr: 0,
        ..Default::default()
    };
    let info_addr = GuestAddress(PVH_INFO_START);
    guest_mem.write_obj(info, info_addr)?;
    Ok(info_addr)
}
```

Register the module in `src/arch/src/x86_64/mod.rs`:

```rust
pub mod pvh;
```

---

## 3. `src/arch/src/x86_64/regs.rs` — PVH register + segment state

The PVH ABI: **32-bit protected mode, paging OFF, interrupts off**, flat
segments, `%eip` = PVH entry, `%ebx` = start_info paddr. Reuse the existing
`gdt_entry` / `kvm_segment_from_gdt` / `write_gdt_table` helpers.

```rust
/// PVH boot regs: entry in %eip, hvm_start_info paddr in %ebx (per the ABI).
pub fn setup_regs_pvh(vcpu: &VcpuFd, entry: u64, start_info: u64) -> Result<()> {
    let regs = kvm_regs {
        rflags: 0x0000_0000_0000_0002u64, // reserved bit set, IF/DF clear
        rip: entry,
        rbx: start_info,
        ..Default::default()
    };
    vcpu.set_regs(&regs).map_err(Error::SetBaseRegisters)
}

/// PVH sregs: 32-bit protected mode, flat 4 GiB segments, NO paging, NO long mode.
pub fn setup_sregs_pvh(mem: &GuestMemoryMmap, vcpu: &VcpuFd) -> Result<()> {
    let mut sregs: kvm_sregs = vcpu.get_sregs().map_err(Error::GetStatusRegisters)?;

    // Note the 0xc0** flags: DB=1 (32-bit) + G=1, vs the Linux path's 0xa0**
    // (L=1, 64-bit). Base 0, limit 0xfffff (×4K = 4 GiB).
    let gdt_table: [u64; 3] = [
        gdt_entry(0, 0, 0),            // NULL
        gdt_entry(0xc09b, 0, 0xfffff), // 32-bit CODE
        gdt_entry(0xc093, 0, 0xfffff), // 32-bit DATA
    ];
    let code_seg = kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = kvm_segment_from_gdt(gdt_table[2], 2);

    write_gdt_table(&gdt_table[..], mem)?;
    sregs.gdt.base = BOOT_GDT_OFFSET;
    sregs.gdt.limit = std::mem::size_of_val(&gdt_table) as u16 - 1;

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;

    // Protected mode ON, paging + long mode OFF.
    sregs.cr0 = X86_CR0_PE;   // NOT X86_CR0_PG
    sregs.cr4 = 0;            // NOT PAE
    sregs.efer = 0;          // NOT LME|LMA
    // cr3 unused (no paging).

    vcpu.set_sregs(&sregs).map_err(Error::SetStatusRegisters)
}
```

(`BOOT_GDT_OFFSET`, `X86_CR0_PE`, `write_gdt_table` are already in this file.)

---

## 4. `src/vmm/src/linux/vstate.rs` — pick the boot protocol in `configure_x86_64`

Replace the `kernel_boot: bool` param with a small enum carrying the PVH
start_info address. (`configure_x86_64` is at ~line 1167.)

```rust
#[derive(Copy, Clone)]
pub enum KernelBoot {
    None,                              // AP / TEE: don't touch regs
    Linux,                             // long mode + zero page (current behaviour)
    Pvh { start_info: GuestAddress },  // 32-bit protected mode + hvm_start_info
}

pub fn configure_x86_64(
    &mut self,
    guest_mem: &GuestMemoryMmap,
    kernel_start_addr: GuestAddress,
    vcpu_config: &VcpuConfig,
    boot: KernelBoot,
) -> Result<()> {
    /* ... existing CPUID setup unchanged ... */

    match boot {
        KernelBoot::None => {}
        KernelBoot::Linux => {
            arch::x86_64::msr::setup_msrs(&self.fd)?;
            arch::x86_64::regs::setup_regs(&self.fd, kernel_start_addr.raw_value(), self.id)?;
            arch::x86_64::regs::setup_fpu(&self.fd)?;
            arch::x86_64::regs::setup_sregs(guest_mem, &self.fd, self.id)?;
            arch::x86_64::interrupts::set_lint(&self.fd)?;
        }
        KernelBoot::Pvh { start_info } => {
            arch::x86_64::msr::setup_msrs(&self.fd)?;
            arch::x86_64::regs::setup_regs_pvh(
                &self.fd, kernel_start_addr.raw_value(), start_info.raw_value(),
            )?;
            arch::x86_64::regs::setup_fpu(&self.fd)?;
            arch::x86_64::regs::setup_sregs_pvh(guest_mem, &self.fd)?;
            arch::x86_64::interrupts::set_lint(&self.fd)?;
        }
    }
    Ok(())
}
```

Update the one caller in `builder.rs` (`configure_x86_64(... kernel_boot)` at
~line 1754) to pass a `KernelBoot` instead of the bool. Thread it from the
payload (below): `if kernel_boot { KernelBoot::Linux } else { KernelBoot::None }`
becomes `boot_kind` carried on the payload/entry.

---

## 5. `src/vmm/src/builder.rs` — select PVH entry + write start_info

### 5a. `load_external_kernel` (~1137): return the boot kind

```rust
use linux_loader::loader::elf::PvhBootCapability;

// KernelFormat::Elf arm:
let load_result = loader::Elf::load(guest_mem, None, &mut file, None)
    .map_err(StartMicrovmError::ElfLoadKernel)?;
let (entry, boot_kind) = match load_result.pvh_boot_cap {
    PvhBootCapability::PvhEntryPresent(addr) => (addr, BootKind::Pvh),
    _ => (load_result.kernel_load, BootKind::Linux),
};
// return `entry` where it used `load_result.kernel_load`, and propagate boot_kind
```

Add `enum BootKind { Linux, Pvh }` and carry it out of `load_external_kernel`
alongside `entry_addr` (extend its return tuple / the `PayloadConfig`).

### 5b. `configure_system` (~1081): write start_info for PVH instead of the zero page

The Linux path builds `boot_params` at `ZERO_PAGE_START` (via
`LinuxBootConfigurator` / the measured region at line ~694). Branch on the boot
kind:

```rust
let boot = match payload_config.boot_kind {
    BootKind::Linux => {
        // ... existing zero-page / boot_params setup ...
        KernelBoot::Linux
    }
    BootKind::Pvh => {
        // Collect RAM ranges from guest memory for the E820 memmap.
        let ram: Vec<(u64, u64)> = guest_mem
            .iter()
            .map(|r| (r.start_addr().raw_value(), r.len()))
            .collect();
        let start_info = arch::x86_64::pvh::configure_pvh(guest_mem, &ram)
            .map_err(StartMicrovmError::Internal)?;
        KernelBoot::Pvh { start_info }
    }
};
// pass `boot` down to each vcpu.configure_x86_64(...)
```

The kernel command line is already written to `CMDLINE_START` by
`load_cmdline(&vmm)` (builder.rs ~1078) for x86_64 — PVH reuses it via
`hvm_start_info.cmdline_paddr`, so no change there.

---

## What this gets you, and the next gotcha

With the above, libkrun enters NetBSD's `PHYS32_ENTRY` in the exact state the
ABI promises, so the **triple fault goes away** and you should finally see
NetBSD console output on libkrun's serial (`com0`).

**The likely next problem is device discovery.** libkrun advertises its
virtio-mmio devices to *Linux* via `virtio_mmio.device=<sz>@<base>:<irq>`
cmdline entries (`add_device_to_cmdline`, builder.rs ~1877). NetBSD's virtio-mmio
driver does **not** parse that Linux-specific cmdline syntax. So NetBSD may boot
(console works) but then panic mounting root because it never enumerates the
virtio-blk disk. Options to investigate once you're past the fault:

- confirm how NetBSD `MICROVM` discovers virtio-mmio devices under Firecracker
  (fixed address table? a NetBSD-specific mechanism?), and match libkrun's
  device placement / cmdline to it;
- or add an ACPI MADT/MCFG-less minimal ACPI (RSDP → what NetBSD probes) — more
  work.

But getting to console output is the milestone: it turns "silent triple fault"
into "normal boot log we can debug", which is exactly where arm64 already is.

---

## Test loop

```sh
# build libkrun with PVH patch (BLK/NET as bsdkrun needs)
make -C libkrun BLK=1 NET=1 && sudo make -C libkrun install BLK=1 NET=1
sudo ldconfig
# rebuild bsdkrun against it, then:
BSDKRUN_NETBSD_AMD64=1 bsdkrun --log-level 5 netbsd -d
bsdkrun logs <id>            # <-- should now show NetBSD console, not KVM_EXIT_SHUTDOWN
bsdkrun logs --boot <id>     # libkrun-side log
```
