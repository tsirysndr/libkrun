//! Userspace GICv2 for the macOS/HVF path.
//!
//! libkrun only ever offered a GICv3 on macOS (`HvfGicV3`, or [`super::GicV3`]
//! when Apple's in-kernel GIC is unavailable). Guests whose aarch64 port
//! predates GICv3 — OSv's released `v0.57.0` kernel is the motivating one, its
//! `arch-setup` aborts with "failed to get GICv2 information from dtb" — have
//! no interrupt controller they can drive, so they halt before reaching any
//! device.
//!
//! This is the GICv2 counterpart of [`super::GicV3`], and it borrows most of
//! that model: the delivery machinery lives in [`VcpuList`], which keeps a
//! per-vCPU FIFO of pending INTIDs and kicks the vCPU out of WFI. There is no
//! priority masking, no active-state tracking and no preemption — the registers
//! that would drive those are accepted and ignored.
//!
//! It departs from GICv3 in one place that matters: this model tracks the
//! **enable** state (`GICD_ISENABLER`/`ICENABLER`) and holds interrupts raised
//! on a masked line until the guest unmasks it. That is not gold-plating.
//! Delivery is a FIFO drained by `GICC_IAR`, so an interrupt handed to a guest
//! that has no handler for it yet is not early — it is *gone*. A guest that
//! brings up virtio-blk and only then unmasks the line would lose the first
//! completion and wait for it forever, which is precisely how OSv hangs just
//! after printing its banner.
//!
//! The one structural difference from GICv3 is where acknowledgement happens.
//! GICv3 acks through the `ICC_IAR1_EL1` system register, which HVF traps and
//! `VcpuList::handle_sysreg_read` services. GICv2 has no such system register:
//! the CPU interface is a second MMIO page, so `GICC_IAR` reads and `GICC_EOIR`
//! writes arrive here as ordinary data aborts and are serviced in
//! [`GicV2::handle_cpuif_read32`] / [`GicV2::handle_cpuif_write32`].
//!
//! Register offsets follow the ARM Generic Interrupt Controller Architecture
//! Specification, version 2.0 (ARM IHI 0048B).

use std::io;
use std::sync::{Arc, Mutex};

use crate::bus::BusDevice;
use crate::legacy::gic::GICDevice;
use crate::legacy::irqchip::IrqChipT;
use crate::legacy::VcpuList;
use crate::Error as DeviceError;

// `get_pending_irq` / `set_sgi_irq` reach the per-vCPU queues through this
// trait; GICv3 gets at them from the sysreg handler instead, so it has no need
// for the import.
use hvf::Vcpus;
use utils::eventfd::EventFd;

/// Number of interrupt IDs the distributor advertises. Matches the GICv3
/// implementation so both controllers describe the same interrupt space.
const IRQ_NUM: u32 = 288;
/// Architectural maximum INTID.
const MAXIRQ: u32 = 1020;
/// SGIs (0..16) plus PPIs (16..32) are banked per-CPU.
const GIC_INTERNAL: u32 = 32;
/// Returned by `GICC_IAR` when there is nothing to acknowledge.
const GIC_INTID_SPURIOUS: u32 = 1023;

/*
 * Distributor registers, offsets from the GICD base.
 */
const GICD_CTLR: u64 = 0x0000;
const GICD_TYPER: u64 = 0x0004;
const GICD_IIDR: u64 = 0x0008;
const GICD_IGROUPR: u64 = 0x0080;
const GICD_ISENABLER: u64 = 0x0100;
const GICD_ICENABLER: u64 = 0x0180;
const GICD_ISPENDR: u64 = 0x0200;
/// ICPENDR (0x280) and ICACTIVER (0x380) fall inside the ranges below; neither
/// is separately actionable, so they are not named individually.
const GICD_ISACTIVER: u64 = 0x0300;
const GICD_IPRIORITYR: u64 = 0x0400;
const GICD_ITARGETSR: u64 = 0x0800;
const GICD_ICFGR: u64 = 0x0C00;
const GICD_SGIR: u64 = 0x0F00;
/// Start of the SGI pending registers: CPENDSGIR and SPENDSGIR (0xF20).
const GICD_CPENDSGIR: u64 = 0x0F10;
const GICD_IDREGS: u64 = 0x0FD0;

/* GICD_CTLR fields (non-secure view, no security extensions) */
const GICD_CTLR_EN_GRP0: u32 = 1 << 0;
const GICD_CTLR_EN_GRP1: u32 = 1 << 1;

/* GICD_TYPER fields */
const GICD_TYPER_CPU_NUMBER_SHIFT: u32 = 5;

/* GICD_SGIR fields */
const GICD_SGIR_TARGET_LIST_FILTER_SHIFT: u32 = 24;
const GICD_SGIR_CPU_TARGET_LIST_SHIFT: u32 = 16;

/*
 * CPU interface registers, offsets from the GICC base.
 */
const GICC_CTLR: u64 = 0x0000;
const GICC_PMR: u64 = 0x0004;
const GICC_BPR: u64 = 0x0008;
const GICC_IAR: u64 = 0x000C;
const GICC_EOIR: u64 = 0x0010;
const GICC_RPR: u64 = 0x0014;
const GICC_HPPIR: u64 = 0x0018;
const GICC_ABPR: u64 = 0x001C;
const GICC_AIAR: u64 = 0x0020;
const GICC_AEOIR: u64 = 0x0024;
const GICC_AHPPIR: u64 = 0x0028;
const GICC_APR0: u64 = 0x00D0;
const GICC_NSAPR0: u64 = 0x00E0;
const GICC_IIDR: u64 = 0x00FC;
const GICC_DIR: u64 = 0x1000;

/// Idle priority: no interrupt is running, so `GICC_RPR` reads as the lowest
/// possible priority.
const GICC_RPR_IDLE: u32 = 0xFF;

/// Both the distributor and the CPU interface get a 64 KiB window. The
/// architecture only requires 4 KiB and 8 KiB respectively, but a 64 KiB stride
/// matches what QEMU's `virt` machine publishes and keeps every region
/// page-aligned on hosts with 16 KiB pages.
const GICV2_BASE_SIZE: u64 = 0x0001_0000;
/// GICv2 has no maintenance interrupt of its own to describe here; this is the
/// PPI the `virt` machine conventionally reports for the vGIC.
const GICV2_MAINT_IRQ: u32 = 9;

/// Per-INTID target CPU masks (`GICD_ITARGETSR`). SPIs are routed by the mask
/// the guest programs; SGIs and PPIs are banked and always target the accessing
/// CPU, so only entries at or above [`GIC_INTERNAL`] are meaningful.
type TargetMasks = [u8; MAXIRQ as usize];

pub struct GicV2 {
    dist_addr: u64,
    dist_size: u64,
    cpuif_addr: u64,
    cpuif_size: u64,

    vcpu_list: Arc<VcpuList>,

    /// Mutable register state. `BusDevice::read` takes `&mut self`, but
    /// `IrqChipT::set_irq` only gets `&self` and has to read the target masks,
    /// so the state that both paths touch lives behind a lock.
    state: Mutex<GicV2State>,

    /// GIC device properties, to be used for setting up the fdt entry.
    properties: [u64; 4],
}

/// One bit per INTID.
type IrqBitmap = [u32; (MAXIRQ as usize).div_ceil(32)];

fn bit_set(map: &IrqBitmap, irq: u32) -> bool {
    map[(irq / 32) as usize] & (1 << (irq % 32)) != 0
}

fn set_bit(map: &mut IrqBitmap, irq: u32) {
    map[(irq / 32) as usize] |= 1 << (irq % 32);
}

fn clear_bit(map: &mut IrqBitmap, irq: u32) {
    map[(irq / 32) as usize] &= !(1 << (irq % 32));
}

struct GicV2State {
    gicd_ctlr: u32,
    gicc_ctlr: u32,
    gicc_pmr: u32,
    gicc_bpr: u32,
    itargetsr: TargetMasks,
    edge_trigger: IrqBitmap,
    /// Interrupts the guest has enabled via `GICD_ISENABLER`.
    ///
    /// Unlike the GICv3 model, which forwards every interrupt the moment a
    /// device raises it, we track this — because an interrupt delivered before
    /// the guest has a handler for it is not merely early, it is *lost*. There
    /// is no re-delivery: the queue in `VcpuList` is drained by `GICC_IAR`, so
    /// an unhandled INTID is gone. A guest that brings up virtio-blk and only
    /// then unmasks its line would miss the first completion and wait forever.
    enabled: IrqBitmap,
    /// Interrupts raised while disabled, delivered when the guest enables them.
    pending: IrqBitmap,
}

impl GicV2State {
    /// Decide what to do with an interrupt a device just raised: deliver it to
    /// a vCPU, or hold it because the guest has the line masked.
    ///
    /// Split out from [`GicV2::set_irq`] so the decision can be tested without
    /// a live vCPU to deliver to.
    fn route(&mut self, irq: u32, cpu_count: u64) -> Option<u64> {
        // SGIs and PPIs are banked and always deliverable — the timer PPI in
        // particular must not be gated on a register write.
        if irq >= GIC_INTERNAL && !bit_set(&self.enabled, irq) {
            set_bit(&mut self.pending, irq);
            return None;
        }
        Some(spi_target(self.itargetsr[irq as usize], cpu_count))
    }

    /// Apply a `GICD_ISENABLER` write, returning the interrupts that were held
    /// on the newly-enabled lines and are now deliverable.
    fn enable_and_take_pending(&mut self, base: u32, val: u32, cpu_count: u64) -> Vec<(u64, u32)> {
        let mut flush = Vec::new();
        for i in 0..32u32 {
            if (val >> i) & 1 == 0 {
                continue;
            }
            let irq = base + i;
            if irq >= MAXIRQ {
                break;
            }
            set_bit(&mut self.enabled, irq);
            if bit_set(&self.pending, irq) {
                clear_bit(&mut self.pending, irq);
                flush.push((spi_target(self.itargetsr[irq as usize], cpu_count), irq));
            }
        }
        flush
    }

    /// Apply a `GICD_ICENABLER` write.
    fn disable(&mut self, base: u32, val: u32) {
        for i in 0..32u32 {
            if (val >> i) & 1 == 1 {
                let irq = base + i;
                if irq < MAXIRQ {
                    clear_bit(&mut self.enabled, irq);
                }
            }
        }
    }
}

impl GicV2 {
    pub fn new(vcpu_list: Arc<VcpuList>) -> Self {
        // Sit in the same window below MMIO_MEM_START that the GICv3 uses, so
        // the two controllers are interchangeable from the device manager's
        // point of view.
        let dist_size = GICV2_BASE_SIZE;
        let cpuif_size = GICV2_BASE_SIZE;
        let dist_addr = arch::MMIO_MEM_START - 3 * GICV2_BASE_SIZE;
        let cpuif_addr = dist_addr - cpuif_size;

        // Default every SPI to CPU 0. A guest that never writes ITARGETSR (the
        // common uniprocessor case) still gets its interrupts delivered.
        let mut itargetsr: TargetMasks = [0; MAXIRQ as usize];
        for target in itargetsr.iter_mut() {
            *target = 0x01;
        }

        Self {
            dist_addr,
            dist_size,
            cpuif_addr,
            cpuif_size,
            vcpu_list,
            state: Mutex::new(GicV2State {
                gicd_ctlr: 0,
                gicc_ctlr: 0,
                gicc_pmr: 0,
                gicc_bpr: 0,
                itargetsr,
                edge_trigger: [0; (MAXIRQ as usize).div_ceil(32)],
                enabled: [0; (MAXIRQ as usize).div_ceil(32)],
                pending: [0; (MAXIRQ as usize).div_ceil(32)],
            }),
            properties: [dist_addr, dist_size, cpuif_addr, cpuif_size],
        }
    }

    pub fn get_dist_addr(&self) -> u64 {
        self.dist_addr
    }

    pub const fn get_dist_size(&self) -> u64 {
        self.dist_size
    }

    pub fn get_cpuif_addr(&self) -> u64 {
        self.cpuif_addr
    }

    pub const fn get_cpuif_size(&self) -> u64 {
        self.cpuif_size
    }

    fn handle_dist_read32(&mut self, vcpuid: u64, offset: u64, data: &mut [u8]) {
        let state = self.state.lock().unwrap();
        let mut val: u32 = 0;
        match offset {
            GICD_CTLR => val = state.gicd_ctlr,
            GICD_TYPER => {
                // ITLinesNumber in bits [4:0], CPUNumber (count - 1) in [7:5].
                // SecurityExtn and LSPI are left clear.
                let itlinesnumber = (IRQ_NUM / 32) - 1;
                let cpu_number = (self.vcpu_list.get_cpu_count() as u32 - 1) & 0x7;
                val = itlinesnumber | (cpu_number << GICD_TYPER_CPU_NUMBER_SHIFT);
            }
            // Implementer 0x43b (ARM), as the GICv3 model reports.
            GICD_IIDR => val = 0x43b,
            _ if (GICD_IGROUPR..GICD_ISENABLER).contains(&offset) => {}
            // ISENABLER and ICENABLER read back the same enable state.
            _ if (GICD_ISENABLER..GICD_ISPENDR).contains(&offset) => {
                let word = ((offset - GICD_ISENABLER) % 0x80) / 4;
                val = state.enabled[word as usize];
            }
            _ if (GICD_ISPENDR..GICD_ISACTIVER).contains(&offset) => {
                let word = ((offset - GICD_ISPENDR) % 0x80) / 4;
                val = state.pending[word as usize];
            }
            // Nothing is ever "active": there is no active state to track.
            _ if (GICD_ISACTIVER..GICD_IPRIORITYR).contains(&offset) => {}
            _ if (GICD_IPRIORITYR..GICD_ITARGETSR).contains(&offset) => {}
            _ if (GICD_ITARGETSR..GICD_ICFGR).contains(&offset) => {
                // One byte of CPU mask per INTID, so the register offset is the
                // INTID of the first of the four bytes in this word.
                let first = (offset - GICD_ITARGETSR) as u32;
                for i in 0..4u32 {
                    let irq = first + i;
                    if irq >= MAXIRQ {
                        break;
                    }
                    // SGI/PPI targets are banked: they always read back as the
                    // CPU doing the read.
                    let mask = if irq < GIC_INTERNAL {
                        1u8 << (vcpuid & 0x7)
                    } else {
                        state.itargetsr[irq as usize]
                    };
                    val |= (mask as u32) << (i * 8);
                }
            }
            _ if (GICD_ICFGR..GICD_SGIR).contains(&offset) => {
                // Two config bits per INTID; bit 1 of each pair is edge/level.
                let irq = ((offset - GICD_ICFGR) * 4) as u32;
                if (GIC_INTERNAL..IRQ_NUM).contains(&irq) {
                    let word = state.edge_trigger[(irq / 32) as usize];
                    for i in 0..16u32 {
                        if (word >> ((irq % 32) + i)) & 1 == 1 {
                            val |= 2 << (i * 2);
                        }
                    }
                }
            }
            GICD_SGIR => {} // write-only
            _ if (GICD_CPENDSGIR..GICD_IDREGS).contains(&offset) => {}
            _ if (GICD_IDREGS..GICD_IDREGS + 0x30).contains(&offset) => {
                val = gicv2_id_reg(offset - GICD_IDREGS);
            }
            _ => {
                debug!("[GICv2] unhandled DIST read32 vcpuid={vcpuid} offset=0x{offset:x}");
            }
        }
        data.copy_from_slice(&val.to_le_bytes());
    }

    fn handle_dist_write32(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        let val = u32::from_le_bytes(data.try_into().unwrap());
        let mut state = self.state.lock().unwrap();
        match offset {
            GICD_CTLR => state.gicd_ctlr = val & (GICD_CTLR_EN_GRP0 | GICD_CTLR_EN_GRP1),
            GICD_TYPER | GICD_IIDR => {} // read-only
            _ if (GICD_IGROUPR..GICD_ISENABLER).contains(&offset) => {}
            // Enabling a line flushes anything that arrived while it was
            // masked, which is the whole point of tracking this.
            _ if (GICD_ISENABLER..GICD_ICENABLER).contains(&offset) => {
                let base = (((offset - GICD_ISENABLER) / 4) * 32) as u32;
                let flush =
                    state.enable_and_take_pending(base, val, self.vcpu_list.get_cpu_count());
                // Drop the lock before signalling: delivery can force a vCPU
                // exit, and we must not hold GIC state across that.
                drop(state);
                for (target, irq) in flush {
                    debug!("[GICv2] delivering IRQ {irq} held pending until enable");
                    self.vcpu_list.set_irq_common(target, irq);
                }
                return;
            }
            _ if (GICD_ICENABLER..GICD_ISPENDR).contains(&offset) => {
                let base = (((offset - GICD_ICENABLER) / 4) * 32) as u32;
                state.disable(base, val);
            }
            // Pending and active state are otherwise not writable here.
            _ if (GICD_ISPENDR..GICD_IPRIORITYR).contains(&offset) => {}
            _ if (GICD_IPRIORITYR..GICD_ITARGETSR).contains(&offset) => {}
            _ if (GICD_ITARGETSR..GICD_ICFGR).contains(&offset) => {
                let first = (offset - GICD_ITARGETSR) as u32;
                for i in 0..4u32 {
                    let irq = first + i;
                    // The first 32 entries are read-only banked registers.
                    if irq < GIC_INTERNAL || irq >= MAXIRQ {
                        continue;
                    }
                    state.itargetsr[irq as usize] = ((val >> (i * 8)) & 0xff) as u8;
                }
            }
            _ if (GICD_ICFGR..GICD_SGIR).contains(&offset) => {
                let irq = ((offset - GICD_ICFGR) * 4) as u32;
                if (GIC_INTERNAL..IRQ_NUM).contains(&irq) {
                    let word = &mut state.edge_trigger[(irq / 32) as usize];
                    for i in 0..16u32 {
                        let bit = (irq % 32) + i;
                        if (val >> (i * 2 + 1)) & 1 == 1 {
                            *word |= 1 << bit;
                        } else {
                            *word &= !(1 << bit);
                        }
                    }
                }
            }
            GICD_SGIR => {
                let intid = val & 0xf;
                let target_list = (val >> GICD_SGIR_CPU_TARGET_LIST_SHIFT) & 0xff;
                let filter = (val >> GICD_SGIR_TARGET_LIST_FILTER_SHIFT) & 0x3;
                let cpu_count = self.vcpu_list.get_cpu_count();
                // Drop the lock before signalling: set_sgi_irq can force a vCPU
                // exit, and we must not hold GIC state across that.
                drop(state);

                debug!("[GICv2] vCPU {vcpuid} GenerateSoftwareInterrupt={intid} (0x{val:x})");
                for target in sgi_targets(filter, target_list, vcpuid, cpu_count) {
                    self.vcpu_list.set_sgi_irq(target, intid);
                }
                return;
            }
            _ if (GICD_CPENDSGIR..GICD_IDREGS).contains(&offset) => {}
            _ => {
                debug!(
                    "[GICv2] unhandled DIST write32 vcpuid={vcpuid} offset=0x{offset:x} data={val:#x}"
                );
            }
        }
    }

    fn handle_cpuif_read32(&mut self, vcpuid: u64, offset: u64, data: &mut [u8]) {
        let val: u32 = match offset {
            GICC_CTLR => self.state.lock().unwrap().gicc_ctlr,
            GICC_PMR => self.state.lock().unwrap().gicc_pmr,
            GICC_BPR | GICC_ABPR => self.state.lock().unwrap().gicc_bpr,
            // Acknowledge: hand the guest the next pending INTID and drop it
            // from the queue. This is the GICv2 spelling of ICC_IAR1_EL1.
            GICC_IAR | GICC_AIAR => self.vcpu_list.get_pending_irq(vcpuid),
            // Priorities are not modelled, so nothing is ever "running" and
            // there is no highest-pending priority to report.
            GICC_RPR => GICC_RPR_IDLE,
            GICC_HPPIR | GICC_AHPPIR => GIC_INTID_SPURIOUS,
            GICC_APR0 | GICC_NSAPR0 => 0,
            // ArchRev 2 in bits [19:16], ARM as the implementer.
            GICC_IIDR => (0x2 << 16) | 0x43b,
            _ => {
                debug!("[GICv2] unhandled CPUIF read32 vcpuid={vcpuid} offset=0x{offset:x}");
                0
            }
        };
        data.copy_from_slice(&val.to_le_bytes());
    }

    fn handle_cpuif_write32(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        let val = u32::from_le_bytes(data.try_into().unwrap());
        let mut state = self.state.lock().unwrap();
        match offset {
            GICC_CTLR => state.gicc_ctlr = val,
            GICC_PMR => state.gicc_pmr = val,
            GICC_BPR | GICC_ABPR => state.gicc_bpr = val,
            // End-of-interrupt and deactivation. There is no active state to
            // clear, so these are accepted and dropped — the same thing the
            // GICv3 path does for ICC_EOIR1_EL1.
            GICC_EOIR | GICC_AEOIR | GICC_DIR => {}
            GICC_APR0 | GICC_NSAPR0 => {}
            _ => {
                debug!(
                    "[GICv2] unhandled CPUIF write32 vcpuid={vcpuid} offset=0x{offset:x} data={val:#x}"
                );
            }
        }
    }
}

impl IrqChipT for GicV2 {
    fn get_mmio_addr(&self) -> u64 {
        self.cpuif_addr
    }

    fn get_mmio_size(&self) -> u64 {
        self.cpuif_size + self.dist_size
    }

    fn set_irq(
        &self,
        irq_line: Option<u32>,
        _interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        let Some(irq_line) = irq_line else {
            return Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::InvalidData,
                "IRQ not line configured",
            )));
        };
        assert!(irq_line < MAXIRQ, "[GICv2] intid out of range");

        let target = self
            .state
            .lock()
            .unwrap()
            .route(irq_line, self.vcpu_list.get_cpu_count());
        match target {
            Some(target) => self.vcpu_list.set_irq_common(target, irq_line),
            None => debug!("[GICv2] holding IRQ {irq_line} pending: not enabled yet"),
        }
        Ok(())
    }
}

impl BusDevice for GicV2 {
    fn read(&mut self, vcpuid: u64, offset: u64, data: &mut [u8]) {
        // The CPU interface is mapped first, the distributor immediately after
        // it — mirroring how GicV3 lays out its redistributors and distributor.
        if offset >= self.cpuif_size {
            let offset = offset - self.cpuif_size;
            match data.len() {
                4 => self.handle_dist_read32(vcpuid, offset, data),
                _ => debug!(
                    "[GICv2] unsupported DIST read size {} vcpuid={vcpuid} offset=0x{offset:x}",
                    data.len()
                ),
            }
        } else {
            match data.len() {
                4 => self.handle_cpuif_read32(vcpuid, offset, data),
                _ => debug!(
                    "[GICv2] unsupported CPUIF read size {} vcpuid={vcpuid} offset=0x{offset:x}",
                    data.len()
                ),
            }
        }
    }

    fn write(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        if offset >= self.cpuif_size {
            let offset = offset - self.cpuif_size;
            match data.len() {
                4 => self.handle_dist_write32(vcpuid, offset, data),
                _ => debug!(
                    "[GICv2] unsupported DIST write size {} vcpuid={vcpuid} offset=0x{offset:x}",
                    data.len()
                ),
            }
        } else {
            match data.len() {
                4 => self.handle_cpuif_write32(vcpuid, offset, data),
                _ => debug!(
                    "[GICv2] unsupported CPUIF write size {} vcpuid={vcpuid} offset=0x{offset:x}",
                    data.len()
                ),
            }
        }
    }
}

impl GICDevice for GicV2 {
    fn device_properties(&self) -> Vec<u64> {
        self.properties.to_vec()
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_list.get_cpu_count()
    }

    fn fdt_compatibility(&self) -> String {
        // Guests match on this string to find the controller. OSv, for one,
        // only looks for "arm,gic-400" and "arm,cortex-a15-gic".
        "arm,gic-400".to_string()
    }

    fn fdt_maint_irq(&self) -> u32 {
        GICV2_MAINT_IRQ
    }

    fn version(&self) -> u32 {
        2
    }
}

/// Which vCPU an SPI goes to. GICv2 routes by CPU mask rather than by affinity,
/// so deliver to the lowest-numbered CPU the guest selected. A mask that is
/// empty, or that names a CPU this VM doesn't have, falls back to CPU 0 so the
/// interrupt is never simply dropped.
fn spi_target(mask: u8, cpu_count: u64) -> u64 {
    let target = mask.trailing_zeros() as u64;
    if target < cpu_count {
        target
    } else {
        0
    }
}

/// Which vCPUs an SGI goes to, per the `GICD_SGIR` TargetListFilter field.
fn sgi_targets(filter: u32, target_list: u32, self_id: u64, cpu_count: u64) -> Vec<u64> {
    match filter {
        // Forward to the CPUs listed in CPUTargetList.
        0 => (0..cpu_count)
            .filter(|target| (target_list >> target) & 1 == 1)
            .collect(),
        // Forward to all CPUs except the one that made the request.
        1 => (0..cpu_count).filter(|target| *target != self_id).collect(),
        // Forward only to the requesting CPU.
        2 => vec![self_id],
        _ => {
            debug!("[GICv2] reserved SGIR target list filter {filter}");
            Vec::new()
        }
    }
}

/// CoreSight ID registers for a GICv2 distributor, indexed from `GICD_IDREGS`.
/// The only field a guest normally inspects is `PIDR2.ArchRev`, which must read
/// as 2 for the controller to be recognised as a GICv2.
fn gicv2_id_reg(offset: u64) -> u32 {
    // Offsets run PIDR4..PIDR7, PIDR0..PIDR3, CIDR0..CIDR3.
    const GICV2_IDS: [u32; 12] = [
        0x04, 0x00, 0x00, 0x00, // PIDR4-7
        0x90, 0xB4, 0x2B, 0x00, // PIDR0-3 (PIDR2 ArchRev = 2)
        0x0D, 0xF0, 0x05, 0xB1, // CIDR0-3
    ];
    GICV2_IDS
        .get((offset / 4) as usize)
        .copied()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gic(cpus: u64) -> GicV2 {
        GicV2::new(Arc::new(VcpuList::new(cpus)))
    }

    fn read32(gic: &mut GicV2, vcpuid: u64, offset: u64) -> u32 {
        let mut data = [0u8; 4];
        gic.read(vcpuid, offset, &mut data);
        u32::from_le_bytes(data)
    }

    fn write32(gic: &mut GicV2, vcpuid: u64, offset: u64, val: u32) {
        gic.write(vcpuid, offset, &val.to_le_bytes());
    }

    /// The distributor sits above the CPU interface in the registered window.
    fn dist(offset: u64) -> u64 {
        GICV2_BASE_SIZE + offset
    }

    #[test]
    fn fdt_contract_matches_what_guests_look_for() {
        let gic = gic(1);
        // OSv's dtb_get_gic_v2 matches this exact string, then reads two
        // address/size pairs out of "reg".
        assert_eq!(gic.fdt_compatibility(), "arm,gic-400");
        assert_eq!(gic.version(), 2);
        let props = gic.device_properties();
        assert_eq!(props.len(), 4);
        assert_eq!(props[0], gic.get_dist_addr());
        assert_eq!(props[1], gic.get_dist_size());
        assert_eq!(props[2], gic.get_cpuif_addr());
        assert_eq!(props[3], gic.get_cpuif_size());
    }

    #[test]
    fn mmio_window_covers_both_frames_and_does_not_overlap_devices() {
        let gic = gic(1);
        assert_eq!(gic.get_mmio_addr(), gic.get_cpuif_addr());
        assert_eq!(gic.get_mmio_size(), gic.get_cpuif_size() + gic.get_dist_size());
        // Everything must stay below the MMIO device region.
        assert!(gic.get_dist_addr() + gic.get_dist_size() <= arch::MMIO_MEM_START);
        assert!(gic.get_cpuif_addr() < gic.get_dist_addr());
    }

    #[test]
    fn pidr2_reports_arch_rev_2() {
        let mut g = gic(1);
        // PIDR2 is the 7th ID register; ArchRev lives in bits [7:4].
        let pidr2 = read32(&mut g, 0, dist(GICD_IDREGS + 0x18));
        assert_eq!((pidr2 >> 4) & 0xf, 2, "PIDR2 = {pidr2:#x}");
    }

    #[test]
    fn typer_reports_line_count_and_cpu_count() {
        let mut g = gic(4);
        let typer = read32(&mut g, 0, dist(GICD_TYPER));
        assert_eq!(typer & 0x1f, (IRQ_NUM / 32) - 1);
        assert_eq!((typer >> GICD_TYPER_CPU_NUMBER_SHIFT) & 0x7, 3);
    }

    #[test]
    fn ctlr_round_trips_enable_bits() {
        let mut g = gic(1);
        write32(&mut g, 0, dist(GICD_CTLR), 0xffff_ffff);
        assert_eq!(
            read32(&mut g, 0, dist(GICD_CTLR)),
            GICD_CTLR_EN_GRP0 | GICD_CTLR_EN_GRP1
        );
    }

    // Raising an interrupt reaches into HVF (VcpuList kicks the target vCPU out
    // of its run loop), so the delivery path itself can only be exercised
    // against a live VM. What is testable here is the routing decision and the
    // register semantics around it.

    #[test]
    fn iar_reads_spurious_when_nothing_is_pending() {
        let mut g = gic(1);
        assert_eq!(read32(&mut g, 0, GICC_IAR), GIC_INTID_SPURIOUS);
    }

    #[test]
    fn eoi_and_deactivate_are_accepted() {
        let mut g = gic(1);
        // A guest EOIs every interrupt it takes; these must not fault or fall
        // through to the "unhandled" path.
        write32(&mut g, 0, GICC_EOIR, 42);
        write32(&mut g, 0, GICC_DIR, 42);
        assert_eq!(read32(&mut g, 0, GICC_RPR), GICC_RPR_IDLE);
    }

    #[test]
    fn spis_route_to_the_cpu_the_guest_targets() {
        let mut g = gic(2);
        // Point SPI 40 at CPU 1, and check set_irq would deliver it there.
        write32(&mut g, 0, dist(GICD_ITARGETSR + 40), 0x02);
        let mask = g.state.lock().unwrap().itargetsr[40];
        assert_eq!(mask, 0x02);
        assert_eq!(spi_target(mask, 2), 1);
    }

    #[test]
    fn spi_routing_falls_back_to_cpu0_for_unusable_masks() {
        // An empty mask, or one naming a CPU this VM does not have, must still
        // land somewhere rather than dropping the interrupt.
        assert_eq!(spi_target(0x00, 2), 0);
        assert_eq!(spi_target(0x80, 2), 0);
        assert_eq!(spi_target(0x01, 1), 0);
        // Lowest set bit wins when several CPUs are targeted.
        assert_eq!(spi_target(0x06, 4), 1);
    }

    /// The register offset covering INTID `irq` in a 1-bit-per-INTID bank.
    fn bank(base: u64, irq: u32) -> u64 {
        dist(base + ((irq / 32) * 4) as u64)
    }

    #[test]
    fn enable_state_round_trips_and_reads_back_from_either_register() {
        let mut g = gic(1);
        write32(&mut g, 0, bank(GICD_ISENABLER, 40), 1 << (40 % 32));
        assert!(bit_set(&g.state.lock().unwrap().enabled, 40));
        // ICENABLER aliases the same state for reads.
        assert_eq!(
            read32(&mut g, 0, bank(GICD_ICENABLER, 40)) & (1 << (40 % 32)),
            1 << (40 % 32)
        );
        write32(&mut g, 0, bank(GICD_ICENABLER, 40), 1 << (40 % 32));
        assert!(!bit_set(&g.state.lock().unwrap().enabled, 40));
    }

    #[test]
    fn an_spi_raised_before_it_is_enabled_is_held_not_dropped() {
        let mut g = gic(1);
        // Nothing enabled yet — this is the virtio-blk-before-unmask case.
        assert_eq!(g.state.lock().unwrap().route(40, 1), None);
        assert!(bit_set(&g.state.lock().unwrap().pending, 40));
        // And it is visible as pending to a guest that asks.
        assert_eq!(
            read32(&mut g, 0, bank(GICD_ISPENDR, 40)) & (1 << (40 % 32)),
            1 << (40 % 32)
        );
    }

    #[test]
    fn enabling_a_line_flushes_what_was_held_on_it() {
        let g = gic(1);
        let mut state = g.state.lock().unwrap();
        state.route(40, 1);
        // Enabling the bank that covers INTID 40 hands it back for delivery...
        let flush = state.enable_and_take_pending(32, 1 << (40 % 32), 1);
        assert_eq!(flush, vec![(0, 40)]);
        // ...exactly once, and it is no longer held.
        assert!(!bit_set(&state.pending, 40));
        assert!(state.enable_and_take_pending(32, 1 << (40 % 32), 1).is_empty());
    }

    #[test]
    fn an_enabled_spi_is_routed_straight_to_its_target() {
        let g = gic(1);
        let mut state = g.state.lock().unwrap();
        state.enable_and_take_pending(32, 1 << (40 % 32), 1);
        assert_eq!(state.route(40, 1), Some(0));
        // Delivered, not held.
        assert!(!bit_set(&state.pending, 40));
    }

    #[test]
    fn disabling_a_line_stops_delivery_again() {
        let g = gic(1);
        let mut state = g.state.lock().unwrap();
        state.enable_and_take_pending(32, 1 << (40 % 32), 1);
        state.disable(32, 1 << (40 % 32));
        assert_eq!(state.route(40, 1), None);
    }

    #[test]
    fn sgis_and_ppis_are_delivered_without_needing_an_enable() {
        let g = gic(1);
        // Banked interrupts (below INTID 32) bypass the enable gate — the timer
        // PPI in particular must not be held hostage to a register write.
        assert_eq!(g.state.lock().unwrap().route(16, 1), Some(0));
        assert_eq!(g.state.lock().unwrap().route(0, 1), Some(0));
    }

    #[test]
    fn sgi_and_ppi_targets_are_banked_per_cpu() {
        let mut g = gic(2);
        // INTID 4 is an SGI: ITARGETSR is read-only and reflects the reader.
        let reg = dist(GICD_ITARGETSR + 4);
        write32(&mut g, 0, reg, 0xff);
        assert_eq!(read32(&mut g, 0, reg) & 0xff, 0x01);
        assert_eq!(read32(&mut g, 1, reg) & 0xff, 0x02);
    }

    #[test]
    fn sgir_target_list_filters_select_the_right_cpus() {
        // Filter 0: use CPUTargetList. Targeting CPU 1 only.
        assert_eq!(sgi_targets(0, 0b0010, 0, 4), vec![1]);
        assert_eq!(sgi_targets(0, 0b1011, 0, 4), vec![0, 1, 3]);
        // A target list naming CPUs beyond this VM is clamped, not panicked on.
        assert_eq!(sgi_targets(0, 0xff, 0, 2), vec![0, 1]);
        // Filter 1: everyone except the requester.
        assert_eq!(sgi_targets(1, 0, 1, 4), vec![0, 2, 3]);
        // Filter 2: the requester only, whatever the target list says.
        assert_eq!(sgi_targets(2, 0xff, 3, 4), vec![3]);
        // Filter 3 is reserved.
        assert!(sgi_targets(3, 0xff, 0, 4).is_empty());
    }

    #[test]
    fn sgir_is_write_only() {
        let mut g = gic(2);
        assert_eq!(read32(&mut g, 0, dist(GICD_SGIR)), 0);
    }

    #[test]
    fn icfgr_round_trips_edge_configuration() {
        let mut g = gic(1);
        // INTID 32 is the first SPI; its config pair is bits [1:0] of the
        // ICFGR word covering INTIDs 32..48.
        let reg = dist(GICD_ICFGR + (32 / 4));
        write32(&mut g, 0, reg, 0x2);
        assert_eq!(read32(&mut g, 0, reg) & 0x3, 0x2);
        write32(&mut g, 0, reg, 0x0);
        assert_eq!(read32(&mut g, 0, reg) & 0x3, 0x0);
    }

    #[test]
    fn unknown_offsets_are_ignored_rather_than_panicking() {
        let mut g = gic(1);
        // A guest probing a register we do not model must not take the VMM
        // down; the GICv3 model panics here, which is not something a guest
        // should be able to trigger. 0x50 is reserved space between GICD_IIDR
        // and GICD_IGROUPR; 0xA0 is reserved on the CPU interface.
        assert_eq!(read32(&mut g, 0, dist(0x0050)), 0);
        write32(&mut g, 0, dist(0x0050), 0xdead_beef);
        assert_eq!(read32(&mut g, 0, 0x00A0), 0);
        write32(&mut g, 0, 0x00A0, 0xdead_beef);
    }
}
