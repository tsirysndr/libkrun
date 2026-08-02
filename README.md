<picture>
   <source media="(prefers-color-scheme: dark)" srcset="docs/images/libkrun_logo_horizontal_darkmode.png">
   <source media="(prefers-color-scheme: light)" srcset="docs/images/libkrun_logo_horizontal.png">
   <img alt="libkrun logo" src="docs/images/libkrun_logo_horizontal_200.png">
</picture>

# libkrun

```libkrun``` is a dynamic library that allows programs to easily acquire the ability to run processes in a partially isolated environment using [KVM](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt) Virtualization on Linux and [HVF](https://developer.apple.com/documentation/hypervisor) on macOS/ARM64.

It integrates a VMM (Virtual Machine Monitor, the userspace side of an Hypervisor) with the minimum amount of emulated devices required to its purpose, abstracting most of the complexity that comes from Virtual Machine management, offering users a simple C API.

> [!NOTE]
> **This fork (`feat/pvh-boot`, based on v1.19.4) adds x86_64 PVH direct boot** — used by
> [bsdkrun](https://github.com/tsirysndr/bsdkrun) to boot **NetBSD/amd64** (`MICROVM` kernel) and
> **FreeBSD/amd64** (`FIRECRACKER` kernel) under libkrun on Linux/KVM; both are PVH-only.
> See [PVH boot (this fork)](#pvh-boot-this-fork) below.

## Use cases

* [crun](https://github.com/containers/crun/blob/main/krun.1.md): Adding Virtualization-based isolation to container and confidential workloads.
* [krunkit](https://github.com/containers/krunkit): Running GPU-enabled (via [venus](https://docs.mesa3d.org/drivers/venus.html)) lightweight VMs on macOS.
* [muvm](https://github.com/AsahiLinux/muvm): Launching a microVM with GPU acceleration (via [native context](https://www.youtube.com/watch?v=9sFP_yddLLQ)) for running games that require 4k pages.

## Goals and non-goals

### Goals

* Enable other projects to easily gain KVM-based process isolation capabilities.
* Be self-sufficient (no need for calling to an external VMM) and very simple to use.
* Be as small as possible, implementing only the features required to achieve its goals.
* Have the smallest possible footprint in every aspect (RAM consumption, CPU usage and boot time).
* Be compatible with a reasonable amount of workloads.

### Non-goals

* Become a generic VMM.
* Be compatible with all kinds of workloads.

## Variants

This project provides the following variants of the library:

- **libkrun**: Generic variant compatible with all Virtualization-capable systems.
- **libkrun-sev**: Variant including support for AMD SEV (SEV, SEV-ES and SEV-SNP) memory encryption and remote attestation. Requires an SEV-capable CPU.
- **libkrun-tdx**: Variant including support for Intel TDX memory encryption. Requires a TDX-capable CPU.
- **libkrun-efi**: Variant that bundles OVMF/EDK2 for booting a distribution-provided kernel (only available on macOS).

Each variant generates a dynamic library with a different name (and ```soname```), so both can be installed at the same time in the same system.

## Virtio device support

### All variants

* virtio-console
* virtio-block
* virtio-fs
* virtio-gpu (venus and native-context)
* virtio-net
* virtio-vsock (for TSI and socket redirection)
* virtio-balloon (only free-page reporting)
* virtio-rng
* virtio-snd

## PVH boot (this fork)

Upstream libkrun enters external x86_64 ELF kernels via the **Linux 64-bit boot
protocol** only (a `boot_params` zero page in `%rsi`, jump to `e_entry` in long
mode). Kernels that don't speak that protocol — e.g. **NetBSD's `MICROVM`
kernel**, which boots via the
[x86/HVM direct boot ABI (PVH)](https://xenbits.xen.org/docs/unstable/misc/pvh.html)
— triple-fault on the first instruction.

This fork adds a PVH boot path for external kernels:

* `load_external_kernel` honors the ELF's Xen `PHYS32_ENTRY` note (already
  parsed by `linux-loader` as `pvh_boot_cap`) and uses it as the entry point.
* An `hvm_start_info` + E820-style memory map are written to low guest RAM
  (`0x6000` / `0x7000`); `cmdline_paddr` points at the kernel command line at
  `CMDLINE_START`, so the existing cmdline plumbing (including the
  `virtio_mmio.device=` entries used for device discovery) works unchanged.
* The boot vCPU enters in **32-bit protected mode, paging off** (flat 4 GiB
  segments, TSS + IDT set, `%ebx` → start_info), per the PVH ABI.

**Opt-in via `KRUN_PVH=1`**: the Linux vmlinux also carries a PVH note but must
keep booting the Linux way, so PVH is only taken when the environment variable
is set *and* the note is present. Without it, behavior is identical to upstream.

The work also fixes a latent bug inherited from Firecracker's `gdt.rs`:
`kvm_segment_from_gdt` returns the **raw 20-bit** descriptor limit, but
`kvm_segment.limit` feeds the byte-granular VMCS/VMCB guest segment limit — so
a "flat 4 GiB" segment was really **1 MiB**. Long mode never noticed (segment
limits are ignored there); in 32-bit protected mode it made any entry point
above 1 MiB `#GP` on the very first instruction fetch. The PVH path expands
limits through the G bit, as Cloud Hypervisor does.

### FreeBSD support

Beyond the PVH entry itself, FreeBSD's `FIRECRACKER` kernel (its firecracker-class
config: no ACPI, legacy enumeration, virtio-mmio built in) needs three more things
this fork provides on the PVH path:

* **MPTable** — with no ACPI, FreeBSD enumerates CPUs/APICs from the legacy Intel
  MPTable (`options MPTABLE_LINUX_BUG_COMPAT`), which upstream libkrun only wrote
  for the Linux boot path. The PVH path now writes it too.
* **TSC frequency via CPUID leaf `0x40000010`** — FreeBSD can't calibrate its TSC
  under libkrun: with `machdep.disable_tsc_calibration` (the FIRECRACKER default)
  `tsc_freq` stays 0 and `lapic_init` panics, and with calibration on, PVH's
  `DELAY` is `xen_delay`, which faults on a Xen pvclock KVM never provides. The
  fork synthesizes the generic hypervisor TSC leaf (`tsc_freq_cpuid_vm()`: eax =
  kHz, max-leaf bumped to cover it) from `KVM_GET_TSC_KHZ`, as QEMU and
  Firecracker do — FreeBSD then skips calibration entirely.
* **Numbered `virtio_mmio.device_N=` cmdline keys** — FreeBSD's discovery
  (`virtio_mmio_cmdline.c`) reads `virtio_mmio.device=<size>@<addr>:<irq>` plus
  `virtio_mmio.device_1=`, `_2=`, ... for additional devices; it can't see
  Linux's repeated-key form (its kernel environment hides duplicate keys).
  Opt-in via `KRUN_VIRTIO_MMIO_HINTS=freebsd`.

Verified end-to-end by [bsdkrun's KVM CI](https://github.com/tsirysndr/bsdkrun/blob/main/.github/workflows/e2e-linux.yml):

* **NetBSD/amd64 `MICROVM`** boots to multiuser with virtio-mmio block/net (kernel
  cmdline: `root=ld0a console=com` — `console=com` is required, since a PVH boot
  passes no NetBSD bootinfo and the console would otherwise default to VGA).
* **FreeBSD/amd64 `FIRECRACKER`** (15.1) boots to multiuser with virtio-mmio
  block/net, rooting on `ufs:/dev/vtbd0` with the console on the 16550 at `0x3f8`
  (`console=comconsole hw.uart.console=io:0x3f8`).

See [PVH_PATCH_SKETCH.md](PVH_PATCH_SKETCH.md) for the design notes.

## Networking

In ```libkrun```, networking is provided by two different, mutually exclusive techniques: **virtio-vsock + TSI** and **virtio-net + passt/gvproxy**.

### virtio-vsock + TSI

This is a novel technique called **Transparent Socket Impersonation** which allows the VM to have network connectivity without a virtual interface. This technique supports both outgoing and incoming connections. It's possible for userspace applications running in the VM to transparently connect to endpoints outside the VM and receive connections from the outside to ports listening inside the VM.

#### Enabling TSI

TSI for AF_INET and AF_INET6 is automatically enabled when no network interface is added to the VM. TSI for AF_UNIX is enabled when, in addition to the previous condition, `krun_set_root` has been used to set `/` as root filesystem.

#### Known limitations

- Requires a custom kernel (like the one bundled in **libkrunfw**).
- It's limited to SOCK_DGRAM and SOCK_STREAM sockets and AF_INET, AF_INET6 and AF_UNIX address families (for instance, raw sockets aren't supported).
- Listening on SOCK_DGRAM sockets from the guest is not supported.
- When TSI is enabled for AF_UNIX sockets, only absolute path are supported as addresses.

### **virtio-net + passt/gvproxy**

A conventional virtual interface that allows the guest to communicate with the outside through the VMM using a supporting application like [passt](https://passt.top/passt/about/) or [gvproxy](https://github.com/containers/gvisor-tap-vsock).

#### Enabling virtio-net

Use `krun_add_net_unixstream` and/or `krun_add_net_unixdgram` to add a virtio-net interface connected to the userspace network proxy.

## Security model

The libkrun security model is primarily defined by the consideration that both the guest and the VMM pertain to the same security context. For many operations, the VMM acts as a proxy for the guest within the host. Host resources that are accessible to the VMM can potentially be accessed by the guest through it.

While defining the security implementation of your environment, you should think about the guest and the VMM as a single entity. To prevent the guest from accessing host's resources, you need to use the host's OS security features to run the VMM inside an isolated context. On Linux, the primary mechanism to be used for this purpose is namespaces. Single-user systems may have a more relaxed security policy and just ensure the VMM runs with a particular UID/GID.

While most virtio devices allow the guest to access resources from the host, two of them require special consideration when used: virtio-fs and virtio-vsock+TSI.

### virtio-fs

When exposing a directory in a filesystem from the host to the guest through virtio-fs devices configured with `krun_set_root` and/or `krun_add_virtiofs`, libkrun **does not** provide any protection against the guest attempting to access other directories in the same filesystem, or even other filesystems in the host.

A mount point isolation mechanism from the host should be used in combination with virtio-fs.

In addition, when using virtio-fs, a guest may exhaust filesystem resources such as inode limits and disk capacity. Controls should be implemented on the host to mitigate this.

### virtio-vsock + TSI

When TSI is enabled, the VMM acts as a proxy for AF_INET, AF_INET6 and AF_UNIX sockets, for both incoming and outgoing connections. For all that matters, the VMM and the guest should be considered to be running in the network context. As such, you should apply on the VMM whatever restrictions you want to apply on the guest.

## Building and installing

### Linux (generic variant)

#### Requirements

* [libkrunfw](https://github.com/containers/libkrunfw)
* A working [Rust](https://www.rust-lang.org/) toolchain
* C Library static libraries, as the [init](src/init_blob/init/init.c) binary is statically linked (package ```glibc-static``` in Fedora)
* patchelf

#### Optional features

* **GPU=1**: Enables virtio-gpu. Requires virglrenderer-devel.
* **VIRGL_RESOURCE_MAP2=1**: Uses virgl_resource_map2 function. Requires a virglrenderer-devel patched with [1374](https://gitlab.freedesktop.org/virgl/virglrenderer/-/merge_requests/1374)
* **BLK=1**: Enables virtio-block.
* **NET=1**: Enables virtio-net.
* **SND=1**: Enables virtio-snd.

#### Compiling

```
make [FEATURE_OPTIONS]
```

#### Installing

```
sudo make [FEATURE_OPTIONS] install
```

### Linux (SEV variant)

#### Requirements

* The SEV variant of [libkrunfw](https://github.com/containers/libkrunfw), which provides a ```libkrunfw-sev.so``` library.
* A working [Rust](https://www.rust-lang.org/) toolchain
* C Library static libraries, as the [init](src/init_blob/init/init.c) binary is statically linked (package ```glibc-static``` in Fedora)
* patchelf
* OpenSSL headers and libraries (package ```openssl-devel``` in Fedora).

#### Compiling

```
make SEV=1
```

#### Installing

```
sudo make SEV=1 install
```

### Linux (TDX variant)

#### Requirements

* The TDX variant of [libkrunfw](https://github.com/containers/libkrunfw), which provides a ```libkrunfw-tdx.so``` library.
* A working [Rust](https://www.rust-lang.org/) toolchain
* C Library static libraries, as the [init](src/init_blob/init/init.c) binary is statically linked (package ```glibc-static``` in Fedora)
* patchelf
* OpenSSL headers and libraries (package ```openssl-devel``` in Fedora).

#### Compiling

```
make TDX=1
```

#### Installing

```
sudo make TDX=1 install
```

#### Limitations

The TDX flavor of libkrun only supports guests with 1 vCPU and memory less than or equal to 3072mib.

### macOS (EFI variant)

#### Requirements

* A working [Rust](https://www.rust-lang.org/) toolchain
* A host running macOS 14 or newer

#### Compiling

```
make EFI=1
```

#### Installing

```
sudo make EFI=1 install

```

### macOS (generic variant)

#### Requirements

* A working [Rust](https://www.rust-lang.org/) toolchain
* A host running macOS 14 or newer
* Homebrew packages `lld` and `xz`

#### Compiling

```
make [FEATURE_OPTIONS]
```

The [init](src/init_blob/init/init.c) binary is cross-compiled using clang and lld.
A suitable sysroot is automatically generated by the Makefile from Debian repository.

#### Installing

```
sudo make [FEATURE_OPTIONS] install
```

## Using the library

Despite being written in Rust, this library provides a simple C API defined in [include/libkrun.h](include/libkrun.h)

## Examples

### chroot_vm

This is a simple example providing ```chroot```-like functionality using ```libkrun```.

#### Building chroot_vm

To be able to ```chroot_vm```, you need need to build libkrun with the `virtio-block` and `virtio-net` optional features:

```
make BLK=1 NET=1
sudo make BLK=1 NET=1 install
cd examples
make
```

#### Running chroot_vm

To be able to ```chroot_vm```, you need first a directory to act as the root filesystem for your isolated program.

Use the ```rootfs``` target to get a rootfs prepared from the Fedora container image (note: you must have [podman](https://podman.io/) installed):

```
make rootfs
```

Now you can use ```chroot_vm``` to run a process within this new root filesystem:

```
./chroot_vm ./rootfs_fedora /bin/sh
```

If the ```libkrun``` and/or ```libkrunfw``` libraries were installed on a path that's not included in your ```/etc/ld.so.conf``` configuration, you may get an error like this one:

```
./chroot_vm: error while loading shared libraries: libkrun.so: cannot open shared object file: No such file or directory
```

To avoid this problem, use the ```LD_LIBRARY_PATH``` environment variable to point to the location where the libraries were installed. For example, if the libraries were installed in ```/usr/local/lib64```, use something like this:

```
LD_LIBRARY_PATH=/usr/local/lib64 ./chroot_vm rootfs_fedora/ /bin/sh
```

## Status

```libkrun``` has achieved maturity and starting version ```1.0.0``` the public API is guaranteed to be stable, following [SemVer](https://semver.org/).

## Getting in contact

The main communication channel is the [libkrun Matrix channel](https://matrix.to/#/#libkrun:matrix.org).

## Acknowledgments

```libkrun``` incorporates code from [Firecracker](https://github.com/firecracker-microvm/firecracker), [rust-vmm](https://github.com/rust-vmm/) and [Cloud-Hypervisor](https://github.com/cloud-hypervisor/).
