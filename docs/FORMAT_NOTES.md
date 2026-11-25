# VxWorks image format notes

Only facts confirmed on real images are recorded here. Each fact names the
images it was confirmed on, using these labels:

| Label | Image | Architecture |
|---|---|---|
| 5.4-PPC | VxWorks 5.4, WIND 2.5 | PowerPC, big-endian |
| 5.5-ARM | VxWorks 5.5.1, WIND 2.6 | ARM, little-endian |
| 6.4-PPC | VxWorks 6.4, WIND 2.10 | PowerPC, big-endian |
| 6.7-ARM | VxWorks 6.7, WIND 2.12 | ARM, little-endian |
| 7-ARM | VxWorks 7 release 21.03 (SDK kernel, i.MX6) | ARM, little-endian, 32-bit |
| 7-A64 | VxWorks 7 release 26.09 (SDK kernel, Raspberry Pi 4) | AArch64 |
| 7-X64 | VxWorks 7 release 26.09 (SDK kernel, QEMU x86-64) | x86-64 |

No MIPS image and no 5.0, 6.1 or 6.8+ image has been examined. Nothing below
should be assumed to hold for them.

## Built-in symbol table (`standTbl`)

A kernel built with a standalone symbol table carries an array of fixed-size
entries in its initialised data, followed directly by a pointer-sized entry
count. In the 7.x ELF kernels the array is the symbol `standTbl` and the count
is `standTblSize`. *Confirmed on all seven images.*

Entry layout, with P the pointer size:

| Field | Size | 5.x | 6.x and 7.x | Notes |
|---|---|---|---|---|
| hash link | P | yes | yes | zero in every entry of every image |
| name | P | yes | yes | virtual address of a NUL-terminated string |
| value | P | yes | yes | |
| reference | P | no | yes | zero in every entry of every image |
| group | 2 | yes | yes | zero in every entry of every image |
| type | 1 | yes | yes | see below |
| padding | 1, then to a multiple of P | yes | yes | zero |

| Layout | Entry size | Confirmed on |
|---|---|---|
| 5.x, 32-bit | 16 bytes | 5.4-PPC, 5.5-ARM |
| 6.x and 7.x, 32-bit | 20 bytes | 6.4-PPC, 6.7-ARM, 7-ARM |
| 7.x, 64-bit | 40 bytes | 7-A64, 7-X64 |

A 32-bit 7.x table is laid out exactly like a 6.x table. The layout alone
cannot tell the two versions apart.

The group, type and padding bytes occupy the same byte positions in big- and
little-endian images: two group bytes, then the type byte, then padding.

Entries are sorted by name (byte order) in 5.4-PPC and 5.5-ARM and are not
sorted in 6.4-PPC. Nothing relies on the order.

### Type byte

Values observed, with the meaning implied by where the values point:

| Value | 5.x | 6.x and 7.x |
|---|---|---|
| 0x03 | not seen | absolute (constants such as `_vx_offset_*`) |
| 0x05 | code | code |
| 0x07 | initialised data | not seen |
| 0x09 | bss | initialised data |
| 0x11 | not seen | bss |

*5.x values confirmed on 5.4-PPC and 5.5-ARM; 6.x/7.x values on 6.4-PPC, 6.7-ARM,
7-ARM, 7-A64, 7-X64.* No other value occurs in any of the seven tables. The
decoder also maps further values (common, local, Thumb) following the public
`symbol.h` definitions; those mappings are unconfirmed.

### Symbol values that are not addresses

- Absolute symbols (type 0x03) are constants. *6.7-ARM, 6.4-PPC, 7.x.*
- 7.x tables contain a few thread-local symbols typed as data or bss whose
  value is an offset into the thread-local block, for example `buffer` and
  `_mi_heap_default`. The ELF `.symtab` marks the same symbols as thread-local.
  *7-ARM (2 symbols), 7-A64 (4 symbols).*

### Agreement with the ELF symbol table

For 7-ARM and 7-A64, every (name, value) pair in `standTbl` also appears in the
ELF's `.symtab`. `standTbl` holds global symbols only, so it is a subset: 14,356
of 537,414 `.symtab` entries on 7-ARM and 26,439 of 85,714 on 7-A64.

`standTbl` and `standTblSize` are not themselves listed in `standTbl`.
*7-ARM, 7-A64.* They do not appear in the 5.x or 6.x tables either.

## Load address

- Name pointers in the table are link-time virtual addresses. Subtracting the
  file offset of the string a pointer refers to gives the address the image is
  linked at. *All seven images.*
- `sysInit` (`_sysInit` on PowerPC) is the first code in the image. Its value
  equals the base address when the image has no header. *5.4-PPC, 5.5-ARM,
  6.4-PPC, 7-ARM, 7-A64.*

| Image | Link address of file offset 0 |
|---|---|
| 5.5-ARM | 0x1000 |
| 5.4-PPC | 0x10000 |
| 6.4-PPC | 0x100000 |
| 6.7-ARM | 0xf2003fe4 (0x1c-byte header, then code at 0xf2004000) |
| 7-ARM | 0x100000 |
| 7-A64 | 0xffffffff80100000 |

### Virtual and physical addresses in 7.x

7.x kernels are linked at a virtual address and loaded at a different physical
address. The ELF program header and the uImage header give the physical
address; symbols use the virtual address.

| Image | Virtual | Physical |
|---|---|---|
| 7-ARM | 0x00100000 | 0x10100000 |
| 7-A64 | 0xffffffff80100000 | 0x00100000 |
| 7-X64 (main segment) | 0xffffffff8040e000 | 0x0040e000 |

7-X64 also has a small low segment at 0x408000 (`.text.locore`,
`.data.locore`) mapped one-to-one, which holds `sysInit`.

## Version identification

| Signal | 5.x | 6.x | 7.x |
|---|---|---|---|
| String `WIND version 2.N` | 2.5 (5.4-PPC), 2.6 (5.5-ARM) | 2.10 (6.4-PPC), 2.12 (6.7-ARM) | absent (7-ARM, 7-A64) |
| String `VxWorks N.N` or `VxWorksN.N.N` | `VxWorks5.5.1` (5.5-ARM); absent on 5.4-PPC | `VxWorks 6.4`, `VxWorks 6.7` | absent |
| `vxWorksVersion` / `runtimeVersion` point to | `5.4` (5.4-PPC), `5.5.1` (5.5-ARM) | `6.4`, `6.7` | `VxWorks SMP 32-bit` / `SMP 64-bit`, not a number |
| `vxWorksVersionMajor` (32-bit integer) | symbol absent (5.4-PPC, 5.5-ARM) | 6 (6.4-PPC, 6.7-ARM) | 7 (7-ARM, 7-A64, 7-X64) |
| Build variables text `set WIND_BASE .../vxworks/NN.NN` | absent | absent | `21.03` (7-ARM), `26.09` (7-A64, 7-X64) |

The build variables are the contents of the ELF section `.wrs_build_vars`,
which lies inside the loaded segment and so survives into the raw binary.

## Packaging

- **ELF.** 7.x SDK kernels (`vxWorks`) are ELF executables with one loadable
  segment (two on 7-X64), full `.symtab` and DWARF. *7-ARM, 7-A64, 7-X64.*
- **Raw binary.** `vxWorks.bin` is byte-for-byte the file contents of the ELF's
  loadable segment. *7-ARM, 7-A64.* The 5.x and 6.x samples are raw binaries.
- **uImage.** `uVxWorks` is the raw binary behind a 64-byte U-Boot legacy
  header, uncompressed, with OS field 14 (VxWorks) and architecture field 2
  (ARM) or 22 (AArch64). Load and entry fields hold the physical address.
  *7-ARM, 7-A64.*
- **Vendor header.** 6.7-ARM starts with a 0x1c-byte header before the code:
  header length (0x1c) at offset 0, the address of the first instruction
  (0xf2004000) at offset 0x10 and the file length at offset 0x14. Seen on this
  one image only.
- **Device tree.** 7-ARM embeds a flattened device tree in its data, identical
  in size to the BSP's `imx6q-sabrelite.dtb`. 7-X64 embeds one the size of
  `itl_generic.dtb`. 7-A64 embeds none; its device tree is a separate file.
- **bss.** Raw binaries end where initialised data ends. bss symbols point past
  the end of the file. *All six raw images.*
- No compressed kernel image has been examined. Decompression support is
  tested on synthetic data only.

## RTPs and kernel modules (7.x)

Built from small C sources with the SDK compilers for 7-ARM (21.03) and 7-A64
(26.09), then imported with Ghidra 12.2's ELF loader.

- An RTP (`.vxe`) is an ELF executable linked at 0x80000000 on both
  architectures. A dynamically linked RTP names `libc.so.1` as needed library
  and has an interpreter entry; a static one has neither.
- Ghidra loads static RTPs with nothing left unresolved. In dynamic RTPs it
  reports the COPY relocations as unsupported (2 on 7-ARM, 4 on 7-A64) and
  applies the rest.
- A kernel module (`.out`) is a relocatable ELF object. Calls into the kernel
  are undefined symbols, resolved by the target's loader at load time. Ghidra
  applies every relocation (56 on 7-ARM, 52 on 7-A64) and places the undefined
  symbols in an `EXTERNAL` block.
- The undefined symbols of the test module (`printf`, `taskSpawn`,
  `semBCreate`, `strlen`) all appear in the matching kernel's `standTbl`.
