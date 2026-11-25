# Using VxAtlas

VxAtlas has two parts:

- `vxatlas`, a pure-Python core with a command-line tool. It identifies an
  image and recovers its load address and symbols. It needs nothing but Python.
- `vxatlas-ghidra`, which uses the core to create a Ghidra program through
  PyGhidra. It needs a Ghidra installation.

## Inspecting an image

```
vxatlas firmware.bin
```

```
VxWorks image:  yes (confidence: high)
Version:        6.x (6.7)
Architecture:   arm, little-endian, 32-bit (confidence: high)
Container:      raw
Base address:   0xf2003fe4 (confidence: high)
Entry point:    0xf2004000
Symbol table:   11519 symbols at offset 0x33645c, layout vx6-32 (confidence: high)
Segment:        image  0xf2003fe4-0xf2372be3 rwx
Segment:        bss    0xf2372be4-0xf23a3be3 rw-
```

| Option | Effect |
|---|---|
| `-v`, `--verbose` | List the evidence behind each conclusion |
| `--json` | Print the full result as JSON |
| `--symbols` | Include the recovered symbols (text: one per line; JSON: in `symbol_table.symbols`) |

The exit status is 0 if the file was identified as VxWorks, 1 if not, and 2 if
it could not be read.

The input may be a raw binary, a U-Boot uImage, an ELF kernel, or any of those
compressed with gzip, zlib, xz, LZMA or bzip2. Offsets in the output refer to
the unwrapped payload; the `Container` line shows what was unwrapped.

### Reading the result

- **Confidence** is `high`, `medium`, `low` or `none`. Run with `-v` to see what
  it rests on. A line starting `[-]` is a signal that did not agree.
- **Base address** is the address the image is linked at, which is where
  symbol values point. For 7.x this is a virtual address and differs from the
  physical load address in a uImage or ELF header; `-v` shows both.
- If several base addresses fit, they are listed as alternatives, best first.
- **bss** is not stored in a raw image. Its segment is sized from the highest
  symbol past the end of the file, so its end is an estimate.
- A stripped image has no symbol table. VxAtlas says so and recovers the base
  address from the image's references to its own strings instead. See
  [Stripped images](#stripped-images).

### Stripped images

Without a symbol table, VxAtlas looks for the base address at which the most
strings in the image are pointed to, by stored pointers or by the instruction
pairs PowerPC and MIPS use to build an address.

```
Base address:   0x10000 (confidence: medium)
Symbol table:   not found
Note:           base address recovered from string references, because there is no symbol table
```

- The result is `medium` confidence at best, because it rests on one kind of
  evidence. It becomes `high` only when a uImage header gives the same address.
- `-v` shows how many strings the base explains and how far ahead it is of the
  next candidate. Treat a lead of less than three times as a guess; it is
  reported as `low`.
- A uImage load address that differs from the recovered base is listed as a
  low-confidence alternative. In 7.x it is the physical address.
- No symbols are recovered. Only the base address and memory map are.

## Importing into Ghidra

```
vxatlas-ghidra import firmware.bin --project ~/ghidra-projects/router
```

This creates the project if needed and adds a program with:

- the processor chosen from the detected architecture
- an `image` block at the recovered base address and a `bss` block after it
- a label for every recovered symbol, and a function at every code symbol
- the entry point marked
- VxAtlas's conclusions, including alternative base addresses, under
  *Edit > Options for ... > Program Information* (entries starting `VxAtlas`)

Open the project in Ghidra afterwards. Auto-analysis has not run, so Ghidra
offers it when you first open the program.

ELF kernels are loaded by Ghidra's own ELF loader. VxAtlas then adds the
symbols from the kernel's built-in table, which helps when the ELF's own
symbol table has been stripped.

### Loader options

| Option | Default | Effect |
|---|---|---|
| `--project DIR` | required | Directory holding the Ghidra project |
| `--project-name NAME` | name of `DIR` | Ghidra project name |
| `--name NAME` | file name | Program name inside the project |
| `--base ADDR` | recovered | Map the image at this address instead. Symbols keep their own values. |
| `--language ID` | detected | Ghidra language ID, for example `ARM:LE:32:v5t` or `PowerPC:BE:32:e500` |
| `--compiler ID` | language default | Ghidra compiler spec ID |
| `--no-functions` | off | Create labels only; do not disassemble or create functions |
| `--analyze` | off | Run Ghidra auto-analysis after importing |
| `--json` | off | Print the import report as JSON |

`--base` is required only when no base address could be recovered, which
happens for a stripped image that holds too few string references.
`--language` is required when the architecture cannot be detected.

Default languages:

| Detected | Ghidra language |
|---|---|
| ARM, 32-bit | `ARM:LE:32:v8` or `ARM:BE:32:v8` |
| AArch64 | `AARCH64:LE:64:v8A` |
| PowerPC, 32-bit | `PowerPC:BE:32:default` or `PowerPC:LE:32:default` |
| MIPS, 32-bit | `MIPS:BE:32:default` or `MIPS:LE:32:default` |
| x86 / x86-64 | `x86:LE:32:default` / `x86:LE:64:default` |

Pass `--language` for a more specific variant, such as a PowerPC e500 core or
an older ARM architecture version.

### Symbols that are not applied

The import summary counts symbols it did not turn into labels:

- **Absolute constants.** Symbols such as `_vx_offset_*` hold structure offsets
  and other constants, not addresses.
- **Outside the memory map.** In 7.x a few thread-local symbols hold offsets
  rather than addresses.

## Kernel modules and RTPs

Real-time processes (`.vxe`) are ordinary ELF executables and downloadable
kernel modules (`.out`) are relocatable ELF objects. Ghidra's own ELF loader
imports both, so import them in Ghidra as usual.

A kernel module calls into the kernel through undefined symbols, which Ghidra
leaves as placeholders in an `EXTERNAL` block. To resolve them against the
kernel the module runs in:

```
vxatlas-ghidra import vxWorks.bin --project ~/ghidra-projects/demo
vxatlas-ghidra module driver.out --kernel vxWorks.bin \
    --project ~/ghidra-projects/demo --kernel-program /vxWorks.bin
```

```
Imported:       /driver.out
Resolved:       4 of 4 undefined symbols
  0xffffffff802d24c0 printf
  ...
```

Each resolved placeholder gets a comment with the kernel address and an
external location in a library named `vxWorks`. With `--kernel-program`, that
library is linked to the kernel program in the same project, so you can follow
a call from the module into the kernel.

| Option | Default | Effect |
|---|---|---|
| `--kernel IMAGE` | required | Kernel image whose symbols resolve the module's undefined symbols |
| `--project DIR` | required | Directory holding the Ghidra project |
| `--project-name NAME` | name of `DIR` | Ghidra project name |
| `--name NAME` | file name | Program name inside the project |
| `--kernel-program PATH` | none | Project path of the already imported kernel, to link the two programs |
| `--json` | off | Print the report as JSON |

RTPs link against user-space libraries, not the kernel, so there is nothing
for VxAtlas to resolve in them.

## From inside Ghidra

For a raw image you have already imported with Ghidra's *Raw Binary* format,
run the script **VxAtlasAnalyze.py** (category *VxWorks*) from the Script
Manager. It moves the image to the recovered base address, adds the bss block
and applies the symbols. It needs Ghidra started in PyGhidra mode
(`support/pyghidraRun`) with `vxatlas-ghidra` installed in PyGhidra's Python
environment, and the script directory added in the Script Manager:

```
python -c "import vxatlas_ghidra, pathlib; print(pathlib.Path(vxatlas_ghidra.__file__).parent / 'ghidra_scripts')"
```

The script cannot unwrap a uImage or compressed image, and it cannot change
the program's processor. Use `vxatlas-ghidra import` for those cases.

## Using the core as a library

```python
from vxatlas import analyze_file

result = analyze_file("firmware.bin")
print(result.version_family, hex(result.base))
for symbol in result.symbol_table.symbols:
    print(hex(symbol.value), symbol.kind, symbol.name)
```

`result.to_dict()` gives the same structure as `vxatlas --json`.
