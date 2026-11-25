# VxAtlas

VxAtlas analyses VxWorks firmware images. Given a kernel image from VxWorks
5.x, 6.x or 7.x, it works out the load address, recovers the symbols from the
kernel's built-in symbol table, and can create a Ghidra program with the
memory map and symbols applied. No manual base address is needed.

It has two parts:

- **`vxatlas`** is a pure-Python library and command-line tool with no
  dependencies. It does all the parsing.
- **`vxatlas-ghidra`** is a thin adapter that feeds the result into Ghidra
  through PyGhidra.

## What it supports

| | 5.x | 6.x | 7.x |
|---|---|---|---|
| Tested on real images | 5.4 PowerPC, 5.5.1 ARM | 6.4 PowerPC, 6.7 ARM | 21.03 ARM, 26.09 AArch64, 26.09 x86-64 |
| Raw binary | yes | yes | yes |
| U-Boot uImage | untested on real images | untested on real images | yes |
| ELF kernel | untested on real images | untested on real images | yes |

MIPS is handled by the same code and passes tests on generated images, but no
real MIPS image has been tested.

For an image with no symbol table, VxAtlas still recovers the base address,
from the image's references to its own strings, at medium confidence. No real
stripped image has been tested; this is checked on the images above with their
symbol table and symbol names removed.

Every conclusion comes with a confidence level and the evidence behind it.
[docs/FORMAT_NOTES.md](docs/FORMAT_NOTES.md) records what has been confirmed
about the image formats.

## Quick start

You need three things on either platform:

- **Python 3.9 to 3.13**, 64-bit. Ghidra 12.2 bundles its Python bridge for
  these versions only.
- **JDK 25**, 64-bit, for example Eclipse Temurin.
- **Ghidra 12.2**, unzipped from the
  [official release](https://github.com/NationalSecurityAgency/ghidra/releases).

If you only want the `vxatlas` command and not the Ghidra import, Python alone
is enough: run `pip install ./core` and skip the rest.

PyGhidra is installed from the copy shipped inside Ghidra, so the two always
match. The last install step downloads `setuptools` from PyPI.

### Linux quick start

```
git clone https://github.com/kevthehermit/VXAtlas.git
cd VXAtlas

export GHIDRA_INSTALL_DIR=/opt/ghidra_12.2_PUBLIC
python3 -m venv .venv
. .venv/bin/activate

pip install --no-index --find-links "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
pip install ./core ./ghidra_adapter
```

Get a sample image and import it:

```
curl -L -o vx5_ppc.bin https://github.com/PAGalaxyLab/vxhunter/raw/master/example_firmware/image_vx5_ppc_big_endian.bin

vxatlas vx5_ppc.bin -v
vxatlas-ghidra import vx5_ppc.bin --project ~/ghidra-projects/demo
```

Then start Ghidra with `$GHIDRA_INSTALL_DIR/ghidraRun` and open the project
`demo` in `~/ghidra-projects/demo`.

On Debian and Ubuntu, `python3 -m venv` needs the `python3-venv` package.

### Windows quick start

In PowerShell:

```powershell
git clone https://github.com/kevthehermit/VXAtlas.git
cd VXAtlas

$env:GHIDRA_INSTALL_DIR = "C:\ghidra_12.2_PUBLIC"
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1

pip install --no-index --find-links "$env:GHIDRA_INSTALL_DIR\Ghidra\Features\PyGhidra\pypkg\dist" pyghidra
pip install .\core .\ghidra_adapter
```

Get a sample image and import it:

```powershell
curl.exe -L -o vx5_ppc.bin https://github.com/PAGalaxyLab/vxhunter/raw/master/example_firmware/image_vx5_ppc_big_endian.bin

vxatlas vx5_ppc.bin -v
vxatlas-ghidra import vx5_ppc.bin --project C:\ghidra-projects\demo
```

Then run `ghidraRun.bat` from the Ghidra folder and open the project `demo` in
`C:\ghidra-projects\demo`.

Notes for Windows:

- `GHIDRA_INSTALL_DIR` must be the folder that contains `ghidraRun.bat`. Set
  this way it lasts for the current PowerShell window; use
  `setx GHIDRA_INSTALL_DIR "C:\ghidra_12.2_PUBLIC"` to keep it.
- If `Activate.ps1` is blocked, run
  `Set-ExecutionPolicy -Scope Process RemoteSigned` first.
- If PyGhidra cannot find Java, check that `java -version` reports 25 in the
  same window.

### After importing

When you first open the imported program, Ghidra offers to analyse it. Say
yes: the import has already set the base address, memory map, labels and
functions, and auto-analysis builds on them. Pass `--analyze` to
`vxatlas-ghidra import` to have that done during the import instead.

On either platform, do not run the commands from a folder that contains a
directory named `ghidra`. It hides Ghidra's own Java package from PyGhidra,
which then fails to start.

## Example

The quick start imports the PowerPC example image from the
[vxhunter](https://github.com/PAGalaxyLab/vxhunter) repository. This is the
full output of that import:

```
$ vxatlas-ghidra import vx5_ppc.bin --project ~/ghidra-projects/demo
VxWorks image:  yes (confidence: high)
Version:        5.x (5.4)
Architecture:   ppc, big-endian, 32-bit (confidence: high)
Container:      raw
Base address:   0x10000 (confidence: high)
Entry point:    0x10000
Symbol table:   10069 symbols at offset 0x301e60, layout vx5-32 (confidence: high)
Segment:        image  0x10000-0x490d2b rwx
Segment:        bss    0x490d2c-0xf01d2b rw-
Note:           bss extent is estimated from the highest symbol past the image
Imported:       /vx5_ppc.bin (PowerPC:BE:32:default, VxAtlas raw loader)
Block:          image 0x00010000-0x00490d2b init
Block:          bss 0x00490d2c-0x00f01d2b uninit
Applied:        10069 labels, 7840 functions, symbol table typed as SYMBOL[10069]
```

In Ghidra the program is mapped at 0x10000 with every kernel symbol labelled,
a function at each code symbol, and bookmarks on `_sysInit`, `usrInit` and
`usrRoot`.

To inspect an image without Ghidra, run `vxatlas image.bin`, adding `-v` for
the evidence or `--json` for machine-readable output.

[docs/USAGE.md](docs/USAGE.md) covers all options, including overriding the
base address or processor, and resolving a kernel module's undefined symbols
against a kernel image.

## Development

Build and test run in Docker against a pinned Ghidra release, so no local
Ghidra is needed.

```
docker compose build ghidra
docker compose run --rm core-test   # core unit tests, no Ghidra
docker compose run --rm build       # build both wheels into dist/
docker compose run --rm test        # all tests, including headless Ghidra
```

The Ghidra version and its checksum are pinned in [.env](.env). To move to a
new release, change them there and re-run the tests.

Tests run on generated images by default. To also run them against real
firmware, point `VXATLAS_SAMPLES` at a directory outside the repository that
holds a `corpus/` folder, as described in
[testdata/README.md](testdata/README.md). Tests that need a missing image are
skipped.

### Layout

| Path | Contents |
|---|---|
| `core/` | `vxatlas`: detection, base recovery, symbol tables. No Ghidra imports. |
| `ghidra_adapter/` | `vxatlas-ghidra`: PyGhidra importer, command-line tool and Ghidra script |
| `docker/` | Build and test environment |
| `testdata/` | Ground-truth records for the external corpus. No firmware. |
| `tools/` | Parity checks against vxhunter and Ghidra's bundled VxWorks script; SDK sample build script |
| `docs/` | Usage and format notes |

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
