# Test data

No firmware is stored in this repository.

- **Synthetic images** are generated in memory by `core/tests/synth.py`. They
  contain filler code and a made-up symbol table laid out per profile. Every
  test that does not need real firmware uses these.
- **`src/`** holds the C sources of a small RTP and kernel module. Building
  them needs a Wind River SDK, so the binaries live in the external corpus.
- **`ground_truth.json`** records facts about real images in the external
  corpus: SHA-256, container, version, architecture, base address, symbol table
  location and size, and a few named symbol values. It holds no image content.

## External corpus

Tests that need real images look in `$VXATLAS_SAMPLES/corpus/` and skip with a
message when a file is missing. A test also skips if a file's SHA-256 differs
from the recorded one.

| Corpus file | Source |
|---|---|
| `vx5_arm_le.bin`, `vx5_ppc_be.bin`, `vx6_arm_le.bin`, `vx6_ppc_be.bin` | `example_firmware/` in the [vxhunter](https://github.com/PAGalaxyLab/vxhunter) repository |
| `vx7_2103_arm_le.{bin,uimage,elf}` | Wind River VxWorks 7 SDK for QEMU sabrelite, `wrsdk-vxworks7-qemu-sabrelite-1.5` |
| `vx7_2609_aarch64.{bin,uimage,elf}` | Wind River VxWorks 7 SDK for Raspberry Pi 4, `wrsdk-vxworks7-raspberrypi4b-1.10.0` |
| `vx7_2609_x86_64.elf` | Wind River VxWorks 7 SDK for QEMU x86-64, `wrsdk-vxworks7-qemu-1.18.0` |

| `vx7_2609_aarch64_hello_*.{vxe,out}`, `vx7_2103_arm_le_hello_*.{vxe,out}` | Built from `testdata/src/` with the matching SDK by `tools/build_sdk_samples.sh` |

The `source` field of each record in `ground_truth.json` gives the path inside
the SDK or repository. Name the files as above (copies or symlinks).

The Wind River SDKs are published under Wind River's non-commercial licence,
which does not allow redistribution. Download them yourself from Wind River,
keep them outside this repository, and do not add anything from them to git or
to a Docker image.

## How the ground truth was established

- **7.x:** the SDKs ship each kernel as an ELF with full symbols next to the
  raw and uImage builds of the same kernel. Base address, table location and
  entry count come from the ELF's program headers and its `standTbl` and
  `standTblSize` symbols, read with `readelf`.
- **5.x and 6.x:** table location, entry count and base address were derived by
  hand from the images, then confirmed against vxhunter, which recovers the
  same base and the same symbols (see `tools/parity/`).
