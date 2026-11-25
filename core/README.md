# vxatlas

VxAtlas analyses VxWorks firmware images. Given a kernel image from VxWorks
5.x, 6.x or 7.x, it works out the load address and recovers the symbols from
the kernel's built-in symbol table. It is pure Python with no dependencies.

```
pip install vxatlas
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
```

- Reads raw binaries, U-Boot uImages and ELF kernels, including gzip, zlib,
  xz, LZMA and bzip2 compressed ones.
- Reports a confidence level and the evidence for every conclusion (`-v`).
- Prints JSON with `--json`, and the recovered symbols with `--symbols`.
- Recovers the base address of an image with no symbol table from its string
  references.

As a library:

```python
from vxatlas import analyze_file

result = analyze_file("firmware.bin")
print(result.version_family, hex(result.base))
for symbol in result.symbol_table.symbols:
    print(hex(symbol.value), symbol.kind, symbol.name)
```

To load the result into Ghidra, install
[vxatlas-ghidra](https://pypi.org/project/vxatlas-ghidra/).

Documentation, supported versions and known limits are in the
[project repository](https://github.com/kevthehermit/VXAtlas).
