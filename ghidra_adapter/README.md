# vxatlas-ghidra

Imports VxWorks 5.x, 6.x and 7.x firmware images into Ghidra using
[vxatlas](https://pypi.org/project/vxatlas/). The image is mapped at the
recovered base address with a bss block, every kernel symbol labelled, a
function at each code symbol and the symbol table typed. No manual base
address is needed.

It needs Ghidra 12.2 or later with a JDK that Ghidra supports, and the
`GHIDRA_INSTALL_DIR` environment variable pointing at the Ghidra folder.

```
pip install vxatlas-ghidra
vxatlas-ghidra import firmware.bin --project ~/ghidra-projects/demo
```

Then open the project in Ghidra.

- `--base`, `--language` and `--compiler` override what was detected.
- `--analyze` runs Ghidra auto-analysis during the import.
- `vxatlas-ghidra module driver.out --kernel vxWorks.bin --project DIR`
  imports a kernel module and resolves its undefined symbols against a kernel
  image.

This package talks to Ghidra through PyGhidra. pip installs PyGhidra from
PyPI; if its version does not match your Ghidra, install the copy shipped
with Ghidra instead:

```
pip install --no-index --find-links "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
```

Documentation, supported versions and known limits are in the
[project repository](https://github.com/kevthehermit/VXAtlas).
