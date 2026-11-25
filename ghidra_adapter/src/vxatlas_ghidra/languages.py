"""Map the core's architecture result onto Ghidra language and compiler spec IDs."""

from __future__ import annotations

from typing import Optional, Tuple

# (arch, endian, pointer_size) -> (language ID, compiler spec ID)
_LANGUAGES = {
    ("arm", "little", 4): ("ARM:LE:32:v8", "default"),
    ("arm", "big", 4): ("ARM:BE:32:v8", "default"),
    ("aarch64", "little", 8): ("AARCH64:LE:64:v8A", "default"),
    ("ppc", "big", 4): ("PowerPC:BE:32:default", "default"),
    ("ppc", "little", 4): ("PowerPC:LE:32:default", "default"),
    ("mips", "big", 4): ("MIPS:BE:32:default", "default"),
    ("mips", "little", 4): ("MIPS:LE:32:default", "default"),
    ("x86", "little", 4): ("x86:LE:32:default", "gcc"),
    ("x86_64", "little", 8): ("x86:LE:64:default", "gcc"),
    ("riscv", "little", 8): ("RISCV:LE:64:RV64GC", "gcc"),
}


def language_for(arch: Optional[str], endian: Optional[str],
                 pointer_size: Optional[int]) -> Optional[Tuple[str, str]]:
    """Return (language ID, compiler spec ID), or None if the combination is not mapped."""
    return _LANGUAGES.get((arch, endian, pointer_size))
