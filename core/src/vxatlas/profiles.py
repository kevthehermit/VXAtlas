"""Symbol-table layout profiles.

Each profile describes one verified on-disk layout of the kernel's built-in
symbol array (``standTbl``). Version-specific behaviour lives here, behind one
interface, so later stages never special-case a version.

All verified layouts share this shape (P = pointer size)::

    P   hash-chain link   zero in a table that was never linked at run time
    P   name pointer
    P   value
    [P  reference field   6.x and 7.x only; zero in static tables]
    2   group
    1   type
    1   padding           (then padded to a multiple of P)

A P-sized entry count directly follows the last entry (``standTblSize``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Pattern, Tuple


@dataclass(frozen=True)
class SymbolProfile:
    name: str
    families: Tuple[str, ...]  # version families that use this layout
    pointer_size: int
    entry_size: int
    name_offset: int
    value_offset: int
    type_offset: int
    type_encoding: str  # key into TYPE_DECODERS
    verified_on: Tuple[str, ...]  # short notes on what this was verified against

    def pattern(self, min_entries: int = 16, strict: bool = True) -> Pattern[bytes]:
        """Regex matching a run of at least ``min_entries`` structurally valid entries.

        The pattern is byte-order independent: it constrains only the bytes
        that are zero or non-zero regardless of endianness.

        With ``strict`` off, the hash link, reference and group fields may hold
        anything. That matches a table whose links were filled in at run time
        (for example one captured from memory), at the cost of more look-alikes.
        """
        p = self.pointer_size
        between = self.type_offset - 2 - self.value_offset - p  # reference field, if any
        tail = self.entry_size - self.type_offset - 1  # padding after the type byte
        if strict:
            entry = (
                rb"\x00{%d}" % p            # hash link
                + rb"[\s\S]{%d}" % (2 * p)  # name pointer, value
                + rb"\x00{%d}" % between    # reference field
                + rb"\x00\x00"              # group
                + rb"[^\x00]"               # type
                + rb"\x00{%d}" % tail       # padding
            )
        else:
            entry = (
                rb"[\s\S]{%d}" % (3 * p + between + 2)
                + rb"[\x01-\x7f]"           # type
                + rb"\x00{%d}" % tail       # padding
            )
        return re.compile(rb"(?:" + entry + rb"){%d,}" % min_entries)

    def decode_type(self, raw: int) -> Tuple[str, bool]:
        return TYPE_DECODERS[self.type_encoding](raw)


def _decode_type_v5(raw: int) -> Tuple[str, bool]:
    # Low bit = global; remaining bits are an enumeration.
    kind = {0x02: "abs", 0x04: "function", 0x06: "data", 0x08: "bss", 0x12: "common"}.get(
        raw & 0xFE, "unknown")
    return kind, bool(raw & 0x01)


def _decode_type_v6(raw: int) -> Tuple[str, bool]:
    # Bit flags.
    if raw & 0x04:
        kind = "function"
    elif raw & 0x08:
        kind = "data"
    elif raw & 0x10:
        kind = "bss"
    elif raw & 0x20:
        kind = "common"
    elif raw & 0x02:
        kind = "abs"
    else:
        kind = "unknown"
    return kind, bool(raw & 0x01)


TYPE_DECODERS = {"v5": _decode_type_v5, "v6": _decode_type_v6}

# Type bytes actually observed in ground-truth images, per encoding. Used for scoring.
OBSERVED_TYPES: Dict[str, frozenset] = {
    "v5": frozenset({0x05, 0x07, 0x09}),
    "v6": frozenset({0x03, 0x05, 0x09, 0x11}),
}

VX5_32 = SymbolProfile(
    name="vx5-32",
    families=("5.x",),
    pointer_size=4,
    entry_size=16,
    name_offset=4,
    value_offset=8,
    type_offset=14,
    type_encoding="v5",
    verified_on=("5.5.1 ARM LE", "5.x PowerPC BE"),
)

VX6_32 = SymbolProfile(
    name="vx6-32",
    families=("6.x", "7.x"),
    pointer_size=4,
    entry_size=20,
    name_offset=4,
    value_offset=8,
    type_offset=18,
    type_encoding="v6",
    verified_on=("6.4 PowerPC BE", "6.7 ARM LE", "7 (21.03) ARM LE"),
)

VX7_64 = SymbolProfile(
    name="vx7-64",
    families=("7.x",),
    pointer_size=8,
    entry_size=40,
    name_offset=8,
    value_offset=16,
    type_offset=34,
    type_encoding="v6",
    verified_on=("7 (26.09) AArch64 LE", "7 (26.09) x86-64"),
)

# Widest entries first: a narrower pattern can never match a wider table for
# long, but checking in this order keeps the scan cheap on 64-bit images.
PROFILES: List[SymbolProfile] = [VX7_64, VX6_32, VX5_32]
