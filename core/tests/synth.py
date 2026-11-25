"""Build small synthetic VxWorks-like images for unit tests.

Nothing here comes from real firmware: the "code" is filler made of one
architecture's return instruction, and the symbol table is generated from a
list of made-up names, laid out according to a profile.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from vxatlas.profiles import SymbolProfile

RETURNS = {
    ("arm", "little"): b"\x1e\xff\x2f\xe1",
    ("ppc", "big"): b"\x4e\x80\x00\x20",
    ("mips", "big"): b"\x03\xe0\x00\x08",
    ("mips", "little"): b"\x08\x00\xe0\x03",
    ("aarch64", "little"): b"\xc0\x03\x5f\xd6",
}


@dataclass
class SynthImage:
    data: bytes
    base: int
    table_offset: int
    symbols: Dict[str, Tuple[int, str]]  # name -> (value, kind)


def build_image(profile: SymbolProfile, arch: str, endian: str, base: int,
                count: int = 200, banner: Optional[bytes] = None,
                with_table: bool = True, header: bytes = b"",
                linked: bool = False, string_refs: int = 0) -> SynthImage:
    """``string_refs`` adds that many message strings, each referenced the way the
    architecture would: by an instruction pair on PowerPC and MIPS, otherwise by
    a pointer-sized word."""
    e = "<" if endian == "little" else ">"
    ptr = e + ("I" if profile.pointer_size == 4 else "Q")
    p = profile.pointer_size
    func_type, data_type, bss_type = ((0x05, 0x07, 0x09) if profile.type_encoding == "v5"
                                      else (0x05, 0x09, 0x11))

    code_words = 2048
    code = RETURNS[(arch, endian)] * code_words
    blob = bytearray(header + code)
    code_start = len(header)

    if string_refs:
        blob += _string_references(arch, e, ptr, base, len(blob), string_refs)

    names: List[str] = ["sysInit", "usrInit", "usrRoot", "taskSpawn", "sysSymTbl"]
    names += ["synthFunc%04d" % i for i in range(count - len(names))]
    strings_off = len(blob) + 1
    blob += b"\x00"
    name_offs = []
    for n in names:
        name_offs.append(len(blob))
        blob += n.encode() + b"\x00"
    if banner:
        blob += banner + b"\x00"
    while len(blob) % 8:
        blob += b"\x00"

    image_end_guess = len(blob) + count * profile.entry_size + 64
    symbols: Dict[str, Tuple[int, str]] = {}
    table_offset = len(blob)
    for i, (n, off) in enumerate(zip(names, name_offs)):
        if n == "sysInit":
            value, typ, kind = base + code_start, func_type, "function"
        elif n == "sysSymTbl":
            value, typ, kind = base + image_end_guess + 0x100, bss_type, "bss"
        elif i % 10 == 9:
            value, typ, kind = base + strings_off, data_type, "data"
        else:
            value, typ, kind = base + code_start + 4 * i, func_type, "function"
        symbols[n] = (value, kind)
        if not with_table:
            continue
        entry = bytearray(profile.entry_size)
        if linked:  # as if the hash chains had been filled in at run time
            struct.pack_into(ptr, entry, 0, base + table_offset + ((i * 7) % count) * profile.entry_size)
        struct.pack_into(ptr, entry, profile.name_offset, base + off)
        struct.pack_into(ptr, entry, profile.value_offset, value)
        entry[profile.type_offset] = typ
        blob += entry
    if with_table:
        blob += struct.pack(ptr, count)
    blob += b"\x00" * 32
    return SynthImage(bytes(blob), base, table_offset, symbols)


def _string_references(arch: str, e: str, ptr: str, base: int, at: int, count: int) -> bytes:
    """Message strings followed by code or data that refers to each one by address."""
    pool = bytearray(b"\x00")
    offsets = []
    for i in range(count):
        offsets.append(at + len(pool))
        # Lengths follow no period, as in real firmware; a periodic layout would
        # let a shifted base explain almost as many strings as the right one.
        filler = int.from_bytes(hashlib.sha256(b"%d" % i).digest()[:2], "big") % 61
        pool += ("message %04d %s" % (i, "x" * filler)).encode() + b"\x00"
    while (at + len(pool)) % 8:
        pool += b"\x00"
    refs = bytearray()
    for off in offsets:
        address = base + off
        if arch in ("ppc", "mips"):
            lo = address & 0xFFFF
            hi = ((address >> 16) + (1 if lo & 0x8000 else 0)) & 0xFFFF
            load_upper, add_lower = ((0x3C600000, 0x38630000) if arch == "ppc"
                                     else (0x3C040000, 0x24840000))
            refs += struct.pack(e + "II", load_upper | hi, add_lower | lo)
        else:
            refs += struct.pack(ptr, address)
    return bytes(pool + refs)


def wrap_uimage(payload: bytes, load: int, arch_id: int, os_id: int = 14) -> bytes:
    name = b"vxworks".ljust(32, b"\x00")
    fields = [0x27051956, 0, 0, len(payload), load, load, zlib.crc32(payload) & 0xFFFFFFFF]
    header = bytearray(struct.pack(">7I4B32s", *fields, os_id, arch_id, 2, 0, name))
    struct.pack_into(">I", header, 4, zlib.crc32(bytes(header)) & 0xFFFFFFFF)
    return bytes(header) + payload
