"""Detect and remove wrappers around a kernel payload.

Supported: U-Boot legacy uImage, and gzip / zlib / xz / LZMA-alone / bzip2
streams that start at offset 0 of a layer. Each unwrapped layer is reported
with its offset so the caller can relate payload offsets back to the file.
"""

from __future__ import annotations

import bz2
import lzma
import struct
import zlib
from typing import Callable, Dict, List, Optional, Tuple

from .model import Layer

UIMAGE_MAGIC = 0x27051956
UIMAGE_HEADER_SIZE = 64

# Values from U-Boot's public image.h.
UIMAGE_OS: Dict[int, str] = {5: "linux", 14: "vxworks", 17: "u-boot"}
UIMAGE_ARCH: Dict[int, Tuple[str, Optional[int]]] = {
    2: ("arm", 4),
    3: ("x86", 4),
    5: ("mips", 4),
    6: ("mips64", 8),
    7: ("ppc", 4),
    22: ("aarch64", 8),
    24: ("x86_64", 8),
    26: ("riscv", None),
}
UIMAGE_COMP: Dict[int, str] = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 5: "lz4"}

FDT_MAGIC = b"\xd0\x0d\xfe\xed"
FDT_MAX_SIZE = 4 << 20

MAX_DEPTH = 4
MAX_DECOMPRESSED = 1 << 30


def _parse_uimage(data: bytes) -> Optional[Tuple[bytes, Layer]]:
    if len(data) < UIMAGE_HEADER_SIZE:
        return None
    (magic, hcrc, timestamp, size, load, entry, dcrc, os_id, arch_id, type_id,
     comp_id, name) = struct.unpack_from(">7I4B32s", data, 0)
    if magic != UIMAGE_MAGIC:
        return None
    header = bytearray(data[:UIMAGE_HEADER_SIZE])
    header[4:8] = b"\x00\x00\x00\x00"
    header_crc_ok = (zlib.crc32(bytes(header)) & 0xFFFFFFFF) == hcrc
    if not header_crc_ok:
        return None  # the magic alone is too weak a signal
    payload = data[UIMAGE_HEADER_SIZE:UIMAGE_HEADER_SIZE + size]
    arch, pointer_size = UIMAGE_ARCH.get(arch_id, (None, None))
    info = {
        "name": name.split(b"\x00")[0].decode("latin-1"),
        "load_address": load,
        "entry_point": entry,
        "os": UIMAGE_OS.get(os_id, "unknown(%d)" % os_id),
        "arch": arch or "unknown(%d)" % arch_id,
        "pointer_size": pointer_size,
        "image_type": type_id,
        "compression": UIMAGE_COMP.get(comp_id, "unknown(%d)" % comp_id),
        "timestamp": timestamp,
        "header_crc_ok": header_crc_ok,
        "data_crc_ok": (zlib.crc32(payload) & 0xFFFFFFFF) == dcrc,
        "truncated": len(payload) < size,
    }
    return payload, Layer("uimage", UIMAGE_HEADER_SIZE, len(payload), info)


def _inflate(decompressor, data: bytes) -> Optional[bytes]:
    try:
        out = decompressor.decompress(data, MAX_DECOMPRESSED)
    except Exception:
        return None
    return out or None


def _try_gzip(data: bytes) -> Optional[bytes]:
    if data[:3] != b"\x1f\x8b\x08":
        return None
    return _inflate(zlib.decompressobj(16 + zlib.MAX_WBITS), data)


def _try_zlib(data: bytes) -> Optional[bytes]:
    if len(data) < 2 or data[0] != 0x78 or ((data[0] << 8) | data[1]) % 31:
        return None
    return _inflate(zlib.decompressobj(), data)


def _try_xz(data: bytes) -> Optional[bytes]:
    if data[:6] != b"\xfd7zXZ\x00":
        return None
    return _inflate(lzma.LZMADecompressor(format=lzma.FORMAT_XZ), data)


def _try_lzma(data: bytes) -> Optional[bytes]:
    # LZMA-alone: properties byte, 4-byte dictionary size, 8-byte uncompressed size.
    if len(data) < 13 or data[0] > 0xE0:
        return None
    dict_size = struct.unpack_from("<I", data, 1)[0]
    if dict_size == 0 or dict_size & (dict_size - 1):
        return None
    return _inflate(lzma.LZMADecompressor(format=lzma.FORMAT_ALONE), data)


def _try_bzip2(data: bytes) -> Optional[bytes]:
    if data[:3] != b"BZh" or data[4:10] != b"1AY&SY":
        return None
    return _inflate(bz2.BZ2Decompressor(), data)


_COMPRESSORS: List[Tuple[str, Callable[[bytes], Optional[bytes]]]] = [
    ("gzip", _try_gzip),
    ("xz", _try_xz),
    ("bzip2", _try_bzip2),
    ("zlib", _try_zlib),
    ("lzma", _try_lzma),
]


def unwrap(data: bytes) -> Tuple[bytes, List[Layer]]:
    """Peel wrappers off ``data``. Returns the innermost payload and the layers, outermost first."""
    layers: List[Layer] = []
    for _ in range(MAX_DEPTH):
        parsed = _parse_uimage(data)
        if parsed:
            data, layer = parsed
            layers.append(layer)
            continue
        for kind, fn in _COMPRESSORS:
            out = fn(data)
            # Require real expansion so a chance header match on raw code is not accepted.
            if out and len(out) >= 4096:
                layers.append(Layer(kind, 0, len(out), {"compressed_size": len(data)}))
                data = out
                break
        else:
            break
    return data, layers


def find_device_trees(data: bytes) -> List[Dict[str, int]]:
    """Locate flattened device tree blobs embedded in ``data``.

    A hit needs the magic plus a self-consistent header, so stray magic bytes
    in code are not reported.
    """
    found: List[Dict[str, int]] = []
    pos = data.find(FDT_MAGIC)
    while pos >= 0:
        if pos + 40 <= len(data):
            (_magic, total, off_struct, off_strings, off_rsvmap, version, last_comp, _cpu,
             size_strings, size_struct) = struct.unpack_from(">10I", data, pos)
            if (40 <= total <= FDT_MAX_SIZE and pos + total <= len(data)
                    and 16 <= last_comp <= version <= 32
                    and off_rsvmap < off_struct < total and off_strings < total
                    and off_struct + size_struct <= total
                    and off_strings + size_strings <= total):
                found.append({"offset": pos, "size": total, "version": version})
                pos = data.find(FDT_MAGIC, pos + total)
                continue
        pos = data.find(FDT_MAGIC, pos + 4)
    return found
