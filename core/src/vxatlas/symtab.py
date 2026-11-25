"""Locate and decode the kernel's built-in symbol table."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from .addrmap import AddressMap
from .model import Confidence, Evidence, Symbol, SymbolTable
from .profiles import OBSERVED_TYPES, PROFILES, SymbolProfile

MIN_ENTRIES = 16
HEURISTIC_MIN_ENTRIES = 64
MAX_NAME_LEN = 1024


@dataclass
class RawTable:
    """A run of structurally valid entries, before names are resolved."""

    profile: SymbolProfile
    offset: int
    endian: str
    names: List[int]
    values: List[int]
    types: List[int]
    heuristic: bool = False
    notes: List[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.names)

    @property
    def end(self) -> int:
        return self.offset + self.count * self.profile.entry_size


def _spread(values: Sequence[int]) -> int:
    """Width of the central 80% of the values: small for real pointers into one image."""
    ordered = sorted(values)
    n = len(ordered)
    return ordered[(n * 9) // 10 - 1 if n >= 10 else n - 1] - ordered[n // 10]


def _decode_run(data: bytes, start: int, end: int, profile: SymbolProfile) -> RawTable:
    p = profile.pointer_size
    code = "I" if p == 4 else "Q"
    chunk = memoryview(data)[start:end]
    best: Optional[Tuple[int, str, List[int], List[int]]] = None
    for endian, prefix in (("little", "<"), ("big", ">")):
        # hash link, name, value, then the rest of the entry as padding bytes
        fmt = prefix + "%dx%s%s%dx" % (p, code, code, profile.entry_size - 3 * p)
        names: List[int] = []
        values: List[int] = []
        for name, value in struct.iter_unpack(fmt, chunk):
            names.append(name)
            values.append(value)
        spread = _spread(names)
        if best is None or spread < best[0]:
            best = (spread, endian, names, values)
    assert best is not None
    _, endian, names, values = best
    types = list(data[start + profile.type_offset:end:profile.entry_size])
    return RawTable(profile, start, endian, names, values, types)


def find_raw_tables(data: bytes, profiles: Sequence[SymbolProfile] = PROFILES,
                    ranges: Optional[Sequence[Tuple[int, int]]] = None,
                    strict: bool = True) -> List[RawTable]:
    """Find every run of entries matching a known profile, largest first.

    ``ranges`` limits the scan to the given (start, end) payload offsets.
    With ``strict`` off the relaxed patterns are used and every result is
    marked heuristic, which caps its confidence at low.
    """
    found: List[RawTable] = []
    claimed: List[Tuple[int, int]] = []
    for profile in profiles:
        pattern = profile.pattern(MIN_ENTRIES if strict else HEURISTIC_MIN_ENTRIES, strict)
        for lo, hi in (ranges or [(0, len(data))]):
            for m in pattern.finditer(data, lo, hi):
                start, end = m.span()
                # A strict match is unambiguous, so a narrower profile need not re-examine
                # it. Relaxed matches are not: keep them all and let name resolution decide.
                if strict and any(start < c_end and end > c_start for c_start, c_end in claimed):
                    continue
                table = _decode_run(data, start, end, profile)
                table.heuristic = not strict
                found.append(table)
                claimed.append((start, end))
    found.sort(key=lambda t: t.count, reverse=True)
    return found


def count_word(data: bytes, table: RawTable, end_offset: int) -> Optional[int]:
    """Read the pointer-sized word that follows the table (``standTblSize``)."""
    p = table.profile.pointer_size
    if end_offset + p > len(data):
        return None
    return int.from_bytes(data[end_offset:end_offset + p], table.endian)


def resolve(data: bytes, table: RawTable, amap: AddressMap) -> SymbolTable:
    """Turn a raw table into symbols, keeping only entries whose name resolves.

    Entries at either end of the run that do not resolve are treated as
    look-alike data outside the real table and trimmed. Unresolved entries
    inside the table are dropped and counted, never emitted.
    """
    profile = table.profile
    if len(set(table.names)) * 2 < table.count:
        # Repeating data (filler, arrays of one value) can satisfy a layout
        # pattern; a symbol table names each entry differently.
        return SymbolTable(profile.name, table.offset, 0, profile.entry_size,
                           profile.pointer_size, table.endian, [], Confidence.NONE,
                           [Evidence("names", "entries repeat the same name pointer", False)])
    resolved: List[Optional[str]] = [amap.cstring(n, MAX_NAME_LEN) if n else None
                                     for n in table.names]
    first = next((i for i, n in enumerate(resolved) if n is not None), None)
    if first is None:
        return SymbolTable(profile.name, table.offset, 0, profile.entry_size,
                           profile.pointer_size, table.endian, [], Confidence.NONE,
                           [Evidence("names", "no entry name resolves to a string", False)])
    last = len(resolved) - 1 - next(i for i, n in enumerate(reversed(resolved)) if n is not None)

    symbols: List[Symbol] = []
    rejected = 0
    for i in range(first, last + 1):
        name = resolved[i]
        if name is None:
            rejected += 1
            continue
        kind, is_global = profile.decode_type(table.types[i])
        symbols.append(Symbol(name, table.values[i], kind, is_global, table.types[i],
                              table.offset + i * profile.entry_size))

    count = last - first + 1
    offset = table.offset + first * profile.entry_size
    end = offset + count * profile.entry_size
    evidence: List[Evidence] = [
        Evidence("layout", "%d consecutive entries match profile %s (%d-byte entries, %s-endian)"
                 % (count, profile.name, profile.entry_size, table.endian)),
    ]
    if table.heuristic:
        evidence.append(Evidence(
            "heuristic", "table does not match the profile exactly (link, reference or group "
            "fields are not zero); found by relaxed scan", False))
    evidence += [
        Evidence("names", "%d of %d entry names resolve to printable strings"
                 % (len(symbols), count), rejected == 0),
    ]
    trailer = count_word(data, table, end)
    count_ok = trailer == count
    if count_ok:
        evidence.append(Evidence("count-word", "word after the table equals the entry count (%d)"
                                 % count))
    else:
        evidence.append(Evidence("count-word", "word after the table is %s, entry count is %d"
                                 % ("absent" if trailer is None else hex(trailer), count), False))
    observed = OBSERVED_TYPES[profile.type_encoding]
    typed = sum(1 for s in symbols if s.raw_type in observed)
    type_ratio = typed / len(symbols)
    evidence.append(Evidence("types", "%.1f%% of entries use a type value seen in reference images"
                             % (100 * type_ratio), type_ratio >= 0.95))

    name_ratio = len(symbols) / count
    if table.heuristic:
        confidence = Confidence.LOW
    elif name_ratio >= 0.99 and count_ok and type_ratio >= 0.95:
        confidence = Confidence.HIGH
    elif name_ratio >= 0.95 and (count_ok or type_ratio >= 0.95):
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.LOW
    return SymbolTable(profile.name, offset, count, profile.entry_size, profile.pointer_size,
                       table.endian, symbols, confidence, evidence, rejected)
