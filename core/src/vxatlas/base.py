"""Load-address recovery for raw images.

The primary signal is the symbol table: every entry holds a pointer to its
name, and the names sit in the image as NUL-terminated strings. The base is
the one offset that makes those pointers land on string starts. Independent
signals (function pointers, the entry symbol, table self-references, a uImage
header) then confirm or contradict each candidate.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Dict, List, Optional, Sequence, Set

from .addrmap import AddressMap
from .model import BaseCandidate, Confidence, Evidence, SymbolTable
from .symtab import RawTable

_IDENT = re.compile(rb"(?<=\x00)[A-Za-z_.$][\x21-\x7e]{1,254}(?=\x00)")
ENTRY_SYMBOLS = ("sysInit", "_sysInit")
MAX_CANDIDATES = 5


def string_starts(data: bytes) -> Set[int]:
    """Offsets of identifier-like NUL-terminated strings."""
    return {m.start() for m in _IDENT.finditer(data)}


def vote_bases(data: bytes, table: RawTable, starts: Optional[Set[int]] = None,
               limit: int = MAX_CANDIDATES) -> List[tuple]:
    """Return [(base, fraction_of_names_on_string_starts)], best first."""
    if starts is None:
        starts = string_starts(data)
    names = [n for n in table.names if n]
    if len(names) < 8 or not starts:
        return []
    lo, hi = len(names) // 20, len(names) - len(names) // 20
    core = names[lo:hi] or names
    step = max(1, len(core) // 48)
    sample = core[::step][:48]
    size = len(data)
    limit = 1 << (8 * table.profile.pointer_size)
    scores: Dict[int, float] = {}
    # Several anchors, in case one sampled entry is not a real symbol.
    for anchor in (sample[0], sample[len(sample) // 2], sample[-1]):
        probes = [p for p in sample if p != anchor][:6]
        for s in starts:
            base = anchor - s
            if base in scores or base < 0 or base + size > limit:
                continue
            if sum(1 for p in probes if (p - base) in starts) < len(probes) - 1:
                continue
            hits = sum(1 for p in sample if 0 <= p - base < size and (p - base) in starts)
            if hits * 10 >= len(sample) * 6:
                scores[base] = sum(1 for p in names if (p - base) in starts) / len(names)
    return sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:limit]


def _alignment(arch: Optional[str]) -> int:
    return 1 if arch in ("x86", "x86_64") else 2 if arch in ("arm", "riscv") else 4


def corroborate(data: bytes, base: int, name_score: float, symtab: SymbolTable,
                arch: Optional[str], uimage_load: Optional[int]) -> BaseCandidate:
    """Score one candidate base against every independent signal available."""
    amap = AddressMap.flat(data, base)
    evidence = [Evidence("name-pointers", "%.1f%% of symbol name pointers land on string starts"
                         % (100 * name_score), name_score >= 0.9)]
    agree = 0

    funcs = [s.value for s in symtab.symbols if s.kind == "function"]
    if funcs:
        align = _alignment(arch)
        inside = sum(1 for v in funcs if amap.to_offset(v) is not None and v % align == 0)
        ratio = inside / len(funcs)
        evidence.append(Evidence(
            "function-pointers",
            "%.1f%% of function symbols point inside the image at an aligned address" % (100 * ratio),
            ratio >= 0.9))
        agree += ratio >= 0.9

    by_name = {s.name: s for s in symtab.symbols}
    for name in ENTRY_SYMBOLS:
        sym = by_name.get(name)
        if sym is None:
            continue
        delta = sym.value - base
        ok = 0 <= delta < 0x200
        evidence.append(Evidence(
            "entry-symbol",
            "%s = 0x%x, which is image offset 0x%x" % (name, sym.value, delta) if ok else
            "%s = 0x%x is not at the start of the image" % (name, sym.value), ok))
        agree += ok
        break

    table_addr = base + symtab.offset
    for name in ("standTbl", "_standTbl"):
        sym = by_name.get(name)
        if sym is not None:
            ok = sym.value == table_addr
            evidence.append(Evidence("table-self-reference",
                                     "%s = 0x%x, table found at 0x%x" % (name, sym.value, table_addr),
                                     ok))
            agree += ok
            break
    for name in ("standTblSize", "_standTblSize"):
        sym = by_name.get(name)
        if sym is not None:
            expect = table_addr + symtab.count * symtab.entry_size
            ok = sym.value == expect
            evidence.append(Evidence("table-self-reference",
                                     "%s = 0x%x, count word found at 0x%x" % (name, sym.value, expect),
                                     ok))
            agree += ok
            break

    if uimage_load is not None:
        if uimage_load == base:
            evidence.append(Evidence("uimage-load", "uImage load address matches (0x%x)" % uimage_load))
            agree += 1
        else:
            # Not a contradiction: the header holds the physical load address,
            # while symbols hold virtual (link) addresses.
            evidence.append(Evidence(
                "uimage-load",
                "uImage physical load address is 0x%x; symbols are linked at 0x%x"
                % (uimage_load, base)))

    if name_score >= 0.95 and agree >= 1:
        confidence = Confidence.HIGH
    elif name_score >= 0.9:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.LOW
    return BaseCandidate(base, confidence, evidence, name_score + 0.05 * agree)
