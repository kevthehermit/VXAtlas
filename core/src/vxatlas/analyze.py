"""The analysis pipeline: unwrap, identify, recover base and symbols."""

from __future__ import annotations

from typing import List, Optional

from . import base as base_mod
from . import strbase
from .addrmap import AddressMap
from .arch import detect_arch
from .containers import find_device_trees, unwrap
from .elf import ELF_MAGIC, ElfError, ElfFile
from .profiles import OBSERVED_TYPES, PROFILES
from .model import Analysis, BaseCandidate, Confidence, Evidence, Segment, SymbolTable
from .symtab import RawTable, find_raw_tables, resolve
from .version import detect_version

# Symbols present in every reference kernel; used to tell a VxWorks table from a look-alike.
KERNEL_SYMBOLS = ("sysInit", "_sysInit", "usrInit", "_usrInit", "usrRoot", "taskSpawn",
                  "_taskSpawn", "sysSymTbl", "_sysSymTbl")
BSS_SLACK = 0x1000
MAX_BSS = 256 << 20


def analyze_file(path: str) -> Analysis:
    with open(path, "rb") as fh:
        return analyze(fh.read())


def analyze(blob: bytes) -> Analysis:
    result = Analysis(size=len(blob))
    payload, result.layers = unwrap(blob)
    result.payload = payload
    result.device_trees = find_device_trees(payload)
    uimage = next((l for l in result.layers if l.kind == "uimage"), None)

    elf: Optional[ElfFile] = None
    if payload[:4] == ELF_MAGIC:
        try:
            elf = ElfFile(payload)
        except ElfError as exc:
            result.notes.append("ELF header present but unreadable: %s" % exc)

    if elf is not None:
        _analyze_elf(result, payload, elf, _find_elf_tables(payload, elf))
    else:
        tables = find_raw_tables(payload) or find_raw_tables(payload, strict=False)
        _analyze_raw(result, payload, tables, uimage.info if uimage else None)

    amap = AddressMap(payload, result.segments) if result.segments else None
    family, version, version_evidence = detect_version(payload, amap, result.symbol_table)
    result.version_family, result.version = family, version
    _conclude(result, version_evidence, uimage.info if uimage else None)
    return result


def _find_elf_tables(payload: bytes, elf: ElfFile) -> List[RawTable]:
    """Scan an ELF for symbol tables, looking in initialised data sections first."""
    profiles = [p for p in PROFILES if p.pointer_size == elf.pointer_size]
    SHT_PROGBITS, SHF_ALLOC, SHF_EXECINSTR = 1, 0x2, 0x4
    data_ranges = [(s.offset, s.offset + s.size) for s in elf.sections
                   if s.type == SHT_PROGBITS and s.flags & SHF_ALLOC
                   and not s.flags & SHF_EXECINSTR and s.size]
    if data_ranges:
        tables = find_raw_tables(payload, profiles, data_ranges)
        if tables:
            return tables
    loaded = [(s.file_offset, s.file_offset + s.file_size) for s in elf.segments if s.file_size]
    return (find_raw_tables(payload, profiles, loaded or None)
            or find_raw_tables(payload, profiles, data_ranges or loaded or None, strict=False))


def _best_table(payload: bytes, tables: List[RawTable], amap: AddressMap) -> Optional[SymbolTable]:
    best: Optional[SymbolTable] = None
    for raw in tables[:8]:
        st = resolve(payload, raw, amap)
        if raw.heuristic and st.symbols and not _plausible_kernel_table(st):
            continue
        if st.symbols and (best is None or len(st.symbols) > len(best.symbols)):
            best = st
    return best


def _analyze_elf(result: Analysis, payload: bytes, elf: ElfFile, tables: List[RawTable]) -> None:
    kind = {1: "relocatable", 2: "executable", 3: "shared object"}.get(elf.type, "type %d" % elf.type)
    result.layers.append(_layer("elf", payload, {"type": kind, "machine": elf.machine,
                                                 "has_symtab": elf.has_symtab}))
    result.arch, result.endian, result.pointer_size = elf.arch, elf.endian, elf.pointer_size
    result.arch_confidence = Confidence.HIGH if elf.arch else Confidence.NONE
    result.segments = list(elf.segments)
    result.entry_point = elf.entry
    if elf.segments:
        lowest = min(s.address for s in elf.segments)
        result.base_candidates = [BaseCandidate(lowest, Confidence.HIGH, [
            Evidence("elf-program-headers", "lowest PT_LOAD virtual address is 0x%x" % lowest)], 1.0)]
        for vaddr, paddr in elf.physical:
            if vaddr != paddr:
                result.notes.append("segment at virtual 0x%x loads at physical 0x%x" % (vaddr, paddr))
        result.symbol_table = _best_table(payload, tables, AddressMap(payload, elf.segments))
    result.symbols_stripped = result.symbol_table is None


def _analyze_raw(result: Analysis, payload: bytes, tables: List[RawTable],
                 uimage: Optional[dict]) -> None:
    result.layers.append(_layer("raw", payload, {}))
    uimage_load = uimage["load_address"] if uimage else None
    # Only an exact profile match is trusted to say what the byte order and
    # pointer size are; relaxed matches are often look-alike data.
    trusted = next((t for t in tables if not t.heuristic), None)
    endian_hint = trusted.endian if trusted else None
    psize_hint = trusted.profile.pointer_size if trusted else None
    arch, endian, psize, conf, arch_evidence = detect_arch(payload, endian_hint, psize_hint)
    if uimage and uimage.get("arch") and not uimage["arch"].startswith("unknown"):
        if arch and arch != uimage["arch"]:
            result.notes.append("uImage header says %s but the code looks like %s"
                                % (uimage["arch"], arch))
        arch, conf = uimage["arch"], Confidence.HIGH
        psize = psize or uimage.get("pointer_size")
        arch_evidence.append(Evidence("uimage-arch", "uImage header architecture is %s" % arch))
    result.arch, result.arch_confidence = arch, conf
    result.endian = endian_hint or endian
    result.pointer_size = psize_hint or psize
    result.evidence.extend(arch_evidence)

    candidates: List[BaseCandidate] = []
    best_table: Optional[SymbolTable] = None
    if tables:
        starts = base_mod.string_starts(payload)
        for raw in tables[:4]:
            for base, score in base_mod.vote_bases(payload, raw, starts):
                st = resolve(payload, raw, AddressMap.flat(payload, base))
                if not st.symbols:
                    continue
                if raw.heuristic and not _plausible_kernel_table(st):
                    continue  # a relaxed match must prove it is a kernel symbol table
                cand = base_mod.corroborate(payload, base, score, st, arch, uimage_load)
                candidates.append(cand)
                if cand is max(candidates, key=lambda c: c.score):
                    best_table = st
            if candidates:
                break  # the largest table that yields a base wins
        if not candidates:
            result.notes.append("data resembling a symbol table was found, but its name "
                                "pointers do not resolve to strings at any base address")
    candidates.sort(key=lambda c: c.score, reverse=True)
    candidates = candidates[:4]
    for other in candidates[1:]:
        # A base that explains fewer names than the best one is a fallback, never a peer.
        if other.score < candidates[0].score:
            other.confidence = Confidence.LOW
            other.evidence.append(Evidence(
                "ranking", "resolves fewer symbol names than 0x%x" % candidates[0].address, False))

    if not candidates:
        candidates = _stripped_candidates(result, payload, uimage_load)
    if best_table is not None:
        result.endian, result.pointer_size = best_table.endian, best_table.pointer_size
    result.base_candidates = candidates
    result.symbol_table = best_table
    result.symbols_stripped = best_table is None
    if uimage:
        result.entry_point = uimage.get("entry_point")

    if candidates:
        base = candidates[0].address
        result.segments = [Segment("image", base, 0, len(payload), len(payload), "rwx")]
        if best_table:
            end = base + len(payload)
            beyond = [s.value for s in best_table.symbols
                      if s.kind in ("bss", "data", "common") and end <= s.value < end + MAX_BSS]
            if beyond:
                size = (max(beyond) - end + BSS_SLACK + 0xFFF) & ~0xFFF
                result.segments.append(Segment("bss", end, len(payload), 0, size, "rw-"))
                result.notes.append("bss extent is estimated from the highest symbol past the image")
            entry = next((s for s in best_table.symbols if s.name in base_mod.ENTRY_SYMBOLS), None)
            if entry is not None:
                if result.entry_point is None or uimage_load != base:
                    result.entry_point = entry.value
                if 0 < entry.value - base < 0x200:
                    result.notes.append("code starts at image offset 0x%x (%s); "
                                        "the bytes before it are a header" % (entry.value - base,
                                                                             entry.name))
    if not tables:
        result.notes.append("no built-in symbol table found; the image may be stripped")


def _plausible_kernel_table(table: SymbolTable) -> bool:
    """Extra proof demanded of a table found by the relaxed scan."""
    observed = OBSERVED_TYPES[next(p for p in PROFILES if p.name == table.profile).type_encoding]
    known_types = sum(1 for s in table.symbols if s.raw_type in observed)
    return (any(s.name in KERNEL_SYMBOLS for s in table.symbols)
            and known_types >= 0.9 * len(table.symbols)
            and len({s.name for s in table.symbols}) >= 0.9 * len(table.symbols))


def _stripped_candidates(result: Analysis, payload: bytes,
                         uimage_load: Optional[int]) -> List[BaseCandidate]:
    """Base candidates for an image with no usable symbol table."""
    candidates: List[BaseCandidate] = []
    if result.endian and result.pointer_size:
        candidates = strbase.recover_base(payload, result.arch, result.endian,
                                          result.pointer_size)
    if uimage_load is not None:
        match = next((c for c in candidates if c.address == uimage_load), None)
        if match is not None:
            match.evidence.append(Evidence(
                "uimage-load", "uImage load address matches (0x%x)" % uimage_load))
            if match is candidates[0]:
                match.confidence = Confidence.HIGH
        else:
            note = ("physical; string references point to a different, virtual base"
                    if candidates else "physical; nothing in the image confirms it")
            candidates.append(BaseCandidate(uimage_load, Confidence.LOW, [Evidence(
                "uimage-load", "uImage load address 0x%x (%s)" % (uimage_load, note))], 0.0))
    if candidates and candidates[0].evidence[0].signal == "string-pointers":
        result.notes.append("base address recovered from string references, "
                            "because there is no symbol table")
    return candidates


def _layer(kind: str, payload: bytes, info: dict):
    from .model import Layer
    return Layer(kind, 0, len(payload), info)


def _conclude(result: Analysis, version_evidence: List[Evidence], uimage: Optional[dict]) -> None:
    points = 0
    st = result.symbol_table
    if st is not None:
        result.evidence.extend(st.evidence)
        names = {s.name for s in st.symbols}
        hits = [n for n in KERNEL_SYMBOLS if n in names]
        if hits:
            result.evidence.append(Evidence("kernel-symbols",
                                            "table contains " + ", ".join(hits[:5])))
            points += 2 if st.confidence >= Confidence.MEDIUM else 1
        else:
            result.evidence.append(Evidence("kernel-symbols",
                                            "table has no well-known VxWorks kernel symbols", False))
    if uimage is not None:
        is_vx = uimage.get("os") == "vxworks"
        result.evidence.append(Evidence("uimage-os", "uImage header OS field is %s" % uimage["os"],
                                        is_vx))
        points += 2 if is_vx else 0
    result.evidence.extend(version_evidence)
    if any(e.supports and e.signal in ("version-symbol", "version-string", "wind-version", "build-vars")
           for e in version_evidence):
        points += 1
    result.is_vxworks = points >= 1
    result.confidence = (Confidence.HIGH if points >= 3 else Confidence.MEDIUM if points == 2
                         else Confidence.LOW if points == 1 else Confidence.NONE)
