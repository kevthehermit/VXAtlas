"""VxWorks version detection."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .addrmap import AddressMap
from .model import Evidence, SymbolTable

_LITERAL = re.compile(rb"VxWorks ?(\d\.\d+(?:\.\d+)*)\x00")
_WIND = re.compile(rb"WIND version (\d+)\.(\d+)")
_VERSION_TEXT = re.compile(r"^\d+(?:\.\d+)+$")

# Build variables the 7.x build embeds in the image (section .wrs_build_vars).
_BUILD_VARS = re.compile(rb"set WIND_BASE [\x21-\x7e]*/vxworks/(\d+\.\d+)\x00")

# Symbols holding a ``char *`` to version text, most specific first.
VERSION_SYMBOLS = ("vxWorksVersion", "_vxWorksVersion", "runtimeVersion", "_runtimeVersion")


def family_of(version: str) -> Optional[str]:
    major = version.split(".")[0]
    if major in ("5", "6", "7"):
        return major + ".x"
    # 7.x releases are also numbered by date, for example 21.03 or 26.09.
    if major.isdigit() and int(major) >= 21:
        return "7.x"
    return None


def _major_from_symbol(amap: AddressMap, symtab: SymbolTable) -> Optional[int]:
    """Read the 32-bit integer behind ``vxWorksVersionMajor``, if the symbol exists."""
    for sym in symtab.symbols:
        if sym.name in ("vxWorksVersionMajor", "_vxWorksVersionMajor"):
            off = amap.to_offset(sym.value)
            if off is not None and off + 4 <= len(amap.data):
                return int.from_bytes(amap.data[off:off + 4], symtab.endian)
    return None


def _from_symbols(amap: AddressMap, symtab: SymbolTable) -> List[Tuple[str, str]]:
    out = []
    by_name = {s.name: s for s in symtab.symbols}
    for name in VERSION_SYMBOLS:
        sym = by_name.get(name)
        if sym is None:
            continue
        off = amap.to_offset(sym.value)
        if off is None or off + symtab.pointer_size > len(amap.data):
            continue
        pointer = int.from_bytes(amap.data[off:off + symtab.pointer_size], symtab.endian)
        text = amap.cstring(pointer, 64)
        if text and _VERSION_TEXT.match(text):
            out.append((name, text))
    return out


def detect_version(data: bytes, amap: Optional[AddressMap], symtab: Optional[SymbolTable],
                   ) -> Tuple[Optional[str], Optional[str], List[Evidence]]:
    """Return (family, version, evidence). Family is "5.x", "6.x", "7.x" or None."""
    evidence: List[Evidence] = []
    votes: List[Tuple[str, Optional[str]]] = []  # (family, version), strongest first

    if amap is not None and symtab is not None:
        for name, text in _from_symbols(amap, symtab):
            fam = family_of(text)
            evidence.append(Evidence("version-symbol", "%s points to \"%s\"" % (name, text),
                                     fam is not None))
            if fam:
                votes.append((fam, text))

        major = _major_from_symbol(amap, symtab)
        if major is not None:
            ok = major in (5, 6, 7)
            evidence.append(Evidence("version-symbol", "vxWorksVersionMajor is %d" % major, ok))
            if ok:
                votes.append(("%d.x" % major, None))

    for release in sorted({m.group(1).decode() for m in _BUILD_VARS.finditer(data)}):
        evidence.append(Evidence("build-vars", "embedded build variables name release %s" % release))
        votes.append(("7.x", release))

    literals = sorted({m.group(1).decode() for m in _LITERAL.finditer(data)})
    for text in literals:
        fam = family_of(text)
        if fam:
            evidence.append(Evidence("version-string", "image contains \"VxWorks %s\"" % text))
            votes.append((fam, text))

    wind = sorted({(int(m.group(1)), int(m.group(2))) for m in _WIND.finditer(data)})
    for major, minor in wind:
        # Verified pairings: 2.5 and 2.6 with 5.x images, 2.10 and 2.12 with 6.x images.
        fam = None
        if major == 2:
            fam = "5.x" if minor <= 6 else "6.x" if minor >= 10 else None
        evidence.append(Evidence("wind-version", "image contains \"WIND version %d.%d\"%s" % (
            major, minor, "" if fam else " (no verified mapping to a VxWorks version)")))
        if fam:
            votes.append((fam, None))

    if symtab is not None:
        layout_family = {"vx5-32": "5.x", "vx7-64": "7.x"}.get(symtab.profile)
        if layout_family:
            evidence.append(Evidence("table-layout", "symbol table layout %s is only used by %s"
                                     % (symtab.profile, layout_family)))
            votes.append((layout_family, None))
        elif symtab.profile == "vx6-32":
            evidence.append(Evidence("table-layout",
                                     "symbol table layout vx6-32 is shared by 6.x and 32-bit 7.x"))
            if not wind and not votes:
                # Every 5.x/6.x reference image carries a "WIND version" string;
                # no 7.x reference image does.
                evidence.append(Evidence("wind-version",
                                         "no \"WIND version\" string, as in 7.x reference images"))
                votes.append(("7.x", None))

    if not votes:
        return None, None, evidence
    family = votes[0][0]
    disagree = sorted({f for f, _ in votes if f != family})
    if disagree:
        evidence.append(Evidence("version-conflict",
                                 "other signals suggest %s" % ", ".join(disagree), False))
    version = next((v for f, v in votes if f == family and v), None)
    if version and family == "7.x" and not version.startswith("7"):
        version = "7 (%s)" % version
    return family, version, evidence
