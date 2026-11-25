"""Architecture detection for raw images, from instruction byte signatures."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .model import Confidence, Evidence

# (arch, endian, pointer_size) -> byte sequences of very common instructions.
_SIGNATURES: Dict[Tuple[str, str, int], List[bytes]] = {
    ("arm", "little", 4): [b"\x1e\xff\x2f\xe1", b"\x0d\xc0\xa0\xe1", b"\x04\xe0\x2d\xe5"],
    ("arm", "big", 4): [b"\xe1\x2f\xff\x1e", b"\xe1\xa0\xc0\x0d", b"\xe5\x2d\xe0\x04"],
    ("aarch64", "little", 8): [b"\xc0\x03\x5f\xd6", b"\xfd\x7b\xbf\xa9", b"\xfd\x7b\xc1\xa8"],
    ("ppc", "big", 4): [b"\x4e\x80\x00\x20", b"\x7c\x08\x02\xa6", b"\x7c\x08\x03\xa6"],
    ("ppc", "little", 4): [b"\x20\x00\x80\x4e", b"\xa6\x02\x08\x7c", b"\xa6\x03\x08\x7c"],
    ("mips", "big", 4): [b"\x03\xe0\x00\x08", b"\x27\xbd\xff", b"\xaf\xbf\x00"],
    ("mips", "little", 4): [b"\x08\x00\xe0\x03", b"\xff\xbd\x27", b"\x00\xbf\xaf"],
    ("x86", "little", 4): [b"\x55\x89\xe5", b"\x5d\xc3", b"\xc9\xc3"],
    ("x86_64", "little", 8): [b"\x55\x48\x89\xe5", b"\x48\x83\xec", b"\x48\x8b\x45"],
    ("riscv", "little", 8): [b"\x67\x80\x00\x00", b"\x82\x80"],
}

MIN_HITS = 64


def detect_arch(data: bytes, endian_hint: Optional[str] = None,
                pointer_size_hint: Optional[int] = None,
                ) -> Tuple[Optional[str], Optional[str], Optional[int], Confidence, List[Evidence]]:
    """Return (arch, endian, pointer_size, confidence, evidence) for raw code."""
    scores: List[Tuple[int, Tuple[str, str, int]]] = []
    for key, patterns in _SIGNATURES.items():
        _arch, endian, psize = key
        if endian_hint and endian != endian_hint:
            continue
        if pointer_size_hint and psize != pointer_size_hint:
            continue
        scores.append((sum(data.count(p) for p in patterns), key))
    scores.sort(reverse=True)
    if not scores or scores[0][0] < MIN_HITS:
        return None, None, None, Confidence.NONE, [
            Evidence("opcode-signatures", "no architecture's common instructions were found", False)]
    top, (arch, endian, psize) = scores[0]
    runner = scores[1][0] if len(scores) > 1 else 0
    detail = "%d hits for %s %s-endian instruction signatures; next best %d" % (
        top, arch, endian, runner)
    if top >= 8 * max(runner, 1):
        confidence = Confidence.HIGH
    elif top >= 3 * max(runner, 1):
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.LOW
    return arch, endian, psize, confidence, [Evidence("opcode-signatures", detail)]
