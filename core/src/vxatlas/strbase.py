"""Load-address recovery without a symbol table.

Firmware refers to its own strings by absolute address. Those addresses are
either stored as pointer-sized words (pointer tables, literal pools) or built
by instruction pairs (PowerPC ``lis``/``addi``, MIPS ``lui``/``addiu``). The
right base is the one that makes the most of them land on string starts.

Candidates come from two votes, then each is scored against every string:

* adjacent pointer words whose distance equals the distance between two nearby
  strings, which works for any base;
* single pointers against long strings, assuming a page-aligned base.
"""

from __future__ import annotations

import array
import re
import sys
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .model import BaseCandidate, Confidence, Evidence

_STRING = re.compile(rb"(?<=\x00)[\x20-\x7e\t\n\r]{4,}(?=\x00)")
PAGE_MASK = 0xFFF
NEIGHBOURS = 8  # how many following strings to pair each string with
MAX_PAIR_DISTANCE = 4096
MAX_BUCKET = 64  # ignore distances shared by more string pairs than this
MIN_STRINGS = 64
MIN_HITS = 48
MAX_CANDIDATES = 4


def string_offsets(data: bytes) -> List[int]:
    return [m.start() for m in _STRING.finditer(data)]


def pointer_words(data: bytes, endian: str, pointer_size: int) -> array.array:
    words = array.array("I" if pointer_size == 4 else "Q")
    words.frombytes(data[:len(data) // pointer_size * pointer_size])
    if (endian == "big") != (sys.byteorder == "big"):
        words.byteswap()
    return words


def constructed_addresses(data: bytes, arch: Optional[str], endian: str,
                          consumed: Optional[Set[int]] = None) -> Set[int]:
    """Addresses built by a load-upper instruction followed by an add or or of the low half.

    The low-half instruction words are added to ``consumed``. Read as a pointer,
    such a word is a constant plus the low half of an address, so it would
    otherwise make a wrong base look as if it explained every reference.
    """
    if arch not in ("ppc", "mips"):
        return set()
    insns = pointer_words(data, endian, 4)
    out: Set[int] = set()
    if consumed is None:
        consumed = set()
    upper: Dict[int, Tuple[int, int]] = {}  # register -> (instruction index, high half)
    if arch == "ppc":
        for i, x in enumerate(insns):
            op = x >> 26
            if op == 15:  # addis; with rA = 0 it is lis
                if (x >> 16) & 0x1F == 0:
                    upper[(x >> 21) & 0x1F] = (i, x & 0xFFFF)
            elif op == 14 or op == 24:  # addi rD,rA,lo / ori rA,rS,lo
                src = (x >> 16) & 0x1F if op == 14 else (x >> 21) & 0x1F
                hit = upper.get(src)
                if hit and i - hit[0] <= 4:
                    lo = x & 0xFFFF
                    if op == 14 and lo & 0x8000:
                        lo -= 0x10000
                    out.add(((hit[1] << 16) + lo) & 0xFFFFFFFF)
                    consumed.add(x)
    else:
        for i, x in enumerate(insns):
            op = x >> 26
            if op == 15:  # lui rt,hi
                upper[(x >> 16) & 0x1F] = (i, x & 0xFFFF)
            elif op == 9 or op == 13:  # addiu rt,rs,lo / ori rt,rs,lo
                hit = upper.get((x >> 21) & 0x1F)
                if hit and i - hit[0] <= 4:
                    lo = x & 0xFFFF
                    if op == 9 and lo & 0x8000:
                        lo -= 0x10000
                    out.add(((hit[1] << 16) + lo) & 0xFFFFFFFF)
                    consumed.add(x)
    return out


def _pair_votes(words: array.array, starts: List[int]) -> Counter:
    by_distance: Dict[int, List[int]] = defaultdict(list)
    for i, s in enumerate(starts):
        for t in starts[i + 1:i + 1 + NEIGHBOURS]:
            d = t - s
            if d >= MAX_PAIR_DISTANCE:
                break
            by_distance[d].append(s)
    usable = {d: v for d, v in by_distance.items() if len(v) <= MAX_BUCKET}
    votes: Counter = Counter()
    prev = 0
    for w in words:
        bucket = usable.get(w - prev)
        if bucket is not None and prev > PAGE_MASK:
            for s in bucket:
                votes[prev - s] += 1
        prev = w
    return votes


def _aligned_votes(data: bytes, pointers: Iterable[int], starts: List[int]) -> Counter:
    by_low: Dict[int, List[int]] = defaultdict(list)
    for p in pointers:
        if p > PAGE_MASK:
            by_low[p & PAGE_MASK].append(p)
    # Long strings are the least likely to be matched by chance; an even spread
    # covers images whose long strings are never referenced.
    chosen = set(sorted(starts, key=lambda s: s - data.index(b"\x00", s))[:400])
    chosen.update(starts[::max(1, len(starts) // 1500)])
    votes: Counter = Counter()
    for s in chosen:
        for p in by_low.get(s & PAGE_MASK, ()):
            if p >= s:
                votes[p - s] += 1
    return votes


def recover_base(data: bytes, arch: Optional[str], endian: str, pointer_size: int,
                 ) -> List[BaseCandidate]:
    """Rank base addresses for an image by how many of its strings they make referenced."""
    starts = string_offsets(data)
    if len(starts) < MIN_STRINGS:
        return []
    words = pointer_words(data, endian, pointer_size)
    consumed: Set[int] = set()
    built = constructed_addresses(data, arch, endian, consumed)
    limit = 1 << (8 * pointer_size)
    size = len(data)

    shortlist: Dict[int, None] = {}
    word_set = set(words) - consumed
    pointers = word_set | built
    # Vote with each pointer source on its own, so plentiful noise in one (code
    # words) cannot crowd the right base out of another's shortlist.
    ballots = [_pair_votes(words, starts), _aligned_votes(data, word_set, starts)]
    if built:
        ballots.append(_aligned_votes(data, built, starts))
    for votes in ballots:
        for base, _n in votes.most_common(200):
            if 0 <= base and base + size <= limit:
                shortlist.setdefault(base)
    if not shortlist:
        return []

    sample = starts[::max(1, len(starts) // 3000)]
    quick = sorted(shortlist, key=lambda b: sum(1 for s in sample if s + b in pointers),
                   reverse=True)[:12]
    scored = []
    for base in quick:
        hits = sum(1 for s in starts if s + base in pointers)
        # Real pointers aim at the first byte of a string. Chance matches against
        # code or data hit one byte further in just as often.
        off_by_one = sum(1 for s in starts if s + base + 1 in pointers)
        scored.append((hits - off_by_one, hits, off_by_one, base))
    scored.sort(reverse=True)
    if scored[0][0] < MIN_HITS:
        return []

    best_net = scored[0][0]
    runner_net = max(scored[1][0], 1) if len(scored) > 1 else 1
    out: List[BaseCandidate] = []
    for rank, (net, hits, off_by_one, base) in enumerate(scored[:MAX_CANDIDATES]):
        if net < MIN_HITS and rank:
            break
        evidence = [Evidence(
            "string-pointers",
            "%d of %d strings are referenced by a pointer at this base "
            "(%d chance-level matches one byte in)" % (hits, len(starts), off_by_one))]
        if rank == 0:
            margin = best_net / runner_net
            evidence.append(Evidence(
                "ranking", "%.1f times the score of the next best base" % margin, margin >= 3))
            confidence = Confidence.MEDIUM if margin >= 3 and net >= 4 * MIN_HITS else Confidence.LOW
        else:
            confidence = Confidence.LOW
            evidence.append(Evidence("ranking", "explains fewer strings than 0x%x" % scored[0][3],
                                     False))
        if built:
            evidence.append(Evidence("pointer-sources",
                                     "%d addresses built by %s instruction pairs were included"
                                     % (len(built), arch)))
        out.append(BaseCandidate(base, confidence, evidence, net / len(starts)))
    return out
