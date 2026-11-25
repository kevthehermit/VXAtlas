"""Result types shared by every stage of the analysis pipeline."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class Confidence(enum.IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Evidence:
    """One observation that supports (or contradicts) a conclusion."""

    signal: str
    detail: str
    supports: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {"signal": self.signal, "detail": self.detail, "supports": self.supports}


@dataclass(frozen=True)
class Layer:
    """One wrapper around the kernel payload, outermost first."""

    kind: str  # "uimage", "gzip", "zlib", "lzma", "xz", "bzip2", "elf", "raw"
    offset: int  # offset of this layer's payload within its parent layer
    size: int  # size of the payload this layer exposes
    info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "offset": self.offset, "size": self.size, "info": self.info}


@dataclass(frozen=True)
class Segment:
    """A region of the payload mapped at a virtual address."""

    name: str
    address: int
    file_offset: int
    file_size: int
    mem_size: int
    perms: str = "rwx"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "address": self.address,
            "file_offset": self.file_offset,
            "file_size": self.file_size,
            "mem_size": self.mem_size,
            "perms": self.perms,
        }


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    kind: str  # "function", "data", "bss", "abs", "common", "unknown"
    is_global: bool
    raw_type: int
    entry_offset: int  # offset of the table entry within the payload

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "kind": self.kind,
            "global": self.is_global,
            "raw_type": self.raw_type,
        }


@dataclass
class SymbolTable:
    profile: str
    offset: int  # payload offset of the first entry
    count: int
    entry_size: int
    pointer_size: int
    endian: str  # "little" or "big"
    symbols: List[Symbol]
    confidence: Confidence
    evidence: List[Evidence] = field(default_factory=list)
    rejected_entries: int = 0

    def to_dict(self, include_symbols: bool = True) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "profile": self.profile,
            "offset": self.offset,
            "count": self.count,
            "entry_size": self.entry_size,
            "pointer_size": self.pointer_size,
            "endian": self.endian,
            "confidence": self.confidence.label(),
            "rejected_entries": self.rejected_entries,
            "evidence": [e.to_dict() for e in self.evidence],
        }
        if include_symbols:
            out["symbols"] = [s.to_dict() for s in self.symbols]
        return out


@dataclass
class BaseCandidate:
    address: int
    confidence: Confidence
    evidence: List[Evidence] = field(default_factory=list)
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "confidence": self.confidence.label(),
            "score": round(self.score, 4),
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class Analysis:
    """Everything VxAtlas concluded about one input blob."""

    size: int
    layers: List[Layer] = field(default_factory=list)
    payload_offset: int = 0  # offset of the kernel payload in the innermost layer
    is_vxworks: bool = False
    confidence: Confidence = Confidence.NONE
    evidence: List[Evidence] = field(default_factory=list)
    version_family: Optional[str] = None  # "5.x", "6.x", "7.x"
    version: Optional[str] = None  # most specific version string found
    arch: Optional[str] = None  # "arm", "aarch64", "ppc", "mips", "x86", "x86_64", "riscv"
    arch_confidence: Confidence = Confidence.NONE
    endian: Optional[str] = None
    pointer_size: Optional[int] = None
    base_candidates: List[BaseCandidate] = field(default_factory=list)
    segments: List[Segment] = field(default_factory=list)
    entry_point: Optional[int] = None
    symbol_table: Optional[SymbolTable] = None
    symbols_stripped: Optional[bool] = None
    device_trees: List[Dict[str, int]] = field(default_factory=list)  # embedded FDT blobs
    notes: List[str] = field(default_factory=list)
    # The unwrapped kernel payload that offsets and segments refer to. Not serialised.
    payload: bytes = field(default=b"", repr=False, compare=False)

    @property
    def base(self) -> Optional[int]:
        return self.base_candidates[0].address if self.base_candidates else None

    def to_dict(self, include_symbols: bool = False) -> Dict[str, Any]:
        return {
            "size": self.size,
            "is_vxworks": self.is_vxworks,
            "confidence": self.confidence.label(),
            "evidence": [e.to_dict() for e in self.evidence],
            "version_family": self.version_family,
            "version": self.version,
            "arch": self.arch,
            "arch_confidence": self.arch_confidence.label(),
            "endian": self.endian,
            "pointer_size": self.pointer_size,
            "layers": [layer.to_dict() for layer in self.layers],
            "payload_offset": self.payload_offset,
            "base": self.base,
            "base_candidates": [c.to_dict() for c in self.base_candidates],
            "segments": [s.to_dict() for s in self.segments],
            "entry_point": self.entry_point,
            "symbols_stripped": self.symbols_stripped,
            "symbol_table": (
                self.symbol_table.to_dict(include_symbols) if self.symbol_table else None
            ),
            "device_trees": list(self.device_trees),
            "notes": list(self.notes),
        }
