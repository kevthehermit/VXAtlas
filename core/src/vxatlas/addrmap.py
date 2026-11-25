"""Virtual-address to payload-offset mapping."""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from .model import Segment


class AddressMap:
    """Maps virtual addresses onto offsets in the payload bytes."""

    def __init__(self, data: bytes, segments: Sequence[Segment]):
        self.data = data
        self.segments: List[Segment] = sorted(segments, key=lambda s: s.address)
        # (start, end_of_file_backed, delta) for fast lookup
        self._spans: List[Tuple[int, int, int]] = [
            (s.address, s.address + s.file_size, s.file_offset - s.address)
            for s in self.segments
            if s.file_size
        ]

    @classmethod
    def flat(cls, data: bytes, base: int, name: str = "image") -> "AddressMap":
        return cls(data, [Segment(name, base, 0, len(data), len(data))])

    def to_offset(self, address: int) -> Optional[int]:
        for start, end, delta in self._spans:
            if start <= address < end:
                return address + delta
        return None

    def to_address(self, offset: int) -> Optional[int]:
        for start, end, delta in self._spans:
            if start + delta <= offset < end + delta:
                return offset - delta
        return None

    def contains(self, address: int) -> bool:
        """True if the address is inside any segment, file-backed or not."""
        return any(s.address <= address < s.address + s.mem_size for s in self.segments)

    def cstring(self, address: int, max_len: int = 1024) -> Optional[str]:
        """Read a NUL-terminated printable ASCII string, or None if it is not one."""
        off = self.to_offset(address)
        if off is None:
            return None
        end = self.data.find(b"\x00", off, off + max_len + 1)
        if end <= off:
            return None
        raw = self.data[off:end]
        if any(b < 0x20 or b > 0x7E for b in raw):
            return None
        return raw.decode("ascii")
