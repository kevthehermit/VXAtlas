"""Minimal ELF reader: just enough to map segments and read .symtab."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple

from .model import Segment

ELF_MAGIC = b"\x7fELF"

# e_machine -> (arch name, pointer size is taken from EI_CLASS)
_MACHINES: Dict[int, str] = {
    3: "x86",
    8: "mips",
    20: "ppc",
    21: "ppc64",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}

ET_REL, ET_EXEC, ET_DYN = 1, 2, 3
PT_LOAD = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3


class ElfError(ValueError):
    pass


@dataclass(frozen=True)
class ElfSection:
    name: str
    type: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    entsize: int


@dataclass(frozen=True)
class ElfSymbol:
    name: str
    value: int
    size: int
    type: int  # STT_*
    bind: int  # STB_*
    shndx: int


class ElfFile:
    def __init__(self, data: bytes):
        if data[:4] != ELF_MAGIC or len(data) < 52:
            raise ElfError("not an ELF file")
        self.data = data
        ei_class, ei_data = data[4], data[5]
        if ei_class not in (1, 2) or ei_data not in (1, 2):
            raise ElfError("unsupported ELF class or data encoding")
        self.pointer_size = 4 if ei_class == 1 else 8
        self.endian = "little" if ei_data == 1 else "big"
        self._e = "<" if ei_data == 1 else ">"
        e = self._e
        if self.pointer_size == 4:
            (self.type, self.machine, _v, self.entry, self.phoff, self.shoff, self.flags,
             _ehsize, self.phentsize, self.phnum, self.shentsize, self.shnum,
             self.shstrndx) = struct.unpack_from(e + "HHIIIIIHHHHHH", data, 16)
        else:
            if len(data) < 64:
                raise ElfError("truncated ELF header")
            (self.type, self.machine, _v, self.entry, self.phoff, self.shoff, self.flags,
             _ehsize, self.phentsize, self.phnum, self.shentsize, self.shnum,
             self.shstrndx) = struct.unpack_from(e + "HHIQQQIHHHHHH", data, 16)
        self.arch: Optional[str] = _MACHINES.get(self.machine)
        self.segments: List[Segment] = self._read_segments()
        self.physical: List[Tuple[int, int]] = self._physical
        self.sections: List[ElfSection] = self._read_sections()

    def _read_segments(self) -> List[Segment]:
        e, data = self._e, self.data
        out: List[Segment] = []
        self._physical: List[Tuple[int, int]] = []
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            if off + self.phentsize > len(data):
                break
            if self.pointer_size == 4:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, _a = (
                    struct.unpack_from(e + "8I", data, off))
            else:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, _a = (
                    struct.unpack_from(e + "IIQQQQQQ", data, off))
            if p_type != PT_LOAD or p_memsz == 0:
                continue
            perms = "".join(c if p_flags & bit else "-" for c, bit in (("r", 4), ("w", 2), ("x", 1)))
            p_filesz = max(0, min(p_filesz, len(data) - p_offset))
            out.append(Segment("load%d" % len(out), p_vaddr, p_offset, p_filesz, p_memsz, perms))
            self._physical.append((p_vaddr, p_paddr))
        return out

    def _read_sections(self) -> List[ElfSection]:
        e, data = self._e, self.data
        raw = []
        for i in range(self.shnum):
            off = self.shoff + i * self.shentsize
            if not self.shoff or off + self.shentsize > len(data):
                return []
            if self.pointer_size == 4:
                name, typ, flags, addr, offset, size, link, _info, _al, entsize = (
                    struct.unpack_from(e + "10I", data, off))
            else:
                name, typ, flags, addr, offset, size, link, _info, _al, entsize = (
                    struct.unpack_from(e + "IIQQQQIIQQ", data, off))
            raw.append((name, typ, flags, addr, offset, size, link, entsize))
        if not raw or self.shstrndx >= len(raw):
            return []
        str_off, str_size = raw[self.shstrndx][4], raw[self.shstrndx][5]
        strtab = data[str_off:str_off + str_size]
        return [ElfSection(_cstr(strtab, r[0]), *r[1:]) for r in raw]

    def section(self, name: str) -> Optional[ElfSection]:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    @property
    def has_symtab(self) -> bool:
        return any(s.type == SHT_SYMTAB for s in self.sections)

    def symbols(self) -> Iterator[ElfSymbol]:
        """Yield entries of the static symbol table (.symtab), if present."""
        e, data = self._e, self.data
        for sec in self.sections:
            if sec.type != SHT_SYMTAB or sec.link >= len(self.sections):
                continue
            strsec = self.sections[sec.link]
            strtab = data[strsec.offset:strsec.offset + strsec.size]
            entsize = sec.entsize or (16 if self.pointer_size == 4 else 24)
            fmt = e + ("IIIBBH" if self.pointer_size == 4 else "IBBHQQ")
            for (fields) in struct.iter_unpack(
                    fmt, data[sec.offset:sec.offset + (sec.size // entsize) * entsize]):
                if self.pointer_size == 4:
                    name, value, size, info, _other, shndx = fields
                else:
                    name, info, _other, shndx, value, size = fields
                yield ElfSymbol(_cstr(strtab, name), value, size, info & 0xF, info >> 4, shndx)


def _cstr(table: bytes, offset: int) -> str:
    end = table.find(b"\x00", offset)
    if end < 0:
        end = len(table)
    return table[offset:end].decode("latin-1")
