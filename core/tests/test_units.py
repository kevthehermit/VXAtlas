"""Unit tests for the smaller building blocks."""

import struct

from synth import build_image, wrap_uimage
from vxatlas.addrmap import AddressMap
from vxatlas.arch import detect_arch
from vxatlas.cli import main
from vxatlas.containers import find_device_trees, unwrap
from vxatlas.elf import ElfFile
from vxatlas.model import Segment
from vxatlas.profiles import PROFILES, VX5_32, VX6_32, VX7_64
from vxatlas.version import family_of


def test_profile_entry_sizes_are_consistent():
    for p in PROFILES:
        assert p.name_offset == p.pointer_size
        assert p.value_offset == 2 * p.pointer_size
        assert p.entry_size % p.pointer_size == 0
        assert p.type_offset < p.entry_size


def test_type_decoding_per_family():
    assert VX5_32.decode_type(0x05) == ("function", True)
    assert VX5_32.decode_type(0x07) == ("data", True)
    assert VX5_32.decode_type(0x09) == ("bss", True)
    assert VX6_32.decode_type(0x05) == ("function", True)
    assert VX6_32.decode_type(0x09) == ("data", True)
    assert VX6_32.decode_type(0x11) == ("bss", True)
    assert VX7_64.decode_type(0x03) == ("abs", True)


def test_family_of():
    assert family_of("5.5.1") == "5.x"
    assert family_of("6.9.4.1") == "6.x"
    assert family_of("26.09") == "7.x"
    assert family_of("2.12") is None


def test_address_map_cstring_rejects_non_text():
    data = b"\x00name\x00\x01\x02\x00"
    amap = AddressMap.flat(data, 0x1000)
    assert amap.cstring(0x1001) == "name"
    assert amap.cstring(0x1006) is None
    assert amap.cstring(0x9999) is None
    assert amap.to_address(1) == 0x1001


def test_address_map_multiple_segments():
    amap = AddressMap(b"A" * 32, [Segment("a", 0x100, 0, 16, 16), Segment("b", 0x8000, 16, 16, 64)])
    assert amap.to_offset(0x8004) == 20
    assert amap.to_offset(0x8020) is None  # in memory, but not file-backed
    assert amap.contains(0x8020)


def test_uimage_with_bad_header_crc_is_not_unwrapped():
    blob = bytearray(wrap_uimage(b"\x00" * 128, 0x1000, 2))
    blob[8] ^= 0xFF
    payload, layers = unwrap(bytes(blob))
    assert layers == [] and payload == bytes(blob)


def test_arch_detection_needs_evidence():
    arch, _endian, _psize, _conf, evidence = detect_arch(b"\x00" * 4096)
    assert arch is None and not evidence[0].supports


def _tiny_elf32() -> bytes:
    ehdr = struct.pack("<4sBBBB8xHHIIIIIHHHHHH", b"\x7fELF", 1, 1, 1, 0, 2, 40, 1, 0x8000, 52, 0, 0,
                       52, 32, 1, 40, 0, 0)
    phdr = struct.pack("<8I", 1, 0x100, 0x8000, 0x10008000, 0x40, 0x80, 7, 0x100)
    return (ehdr + phdr).ljust(0x100, b"\x00") + b"\xcc" * 0x40


def test_elf_segments_and_physical_addresses():
    elf = ElfFile(_tiny_elf32())
    assert (elf.arch, elf.endian, elf.pointer_size) == ("arm", "little", 4)
    assert [(s.address, s.file_offset, s.file_size, s.mem_size) for s in elf.segments] == [
        (0x8000, 0x100, 0x40, 0x80)]
    assert elf.physical == [(0x8000, 0x10008000)]
    assert not elf.has_symtab


def test_cli_text_and_json(tmp_path, capsys):
    img = build_image(VX5_32, "arm", "little", 0x1000, banner=b"VxWorks5.5.1")
    path = tmp_path / "img.bin"
    path.write_bytes(img.data)
    assert main([str(path)]) == 0
    assert "Base address:   0x1000" in capsys.readouterr().out
    assert main([str(path), "--json"]) == 0
    assert '"version_family": "5.x"' in capsys.readouterr().out
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\x00" * 4096)
    assert main([str(junk)]) == 1
    assert main([str(tmp_path / "missing.bin")]) == 2


def test_device_tree_detection_validates_the_header():
    header = struct.pack(">10I", 0xD00DFEED, 72, 56, 64, 40, 17, 16, 0, 8, 8)
    blob = header + b"\x00" * 32
    data = b"\xd0\x0d\xfe\xed" + b"\x11" * 60 + blob + b"\xff" * 16  # stray magic first
    assert find_device_trees(data) == [{"offset": 64, "size": 72, "version": 17}]
    assert find_device_trees(b"\x00" * 256) == []
