"""Pipeline tests on generated images: every profile, both byte orders, wrappers."""

import gzip
import os

import pytest

from synth import build_image, wrap_uimage
from vxatlas import Confidence, analyze
from vxatlas.profiles import VX5_32, VX6_32, VX7_64

CASES = [
    (VX5_32, "arm", "little", 0x1000, b"VxWorks5.5.1", "5.x"),
    (VX5_32, "ppc", "big", 0x10000, b"WIND version 2.5", "5.x"),
    (VX5_32, "mips", "big", 0x80010000, b"WIND version 2.6", "5.x"),
    (VX6_32, "ppc", "big", 0x100000, b"VxWorks 6.4", "6.x"),
    (VX6_32, "arm", "little", 0xF2004000, b"WIND version 2.12", "6.x"),
    (VX6_32, "mips", "little", 0x80100000, b"VxWorks 6.9", "6.x"),
    (VX6_32, "arm", "little", 0x100000, None, "7.x"),
    (VX7_64, "aarch64", "little", 0xFFFFFFFF80100000, None, "7.x"),
]
IDS = ["%s-%s-%s-%s" % (c[0].name, c[1], c[2], c[5]) for c in CASES]


@pytest.mark.parametrize("profile,arch,endian,base,banner,family", CASES, ids=IDS)
def test_recovers_base_symbols_and_version(profile, arch, endian, base, banner, family):
    img = build_image(profile, arch, endian, base, banner=banner)
    a = analyze(img.data)

    assert a.is_vxworks
    assert a.base == base
    assert a.base_candidates[0].confidence == Confidence.HIGH
    # Near-miss bases (off by one evenly spaced name) may be listed, but never as peers.
    assert all(c.confidence == Confidence.LOW for c in a.base_candidates[1:])
    assert (a.arch, a.endian, a.pointer_size) == (arch, endian, profile.pointer_size)
    assert a.version_family == family

    st = a.symbol_table
    assert st is not None and st.profile == profile.name
    assert st.offset == img.table_offset
    assert st.confidence == Confidence.HIGH
    recovered = {s.name: (s.value, s.kind) for s in st.symbols}
    assert recovered == img.symbols  # nothing missing, nothing invented
    assert a.symbols_stripped is False


def test_header_before_code_is_reported():
    img = build_image(VX6_32, "arm", "little", 0xF2003FE4, banner=b"VxWorks 6.7",
                      header=b"\x1c\x00\x00\x00" + b"\xaa" * 24)
    a = analyze(img.data)
    assert a.base == 0xF2003FE4
    assert a.entry_point == 0xF2004000
    assert any("header" in n for n in a.notes)


def test_bss_segment_covers_symbols_past_the_image():
    img = build_image(VX5_32, "ppc", "big", 0x10000, banner=b"WIND version 2.5")
    a = analyze(img.data)
    bss = [s for s in a.segments if s.name == "bss"]
    assert len(bss) == 1
    value = img.symbols["sysSymTbl"][0]
    assert bss[0].address == 0x10000 + len(img.data)
    assert bss[0].address <= value < bss[0].address + bss[0].mem_size


def test_uimage_wrapper_is_unwrapped_and_physical_load_is_reported():
    img = build_image(VX6_32, "arm", "little", 0x100000)
    a = analyze(wrap_uimage(img.data, load=0x10100000, arch_id=2))
    assert [l.kind for l in a.layers] == ["uimage", "raw"]
    assert a.layers[0].info["os"] == "vxworks"
    assert a.layers[0].info["data_crc_ok"]
    assert a.base == 0x100000  # the linked address, not the physical load address
    assert any(e.signal == "uimage-load" and "0x10100000" in e.detail
               for e in a.base_candidates[0].evidence)
    assert a.symbol_table.offset == img.table_offset


def test_gzip_wrapper_is_unwrapped():
    img = build_image(VX5_32, "arm", "little", 0x1000, banner=b"VxWorks5.5.1")
    a = analyze(gzip.compress(img.data))
    assert [l.kind for l in a.layers] == ["gzip", "raw"]
    assert a.base == 0x1000
    assert len(a.symbol_table.symbols) == len(img.symbols)


def test_stripped_image_fails_gracefully():
    img = build_image(VX6_32, "ppc", "big", 0x100000, banner=b"VxWorks 6.4", with_table=False)
    a = analyze(img.data)
    assert a.symbol_table is None
    assert a.symbols_stripped is True
    assert a.base is None
    assert a.is_vxworks and a.confidence == Confidence.LOW  # version string only
    assert a.version_family == "6.x"
    assert any("stripped" in n for n in a.notes)


STRIPPED = [
    (VX5_32, "arm", "little", 0x1000),
    (VX6_32, "arm", "little", 0xF2003FE4),       # not page-aligned
    (VX5_32, "ppc", "big", 0x10000),             # references are lis/addi pairs
    (VX6_32, "mips", "big", 0x80100000),         # references are lui/addiu pairs
    (VX6_32, "mips", "little", 0x80010000),
    (VX7_64, "aarch64", "little", 0xFFFFFFFF80100000),
]


@pytest.mark.parametrize("profile,arch,endian,base", STRIPPED,
                         ids=["%s-%s-0x%x" % (c[1], c[2], c[3]) for c in STRIPPED])
def test_stripped_image_base_from_string_references(profile, arch, endian, base):
    img = build_image(profile, arch, endian, base, banner=b"VxWorks 6.4", with_table=False,
                      string_refs=400)
    a = analyze(img.data)
    assert a.symbol_table is None and a.symbols_stripped is True
    assert a.base == base
    best = a.base_candidates[0]
    assert best.confidence == Confidence.MEDIUM  # one kind of evidence, so never high
    assert best.evidence[0].signal == "string-pointers"
    assert all(c.confidence == Confidence.LOW for c in a.base_candidates[1:])
    assert any("string references" in n for n in a.notes)


def test_stripped_uimage_with_matching_load_address_is_high_confidence():
    img = build_image(VX5_32, "ppc", "big", 0x10000, banner=b"WIND version 2.5",
                      with_table=False, string_refs=400)
    a = analyze(wrap_uimage(img.data, load=0x10000, arch_id=7))
    assert a.base == 0x10000
    assert a.base_candidates[0].confidence == Confidence.HIGH


def test_stripped_uimage_with_different_load_address_keeps_both():
    img = build_image(VX6_32, "arm", "little", 0x100000, with_table=False, string_refs=400)
    a = analyze(wrap_uimage(img.data, load=0x10100000, arch_id=2))
    assert a.base == 0x100000  # where the strings are referenced
    assert a.base_candidates[0].confidence == Confidence.MEDIUM
    assert a.base_candidates[-1].address == 0x10100000
    assert a.base_candidates[-1].confidence == Confidence.LOW


def test_stripped_uimage_offers_load_address_at_low_confidence():
    img = build_image(VX6_32, "ppc", "big", 0x100000, banner=b"VxWorks 6.4", with_table=False)
    a = analyze(wrap_uimage(img.data, load=0x100000, arch_id=7))
    assert a.base == 0x100000
    assert a.base_candidates[0].confidence == Confidence.LOW


@pytest.mark.parametrize("blob", [b"", b"\x00" * 65536, os.urandom(1 << 18),
                                  b"just some text, not firmware\n" * 500],
                         ids=["empty", "zeros", "random", "text"])
def test_non_vxworks_input_is_rejected(blob):
    a = analyze(blob)
    assert not a.is_vxworks
    assert a.confidence == Confidence.NONE
    assert a.symbol_table is None
    assert a.base is None


def test_corrupt_names_are_dropped_not_invented():
    img = build_image(VX5_32, "arm", "little", 0x1000, banner=b"VxWorks5.5.1")
    data = bytearray(img.data)
    # Point one mid-table entry's name at non-string bytes (inside the code filler).
    entry = img.table_offset + 50 * VX5_32.entry_size
    data[entry + 4:entry + 8] = (0x1000 + 0x10).to_bytes(4, "little")
    a = analyze(bytes(data))
    st = a.symbol_table
    assert st.rejected_entries == 1
    assert len(st.symbols) == len(img.symbols) - 1
    assert {s.name for s in st.symbols} <= set(img.symbols)


@pytest.mark.parametrize("profile,arch,endian,base", [
    (VX5_32, "ppc", "big", 0x10000),
    (VX6_32, "arm", "little", 0x100000),
    (VX7_64, "aarch64", "little", 0xFFFFFFFF80100000),
], ids=["vx5-32", "vx6-32", "vx7-64"])
def test_table_with_populated_hash_links_is_found_at_low_confidence(profile, arch, endian, base):
    img = build_image(profile, arch, endian, base, banner=b"WIND version 2.6", linked=True)
    a = analyze(img.data)
    st = a.symbol_table
    assert st is not None and st.profile == profile.name
    assert st.confidence == Confidence.LOW
    assert any(e.signal == "heuristic" for e in st.evidence)
    assert a.base == base
    assert {s.name: (s.value, s.kind) for s in st.symbols} == img.symbols


def test_lookalike_table_without_strings_yields_no_symbols():
    # Structurally valid entries whose name pointers lead nowhere.
    entry = b"\x00" * 4 + b"\x12\x34\x56\x78" + b"\x00\x01\x00\x00" + b"\x00\x00\x05\x00"
    blob = b"\x4e\x80\x00\x20" * 1024 + entry * 300 + b"\x00" * 64
    a = analyze(blob)
    assert a.symbol_table is None and a.base is None and not a.is_vxworks
