"""Ground-truth tests against real images. Skipped unless the corpus is mounted.

The corpus lives outside the repository (see testdata/README.md). Each record in
testdata/ground_truth.json was established independently of the code under test.
"""

import hashlib

import pytest

from corpus import GROUND_TRUTH, corpus_path
from vxatlas import Confidence, analyze, analyze_file
from vxatlas.elf import ElfFile


@pytest.mark.parametrize("truth", GROUND_TRUTH, ids=[t["file"] for t in GROUND_TRUTH])
def test_image_matches_ground_truth(truth):
    path = corpus_path(truth["file"])
    if hashlib.sha256(path.read_bytes()).hexdigest() != truth["sha256"]:
        pytest.skip("%s is not the image the ground truth was recorded for" % truth["file"])
    a = analyze_file(str(path))

    assert a.is_vxworks and a.confidence == Confidence.HIGH
    assert [l.kind for l in a.layers] == truth["container"]
    assert a.version_family == truth["version_family"]
    assert a.version == truth["version"]
    assert (a.arch, a.endian, a.pointer_size) == (truth["arch"], truth["endian"],
                                                  truth["pointer_size"])
    assert a.base == int(truth["base"], 16)
    assert a.base_candidates[0].confidence == Confidence.HIGH

    assert [(d["offset"], d["size"]) for d in a.device_trees] == [
        (int(d["offset"], 16), d["size"]) for d in truth["device_trees"]]

    st, want = a.symbol_table, truth["symbol_table"]
    assert st is not None and a.symbols_stripped is False
    assert (st.profile, st.entry_size) == (want["profile"], want["entry_size"])
    assert st.offset == int(want["offset"], 16)
    assert st.count == want["count"]
    assert len(st.symbols) == want["count"] and st.rejected_entries == 0
    by_name = {s.name: s.value for s in st.symbols}
    for name, value in truth["symbols"].items():
        assert by_name[name] == int(value, 16), name


@pytest.mark.parametrize("truth", [t for t in GROUND_TRUTH if t["elf_reference"]],
                         ids=lambda t: t["file"])
def test_no_false_symbols_against_elf_symtab(truth):
    """Every symbol recovered from a raw 7.x image must exist in the matching ELF's .symtab."""
    image, reference = corpus_path(truth["file"]), corpus_path(truth["elf_reference"])
    elf_values = {}
    for sym in ElfFile(reference.read_bytes()).symbols():
        elf_values.setdefault(sym.name, set()).add(sym.value)
    recovered = analyze_file(str(image)).symbol_table.symbols
    false = [(s.name, hex(s.value)) for s in recovered if s.value not in elf_values.get(s.name, ())]
    assert false == []


RAW_IMAGES = [t for t in GROUND_TRUTH if t["container"] == ["raw"]]


def _strip(analysis):
    """Remove the symbol table and every symbol name, as a stripped build would."""
    table = analysis.symbol_table
    data = bytearray(analysis.payload)
    p = table.pointer_size
    for sym in table.symbols:
        name_address = int.from_bytes(data[sym.entry_offset + p:sym.entry_offset + 2 * p],
                                      table.endian)
        if name_address:
            start = name_address - analysis.base
            end = data.index(b"\x00", start)
            data[start:end] = bytes(end - start)
    size = table.count * table.entry_size + p  # entries and the count word
    data[table.offset:table.offset + size] = bytes(size)
    return bytes(data)


@pytest.mark.parametrize("truth", RAW_IMAGES, ids=[t["file"] for t in RAW_IMAGES])
def test_base_recovered_after_stripping_the_symbol_table(truth):
    full = analyze_file(str(corpus_path(truth["file"])))
    a = analyze(_strip(full))

    assert a.symbol_table is None and a.symbols_stripped is True
    assert a.base == int(truth["base"], 16)
    assert a.base_candidates[0].confidence == Confidence.MEDIUM
    assert all(c.confidence == Confidence.LOW for c in a.base_candidates[1:])
    assert (a.arch, a.endian, a.pointer_size) == (truth["arch"], truth["endian"],
                                                  truth["pointer_size"])
    assert a.version_family == truth["version_family"]
