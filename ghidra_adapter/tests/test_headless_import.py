"""Headless Ghidra tests: import an image and assert on the resulting program."""

import pytest

from corpus import GROUND_TRUTH_BY_FILE as GROUND_TRUTH, corpus_path
from synth import build_image
from vxatlas.profiles import VX5_32, VX6_32, VX7_64
from vxatlas_ghidra.importer import ImportError_, import_image


def _blocks(program):
    return {b.getName(): (b.getStart().getOffsetAsBigInteger().longValue() & (2**64 - 1),
                          int(b.getSize()), bool(b.isInitialized()))
            for b in program.getMemory().getBlocks()}


def _label_address(program, name):
    syms = list(program.getSymbolTable().getGlobalSymbols(name))
    assert syms, "symbol %s not found" % name
    return syms[0].getAddress().getOffsetAsBigInteger().longValue() & (2**64 - 1)


SYNTH = [
    ("vx5-ppc-be", VX5_32, "ppc", "big", 0x10000, "PowerPC:BE:32:default"),
    ("vx6-arm-le", VX6_32, "arm", "little", 0xF2004000, "ARM:LE:32:v8"),
    ("vx6-mips-be", VX6_32, "mips", "big", 0x80100000, "MIPS:BE:32:default"),
    ("vx7-aarch64", VX7_64, "aarch64", "little", 0xFFFFFFFF80100000, "AARCH64:LE:64:v8A"),
]


@pytest.mark.parametrize("name,profile,arch,endian,base,language", SYNTH,
                         ids=[c[0] for c in SYNTH])
def test_synthetic_image_import(ghidra, project, tmp_path, name, profile, arch, endian, base,
                                language):
    img = build_image(profile, arch, endian, base, banner=b"VxWorks 6.4" if "vx6" in name else None)
    path = tmp_path / (name + ".bin")
    path.write_bytes(img.data)
    report = import_image(project, str(path))

    assert report.language == language
    assert report.base == base
    with ghidra.program_context(project, report.program_path) as program:
        blocks = _blocks(program)
        assert blocks["image"] == (base, len(img.data), True)
        assert blocks["bss"][0] == base + len(img.data) and blocks["bss"][2] is False
        for sym, (value, _kind) in img.symbols.items():
            assert _label_address(program, sym) == value, sym
        functions = program.getFunctionManager()
        expected = {v for v, kind in img.symbols.values() if kind == "function"}
        assert report.applied.functions == len(expected)
        assert functions.getFunctionCount() == len(expected)  # no auto-analysis side effects
        info = program.getOptions("Program Information")
        assert "0x%x" % base in info.getString("VxAtlas Recovered Base", "")
        table = program.getListing().getDataAt(
            program.getSymbolTable().getGlobalSymbols("standTbl")[0].getAddress())
        assert table is not None and table.isArray()
        assert table.getNumComponents() == len(img.symbols)
        entry = table.getComponent(0)
        assert entry.getDataType().getName() == "SYMBOL"
        assert entry.getLength() == profile.entry_size
        assert [entry.getComponent(i).getFieldName() for i in range(3)] == [
            "hashLink", "name", "value"]
        notes = [str(b.getComment()) for b in program.getBookmarkManager().getBookmarksIterator("Note")
                 if str(b.getCategory()) == "VxAtlas"]
        assert sorted(n.split(":")[0] for n in notes) == ["sysInit", "usrInit", "usrRoot"]
        assert report.applied.table_typed and report.applied.bookmarks == 3
        alternatives = info.getString("VxAtlas Base Alternatives", "")
        assert "high" not in alternatives and "medium" not in alternatives
    assert report.applied.labels == len(img.symbols)


def test_base_and_language_overrides(ghidra, project, tmp_path):
    img = build_image(VX5_32, "arm", "little", 0x1000, banner=b"VxWorks5.5.1")
    path = tmp_path / "override.bin"
    path.write_bytes(img.data)
    report = import_image(project, str(path), base=0x20000, language="ARM:LE:32:v5t",
                          create_functions=False)
    assert report.language == "ARM:LE:32:v5t"
    assert report.base == 0x20000
    assert report.applied.functions == 0
    with ghidra.program_context(project, report.program_path) as program:
        assert _blocks(program)["image"][0] == 0x20000
        assert program.getFunctionManager().getFunctionCount() == 0
        info = program.getOptions("Program Information")
        assert info.getString("VxAtlas Base Address", "") == "0x20000"
        assert "0x1000" in info.getString("VxAtlas Recovered Base", "")


def test_stripped_image_needs_a_base(ghidra, project, tmp_path):
    img = build_image(VX6_32, "ppc", "big", 0x100000, banner=b"VxWorks 6.4", with_table=False)
    path = tmp_path / "stripped.bin"
    path.write_bytes(img.data)
    with pytest.raises(ImportError_, match="base address"):
        import_image(project, str(path))
    report = import_image(project, str(path), base=0x100000)
    assert report.applied.labels == 0
    assert "no symbol table" in report.applied.notes[0]


CORPUS_RAW = ["vx5_arm_le.bin", "vx5_ppc_be.bin", "vx6_arm_le.bin", "vx6_ppc_be.bin",
              "vx7_2103_arm_le.bin", "vx7_2103_arm_le.uimage", "vx7_2609_aarch64.bin",
              "vx7_2609_aarch64.uimage"]


@pytest.mark.parametrize("name", CORPUS_RAW)
def test_corpus_image_import(ghidra, project, name):
    truth = GROUND_TRUTH[name]
    report = import_image(project, str(corpus_path(name)))
    base = int(truth["base"], 16)
    assert report.base == base
    with ghidra.program_context(project, report.program_path) as program:
        blocks = _blocks(program)
        assert blocks["image"][0] == base and blocks["image"][2] is True
        for sym, value in truth["symbols"].items():
            assert _label_address(program, sym) == int(value, 16), sym
        entry = "sysInit" if "sysInit" in truth["symbols"] else "_sysInit"
        fn = program.getFunctionManager().getFunctionAt(
            program.getSymbolTable().getGlobalSymbols(entry)[0].getAddress())
        assert fn is not None
    applied = report.applied
    assert applied.skipped_invalid == 0
    assert applied.labels + applied.skipped_abs + applied.skipped_unmapped == \
        truth["symbol_table"]["count"]
    # 7.x tables carry a few thread-local symbols whose values are TLS offsets, not addresses.
    assert applied.skipped_unmapped <= (4 if truth["version_family"] == "7.x" else 0)
    function_addresses = {s.value & ~1 for s in report.analysis.symbol_table.symbols
                          if s.kind == "function"}
    assert applied.functions >= 0.95 * len(function_addresses)


def test_corpus_elf_uses_ghidra_elf_loader_and_gains_symbols(ghidra, project):
    truth = GROUND_TRUTH["vx7_2103_arm_le.elf"]
    report = import_image(project, str(corpus_path("vx7_2103_arm_le.elf")))
    assert report.loader.startswith("ELF")
    with ghidra.program_context(project, report.program_path) as program:
        assert program.getExecutableFormat().startswith("Executable and Linking Format")
        for sym, value in truth["symbols"].items():
            assert _label_address(program, sym) == int(value, 16), sym


def test_elf_base_override_rebases_the_program(ghidra, project):
    report = import_image(project, str(corpus_path("vx7_2103_arm_le.elf")), name="rebased.elf",
                          base=0x40100000, create_functions=False)
    with ghidra.program_context(project, report.program_path) as program:
        assert program.getImageBase().getOffset() == 0x40100000


def test_ghidra_script_fixes_up_a_raw_binary_import(ghidra, project, tmp_path):
    """The in-GUI path: import as Raw Binary at address 0, then run VxAtlasAnalyze.py."""
    from pathlib import Path

    import vxatlas_ghidra
    from ghidra.app.util.opinion import BinaryLoader
    from java.lang import Object

    img = build_image(VX5_32, "ppc", "big", 0x10000, banner=b"WIND version 2.5")
    path = tmp_path / "rawimport.bin"
    path.write_bytes(img.data)
    script = Path(vxatlas_ghidra.__file__).parent / "ghidra_scripts" / "VxAtlasAnalyze.py"
    consumer = Object()
    loader = (ghidra.program_loader().project(project).source(str(path)).name("rawimport.bin")
              .loaders(BinaryLoader.class_).language("PowerPC:BE:32:default"))
    with loader.load() as results:
        program = results.getPrimaryDomainObject(consumer)
        try:
            assert _blocks(program)[next(iter(_blocks(program)))][0] == 0
            stdout, stderr = ghidra.ghidra_script(str(script), project, program,
                                                  echo_stdout=False, echo_stderr=False)
            assert "base 0x10000" in str(stdout), str(stdout) + str(stderr)
            blocks = _blocks(program)
            assert blocks["image"] == (0x10000, len(img.data), True)
            assert "bss" in blocks
            for sym, (value, _kind) in img.symbols.items():
                assert _label_address(program, sym) == value, sym
            assert _label_address(program, "standTbl") == 0x10000 + img.table_offset
        finally:
            program.release(consumer)


def test_stripped_image_imports_at_the_base_found_from_string_references(ghidra, project,
                                                                         tmp_path):
    img = build_image(VX6_32, "mips", "big", 0x80100000, banner=b"VxWorks 6.4",
                      with_table=False, string_refs=400)
    path = tmp_path / "stripped_refs.bin"
    path.write_bytes(img.data)
    report = import_image(project, str(path))
    assert report.base == 0x80100000 and report.applied.labels == 0
    with ghidra.program_context(project, report.program_path) as program:
        assert _blocks(program)["image"][0] == 0x80100000
        info = program.getOptions("Program Information")
        assert "confidence medium" in info.getString("VxAtlas Recovered Base", "")
        assert "not found" in info.getString("VxAtlas Symbol Table", "")
