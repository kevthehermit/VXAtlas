"""Headless tests for RTPs and kernel modules built with the SDK (corpus only)."""

import pytest

from corpus import corpus_path
from vxatlas import analyze_file
from vxatlas_ghidra.importer import import_image
from vxatlas_ghidra.link import LinkError, import_module

PAIRS = [("vx7_2609_aarch64_hello_dkm.out", "vx7_2609_aarch64.bin"),
         ("vx7_2103_arm_le_hello_dkm.out", "vx7_2103_arm_le.bin")]
WANTED = {"printf", "taskSpawn", "semBCreate", "strlen"}  # what testdata/src/hello_dkm.c calls


@pytest.mark.parametrize("module,kernel", PAIRS, ids=[p[0] for p in PAIRS])
def test_module_externals_resolve_to_kernel_symbols(ghidra, project, module, kernel):
    module_path, kernel_path = corpus_path(module), corpus_path(kernel)
    kernel_report = import_image(project, str(kernel_path), name="kernel_for_" + module,
                                 create_functions=False)
    report = import_module(project, str(module_path), str(kernel_path),
                           kernel_program_path=kernel_report.program_path)

    truth = {s.name: s.value for s in analyze_file(str(kernel_path)).symbol_table.symbols}
    assert set(report.resolved) == WANTED and report.unresolved == []
    assert all(report.resolved[n] == truth[n] for n in WANTED)

    with ghidra.program_context(project, report.program_path) as program:
        externals = program.getExternalManager()
        assert str(externals.getExternalLibraryPath("vxWorks")) == kernel_report.program_path
        for name in WANTED:
            loc = externals.getUniqueExternalLocation("vxWorks", name)
            assert loc is not None, name
            assert loc.getAddress().getOffsetAsBigInteger().longValue() & (2**64 - 1) == truth[name]
        # The module's own code is untouched and its relocations were all applied.
        assert list(program.getSymbolTable().getGlobalSymbols("helloStart"))
        assert all(str(r.getStatus()) == "APPLIED"
                   for r in program.getRelocationTable().getRelocations())


def test_module_link_needs_a_kernel_with_symbols(ghidra, project, tmp_path):
    module = corpus_path("vx7_2609_aarch64_hello_dkm.out")
    not_a_kernel = tmp_path / "zeros.bin"
    not_a_kernel.write_bytes(b"\x00" * 4096)
    with pytest.raises(LinkError):
        import_module(project, str(module), str(not_a_kernel))


@pytest.mark.parametrize("rtp", ["vx7_2609_aarch64_hello_static.vxe",
                                 "vx7_2609_aarch64_hello_dynamic.vxe",
                                 "vx7_2103_arm_le_hello_static.vxe",
                                 "vx7_2103_arm_le_hello_dynamic.vxe"])
def test_rtp_loads_with_ghidra_elf_loader(ghidra, project, rtp):
    """RTPs are ordinary ELF executables: check Ghidra's own loader copes with them."""
    path = corpus_path(rtp)
    loader = ghidra.program_loader().project(project).source(str(path)).name(rtp)
    from java.lang import Object
    consumer = Object()
    with loader.load() as results:
        program = results.getPrimaryDomainObject(consumer)
        try:
            assert str(program.getExecutableFormat()).startswith("Executable and Linking")
            assert program.getImageBase().getOffset() == 0x80000000
            for name in ("main", "add_numbers"):
                syms = list(program.getSymbolTable().getGlobalSymbols(name))
                assert syms and str(syms[0].getSymbolType()) == "Function", name
            statuses = {str(r.getStatus()) for r in program.getRelocationTable().getRelocations()}
            # Dynamic RTPs carry a few COPY relocations that Ghidra does not apply.
            assert statuses <= {"APPLIED", "UNSUPPORTED"}
        finally:
            program.release(consumer)
