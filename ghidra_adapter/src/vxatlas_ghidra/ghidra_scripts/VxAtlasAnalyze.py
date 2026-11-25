# Recover the base address and symbols of a VxWorks image imported as raw binary.
#
# Import the firmware with Ghidra's "Raw Binary" format and the right processor,
# then run this script. It moves the image to the recovered base address, adds
# a bss block and applies the symbols from the kernel's built-in symbol table.
#
# @category VxWorks
# @runtime PyGhidra
# @menupath Tools.VxAtlas.Recover base and symbols

from vxatlas import analyze
from vxatlas_ghidra.apply import (add_bss_blocks, apply_symbols, apply_table_type,
                                  record_metadata, to_address)
from vxatlas_ghidra.languages import language_for


def _original_bytes(program):
    all_bytes = program.getMemory().getAllFileBytes()
    if all_bytes.isEmpty():
        raise RuntimeError("the program has no stored file bytes; re-import the image")
    fb = all_bytes.get(0)
    from jpype import JArray, JByte
    buf = JArray(JByte)(int(fb.getSize()))
    fb.getOriginalBytes(0, buf)
    return bytes(buf)


def run():
    program = currentProgram  # noqa: F821 - provided by Ghidra
    blob = _original_bytes(program)
    analysis = analyze(blob)
    if not analysis.is_vxworks:
        popup("VxAtlas did not identify this program as a VxWorks image.")  # noqa: F821
        return
    if any(layer.kind != "raw" for layer in analysis.layers):
        popup("This image is wrapped (%s). Import it with the vxatlas-ghidra command "  # noqa: F821
              "instead, which unwraps it first." % " > ".join(l.kind for l in analysis.layers))
        return
    if analysis.base is None:
        popup("VxAtlas found no symbol table, so it cannot recover the base address.")  # noqa: F821
        return

    expected = language_for(analysis.arch, analysis.endian, analysis.pointer_size)
    actual = str(program.getLanguageID())
    if expected and expected[0].split(":")[:3] != actual.split(":")[:3]:
        if not askYesNo("VxAtlas", "The image looks like %s but the program uses %s.\n"  # noqa: F821
                        "Continue anyway?" % (expected[0], actual)):
            return

    memory = program.getMemory()
    block = memory.getBlocks()[0]
    target = to_address(program, analysis.base)
    if block.getStart() != target:
        memory.moveBlock(block, target, monitor)  # noqa: F821
    block.setName("image")
    add_bss_blocks(program, analysis)
    report = apply_symbols(program, analysis, True, monitor)  # noqa: F821
    apply_table_type(program, analysis, report)
    record_metadata(program, analysis, analysis.base)
    best = analysis.base_candidates[0]
    println("VxAtlas: %s %s, base 0x%x (confidence %s), %d labels, %d functions" % (  # noqa: F821
        analysis.version_family or "VxWorks", analysis.version or "", analysis.base,
        best.confidence.label(), report.labels, report.functions))
    for other in analysis.base_candidates[1:]:
        println("VxAtlas: alternative base 0x%x (confidence %s)" % (  # noqa: F821
            other.address, other.confidence.label()))


run()
