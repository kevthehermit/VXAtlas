"""Import a VxWorks image into a Ghidra project using the core's analysis."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

from vxatlas import analyze_file
from vxatlas.model import Analysis

from .apply import (ApplyReport, add_bss_blocks, apply_symbols, apply_table_type,
                    record_metadata)
from .languages import language_for


class ImportError_(Exception):
    """The image cannot be imported without more information from the user."""


@dataclass
class ImportReport:
    program_path: str
    language: str
    compiler: str
    base: Optional[int]
    loader: str
    analysis: Analysis
    applied: ApplyReport
    blocks: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "program_path": self.program_path,
            "language": self.language,
            "compiler": self.compiler,
            "base": self.base,
            "loader": self.loader,
            "blocks": self.blocks,
            "applied": self.applied.to_dict(),
            "analysis": self.analysis.to_dict(),
        }


def import_image(project, path: str, *, name: Optional[str] = None, folder: str = "/",
                 base: Optional[int] = None, language: Optional[str] = None,
                 compiler: Optional[str] = None, create_functions: bool = True,
                 run_analysis: bool = False, analysis: Optional[Analysis] = None,
                 monitor=None) -> ImportReport:
    """Analyse ``path`` with the core and create a Ghidra program from the result.

    ``base``, ``language`` and ``compiler`` override what the core recovered.
    Auto-analysis only runs when ``run_analysis`` is set.
    """
    import pyghidra
    from ghidra.app.util.opinion import BinaryLoader
    from ghidra.util.task import TaskMonitor
    from java.lang import Object
    from jpype import JArray, JByte

    monitor = monitor or TaskMonitor.DUMMY
    analysis = analysis or analyze_file(path)
    name = name or os.path.basename(path)
    is_elf = any(layer.kind == "elf" for layer in analysis.layers)

    if language is None:
        mapped = language_for(analysis.arch, analysis.endian, analysis.pointer_size)
        if mapped is None and not is_elf:
            raise ImportError_(
                "could not determine the processor (arch=%s, endian=%s); pass a language ID"
                % (analysis.arch, analysis.endian))
        if mapped:
            language, compiler = mapped[0], compiler or mapped[1]
    chosen_base = base if base is not None else analysis.base
    if chosen_base is None and not is_elf:
        raise ImportError_("could not recover a load address; pass a base address")

    builder = (pyghidra.program_loader().project(project).projectFolderPath(folder)
               .name(name).monitor(monitor)
               .source(JArray(JByte)(analysis.payload)))
    if is_elf:
        loader = "ELF (Ghidra)"
        # Ghidra's own ELF loader builds the memory map; a base override rebases it.
        if base is not None:
            builder = builder.addLoaderArg("-loader-imagebase", "%x" % base)
    else:
        loader = "VxAtlas raw"
        builder = (builder.loaders(BinaryLoader.class_).language(language)
                   .compiler(compiler or "default")
                   .addLoaderArg("-loader-baseAddr", "0x%x" % chosen_base)
                   .addLoaderArg("-loader-blockName", "image"))

    consumer = Object()
    with builder.load() as results:
        program = results.getPrimaryDomainObject(consumer)
        try:
            shift = 0 if is_elf or analysis.base is None else chosen_base - analysis.base
            with pyghidra.transaction(program, "VxAtlas import"):
                if not is_elf:
                    add_bss_blocks(program, analysis, shift)
                applied = apply_symbols(program, analysis, create_functions, monitor)
                if shift == 0:
                    apply_table_type(program, analysis, applied)
                record_metadata(program, analysis, None if is_elf else chosen_base)
            if run_analysis:
                pyghidra.analyze(program, monitor)
            blocks = ["%s 0x%s-0x%s %s" % (b.getName(), b.getStart(), b.getEnd(),
                                           "init" if b.isInitialized() else "uninit")
                      for b in program.getMemory().getBlocks()]
            report = ImportReport(
                program_path=(folder.rstrip("/") + "/" + name),
                language=str(program.getLanguageID()),
                compiler=str(program.getCompilerSpec().getCompilerSpecID()),
                base=None if is_elf else chosen_base, loader=loader, analysis=analysis,
                applied=applied, blocks=blocks)
            results.save(monitor)
        finally:
            program.release(consumer)
    return report
