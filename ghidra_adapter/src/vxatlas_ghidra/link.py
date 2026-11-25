"""Resolve a kernel module's undefined symbols against a kernel image.

A downloadable kernel module (``.out``) is a relocatable ELF object. Ghidra's
ELF loader imports it and parks each undefined symbol on a placeholder in an
``EXTERNAL`` block. This step looks those names up in the kernel's recovered
symbol table and records where each one lives in the kernel.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vxatlas import analyze_file
from vxatlas.model import Analysis

from .apply import to_address

KERNEL_LIBRARY = "vxWorks"
EXTERNAL_BLOCK = "EXTERNAL"


class LinkError(Exception):
    pass


@dataclass
class LinkReport:
    program_path: str
    kernel_program_path: Optional[str]
    resolved: Dict[str, int] = field(default_factory=dict)  # name -> kernel address
    unresolved: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "program_path": self.program_path,
            "kernel_program_path": self.kernel_program_path,
            "resolved": self.resolved,
            "unresolved": self.unresolved,
        }


def kernel_symbol_map(kernel: Analysis) -> Dict[str, int]:
    """Name -> address for kernel symbols a module can link against."""
    if kernel.symbol_table is None:
        raise LinkError("the kernel image has no recoverable symbol table")
    out: Dict[str, int] = {}
    for sym in kernel.symbol_table.symbols:
        if sym.kind != "abs":
            out.setdefault(sym.name, sym.value)
    return out


def link_externals(program, kernel: Analysis, kernel_program_path: Optional[str] = None,
                   report: Optional[LinkReport] = None) -> LinkReport:
    """Annotate ``program``'s undefined symbols with their kernel addresses.

    Must run inside an open transaction. Each resolved placeholder gets an
    external location in library ``vxWorks`` carrying the kernel address, a
    reference to it, and a comment. When ``kernel_program_path`` is given the
    library is linked to that program, so Ghidra can navigate into the kernel.
    """
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import RefType, SourceType

    report = report or LinkReport(str(program.getDomainFile().getPathname()), kernel_program_path)
    block = program.getMemory().getBlock(EXTERNAL_BLOCK)
    if block is None:
        return report
    kernel_symbols = kernel_symbol_map(kernel)
    externals = program.getExternalManager()
    references = program.getReferenceManager()
    listing = program.getListing()
    for sym in program.getSymbolTable().getSymbolIterator(block.getStart(), True):
        addr = sym.getAddress()
        if not block.contains(addr):
            break
        if not sym.isPrimary() or sym.getSource() == SourceType.DEFAULT:
            continue
        name = str(sym.getName())
        value = kernel_symbols.get(name)
        if value is None:
            report.unresolved.append(name)
            continue
        target = to_address(program, value)
        externals.addExtLocation(KERNEL_LIBRARY, name, target, SourceType.IMPORTED)
        references.addExternalReference(addr, KERNEL_LIBRARY, name, target,
                                        SourceType.IMPORTED, 0, RefType.DATA)
        listing.setComment(addr, CodeUnit.EOL_COMMENT, "kernel %s at 0x%x" % (name, value))
        report.resolved[name] = value
    if kernel_program_path and report.resolved:
        externals.setExternalPath(KERNEL_LIBRARY, kernel_program_path, True)
    return report


def import_module(project, module_path: str, kernel_path: str, *, name: Optional[str] = None,
                  folder: str = "/", kernel_program_path: Optional[str] = None,
                  kernel: Optional[Analysis] = None, monitor=None) -> LinkReport:
    """Import a kernel module with Ghidra's ELF loader and link it to a kernel image."""
    import pyghidra
    from ghidra.util.task import TaskMonitor
    from java.lang import Object

    monitor = monitor or TaskMonitor.DUMMY
    kernel = kernel or analyze_file(kernel_path)
    if not kernel.is_vxworks:
        raise LinkError("%s was not identified as a VxWorks kernel" % kernel_path)
    kernel_symbol_map(kernel)  # fail early if the kernel is stripped
    name = name or os.path.basename(module_path)
    program_path = folder.rstrip("/") + "/" + name
    builder = (pyghidra.program_loader().project(project).projectFolderPath(folder)
               .name(name).monitor(monitor).source(str(module_path)))
    consumer = Object()
    with builder.load() as results:
        program = results.getPrimaryDomainObject(consumer)
        try:
            if not str(program.getExecutableFormat()).startswith("Executable and Linking"):
                raise LinkError("%s is not an ELF object" % module_path)
            report = LinkReport(program_path, kernel_program_path)
            with pyghidra.transaction(program, "VxAtlas link to kernel"):
                link_externals(program, kernel, kernel_program_path, report)
            results.save(monitor)
        finally:
            program.release(consumer)
    return report
