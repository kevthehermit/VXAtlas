"""Apply a core ``Analysis`` to a Ghidra program: memory, symbols, functions, metadata.

Everything here needs a running Ghidra (``pyghidra.start()``), so Ghidra
classes are imported inside the functions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from vxatlas.model import Analysis

INFO_PREFIX = "VxAtlas "


@dataclass
class ApplyReport:
    labels: int = 0
    functions: int = 0
    skipped_abs: int = 0  # absolute symbols are constants, not addresses
    skipped_unmapped: int = 0  # value is outside every memory block
    skipped_invalid: int = 0  # name unusable as a Ghidra label
    table_typed: bool = False  # the symbol table itself was typed as SYMBOL[n]
    bookmarks: int = 0  # boot routines bookmarked
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def to_address(program, value: int):
    """Address in the default space for an unsigned value (handles 64-bit kernel addresses)."""
    space = program.getAddressFactory().getDefaultAddressSpace()
    if value >= 1 << 63:
        value -= 1 << 64  # Java longs are signed; the bit pattern is what matters
    return space.getAddress(value)


def add_bss_blocks(program, analysis: Analysis, shift: int = 0) -> None:
    """Create uninitialised blocks for segments that have no file bytes."""
    memory = program.getMemory()
    for seg in analysis.segments:
        if seg.file_size or not seg.mem_size:
            continue
        start = to_address(program, seg.address + shift)
        if memory.contains(start):
            continue
        block = memory.createUninitializedBlock(seg.name, start, seg.mem_size, False)
        block.setPermissions("r" in seg.perms, "w" in seg.perms, "x" in seg.perms)


def apply_symbols(program, analysis: Analysis, create_functions: bool = True,
                  monitor=None) -> ApplyReport:
    """Label every recovered symbol; optionally disassemble and create functions.

    Must run inside an open transaction.
    """
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.symbol import SourceType, SymbolUtilities
    from ghidra.util.task import TaskMonitor

    monitor = monitor or TaskMonitor.DUMMY
    report = ApplyReport()
    table = analysis.symbol_table
    if table is None:
        report.notes.append("no symbol table was recovered; nothing to apply")
        return report

    memory = program.getMemory()
    symbols = program.getSymbolTable()
    is_arm = analysis.arch == "arm"
    code_starts = AddressSet()
    for sym in table.symbols:
        if sym.kind == "abs":
            report.skipped_abs += 1
            continue
        value = sym.value
        if is_arm and sym.kind == "function":
            value &= ~1  # a set low bit marks Thumb code, it is not part of the address
        addr = to_address(program, value)
        if not memory.contains(addr):
            report.skipped_unmapped += 1
            continue
        name = SymbolUtilities.replaceInvalidChars(sym.name, True)
        if not name:
            report.skipped_invalid += 1
            continue
        try:
            symbols.createLabel(addr, name, SourceType.IMPORTED)
        except Exception:  # InvalidInputException for names Ghidra still rejects
            report.skipped_invalid += 1
            continue
        report.labels += 1
        if sym.kind == "function" and memory.getBlock(addr).isInitialized():
            if is_arm and sym.value & 1:
                _set_thumb(program, addr)
            code_starts.add(addr)

    _label_table(program, analysis, report)
    _bookmark_boot_routines(program, analysis, report)

    if analysis.entry_point is not None:
        entry = to_address(program, analysis.entry_point)
        if memory.contains(entry):
            symbols.addExternalEntryPoint(entry)

    if create_functions and not code_starts.isEmpty():
        DisassembleCommand(code_starts, None, True).applyTo(program, monitor)
        CreateFunctionCmd(code_starts, SourceType.IMPORTED).applyTo(program, monitor)
        functions = program.getFunctionManager()
        report.functions = sum(1 for a in code_starts.getAddresses(True)
                               if functions.getFunctionAt(a) is not None)
    return report


# Routines every VxWorks kernel boots through, in order. Bookmarked when the
# recovered table names them as code.
BOOT_ROUTINES = (
    (("sysInit", "_sysInit"), "Kernel entry point"),
    (("usrInit", "_usrInit"), "First C routine, called from sysInit"),
    (("usrRoot", "_usrRoot"), "Entry of the root task, started by usrInit"),
)
BOOKMARK_CATEGORY = "VxAtlas"


def _bookmark_boot_routines(program, analysis: Analysis, report: ApplyReport) -> None:
    from ghidra.program.model.listing import BookmarkType

    functions = {s.name: s for s in analysis.symbol_table.symbols if s.kind == "function"}
    memory, bookmarks = program.getMemory(), program.getBookmarkManager()
    for names, comment in BOOT_ROUTINES:
        sym = next((functions[n] for n in names if n in functions), None)
        if sym is None:
            continue
        addr = to_address(program, sym.value & ~1 if analysis.arch == "arm" else sym.value)
        if memory.contains(addr):
            bookmarks.setBookmark(addr, BookmarkType.NOTE, BOOKMARK_CATEGORY,
                                  "%s: %s" % (sym.name, comment))
            report.bookmarks += 1


def table_address(analysis: Analysis) -> Optional[int]:
    """Virtual address of the recovered symbol table, if it lies in a file-backed segment."""
    table = analysis.symbol_table
    if table is None:
        return None
    return next((s.address + table.offset - s.file_offset for s in analysis.segments
                 if s.file_size and s.file_offset <= table.offset < s.file_offset + s.file_size),
                None)


def apply_table_type(program, analysis: Analysis, report: ApplyReport, shift: int = 0) -> None:
    """Type the symbol table as an array of SYMBOL structures, with its count word.

    The structure follows the layout verified for the table's profile. Field
    names are descriptive; they are not taken from Wind River headers.
    """
    from ghidra.program.model.data import (ArrayDataType, ByteDataType, CategoryPath,
                                           CharDataType, DataTypeConflictHandler,
                                           PointerDataType, StructureDataType,
                                           UnsignedIntegerDataType, UnsignedLongLongDataType,
                                           UnsignedShortDataType, VoidDataType)
    from vxatlas.profiles import PROFILES

    table = analysis.symbol_table
    start_value = table_address(analysis)
    if table is None or start_value is None or table.confidence.label() != "high":
        return
    profile = next(p for p in PROFILES if p.name == table.profile)
    p = profile.pointer_size
    void_ptr = PointerDataType(VoidDataType.dataType, p)
    struct = StructureDataType(CategoryPath("/VxWorks"), "SYMBOL", 0)
    struct.setPackingEnabled(False)
    struct.add(void_ptr, p, "hashLink", "hash chain link, zero until the table is linked")
    struct.add(PointerDataType(CharDataType.dataType, p), p, "name", None)
    struct.add(void_ptr, p, "value", None)
    if profile.type_offset - 2 - profile.value_offset - p:
        struct.add(void_ptr, p, "reference", None)
    struct.add(UnsignedShortDataType.dataType, 2, "group", None)
    struct.add(ByteDataType.dataType, 1, "type", None)
    tail = profile.entry_size - profile.type_offset - 1
    struct.add(ArrayDataType(ByteDataType.dataType, tail, 1) if tail > 1
               else ByteDataType.dataType, tail, "pad", None)
    if struct.getLength() != profile.entry_size:
        report.notes.append("SYMBOL structure size mismatch; table left untyped")
        return

    start = to_address(program, start_value + shift)
    size = table.count * profile.entry_size
    end = start.add(size + p - 1)
    memory, listing = program.getMemory(), program.getListing()
    if not (memory.contains(start) and memory.contains(end)):
        return
    resolved = program.getDataTypeManager().addDataType(struct,
                                                        DataTypeConflictHandler.REPLACE_HANDLER)
    listing.clearCodeUnits(start, end, False)
    listing.createData(start, ArrayDataType(resolved, table.count, profile.entry_size))
    listing.createData(start.add(size), UnsignedIntegerDataType.dataType if p == 4
                       else UnsignedLongLongDataType.dataType)
    report.table_typed = True


def _label_table(program, analysis: Analysis, report: ApplyReport) -> None:
    """Label the symbol table itself, unless the table already names it."""
    from ghidra.program.model.symbol import SourceType

    table = analysis.symbol_table
    start = table_address(analysis)
    if start is None:
        return
    known = {s.name for s in table.symbols}
    memory, symbols = program.getMemory(), program.getSymbolTable()
    for name, value in (("standTbl", start),
                        ("standTblSize", start + table.count * table.entry_size)):
        addr = to_address(program, value)
        if name not in known and memory.contains(addr):
            symbols.createLabel(addr, name, SourceType.ANALYSIS)


def _set_thumb(program, addr) -> None:
    from java.math import BigInteger

    context = program.getProgramContext()
    tmode = context.getRegister("TMode")
    if tmode is not None:
        context.setValue(tmode, addr, addr, BigInteger.ONE)


def record_metadata(program, analysis: Analysis, chosen_base: Optional[int]) -> None:
    """Store what VxAtlas concluded under Program Information, so the user can see it."""
    from ghidra.program.model.listing import Program

    info = program.getOptions(Program.PROGRAM_INFO)

    def put(key: str, value) -> None:
        if value is not None:
            info.setString(INFO_PREFIX + key, str(value))

    put("Identification", "VxWorks, confidence %s" % analysis.confidence.label()
        if analysis.is_vxworks else "not identified as VxWorks")
    put("Version", " ".join(v for v in (analysis.version_family, analysis.version) if v) or None)
    put("Container", " > ".join(layer.kind for layer in analysis.layers))
    if chosen_base is not None:
        put("Base Address", "0x%x" % chosen_base)
    if analysis.base_candidates:
        best = analysis.base_candidates[0]
        put("Recovered Base", "0x%x (confidence %s)" % (best.address, best.confidence.label()))
        put("Base Evidence", "; ".join(e.detail for e in best.evidence))
        others = ["0x%x (%s)" % (c.address, c.confidence.label())
                  for c in analysis.base_candidates[1:]]
        put("Base Alternatives", ", ".join(others) or "none")
    table = analysis.symbol_table
    if table is not None:
        put("Symbol Table", "%d symbols, layout %s, payload offset 0x%x, confidence %s" % (
            len(table.symbols), table.profile, table.offset, table.confidence.label()))
    else:
        put("Symbol Table", "not found (image may be stripped)")
    if analysis.notes:
        put("Notes", "; ".join(analysis.notes))
