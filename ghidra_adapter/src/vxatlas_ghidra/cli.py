"""Command-line front end: ``vxatlas-ghidra import <image> --project <dir>``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from vxatlas import analyze_file
from vxatlas.cli import render_text

from .importer import ImportError_, import_image


def _int(text: str) -> int:
    return int(text, 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vxatlas-ghidra",
        description="Import a VxWorks image into a Ghidra project with the recovered "
                    "base address, memory map and symbols.")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", help="create a Ghidra program from an image")
    imp.add_argument("image", help="firmware image (raw, uImage, ELF or compressed)")
    imp.add_argument("--project", required=True, metavar="DIR",
                     help="directory holding the Ghidra project (created if missing)")
    imp.add_argument("--project-name", default=None,
                     help="Ghidra project name (default: the directory's name)")
    imp.add_argument("--name", default=None, help="program name (default: the file name)")
    imp.add_argument("--base", type=_int, default=None, metavar="ADDR",
                     help="override the recovered base address")
    imp.add_argument("--language", default=None, metavar="ID",
                     help="override the Ghidra language ID, for example ARM:LE:32:v8")
    imp.add_argument("--compiler", default=None, metavar="ID",
                     help="override the compiler spec ID (default: the language's default)")
    imp.add_argument("--no-functions", action="store_true",
                     help="label symbols but do not disassemble or create functions")
    imp.add_argument("--analyze", action="store_true",
                     help="run Ghidra auto-analysis after importing")
    imp.add_argument("--json", action="store_true", help="print the import report as JSON")

    mod = sub.add_parser("module", help="import a kernel module (.out) and resolve its "
                                        "undefined symbols against a kernel image")
    mod.add_argument("module", help="kernel module, a relocatable ELF object")
    mod.add_argument("--kernel", required=True, metavar="IMAGE",
                     help="kernel image the module is loaded into")
    mod.add_argument("--project", required=True, metavar="DIR",
                     help="directory holding the Ghidra project (created if missing)")
    mod.add_argument("--project-name", default=None,
                     help="Ghidra project name (default: the directory's name)")
    mod.add_argument("--name", default=None, help="program name (default: the file name)")
    mod.add_argument("--kernel-program", default=None, metavar="PATH",
                     help="project path of the kernel program, for example /vxWorks.bin, "
                          "to link the module to it")
    mod.add_argument("--json", action="store_true", help="print the report as JSON")
    return parser


def _open_project(args):
    import pyghidra

    pyghidra.start()
    project_dir = Path(args.project)
    project_dir.mkdir(parents=True, exist_ok=True)
    return pyghidra.open_project(project_dir, args.project_name or project_dir.name, create=True)


def _run_module(args) -> int:
    from .link import LinkError, import_module

    try:
        kernel = analyze_file(args.kernel)
    except OSError as exc:
        print("vxatlas-ghidra: %s" % exc, file=sys.stderr)
        return 2
    project = _open_project(args)
    try:
        report = import_module(project, args.module, args.kernel, name=args.name,
                               kernel_program_path=args.kernel_program, kernel=kernel)
    except LinkError as exc:
        print("vxatlas-ghidra: %s" % exc, file=sys.stderr)
        return 1
    finally:
        project.close()
    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    print("Imported:       %s" % report.program_path)
    print("Resolved:       %d of %d undefined symbols" % (
        len(report.resolved), len(report.resolved) + len(report.unresolved)))
    for name, value in sorted(report.resolved.items()):
        print("  0x%x %s" % (value, name))
    for name in sorted(report.unresolved):
        print("  unresolved   %s" % name)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "module":
        return _run_module(args)
    try:
        analysis = analyze_file(args.image)
    except OSError as exc:
        print("vxatlas-ghidra: %s" % exc, file=sys.stderr)
        return 2
    if not args.json:
        print(render_text(analysis))

    project = _open_project(args)
    try:
        report = import_image(
            project, args.image, name=args.name, base=args.base, language=args.language,
            compiler=args.compiler, create_functions=not args.no_functions,
            run_analysis=args.analyze, analysis=analysis)
    except ImportError_ as exc:
        print("vxatlas-ghidra: %s" % exc, file=sys.stderr)
        return 1
    finally:
        project.close()

    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        applied = report.applied
        print("Imported:       %s (%s, %s loader)" % (report.program_path, report.language,
                                                      report.loader))
        for block in report.blocks:
            print("Block:          " + block)
        print("Applied:        %d labels, %d functions%s" % (
            applied.labels, applied.functions,
            ", symbol table typed as SYMBOL[%d]" % report.analysis.symbol_table.count
            if applied.table_typed else ""))
        skipped = applied.skipped_abs + applied.skipped_unmapped + applied.skipped_invalid
        if skipped:
            print("Not applied:    %d absolute constants, %d outside the memory map, "
                  "%d unusable names" % (applied.skipped_abs, applied.skipped_unmapped,
                                         applied.skipped_invalid))
    return 0


if __name__ == "__main__":
    sys.exit(main())
