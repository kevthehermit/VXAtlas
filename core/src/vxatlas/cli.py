"""Command-line front end: ``vxatlas <image>``."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .analyze import analyze_file
from .model import Analysis


def _hex(value: Optional[int]) -> str:
    return "unknown" if value is None else "0x%x" % value


def render_text(a: Analysis, verbose: bool = False) -> str:
    lines = [
        "VxWorks image:  %s (confidence: %s)" % ("yes" if a.is_vxworks else "no",
                                                  a.confidence.label()),
        "Version:        %s%s" % (a.version_family or "unknown",
                                  " (%s)" % a.version if a.version else ""),
        "Architecture:   %s, %s-endian, %s-bit (confidence: %s)" % (
            a.arch or "unknown", a.endian or "unknown",
            a.pointer_size * 8 if a.pointer_size else "?", a.arch_confidence.label()),
        "Container:      %s" % " > ".join(l.kind for l in a.layers),
        "Base address:   %s%s" % (_hex(a.base), " (confidence: %s)"
                                  % a.base_candidates[0].confidence.label()
                                  if a.base_candidates else ""),
        "Entry point:    %s" % _hex(a.entry_point),
    ]
    for cand in a.base_candidates[1:]:
        lines.append("  alternative:  %s (confidence: %s)" % (_hex(cand.address),
                                                              cand.confidence.label()))
    st = a.symbol_table
    if st is None:
        lines.append("Symbol table:   not found")
    else:
        lines.append("Symbol table:   %d symbols at offset 0x%x, layout %s (confidence: %s)" % (
            len(st.symbols), st.offset, st.profile, st.confidence.label()))
    for seg in a.segments:
        lines.append("Segment:        %-6s 0x%x-0x%x %s" % (
            seg.name, seg.address, seg.address + seg.mem_size - 1, seg.perms))
    for dt in a.device_trees:
        lines.append("Device tree:    %d bytes at payload offset 0x%x" % (dt["size"], dt["offset"]))
    for note in a.notes:
        lines.append("Note:           " + note)
    if verbose:
        lines.append("Evidence:")
        for ev in a.evidence:
            lines.append("  [%s] %s: %s" % ("+" if ev.supports else "-", ev.signal, ev.detail))
        for cand in a.base_candidates:
            lines.append("Base %s:" % _hex(cand.address))
            for ev in cand.evidence:
                lines.append("  [%s] %s: %s" % ("+" if ev.supports else "-", ev.signal, ev.detail))
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vxatlas", description="Identify a VxWorks image and recover its base and symbols.")
    parser.add_argument("image", help="firmware image (raw, uImage, ELF or compressed)")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("--symbols", action="store_true", help="include the recovered symbols")
    parser.add_argument("-v", "--verbose", action="store_true", help="show the evidence")
    args = parser.parse_args(argv)

    try:
        result = analyze_file(args.image)
    except OSError as exc:
        print("vxatlas: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        json.dump(result.to_dict(include_symbols=args.symbols), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(render_text(result, args.verbose))
        if args.symbols and result.symbol_table:
            for sym in result.symbol_table.symbols:
                print("0x%x %s %s" % (sym.value, sym.kind, sym.name))
    return 0 if result.is_vxworks else 1


if __name__ == "__main__":
    sys.exit(main())
