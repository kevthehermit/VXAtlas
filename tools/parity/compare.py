#!/usr/bin/env python3
"""Compare an oracle's symbols (JSON from the *_oracle.py scripts) with VxAtlas's.

Exit status is 0 when VxAtlas recovers every (name, address) pair the oracle
does, and 1 otherwise. Differences in either direction are listed.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "core" / "src"))

from vxatlas import analyze_file  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("image")
    ap.add_argument("oracle_json")
    ap.add_argument("--show", type=int, default=10, help="differences to list per direction")
    args = ap.parse_args()

    oracle = json.loads(Path(args.oracle_json).read_text())
    analysis = analyze_file(args.image)
    table = analysis.symbol_table
    ours = {(s.name, s.value) for s in table.symbols} if table else set()
    theirs = {(n, v) for n, v in oracle["symbols"]}

    missing = sorted(theirs - ours)
    extra = sorted(ours - theirs)
    load = oracle.get("load_address")
    print("oracle:        %s" % oracle["tool"])
    print("base address:  ours %s, oracle %s" % (
        "0x%x" % analysis.base if analysis.base is not None else "none",
        "0x%x" % load if load is not None else "none"))
    print("symbols:       ours %d, oracle %d, common %d" % (len(ours), len(theirs),
                                                            len(ours & theirs)))
    print("only oracle:   %d" % len(missing))
    for name, value in missing[:args.show]:
        print("    0x%x %s" % (value, name))
    print("only VxAtlas:  %d" % len(extra))
    for name, value in extra[:args.show]:
        print("    0x%x %s" % (value, name))
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
