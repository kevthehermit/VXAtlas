#!/usr/bin/env python3
"""Run vxhunter's Python core on an image and print what it recovers, as JSON.

vxhunter is used only as an external oracle for the 5.x/6.x parity gate: this
script imports it from a checkout you provide and never copies its code.

    python tools/parity/vxhunter_oracle.py --vxhunter ~/src/vxhunter \
        --version 5 --endian big image.bin > vxhunter.json
"""

import argparse
import importlib.util
import json
import logging
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("image")
    ap.add_argument("--vxhunter", required=True, help="path to a vxhunter checkout")
    ap.add_argument("--version", type=int, choices=(5, 6), required=True)
    ap.add_argument("--endian", choices=("little", "big"), required=True)
    args = ap.parse_args()

    core = Path(args.vxhunter) / "firmware_tools" / "vxhunter_core_py3.py"
    spec = importlib.util.spec_from_file_location("vxhunter_core", core)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    logger = logging.getLogger("vxhunter")
    logger.addHandler(logging.NullHandler())
    logger.propagate = False
    target = module.VxTarget(firmware=Path(args.image).read_bytes(), vx_version=args.version,
                             is_big_endian=args.endian == "big", logger=logger)
    target.prepare()
    load = target.quick_test()
    if load is None:
        target.find_loading_address()
        load = target.load_address
    symbols = target.get_symbols() or []
    json.dump({
        "tool": "vxhunter",
        "load_address": load,
        "symbol_table_start": target.symbol_table_start,
        "symbol_table_end": target.symbol_table_end,
        "symbols": [[s["symbol_name"], s["symbol_dest_addr"]] for s in symbols],
    }, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
