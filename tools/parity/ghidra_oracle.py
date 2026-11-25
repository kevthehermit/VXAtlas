#!/usr/bin/env python3
"""Run Ghidra's bundled VxWorksSymTab_Finder script on an image and print its labels as JSON.

Used only as an external oracle for the 5.x/6.x parity gate. The bundled script
needs the image mapped at the right base and with the right processor, so both
are passed in. Run inside the VxAtlas container:

    docker compose run --rm ghidra python tools/parity/ghidra_oracle.py \
        --language PowerPC:BE:32:default --base 0x10000 /samples/corpus/vx5_ppc_be.bin
"""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("image")
    ap.add_argument("--language", required=True)
    ap.add_argument("--base", required=True, type=lambda s: int(s, 0))
    ap.add_argument("--script", default="VxWorksSymTab_Finder.java")
    args = ap.parse_args()

    import pyghidra
    pyghidra.start()
    from ghidra.app.util.opinion import BinaryLoader
    from ghidra.program.model.symbol import SourceType
    from java.lang import Object

    install = os.environ.get("GHIDRA_INSTALL_DIR", "")
    script = next((Path(root) / args.script for root, _dirs, files in os.walk(install)
                   if args.script in files), None)
    if script is None:
        print("script %s not found under GHIDRA_INSTALL_DIR" % args.script, file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        project = pyghidra.open_project(tmp, "oracle", create=True)
        consumer = Object()
        loader = (pyghidra.program_loader().project(project).source(str(Path(args.image)))
                  .name("image").loaders(BinaryLoader.class_).language(args.language)
                  .addLoaderArg("-loader-baseAddr", "0x%x" % args.base))
        with loader.load() as results:
            program = results.getPrimaryDomainObject(consumer)
            try:
                print("running %s" % str(script), file=sys.stderr, flush=True)
                stdout, stderr = pyghidra.ghidra_script(str(script), project, program,
                                                        echo_stdout=False, echo_stderr=False)
                symbols = []
                for sym in program.getSymbolTable().getAllSymbols(False):
                    if sym.getSource() == SourceType.DEFAULT or sym.isExternal():
                        continue
                    if str(sym.getSymbolType()) not in ("Label", "Function"):
                        continue
                    offset = sym.getAddress().getOffsetAsBigInteger().longValue() & (2**64 - 1)
                    symbols.append([str(sym.getName()), offset])
            finally:
                program.release(consumer)
        project.close()
    json.dump({"tool": "ghidra:" + args.script, "load_address": args.base, "symbols": symbols,
               "log": (str(stdout) + str(stderr))[-4000:]}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
