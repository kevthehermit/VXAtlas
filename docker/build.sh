#!/usr/bin/env bash
# Build the vxatlas (core) and vxatlas-ghidra (adapter) wheels into dist/.
set -euo pipefail
cd /work
rm -rf dist
python -m build --wheel --outdir dist core
python -m build --wheel --outdir dist ghidra_adapter
ls -1 dist
