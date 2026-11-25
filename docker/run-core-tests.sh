#!/usr/bin/env bash
# Pure-Python unit tests for the core package. No Ghidra involved.
set -euo pipefail
cd /work
PYTHONPATH=core/src python -m pytest core/tests -q -rs -p no:cacheprovider "$@"
