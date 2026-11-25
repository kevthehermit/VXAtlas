#!/usr/bin/env bash
# Install the built wheels into a throwaway directory on top of the image's PyGhidra,
# then run the core and headless Ghidra tests against the installed packages.
set -euo pipefail
cd /work
if ! ls dist/vxatlas-*.whl dist/vxatlas_ghidra-*.whl >/dev/null 2>&1; then
  echo "No wheels in dist/. Run: docker compose run --rm build" >&2
  exit 1
fi
site=$(mktemp -d)
pip install --quiet --no-deps --target "$site" dist/vxatlas-*.whl dist/vxatlas_ghidra-*.whl
PYTHONPATH="$site" python -m pytest core/tests ghidra_adapter/tests -q -rs -p no:cacheprovider "$@"
