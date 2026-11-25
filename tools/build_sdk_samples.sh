#!/usr/bin/env bash
# Build the RTP and kernel-module test inputs from testdata/src with a Wind River
# VxWorks 7 SDK. The outputs link SDK libraries, so they go to the external
# corpus, never into this repository.
#
#   tools/build_sdk_samples.sh <extracted-sdk-dir> <tag> <output-dir>
#   tools/build_sdk_samples.sh ~/sdk/wrsdk-vxworks7-raspberrypi4b-1.10.0 \
#       vx7_2609_aarch64 "$VXATLAS_SAMPLES/corpus"
set -euo pipefail
if [ $# -ne 3 ]; then
  sed -n '2,9p' "$0" >&2
  exit 2
fi
sdk=$(realpath "$1"); tag=$2; out=$(realpath "$3")
src=$(cd "$(dirname "$0")/../testdata/src" && pwd)

# The same environment sdkenv.sh sets up, without its requirement that /bin/sh is bash.
export WIND_SDK_HOME=$sdk
export WIND_SDK_CC_SYSROOT=$sdk/vxsdk/sysroot
export WRSD_LICENSE_FILE=$sdk/license
export PATH=$sdk/vxsdk/host/x86_64-linux/bin:$PATH
export LD_LIBRARY_PATH=$sdk/vxsdk/host/x86_64-linux/lib:${LD_LIBRARY_PATH:-}

wr-cc -rtp "$src/hello_rtp.c" -static -o "$out/${tag}_hello_static.vxe"
wr-cc -rtp "$src/hello_rtp.c" -o "$out/${tag}_hello_dynamic.vxe"
wr-cc -dkm "$src/hello_dkm.c" -o "$out/${tag}_hello_dkm.out"
ls -1 "$out/${tag}"_hello_*
