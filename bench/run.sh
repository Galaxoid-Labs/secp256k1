#!/bin/sh
# Runs the benchmarks side by side with libsecp256k1.
#
# Requires the oracle library: ./oracle/link-lib.sh /path/to/libsecp256k1.a
set -e
root=$(cd "$(dirname "$0")/.." && pwd)
if [ ! -e "$root/oracle/libsecp256k1.a" ]; then
    echo "missing $root/oracle/libsecp256k1.a — run ./oracle/link-lib.sh first" >&2
    exit 1
fi
odin run "$root/bench" -o:speed -out:"$root/bench.bin" "$@"
