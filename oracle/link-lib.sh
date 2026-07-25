#!/bin/sh
# Links a built libsecp256k1.a into this directory so the differential oracle can link
# against it. The library is not committed: see oracle.odin.
#
#   ./oracle/link-lib.sh /path/to/secp256k1/build/lib/libsecp256k1.a
set -e
if [ $# -ne 1 ]; then
    echo "usage: $0 /path/to/libsecp256k1.a" >&2
    exit 1
fi
if [ ! -f "$1" ]; then
    echo "$0: no such file: $1" >&2
    exit 1
fi
dir=$(cd "$(dirname "$0")" && pwd)
ln -sf "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")" "$dir/libsecp256k1.a"
echo "linked $dir/libsecp256k1.a -> $1"
