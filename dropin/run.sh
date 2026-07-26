#!/bin/sh
# Proves this library is a drop-in replacement for libsecp256k1.
#
# Compiles one unmodified C consumer twice — against upstream's archive and against ours,
# using upstream's own headers both times — and diffs the output byte for byte.
#
#   ./dropin/run.sh <path-to-upstream-checkout>
#
# The checkout must be built; `<checkout>/build/lib/libsecp256k1.a` and `<checkout>/include`
# are what this reads. Upstream must be configured with every module enabled, because the
# consumer calls all of them.
set -e

if [ $# -ne 1 ]; then
    echo "usage: $0 <path-to-upstream-secp256k1-checkout>" >&2
    exit 2
fi

upstream=$1
dir=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$dir")
work=${TMPDIR:-/tmp}/secp256k1-dropin.$$
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

inc="$upstream/include"
real_lib="$upstream/build/lib/libsecp256k1.a"

[ -d "$inc" ] || { echo "$0: no headers at $inc" >&2; exit 1; }
[ -f "$real_lib" ] || { echo "$0: no archive at $real_lib — build upstream first" >&2; exit 1; }

echo "building the Odin implementation as libsecp256k1.a"
odin build "$root/capi" -build-mode:static -no-entry-point -o:speed \
    -out:"$work/libsecp256k1_odin.a"

# The consumer includes <secp256k1.h> and calls the documented API. It is compiled from the
# same source, with the same flags, against the same headers, both times: the only variable
# is which archive the linker resolves the symbols from.
for which in real odin; do
    case $which in
        real) lib=$real_lib ;;
        odin) lib=$work/libsecp256k1_odin.a ;;
    esac
    cc -O2 -Wall -Wextra -Werror -I"$inc" "$dir/dropin_test.c" "$lib" -o "$work/consumer_$which"
done

echo
echo "running against the real libsecp256k1"
"$work/consumer_real" > "$work/out_real.txt" || {
    echo "$0: the reference build itself failed — check the upstream build" >&2
    cat "$work/out_real.txt" >&2
    exit 1
}

echo "running against this implementation"
set +e
"$work/consumer_odin" > "$work/out_odin.txt"
odin_status=$?
set -e

if [ $odin_status -ne 0 ]; then
    echo "$0: the consumer reported failures when linked against this implementation" >&2
    cat "$work/out_odin.txt" >&2
    exit 1
fi

echo
if diff -u "$work/out_real.txt" "$work/out_odin.txt" > "$work/diff.txt"; then
    lines=$(wc -l < "$work/out_real.txt" | tr -d ' ')
    echo "IDENTICAL — $lines lines of output match byte for byte"
    echo "the same C program, unmodified, linked against either archive"
else
    echo "DIVERGENCE — the two archives produce different output:"
    cat "$work/diff.txt"
    exit 1
fi
