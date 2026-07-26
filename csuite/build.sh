#!/bin/sh
# Builds the csuite export surface, then runs two C-side suites against it:
#
#   1. test_csuite.c        — layout verification and hand-written smoke tests.
#   2. shim/run_upstream_tests.c — upstream's own test bodies, lifted verbatim by
#                                  tools/extract_upstream_tests.py.
#
# The library must be built with the internal invariant layer OFF: `VERIFY` adds magnitude
# and normalized fields to `Field_Elem`, which changes every struct offset the C side
# compiles against. The package asserts this at compile time rather than trusting the flag.
set -e
dir=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$dir")

odin build "$dir" -build-mode:static -o:speed -no-entry-point \
    -define:SECP256K1_VERIFY=false -out:"$root/libsecp256k1_csuite.a"

# The stack protector is not optional here: the C side declares the arrays the Odin side
# writes into, and a count that drifts apart is a silent overflow rather than a failed
# assertion. It has already caught one.
cflags="-Wall -Wextra -fstack-protector-strong"
cc $cflags "$dir/test_csuite.c" "$root/libsecp256k1_csuite.a" -o "$root/csuite_test"
"$root/csuite_test"

echo
# The lifted bodies are upstream's, verbatim, and not every helper they bring along is
# used by the subset we run. Editing them to silence that would defeat the point of
# lifting them unmodified.
cc $cflags -Wno-unused-function -I "$dir/shim" "$dir/shim/run_upstream_tests.c" "$root/libsecp256k1_csuite.a" \
    -o "$root/csuite_upstream_test"
"$root/csuite_upstream_test"
