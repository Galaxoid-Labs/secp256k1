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

cc "$dir/test_csuite.c" "$root/libsecp256k1_csuite.a" -o "$root/csuite_test"
"$root/csuite_test"

echo
cc -I "$dir/shim" "$dir/shim/run_upstream_tests.c" "$root/libsecp256k1_csuite.a" \
    -o "$root/csuite_upstream_test"
"$root/csuite_upstream_test"
