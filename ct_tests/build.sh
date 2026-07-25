#!/bin/sh
# Builds the constant-time harness.
#
# The checkmem shim is a C file and must be compiled to an object before Odin can link it;
# Odin's `foreign import` cannot consume a .c directly.
#
#   ./ct_tests/build.sh              # build without a checker (harness reports and exits 2)
#   ./ct_tests/build.sh --valgrind   # build with valgrind client requests
#
# Then, on a platform with valgrind:
#
#   valgrind --error-exitcode=1 ./ct_tests.bin
set -e
dir=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$dir")

cflags=""
if [ "$1" = "--valgrind" ]; then
    cflags="-DVALGRIND"
elif [ "$1" = "--msan" ]; then
    cflags="-fsanitize=memory"
fi

cc -c $cflags -O1 -o "$dir/checkmem.o" "$dir/checkmem.c"
odin build "$dir" -debug -o:none -out:"$root/ct_tests.bin" -extra-linker-flags:"$dir/checkmem.o"
echo "built $root/ct_tests.bin"
