#!/bin/sh
# Builds the constant-time harness.
#
# The checkmem shim is C and must be compiled to an object first; Odin's `foreign import`
# cannot consume a .c directly. It then links the object by name, so it must NOT also be
# passed to the linker explicitly or every symbol in it is duplicated.
#
#   ./ct_tests/build.sh              # no checker: the harness reports that and exits 2
#   ./ct_tests/build.sh --valgrind   # valgrind client requests  (needs valgrind-devel)
#   ./ct_tests/build.sh --msan       # MemorySanitizer           (Linux/FreeBSD only)
#
# Then, on a platform with valgrind:
#
#   valgrind --error-exitcode=1 ./ct_tests.bin
#
# A statistical timing test runs anywhere and needs none of the above:
#
#   odin run ct_tests/ -o:speed -define:DUDECT=true
set -e
dir=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$dir")

cflags=""
odinflags=""
case "$1" in
    --valgrind) cflags="-DVALGRIND" ;;
    --msan)     cflags="-fsanitize=memory"; odinflags="-sanitize:memory" ;;
    "")         ;;
    *)          echo "$0: unknown option $1" >&2; exit 1 ;;
esac

cc -c $cflags -O1 -o "$dir/checkmem.o" "$dir/checkmem.c"

# `foreign import checkmem "checkmem.o"` links the object; do not repeat it here.
odin build "$dir" -debug -o:none $odinflags -out:"$root/ct_tests.bin"

echo "built $root/ct_tests.bin"
