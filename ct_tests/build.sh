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
#   ./ct_tests/build.sh --dudect     # statistical timing test; runs anywhere
#
# Every mode goes through this script, including `--dudect`, which needs no checker at all.
# That is not tidiness: `foreign import checkmem "checkmem.o"` is unconditional, so *any*
# build of this package needs the object to exist. Invoking `odin run ct_tests/` directly
# links only if some earlier run of this script happened to leave one behind — which is
# exactly what made the dudect job pass locally and fail in CI on a clean checkout.
#
# An optional second argument sets the optimization level. Run the valgrind gate at -o:speed
# as well as the default -o:none: two of the defects it has found existed only there, where
# the optimizer rewrote a constant-time select into a branch and DCE reshaped a
# secret-dependent test.
#
#   ./ct_tests/build.sh --valgrind -o:speed
#
# Any further arguments are passed through to the compiler, which is how the sample count
# reaches the statistical mode:
#
#   ./ct_tests/build.sh --dudect -o:speed -define:DUDECT_SAMPLES=40000
#
# Then, on a platform with valgrind:
#
#   valgrind --error-exitcode=1 ./ct_tests.bin
set -e
dir=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$dir")

mode=${1:-}
[ $# -gt 0 ] && shift

cflags=""
odinflags=""
# `-debug` buys the DWARF line numbers that make a checker finding actionable, and costs
# nothing that matters when the checker dominates the runtime. The statistical mode is the
# exception: it measures wall-clock time, so it must build the way a release build does or
# it is measuring the debug build's overhead instead of the library's behaviour.
debugflag="-debug"
opt="-o:none"

case "$mode" in
    --valgrind) cflags="-DVALGRIND" ;;
    --msan)     cflags="-fsanitize=memory"; odinflags="-sanitize:memory" ;;
    --dudect)   odinflags="-define:DUDECT=true"; debugflag=""; opt="-o:speed" ;;
    "")         ;;
    *)          echo "$0: unknown option $mode" >&2; exit 1 ;;
esac

case "${1:-}" in
    -o:*) opt=$1; shift ;;
esac

cc -c $cflags -O1 -o "$dir/checkmem.o" "$dir/checkmem.c"

# The internal `*_verify` layer must be OFF here. Those checks branch on field magnitudes
# and limb values by design, so with them compiled in memcheck reports hundreds of contexts
# that are invariant assertions, not leaks — drowning any real finding. Upstream builds
# `ctime_tests.c` without `VERIFY` for the same reason.
#
# `foreign import checkmem "checkmem.o"` links the object; do not repeat it here.
# SECP256K1_DECLASSIFY turns on the library's declassification hook, which this harness
# installs. Without it the library cannot tell the checker that a value has legitimately
# become public, and every such point is reported as a leak. The statistical mode has no
# checker to inform, so it leaves the hook out entirely.
declassify="-define:SECP256K1_DECLASSIFY=true"
if [ "$mode" = "--dudect" ]; then
    declassify=""
fi

# shellcheck disable=SC2086
odin build "$dir" $debugflag "$opt" -define:SECP256K1_VERIFY=false \
    $declassify $odinflags "$@" -out:"$root/ct_tests.bin"

echo "built $root/ct_tests.bin ($mode${mode:+ }$opt)"
