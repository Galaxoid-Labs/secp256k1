#!/usr/bin/env python3
"""Extracts test function bodies verbatim from upstream's tests.c.

`tests.c` cannot be compiled against this implementation — it `#include`s the entire C
library rather than linking one (see TODO.md item 5). This pulls the named functions out
byte-for-byte so they can be compiled against `csuite/shim/secp256k1_shim.h` instead. The
*bodies* are upstream's and unmodified; only what surrounds them changes.

Generated output must reproduce byte-for-byte from a given upstream tag, which is the check
that no assertion was quietly softened on the way across.
"""
import re
import sys

import os

# Paths are environment-driven so CI can point these at a fresh upstream checkout and prove
# the committed tables reproduce byte-for-byte. Defaults preserve the original local layout.
UPSTREAM = os.environ.get("UPSTREAM", "/home/jdavis/Development/secp256k1-upstream")
REPO = os.environ.get("REPO", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = f"{UPSTREAM}/src/tests.c"
# Shared helpers (random element generation, comparison) live in a separate header upstream.
SRC_UTIL = f"{UPSTREAM}/src/testutil.h"
OUT = f"{REPO}/csuite/shim/upstream_bodies.h"

# Functions to lift. Each must be reachable using only the API the shim declares; a name
# that needs something unexported fails loudly at compile time rather than being skipped.
# Helpers from testutil.h, extracted first because the test bodies call them.
WANTED_UTIL = [
    "testutil_random_fe",
    "testutil_random_fe_test",
    "testutil_random_fe_non_zero",
    "testutil_random_fe_non_zero_test",
    "testutil_random_fe_magnitude",
    "testutil_random_ge_x_magnitude",
    "testutil_random_ge_y_magnitude",
    "testutil_random_gej_x_magnitude",
    "testutil_random_gej_y_magnitude",
    "testutil_random_gej_z_magnitude",
    "testutil_random_ge_test",
    "testutil_random_ge_jacobian_test",
    "testutil_random_scalar_order",
    "testutil_random_scalar_order_test",
    "testutil_random_scalar_order_b32",
]

# Test bodies from tests.c. A name that needs something the shim does not declare fails at
# compile time rather than being silently skipped.
WANTED = [
    "fe_equal",
    "fe_identical",
    "random_fe_non_square",
    "test_sqrt",
    "run_field_convert",
    "run_field_half",
    "run_field_misc",
    "run_sqrt",
    # scalar
    "scalar_test",
    "run_scalar_tests",
    "run_scalar_set_b32_seckey_tests",
    # group
    "test_ge",
    "test_add_neg_y_diff_x",
    "test_initialized_inf",
    # ecmult
    "run_ecmult_chain",
    "test_wnaf",
    "run_fe_mul", "test_fe_mul", "run_sqr",
    "run_field_be32_overflow",
    "run_group_decompress", "test_group_decompress",
    "run_endomorphism_tests",
    "run_cmov_tests", "int_cmov_test", "fe_cmov_test", "fe_storage_cmov_test",
    "scalar_cmov_test", "ge_storage_cmov_test",
    "run_point_times_order", "test_point_times_order",
    "gej_xyz_equals_gej", "mulmod256", "test_scalar_split",
    "run_ecmult_near_split_bound", "test_ecmult_target",
    # ecdsa
    "random_sign",
    "test_ecdsa_sign_verify",
    "run_ecdsa_sign_verify",
]


def extract(text, name):
    """Returns the full text of `static <type> name(...) { ... }`, brace-balanced."""
    m = re.search(r"^static[^\n(]*\b%s\s*\(" % re.escape(name), text, re.M)
    if not m:
        return None
    # Find the opening brace of the body, skipping the parameter list.
    i = text.index("(", m.end() - 1)
    depth = 0
    while True:
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    j = text.index("{", i)
    depth = 0
    k = j
    while True:
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return text[m.start():k + 1]
        k += 1


WANTED_DATA = [
    "scalars_near_split_bounds",
]


def extract_data(text, name):
    """Returns a `static const ... name[...] = { ... };` declaration, brace-balanced."""
    m = re.search(r"^static const [^\n=]*\b%s\s*\[[^\]]*\]\s*=\s*" % re.escape(name), text, re.M)
    if not m:
        return None
    i = text.index("{", m.end() - 1)
    depth, j = 0, i
    while True:
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[m.start():j + 1] + ";"
        j += 1


def main():
    text = open(SRC).read()
    util = open(SRC_UTIL).read()
    out = []
    data_out = []
    found, missing = [], []
    data_seen = set()
    for name in WANTED_DATA:
        if name in data_seen:
            continue
        data_seen.add(name)
        d = extract_data(text, name)
        if d is None:
            missing.append(name)
        else:
            found.append(name)
            data_out.append(d)

    seen = set()
    for src, names in ((util, WANTED_UTIL), (text, WANTED)):
        for name in names:
            if name in seen:
                continue
            seen.add(name)
            body = extract(src, name)
            if body is None:
                missing.append(name)
                continue
            found.append(name)
            out.append(body)

    # Forward declarations for the functions only, so the order of WANTED need not match
    # call order. Data declarations are emitted first instead and never forward-declared.
    decls = []
    for body in out:
        sig = body[:body.index("{")].strip()
        decls.append(sig + ";")

    header = '''/*
 * Test bodies lifted verbatim from bitcoin-core/secp256k1 v0.7.1 `src/tests.c`.
 *
 * GENERATED by tools/extract_upstream_tests.py — do not edit. Regenerating from the same
 * upstream tag must reproduce this file byte for byte; that reproduction is the check that
 * no assertion was softened in transit.
 *
 * These are upstream's assertions, unmodified, compiled against this implementation through
 * `secp256k1_shim.h`. See TODO.md item 5 for why the file they came from cannot itself be
 * linked, and for exactly what claim this licenses.
 *
 * Functions lifted: %d
 */

''' % len(found)

    open(OUT, "w").write(
        header + "\n\n".join(data_out) + "\n\n" + "\n".join(decls) + "\n\n" +
        "\n\n".join(out) + "\n")
    print("extracted %d function(s)" % len(found))
    if missing:
        print("NOT FOUND (name changed upstream?): " + ", ".join(missing), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
