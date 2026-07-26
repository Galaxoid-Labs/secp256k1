#!/usr/bin/env python3
"""Transcribes the BIP327 MuSig2 vectors from upstream's vectors.h into an Odin table.

Parses the C initializers structurally rather than by regex over hex, so a shape change in
upstream's generated header is a parse error here rather than a silently wrong table.
"""
import re, sys

import os

# Paths are environment-driven so CI can point these at a fresh upstream checkout and prove
# the committed tables reproduce byte-for-byte. Defaults preserve the original local layout.
UPSTREAM = os.environ.get("UPSTREAM", "/home/jdavis/Development/secp256k1-upstream")
REPO = os.environ.get("REPO", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = f"{UPSTREAM}/src/modules/musig/vectors.h"
OUT = f"{REPO}/tests/musig/bip327_vectors.odin"

text = open(SRC).read()
# Strip comments so they cannot be mistaken for tokens.
text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)


def extract(name):
    """Returns the brace-balanced initializer of `static const struct X name = {...};`."""
    m = re.search(r"static const struct \w+ %s = " % re.escape(name), text)
    if not m:
        raise SystemExit(f"{name}: initializer not found")
    i = text.index("{", m.end())
    depth, j = 0, i
    while True:
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
        j += 1


def parse(s):
    """Parses a C brace initializer into nested Python lists of tokens."""
    toks = re.findall(r"\{|\}|[^\s,{}]+", s)
    pos = 0

    def node():
        nonlocal pos
        assert toks[pos] == "{", toks[pos]
        pos += 1
        out = []
        while toks[pos] != "}":
            if toks[pos] == "{":
                out.append(node())
            else:
                out.append(toks[pos])
                pos += 1
        pos += 1
        return out

    return node()


def hexstr(byte_list):
    """Renders a list of C byte tokens as a lowercase hex string.

    A `{ 0 }` initializer in C zero-fills the whole array; the callers below only use such
    fields when a sibling flag says they are absent, so the short form is preserved as-is
    and never silently padded to a wrong length.
    """
    return "".join(f"{int(b, 0):02x}" for b in byte_list)


ka = parse(extract("musig_key_agg_vector"))
pubkeys, tweaks, valid, error = ka

na = parse(extract("musig_nonce_agg_vector"))
pnonces, na_valid, na_error = na

lines = []
lines.append('''/*
BIP327 MuSig2 test vectors, transcribed from upstream's `src/modules/musig/vectors.h`
(bitcoin-core/secp256k1 v0.7.1), which is itself generated from the BIP327 reference
`test_vectors_musig2_generate.py`.

Generated, not hand-written. Regenerating from the header must reproduce this file byte for
byte. Do not edit — `CLAUDE.md`: vectors come from upstream, unmodified.

MuSig2 is the highest-risk module in this project and had the least external validation, so
the *error* cases matter at least as much as the valid ones: they pin what must be
**rejected**. An implementation that aggregates an invalid public key, or accepts a
malformed nonce, is not lenient — it is exploitable.
*/
package test_musig

Key_Agg_Valid :: struct {
	key_indices: []int,
	expected:    string, // x-only aggregate key
}

Key_Agg_Error :: struct {
	key_indices:   []int,
	tweak_indices: []int,
	is_xonly:      []bool,
	error:         string, // upstream's MUSIG_* discriminant
}

Nonce_Agg_Valid :: struct {
	pnonce_indices: []int,
	expected:       string, // 66-byte aggregate nonce
}

Nonce_Agg_Error :: struct {
	pnonce_indices:    []int,
	invalid_nonce_idx: int,
}
''')

lines.append("// The 7 candidate public keys, compressed. Indices 3..6 are deliberately malformed.")
lines.append("KEY_AGG_PUBKEYS := [%d]string{" % len(pubkeys))
for pk in pubkeys:
    lines.append('\t"%s",' % hexstr(pk))
lines.append("}\n")

lines.append("KEY_AGG_TWEAKS := [%d]string{" % len(tweaks))
for tw in tweaks:
    lines.append('\t"%s",' % hexstr(tw))
lines.append("}\n")

lines.append("KEY_AGG_VALID := [%d]Key_Agg_Valid{" % len(valid))
for c in valid:
    n = int(c[0], 0)
    idx = [int(x, 0) for x in c[1][:n]]
    lines.append('\t{{%s}, "%s"},' % (", ".join(map(str, idx)), hexstr(c[2])))
lines.append("}\n")

lines.append("KEY_AGG_ERROR := [%d]Key_Agg_Error{" % len(error))
for c in error:
    nk = int(c[0], 0)
    keys = [int(x, 0) for x in c[1][:nk]]
    nt = int(c[2], 0)
    tws = [int(x, 0) for x in c[3][:nt]]
    xonly = [int(x, 0) != 0 for x in c[4][:nt]]
    lines.append('\t{{%s}, {%s}, {%s}, "%s"},' % (
        ", ".join(map(str, keys)),
        ", ".join(map(str, tws)),
        ", ".join("true" if b else "false" for b in xonly),
        c[5]))
lines.append("}\n")

lines.append("// The 7 candidate public nonces. Indices 4..6 are deliberately malformed.")
lines.append("NONCE_AGG_PNONCES := [%d]string{" % len(pnonces))
for p in pnonces:
    lines.append('\t"%s",' % hexstr(p))
lines.append("}\n")

lines.append("NONCE_AGG_VALID := [%d]Nonce_Agg_Valid{" % len(na_valid))
for c in na_valid:
    idx = [int(x, 0) for x in c[0]]
    lines.append('\t{{%s}, "%s"},' % (", ".join(map(str, idx)), hexstr(c[1])))
lines.append("}\n")

lines.append("NONCE_AGG_ERROR := [%d]Nonce_Agg_Error{" % len(na_error))
for c in na_error:
    idx = [int(x, 0) for x in c[0]]
    lines.append('\t{{%s}, %d},' % (", ".join(map(str, idx)), int(c[2], 0)))
lines.append("}")

ng = parse(extract("musig_nonce_gen_vector"))[0]
lines.append("\n// Nonce generation vectors: the full derivation input set, including the optional")
lines.append("// fields, with the exact secnonce and pubnonce BIP327 requires.")
lines.append("Nonce_Gen_Case :: struct {")
lines.append("\trand, sk, pk, aggpk, msg, extra_in: string, // empty means absent")
lines.append("\texpected_secnonce, expected_pubnonce: string,")
lines.append("}\n")
lines.append("NONCE_GEN := [%d]Nonce_Gen_Case{" % len(ng))
for c in ng:
    has_sk = int(c[1], 0)
    has_agg = int(c[4], 0)
    has_msg = int(c[6], 0)
    has_ex = int(c[8], 0)
    lines.append('\t{"%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"},' % (
        hexstr(c[0]),
        hexstr(c[2]) if has_sk else "",
        hexstr(c[3]),
        hexstr(c[5]) if has_agg else "",
        hexstr(c[7]) if has_msg else "",
        hexstr(c[9]) if has_ex else "",
        hexstr(c[10]),
        hexstr(c[11]),
    ))
lines.append("}")

open(OUT, "w").write("\n".join(lines) + "\n")
print(f"key_agg: {len(valid)} valid, {len(error)} error, {len(pubkeys)} pubkeys, {len(tweaks)} tweaks")
print(f"nonce_agg: {len(na_valid)} valid, {len(na_error)} error, {len(pnonces)} pnonces")
print(f"nonce_gen: {len(ng)} cases")

# --- sig_agg and tweak groups ---------------------------------------------------------

sa = parse(extract("musig_sig_agg_vector"))
sa_pubkeys, sa_tweaks, sa_psigs, sa_msg, sa_valid, sa_error = sa

extra = []
extra.append("\n// Signature aggregation: partial signatures combined into one BIP340 signature.")
extra.append("Sig_Agg_Case :: struct {")
extra.append("\tkey_indices, tweak_indices: []int,")
extra.append("\tis_xonly:                   []bool,")
extra.append("\taggnonce:                   string,")
extra.append("\tpsig_indices:               []int,")
extra.append("\texpected:                   string, // 64-byte signature; empty for error cases")
extra.append("\tinvalid_sig_idx:            int,")
extra.append("}\n")

extra.append("SIG_AGG_PUBKEYS := [%d]string{" % len(sa_pubkeys))
for x in sa_pubkeys:
    extra.append('\t"%s",' % hexstr(x))
extra.append("}\n")
extra.append("SIG_AGG_TWEAKS := [%d]string{" % len(sa_tweaks))
for x in sa_tweaks:
    extra.append('\t"%s",' % hexstr(x))
extra.append("}\n")
extra.append("SIG_AGG_PSIGS := [%d]string{" % len(sa_psigs))
for x in sa_psigs:
    extra.append('\t"%s",' % hexstr(x))
extra.append("}\n")
extra.append('SIG_AGG_MSG :: "%s"\n' % hexstr(sa_msg))


def sig_agg_rows(cases, is_error):
    out = []
    for c in cases:
        nk = int(c[0], 0); keys = [int(x, 0) for x in c[1][:nk]]
        nt = int(c[2], 0); tws = [int(x, 0) for x in c[3][:nt]]
        xo = [int(x, 0) != 0 for x in c[4][:nt]]
        agg = hexstr(c[5])
        np_ = int(c[6], 0); psigs = [int(x, 0) for x in c[7][:np_]]
        exp = "" if is_error else hexstr(c[8])
        bad = int(c[9], 0)
        out.append('\t{{%s}, {%s}, {%s}, "%s", {%s}, "%s", %d},' % (
            ", ".join(map(str, keys)), ", ".join(map(str, tws)),
            ", ".join("true" if b else "false" for b in xo),
            agg, ", ".join(map(str, psigs)), exp, bad))
    return out


extra.append("SIG_AGG_VALID := [%d]Sig_Agg_Case{" % len(sa_valid))
extra += sig_agg_rows(sa_valid, False)
extra.append("}\n")
extra.append("SIG_AGG_ERROR := [%d]Sig_Agg_Case{" % len(sa_error))
extra += sig_agg_rows(sa_error, True)
extra.append("}")

open(OUT, "a").write("\n".join(extra) + "\n")
print(f"sig_agg: {len(sa_valid)} valid, {len(sa_error)} error, {len(sa_psigs)} psigs")

# --- sign_verify and tweak groups -----------------------------------------------------

sv = parse(extract("musig_sign_verify_vector"))
sv_sk, sv_pubkeys, sv_secnonces, sv_pubnonces, sv_aggnonces, sv_msgs, \
    sv_valid, sv_sign_err, sv_vfail, sv_verr = sv

tw = parse(extract("musig_tweak_vector"))
tw_sk, tw_secnonce, tw_aggnonce, tw_msg, tw_pubkeys, tw_pubnonces, tw_tweaks, \
    tw_valid, tw_error = tw

e2 = []
e2.append("\n// Signing and verification: one signer's partial signature within a session.")
e2.append("Sign_Verify_Valid :: struct {")
e2.append("\tkey_indices:   []int,")
e2.append("\taggnonce_index, msg_index, signer_index: int,")
e2.append("\texpected:      string, // 32-byte partial signature")
e2.append("}\n")
e2.append("Sign_Verify_Error :: struct {")
e2.append("\tkey_indices:   []int,")
e2.append("\taggnonce_index, msg_index, secnonce_index: int,")
e2.append("\terror:         string,")
e2.append("}\n")

e2.append('SV_SK :: "%s"\n' % hexstr(sv_sk))
for name, arr in (("SV_PUBKEYS", sv_pubkeys), ("SV_SECNONCES", sv_secnonces),
                  ("SV_PUBNONCES", sv_pubnonces), ("SV_AGGNONCES", sv_aggnonces),
                  ("SV_MSGS", sv_msgs)):
    e2.append("%s := [%d]string{" % (name, len(arr)))
    for x in arr:
        e2.append('\t"%s",' % hexstr(x))
    e2.append("}\n")

e2.append("SV_VALID := [%d]Sign_Verify_Valid{" % len(sv_valid))
for c in sv_valid:
    nk = int(c[0], 0)
    keys = [int(x, 0) for x in c[1][:nk]]
    e2.append('\t{{%s}, %d, %d, %d, "%s"},' % (
        ", ".join(map(str, keys)), int(c[2], 0), int(c[3], 0), int(c[4], 0), hexstr(c[5])))
e2.append("}\n")

e2.append("SV_SIGN_ERROR := [%d]Sign_Verify_Error{" % len(sv_sign_err))
for c in sv_sign_err:
    nk = int(c[0], 0)
    keys = [int(x, 0) for x in c[1][:nk]]
    e2.append('\t{{%s}, %d, %d, %d, "%s"},' % (
        ", ".join(map(str, keys)), int(c[2], 0), int(c[3], 0), int(c[4], 0), c[5]))
e2.append("}\n")

e2.append("// Tweak vectors: chains of x-only and plain EC tweaks applied before signing.")
e2.append("Tweak_Case :: struct {")
e2.append("\tkey_indices, nonce_indices, tweak_indices: []int,")
e2.append("\tis_xonly:     []bool,")
e2.append("\tsigner_index: int,")
e2.append("\texpected:     string,")
e2.append("}\n")
e2.append('TW_SK :: "%s"' % hexstr(tw_sk))
e2.append('TW_SECNONCE :: "%s"' % hexstr(tw_secnonce))
e2.append('TW_AGGNONCE :: "%s"' % hexstr(tw_aggnonce))
e2.append('TW_MSG :: "%s"\n' % hexstr(tw_msg))
for name, arr in (("TW_PUBKEYS", tw_pubkeys), ("TW_PUBNONCES", tw_pubnonces),
                  ("TW_TWEAKS", tw_tweaks)):
    e2.append("%s := [%d]string{" % (name, len(arr)))
    for x in arr:
        e2.append('\t"%s",' % hexstr(x))
    e2.append("}\n")


def tweak_rows(cases):
    out = []
    for c in cases:
        nk = int(c[0], 0); keys = [int(x, 0) for x in c[1][:nk]]
        nn = int(c[2], 0); nonces = [int(x, 0) for x in c[3][:nn]]
        nt = int(c[4], 0); tws = [int(x, 0) for x in c[5][:nt]]
        xo = [int(x, 0) != 0 for x in c[6][:nt]]
        out.append('\t{{%s}, {%s}, {%s}, {%s}, %d, "%s"},' % (
            ", ".join(map(str, keys)), ", ".join(map(str, nonces)),
            ", ".join(map(str, tws)),
            ", ".join("true" if b else "false" for b in xo),
            int(c[7], 0), hexstr(c[8])))
    return out


e2.append("TW_VALID := [%d]Tweak_Case{" % len(tw_valid))
e2 += tweak_rows(tw_valid)
e2.append("}\n")
e2.append("TW_ERROR := [%d]Tweak_Case{" % len(tw_error))
e2 += tweak_rows(tw_error)
e2.append("}")

open(OUT, "a").write("\n".join(e2) + "\n")
print(f"sign_verify: {len(sv_valid)} valid, {len(sv_sign_err)} sign-error")
print(f"tweak: {len(tw_valid)} valid, {len(tw_error)} error")
