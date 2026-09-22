#!/usr/bin/env python3
"""Adds secret-scrubbing to the vendored PQClean sources.

Upstream PQClean never clears its stack buffers, so seeds, decrypted messages,
secret polynomials, and derived shared secrets stay resident after every call.
This script inserts PQCLEAN_zeroize() calls at the points where those locals die.

It is idempotent and asserts on every substitution, so it fails loudly rather
than silently mis-patching after a PQClean update. Run from the repository root:

    python3 patches/apply_zeroize.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "Sources" / "CryptoPQC"

INCLUDE = '#include "pqclean_zeroize.h"'
KEM_VARIANTS = [("ml-kem-768", "PQCLEAN_MLKEM768_CLEAN"), ("ml-kem-1024", "PQCLEAN_MLKEM1024_CLEAN")]
DSA_VARIANTS = [
    ("ml-dsa-44", "PQCLEAN_MLDSA44_CLEAN"),
    ("ml-dsa-65", "PQCLEAN_MLDSA65_CLEAN"),
    ("ml-dsa-87", "PQCLEAN_MLDSA87_CLEAN"),
]

edits = 0


def patch(path, replacements, include_anchor):
    """Applies (old, new) pairs to `path`, adding the zeroize include first."""
    global edits
    text = path.read_text()

    if INCLUDE not in text:
        assert include_anchor in text, f"{path}: missing include anchor"
        text = text.replace(include_anchor, include_anchor + "\n" + INCLUDE, 1)

    for old, new in replacements:
        if new in text:
            continue  # already patched
        assert old in text, f"{path}: pattern not found:\n{old}"
        assert text.count(old) == 1, f"{path}: pattern is ambiguous:\n{old}"
        text = text.replace(old, new, 1)
        edits += 1

    path.write_text(text)


def zeroize(*names):
    return "".join(f"    PQCLEAN_zeroize(&{n}, sizeof({n}));\n" for n in names)


# --- ML-KEM: kem.c ------------------------------------------------------------
# keypair/enc leak the sampled coins; enc_derand and dec leak `buf` (the message
# and H(pk)), `kr` (the shared secret and encryption coins), and `cmp`.
for directory, p in KEM_VARIANTS:
    patch(
        SRC / directory / "kem.c",
        [
            (
                f"    {p}_crypto_kem_keypair_derand(pk, sk, coins);\n    return 0;",
                f"    {p}_crypto_kem_keypair_derand(pk, sk, coins);\n"
                "    PQCLEAN_zeroize(coins, sizeof(coins));\n    return 0;",
            ),
            (
                "    memcpy(ss, kr, KYBER_SYMBYTES);\n    return 0;",
                "    memcpy(ss, kr, KYBER_SYMBYTES);\n"
                "    PQCLEAN_zeroize(buf, sizeof(buf));\n"
                "    PQCLEAN_zeroize(kr, sizeof(kr));\n    return 0;",
            ),
            (
                f"    {p}_crypto_kem_enc_derand(ct, ss, pk, coins);\n    return 0;",
                f"    {p}_crypto_kem_enc_derand(ct, ss, pk, coins);\n"
                "    PQCLEAN_zeroize(coins, sizeof(coins));\n    return 0;",
            ),
            (
                f"    {p}_cmov(ss, kr, KYBER_SYMBYTES, (uint8_t) (1 - fail));\n\n    return 0;",
                f"    {p}_cmov(ss, kr, KYBER_SYMBYTES, (uint8_t) (1 - fail));\n\n"
                "    PQCLEAN_zeroize(buf, sizeof(buf));\n"
                "    PQCLEAN_zeroize(kr, sizeof(kr));\n"
                "    PQCLEAN_zeroize(cmp, sizeof(cmp));\n    return 0;",
            ),
        ],
        include_anchor='#include "verify.h"',
    )

# --- ML-KEM: indcpa.c ---------------------------------------------------------
# skpv/e are the secret key and error vectors, sp/ep/epp the encryption noise,
# k the message polynomial, and mp the decrypted message polynomial.
for directory, p in KEM_VARIANTS:
    patch(
        SRC / directory / "indcpa.c",
        [
            (
                "    pack_sk(sk, &skpv);\n    pack_pk(pk, &pkpv, publicseed);\n}",
                "    pack_sk(sk, &skpv);\n    pack_pk(pk, &pkpv, publicseed);\n\n"
                + "    PQCLEAN_zeroize(buf, sizeof(buf));\n"
                + zeroize("skpv", "e")
                + "}",
            ),
            (
                "    pack_ciphertext(c, &b, &v);\n}",
                "    pack_ciphertext(c, &b, &v);\n\n" + zeroize("sp", "ep", "epp", "k") + "}",
            ),
            (
                f"    {p}_poly_tomsg(m, &mp);\n}}",
                f"    {p}_poly_tomsg(m, &mp);\n\n" + zeroize("skpv", "mp") + "}",
            ),
        ],
        include_anchor='#include "polyvec.h"',
    )

# --- ML-DSA: sign.c -----------------------------------------------------------
# seedbuf holds rho, tr, key, mu, rhoprime and the signing nonce; s1/s2/t0 are
# the secret key vectors; y and w0 are the per-signature masking values.
for directory, p in DSA_VARIANTS:
    patch(
        SRC / directory / "sign.c",
        [
            (
                f"    {p}_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);\n\n    return 0;",
                f"    {p}_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);\n\n"
                + "    PQCLEAN_zeroize(seedbuf, sizeof(seedbuf));\n"
                + zeroize("s1", "s1hat", "s2", "t0")
                + "    return 0;",
            ),
            (
                f"    {p}_pack_sig(sig, sig, &z, &h);\n    *siglen = {p}_CRYPTO_BYTES;\n    return 0;",
                f"    {p}_pack_sig(sig, sig, &z, &h);\n    *siglen = {p}_CRYPTO_BYTES;\n\n"
                + "    PQCLEAN_zeroize(seedbuf, sizeof(seedbuf));\n"
                + zeroize("s1", "s2", "t0", "y", "w0", "cp")
                + "    return 0;",
            ),
        ],
        include_anchor='#include "symmetric.h"',
    )

# --- FIPS 202 sponge states ---------------------------------------------------
# *_ctx_release() frees the heap-allocated Keccak state without clearing it,
# and for ML-DSA that state has absorbed the secret key.
fips = SRC / "common" / "fips202.c"
text = fips.read_text()
if INCLUDE not in text:
    anchor = '#include "fips202.h"'
    assert anchor in text, "fips202.c: missing include anchor"
    text = text.replace(anchor, anchor + "\n" + INCLUDE, 1)

for match in re.finditer(r"void (\w+_ctx_release)\((\w+) \*state\) \{\n    free\(state->ctx\);\n\}", text):
    name, ctype = match.group(1), match.group(2)
    size = "PQC_SHAKEINCCTX_BYTES" if "_inc_" in name else "PQC_SHAKECTX_BYTES"
    replacement = (
        f"void {name}({ctype} *state) {{\n"
        f"    PQCLEAN_zeroize(state->ctx, {size});\n"
        "    free(state->ctx);\n}"
    )
    text = text.replace(match.group(0), replacement, 1)
    edits += 1

fips.write_text(text)

print(f"applied {edits} substitutions")
if edits == 0:
    print("(already patched)")
sys.exit(0)
