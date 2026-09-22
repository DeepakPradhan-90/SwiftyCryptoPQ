# Local modifications to vendored PQClean

The sources under `Sources/CryptoPQC/ml-kem-*` and `Sources/CryptoPQC/ml-dsa-*`, plus
`common/fips202.c` and `common/sha2.c`, are vendored from
[PQClean](https://github.com/PQClean/PQClean) and are otherwise unmodified.

## Secret scrubbing

Upstream PQClean does not clear its stack buffers. Every call therefore leaves secret
material resident after returning: seeds and sampled coins, the secret key and error
polynomial vectors, the decrypted message, and the derived shared secret. On the ML-DSA side
the heap-allocated Keccak sponge state is `free()`d without being cleared, and by that point
it has absorbed the secret key.

`patches/apply_zeroize.py` inserts `PQCLEAN_zeroize()` calls at the points where those locals
die. `PQCLEAN_zeroize` is defined in `common/pqclean_zeroize.c` and routes `memset` through a
volatile function pointer so the compiler cannot discard it as a dead store.

The patched locations are:

| File | Scrubbed |
| --- | --- |
| `ml-kem-*/kem.c` | `coins`, `buf` (message and `H(pk)`), `kr` (shared secret and coins), `cmp` |
| `ml-kem-*/indcpa.c` | `buf`, `skpv`, `e`, `sp`, `ep`, `epp`, `k` (message polynomial), `mp` |
| `ml-dsa-*/sign.c` | `seedbuf` (rho, tr, key, mu, rhoprime, rnd), `s1`, `s1hat`, `s2`, `t0`, `y`, `w0`, `cp` |
| `common/fips202.c` | Keccak sponge state, cleared before `free()` in every `*_ctx_release` |

### Re-applying after a PQClean update

Run the script from the repository root:

    python3 patches/apply_zeroize.py

It is idempotent, and it asserts on every substitution rather than patching silently, so an
upstream change that moves any of these code sites will make it fail with the pattern it could
not find. Fix the pattern, re-run, and confirm the known-answer tests still pass with
`swift test`.

### Limitations

This reduces residue; it does not eliminate it. The compiler may still spill intermediate
values to registers or to stack slots that no `memset` can reach, and neither this nor any
source-level measure protects against an attacker with live access to the process. See the
threat model notes in the main README.
