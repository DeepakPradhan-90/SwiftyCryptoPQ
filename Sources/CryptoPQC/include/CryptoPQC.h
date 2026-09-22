#ifndef CRYPTO_PQC_H
#define CRYPTO_PQC_H

#include <stddef.h>
#include <stdint.h>

#include "compat.h"
#include "fips202.h"
#include "pqclean_zeroize.h"
#include "randombytes.h"
#include "sha2.h"

#ifdef __cplusplus
extern "C" {
#endif

// --- ML-KEM-768 ---
#define CRYPTO_PQC_MLKEM768_SECRETKEYBYTES  2400
#define CRYPTO_PQC_MLKEM768_PUBLICKEYBYTES  1184
#define CRYPTO_PQC_MLKEM768_CIPHERTEXTBYTES 1088
#define CRYPTO_PQC_MLKEM768_BYTES           32

int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// Derandomized variants. `coins` is d || z (64 bytes) for keypair and m (32 bytes) for enc.
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

// --- ML-KEM-1024 ---
#define CRYPTO_PQC_MLKEM1024_SECRETKEYBYTES  3168
#define CRYPTO_PQC_MLKEM1024_PUBLICKEYBYTES  1568
#define CRYPTO_PQC_MLKEM1024_CIPHERTEXTBYTES 1568
#define CRYPTO_PQC_MLKEM1024_BYTES           32

int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

// --- ML-DSA-44 ---
#define CRYPTO_PQC_MLDSA44_PUBLICKEYBYTES 1312
#define CRYPTO_PQC_MLDSA44_SECRETKEYBYTES 2560
#define CRYPTO_PQC_MLDSA44_BYTES 2420

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);

// --- ML-DSA-65 ---
#define CRYPTO_PQC_MLDSA65_PUBLICKEYBYTES 1952
#define CRYPTO_PQC_MLDSA65_SECRETKEYBYTES 4032
#define CRYPTO_PQC_MLDSA65_BYTES 3309

int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);

// --- ML-DSA-87 ---
#define CRYPTO_PQC_MLDSA87_PUBLICKEYBYTES 2592
#define CRYPTO_PQC_MLDSA87_SECRETKEYBYTES 4896
#define CRYPTO_PQC_MLDSA87_BYTES 4627

int PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);

// --- FIPS 202 ---
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_PQC_H
