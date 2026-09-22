// Secure random provider using Apple's SecRandomCopyBytes
#include "randombytes.h"
#include <Security/SecRandom.h>
#include <stddef.h>
#include <stdlib.h>

int randombytes(uint8_t *output, size_t n) {
    if (SecRandomCopyBytes(kSecRandomDefault, n, output) == errSecSuccess) {
        return 0;
    }
    // PQClean's callers discard this return value, so a soft failure would let
    // key generation proceed over uninitialized memory. Refuse to continue.
    abort();
}
