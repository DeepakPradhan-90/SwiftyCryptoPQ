#ifndef PQCLEAN_ZEROIZE_H
#define PQCLEAN_ZEROIZE_H

#include <stddef.h>

/* Overwrites `len` bytes at `ptr` with zeros in a way the optimizer may not
 * discard, even when the storage is dead immediately afterwards.
 *
 * Upstream PQClean does not scrub its stack buffers, so this is used by the
 * local patches described in patches/README.md. */
void PQCLEAN_zeroize(void *ptr, size_t len);

#endif /* PQCLEAN_ZEROIZE_H */
