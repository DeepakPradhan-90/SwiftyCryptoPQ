#include "pqclean_zeroize.h"

#include <string.h>

/* Routing the call through a volatile function pointer means the compiler
 * cannot prove that the store is unobservable, so it cannot elide the memset
 * as a dead store to memory that is about to go out of scope. */
static void *(*const volatile pqclean_memset)(void *, int, size_t) = memset;

void PQCLEAN_zeroize(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
    pqclean_memset(ptr, 0, len);
}
