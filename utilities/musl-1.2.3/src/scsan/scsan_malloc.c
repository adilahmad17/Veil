#include <stddef.h>

#define NO_MALLOC_STATS 1
#define USE_LOCKS 1
#define HAVE_MMAP 0
#define HAVE_MREMAP 0
#define MSPACES 1
#define ONLY_MSPACES 1
#define USE_DL_PREFIX 1
#define MORECORE_CANNOT_TRIM 1
#define LACKS_TIME_H
#define LACKS_SCHED_H
#include "dlmalloc.h"

void *msp;

void *scsan_malloc(size_t size) {
    return mspace_malloc(msp, size);
}

void *scsan_realloc(void *ptr, size_t size) {
    return mspace_realloc(msp, ptr, size);
}

void scsan_free(void *ptr) {
    mspace_free(msp, ptr);
}

// void *aligned_alloc(size_t align, size_t size) {
//     return mspace_memalign(msp, align, size);
// }

void scsan_malloc_init(void *base, size_t size) {
    msp = create_mspace_with_base(base, size, 1);
}