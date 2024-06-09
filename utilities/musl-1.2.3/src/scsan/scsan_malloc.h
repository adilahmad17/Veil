#include <stddef.h>

void *scsan_malloc(size_t size);

void *scsan_realloc(void *ptr, size_t size);

void scsan_free(void *ptr);

void scsan_malloc_init(void *base, size_t size);