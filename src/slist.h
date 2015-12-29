#ifndef SLIST_H
#define SLIST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/**
 * Array-backed key-value storage.
 *
 * Insertion is O(1)
 * Lookup by index is O(1)
 * Lookup by key is O(N)
 *
 * Usable for small-ish datasets only.
 */

struct simple_list {
	void** key;
	char* value;

	size_t size;         /* slots in use */
	size_t capacity;     /* slots available */
	size_t key_size;     /* sizeof(key) */
	size_t element_size; /* sizeof(value) */
};

typedef int (*slist_cmp)(const void* cur, const void* key);

void slist_init(struct simple_list* slist, size_t key_size, size_t element_size, size_t initial_size);

void slist_alloc(struct simple_list* slist, size_t growth);

void slist_clear(struct simple_list* slist);

void slist_free(struct simple_list* slist);

/**
 * Lookup element by index.
 * Indices may change during modifications of the array.
 */
void* slist_get(const struct simple_list* slist, unsigned int index);

/**
 * Lookup element by key.
 */
void* slist_find(const struct simple_list* slist, const void* key, slist_cmp cmp);

/**
 * Insert new element.
 */
void* slist_put(struct simple_list* slist, void* key);

/**
 * Adapter for strcmp.
 */
int slist_strcmp(const void* cur, const void* key);

#ifdef __cplusplus
}
#endif

#endif /* SLIST_H */
