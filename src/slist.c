#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "slist.h"
#include <stdlib.h>
#include <string.h>

#ifndef NVALGRIND
#include <valgrind/memcheck.h>
#endif

#ifndef NVALGRIND
static const size_t gutter = 4;
#else
static const size_t gutter = 0;
#endif

void slist_init(struct simple_list* slist, size_t key_size, size_t element_size, size_t initial_size){
	slist->key   = NULL;
	slist->value = NULL;
	slist->size = 0;
	slist->capacity = 0;
	slist->key_size = key_size;
	slist->element_size = element_size;
	slist_alloc(slist, initial_size);

#ifndef NVALGRIND
	VALGRIND_CREATE_MEMPOOL(slist->value, 0, 0);
#endif
}

void slist_alloc(struct simple_list* slist, size_t growth){
	const size_t delta = slist->element_size + gutter;
	slist->capacity += growth;
	slist->key   = realloc(slist->key,   slist->key_size * slist->capacity);
	slist->value = realloc(slist->value, delta * slist->capacity);

#ifndef NVALGRIND
	VALGRIND_MAKE_MEM_NOACCESS(slist->value, delta * slist->capacity);
#endif
}

void slist_clear(struct simple_list* slist){
	for ( unsigned int i = 0; i < slist->size; i++ ){
		free(slist->key[i]);
	}
	slist->size = 0;
}

void slist_free(struct simple_list* slist){
#ifndef NVALGRIND
	VALGRIND_DESTROY_MEMPOOL(slist->value);
#endif

	slist_clear(slist);
	free(slist->key);
	free(slist->value);
	slist->capacity = 0;
}

void* slist_get(const struct simple_list* slist, unsigned int index){
	const size_t delta = slist->element_size + gutter;
	const size_t offset = delta * index;
	return ((char *)slist->value) + offset;
}

void* slist_find(const struct simple_list* slist, const void* key, slist_cmp cmp){
	for ( unsigned int i = 0; i < slist->size; i++ ){
		if ( cmp(slist->key[i], key) == 0 ){
			return slist_get(slist, i);
		}
	}
	return NULL;
}

void* slist_put(struct simple_list* slist, void* key){
	if ( slist->size == slist->capacity ){
		slist_alloc(slist, /* growth = */ slist->capacity);
	}

	unsigned int index = slist->size;
	slist->key[index] = key;
	slist->size++;
	void* ptr = slist_get(slist, index);

#ifndef NVALGRIND
	VALGRIND_MEMPOOL_ALLOC(slist->value, ptr, slist->element_size);
#endif

	return ptr;
}

int slist_strcmp(const void* cur, const void* key){
	return strcmp((const char*)cur, (const char*)key);
}
