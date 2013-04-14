#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/marc_dstat.h"

const struct MPDStatHdr* mp_dstat_next(const struct MPDStatHdr* cur){
	if ( ntohs(cur->type) == MP_DSTAT_TRAILER ) return NULL;
	return (const struct MPDStatHdr*)((const char*)cur + ntohs(cur->length));
}

struct MPDStatHdr* mp_dstat_nextw(struct MPDStatHdr* cur){
	if ( ntohs(cur->type) == MP_DSTAT_TRAILER ) return NULL;
	return (struct MPDStatHdr*)((char*)cur + ntohs(cur->length));
}

size_t mp_dstat_size(const struct MPDStat* event){
	size_t bytes = sizeof(struct MPDStat);
	const struct MPDStatHdr* cur = event->next;
	while ( cur ){
		bytes += ntohs(cur->length);
		cur = mp_dstat_next(cur);
	}
	return bytes + sizeof(struct MPDStatHdr); /* accumulated size + trailer */
}
