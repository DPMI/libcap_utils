#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/packet.h"
#include "caputils/caputils.h"
#include "src/format/format.h"
#include "src/slist.h"
#include <string.h>

#include <netinet/ip.h>

struct entry {
	enum caputils_protocol_type protocol;

	union {
		struct {
			int src;
			int dst;
			int sport;
			int dport;
		} ip;
	};
};

static struct simple_list list = {0,};
static int initialized = 0;
static int counter = 0;

static void ipv4_forward(struct entry* entry, const struct ip* ip, int sport, int dport){
	entry->protocol = PROTOCOL_IPV4;
	entry->ip.src = ip->ip_src.s_addr;
	entry->ip.dst = ip->ip_dst.s_addr;
	entry->ip.sport = sport;
	entry->ip.dport = dport;
}

static void ipv4_backward(struct entry* entry, const struct ip* ip, int sport, int dport){
	entry->protocol = PROTOCOL_IPV4;
	entry->ip.src = ip->ip_dst.s_addr;
	entry->ip.dst = ip->ip_src.s_addr;
	entry->ip.sport = dport;
	entry->ip.dport = sport;
}

static int stream_id_cmp(const void* cur, const void* key){
	return memcmp(cur, key, sizeof(struct entry));
}

static void ipv4_stream_id(const struct cap_header* cp, const struct ip* ip, struct entry entry[2]){
	uint16_t sport;
	uint16_t dport;
	find_tcp_header(cp->payload, cp->ethhdr, ip, &sport, &dport);
	find_udp_header(cp->payload, cp->ethhdr, ip, &sport, &dport);
	ipv4_forward (&entry[0], ip, sport, dport);
	ipv4_backward(&entry[1], ip, sport, dport);
}

static stream_id_t stream_id_search(struct entry entry[2]){
	int* id = NULL;

	/* search both forward and backward entries for existing connection */
	for ( unsigned int i = 0; i < 2; i++ ){
		id = slist_find(&list, &entry[i], stream_id_cmp);
		if ( id ) return *id;
	}

	/* create new entry for this connection */
	void* key = malloc(sizeof(struct entry));
	memcpy(key, &entry[0], sizeof(struct entry));
	id = slist_put(&list, key);
	*id = ++counter;
	return *id;
}

stream_id_t stream_id(const struct cap_header* cp){
	if ( !initialized ){
		slist_init(&list, sizeof(void*), sizeof(int), 32);
		initialized = 1;
	}

	struct entry entry[2];

	/* IPv4 */
	const struct ip* ip = find_ipv4_header(cp->ethhdr, NULL);
	if ( ip ){
		ipv4_stream_id(cp, ip, entry);
		return stream_id_search(entry);
	}

	return STREAM_ID_NONE;
}
