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
	int finished;

	union {
		struct {
			int src;
			int dst;
			int sport;
			int dport;
		} ip;
	};
};

struct state {
	int seq; /* sequence number of initializing packet */
	struct entry* entry;
	struct state* sibling;

	connection_id_t id;
};

static struct simple_list list = {0,};
static int initialized = 0;
static int counter = 0;

static struct state* entry_put(const struct entry* entry, connection_id_t id){
	/* allocate new entry (key) */
	void* key = malloc(sizeof(struct entry));
	memcpy(key, entry, sizeof(struct entry));

	/* initialize new state */
	struct state* state = slist_put(&list, key);
	memset(state, 0, sizeof(struct state));
	state->entry = key;
	state->id = id;

	return state;
}

static void ipv4_forward(struct entry* entry, const struct ip* ip, int sport, int dport){
	entry->protocol = PROTOCOL_IPV4;
	entry->finished = 0;
	entry->ip.src = ip->ip_src.s_addr;
	entry->ip.dst = ip->ip_dst.s_addr;
	entry->ip.sport = sport;
	entry->ip.dport = dport;
}

static void ipv4_backward(struct entry* entry, const struct ip* ip, int sport, int dport){
	entry->protocol = PROTOCOL_IPV4;
	entry->finished = 0;
	entry->ip.src = ip->ip_dst.s_addr;
	entry->ip.dst = ip->ip_src.s_addr;
	entry->ip.sport = dport;
	entry->ip.dport = sport;
}

static int connection_id_cmp(const void* cur, const void* key){
	return memcmp(cur, key, sizeof(struct entry));
}

static int ipv4_connection_id(const struct cap_header* cp, const struct ip* ip, struct entry entry[2]){
	uint16_t sport = 0;
	uint16_t dport = 0;
	const void* tcp = find_tcp_header(cp->payload, cp->ethhdr, ip, &sport, &dport);
	const void* udp = find_udp_header(cp->payload, cp->ethhdr, ip, &sport, &dport);

	if ( tcp || udp ){
		ipv4_forward (&entry[0], ip, sport, dport);
		ipv4_backward(&entry[1], ip, sport, dport);
		return 1;
	} else {
		return 0;
	}
}

static struct state* connection_id_tcp_syn(const struct cap_header* cp, struct state* state){
	const struct ip* ip = find_ipv4_header(cp->ethhdr, NULL);
	if ( !ip ) return state;

	const struct tcphdr* tcp = find_tcp_header(cp->payload, cp->ethhdr, ip, NULL, NULL);
	if ( !(tcp && tcp->syn && !tcp->ack) ) return state;

	/* state changes already made by this packet, dont redo it */
	if ( state->seq == (int)tcp->seq ){
		return state;
	}

	/* new SYN detected, assume new connection */
	const connection_id_t id = ++counter;
	struct state* new[2] = {
		entry_put(state->entry, id),
		entry_put(state->sibling->entry, id),
	};

	/* setup new connection */
	for ( unsigned int i = 0; i < 2; i++ ){
		new[i]->seq = tcp->seq;
		new[i]->sibling = new[1-i];
	}

	/* close the old connection */
	state->entry->finished = 1;
	state->sibling->entry->finished = 1;

	return new[0];
}

static connection_id_t connection_id_search(const struct cap_header* cp, struct entry entry[2]){
	/* search both forward and backward entries for existing connection */
	struct state* state = slist_find(&list, &entry[0], connection_id_cmp);
	if ( state ){
		state = connection_id_tcp_syn(cp, state);
		return state->id;
	}

	const int id = ++counter;

	/* create new entry for this connection */
	struct state* new[2] = {0,};
	for ( unsigned int i = 0; i < 2; i++ ){
		new[i] = entry_put(&entry[i], id);

		/* try to get a sequence number */
		const struct ip* ip = find_ipv4_header(cp->ethhdr, NULL);
		const struct tcphdr* tcp = find_tcp_header(cp->payload, cp->ethhdr, ip, NULL, NULL);
		new[i]->seq = tcp ? tcp->seq : 0;
	}

	/* set siblings for connection closing and new handshakes */
	for ( unsigned int i = 0; i < 2; i++ ){
		new[i]->sibling = new[1-i];
	}

	return id;
}

connection_id_t connection_id(const struct cap_header* cp){
	if ( !initialized ){
		slist_init(&list, sizeof(void*), sizeof(struct state), 32);
		initialized = 1;
	}

	struct entry entry[2];

	/* IPv4 */
	const struct ip* ip = find_ipv4_header(cp->ethhdr, NULL);
	if ( ip && ipv4_connection_id(cp, ip, entry) ){
		return connection_id_search(cp, entry);
	}

	return CONNECTION_ID_NONE;
}
