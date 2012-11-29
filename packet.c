#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/packet.h"
#include "caputils/caputils.h"

#include <stdio.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

enum Level level_from_string(const char* str){
	struct entry { const char* name; enum Level level; };
	static const struct entry lut[] = {
		{"physical",    LEVEL_PHYSICAL},
		{"link",        LEVEL_LINK},
		{"network",     LEVEL_NETWORK},
		{"transport",   LEVEL_TRANSPORT},
		{"application", LEVEL_APPLICATION},
		{0, (enum Level)0} /* sentinel */
	};

	const struct entry* cur = lut;
	while ( cur->name ){
		if ( strcasecmp(cur->name, str) == 0 ){
			return cur->level;
		}
		cur++;
	}

	return LEVEL_INVALID;
}

static size_t payload_tcp(enum Level level, const struct ip* ip, const struct tcphdr* tcp){
	if ( level == LEVEL_TRANSPORT ){
		return ntohs(ip->ip_len) - 4*tcp->doff - 4*ip->ip_hl;
	}

	return 0; /* application layer not supported yet */
}

static size_t payload_udp(enum Level level, const struct udphdr* udp){
	if ( level == LEVEL_TRANSPORT ){
		return ntohs(udp->len) - sizeof(struct udphdr);
	}

	return 0; /* application layer not supported yet */
}

static size_t payload_ip(enum Level level, const struct ip* ip){
	const size_t hl = 4*ip->ip_hl;
	const char* payload = (const char*)ip + hl;
	if ( level == LEVEL_NETWORK ) {
		return ntohs(ip->ip_len) - hl;
	}

	switch ( ip->ip_p ) {
	case IPPROTO_TCP:
		return payload_tcp(level, ip, (const struct tcphdr*)payload);

	case IPPROTO_UDP:
		return payload_udp(level, (const struct udphdr*)payload);

	default:
		fprintf(stderr, "Unknown IP transport protocol: %d\n", ip->ip_p);
		return 0; /* there is no way to know the actual payload size here */
	}
}

static size_t payload_network(enum Level level, const struct ethhdr* ether){
	switch(ntohs(ether->h_proto)) {
	case ETHERTYPE_IP:/* Packet contains an IP, PASS TWO! */
		return payload_ip(level, (const struct ip*)((const char*)ether + sizeof(struct ethhdr)));

	case ETHERTYPE_VLAN:
		return payload_ip(level, (const struct ip*)((const char*)ether + sizeof(struct ether_vlan_header)));

	case ETHERTYPE_IPV6:
		fprintf(stderr, "IPv6 not handled, ignored\n");
		return 0;

	case ETHERTYPE_ARP:
		fprintf(stderr, "ARP not handled, ignored\n");
		return 0;

	case STPBRIDGES:
		fprintf(stderr, "STP not handled, ignored\n");
		return 0;

	case CDPVTP:
		fprintf(stderr, "CDPVTP not handled, ignored\n");
		return 0;

	default:      /* Packet contains unknown link . */
		fprintf(stderr, "Unknown ETHERTYPE 0x%0x \n", ntohs(ether->h_proto));
		return 0; /* there is no way to know the actual payload size here, a zero will ignore it in the calculation */
	}
}

size_t payload_size(enum Level level, const cap_head* caphead){
	switch ( level ){
	case LEVEL_INVALID: return 0;
	case LEVEL_PHYSICAL: return caphead->len;
	case LEVEL_LINK: return caphead->len - sizeof(struct ethhdr);
	default: return payload_network(level, caphead->ethhdr);
	}
}
