/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2013 (see AUTHORS)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/packet.h"
#include "caputils/caputils.h"
#include "src/format/format.h"

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

/* sanity check: should not happen because the previous protocol should flag as truncated or otherwise deal with it */
static void ptr_sanity(const cap_head* cp, const char* ptr, const struct caputils_protocol* proto){
	const char* begin = cp->payload;
	const char* end   = cp->payload + cp->caplen;
	if ( !ptr || ptr < begin || ptr > end ){
		fprintf(stderr,
		        "\n\n"
		        "invalid payload pointer\n"
		        "  ptr: %p\n"
		        "  packet: %p - %p (%zd bytes)\n"
		        "  offset: %zd bytes (from beginning of packet)\n"
		        "  protocol: %s\n"
		        "this is an error in the protocol decoder (but the packet is probably corrupted)\n"
		        "\n",
		        ptr, begin, end, end - begin, ptr - begin,
		        proto ? proto->name : "N/A");
		abort();
	}
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

size_t layer_size(enum Level level, const cap_head* caphead){
	/* layer size at physical is not supported, traces does not include necessary data */
	if ( level == LEVEL_INVALID || level == LEVEL_PHYSICAL ){
		return 0;
	}

	const enum Level q = (enum Level)((int)level - 1);
	return payload_size(q, caphead);
}

static int find_ipv4_header_int(const struct ethhdr* ether, int* ptr){
	const char* const ref = (const char*)ether;
	const char* cur = ref + sizeof(struct ethhdr);
	uint16_t proto = ntohs(ether->h_proto);

	retry:
	switch ( proto ){
	case ETHERTYPE_IP:
		break;

	case ETHERTYPE_VLAN:
	{
		/* Packet contains a VLAN tag */
		cur += 2;
		proto = ntohs(*((const uint16_t*)cur));
		cur += 2;
		goto retry;
	}

	default:
		/* Not an IPv4 packet */
		if ( ptr ) *ptr = -1;
		return -1;
	}

	const int offset = cur-ref;
	const struct ip* ip = (const struct ip*)cur;
	if ( ptr ){
		const size_t hl = 4*ip->ip_hl;
		*ptr = offset + hl;
	}
	return offset;
}

const struct ip* find_ipv4_header(const struct ethhdr* ether, const char** ptr){
	int payload;
	const char* ref = (const char*)ether;
	const int offset = find_ipv4_header_int(ether, &payload);
	if ( offset == -1 ){
		if ( ptr ) *ptr = NULL;
		return NULL;
	}

	if ( ptr ) *ptr = ref + payload;
	return (const struct ip*)(ref + offset);
}

struct ip* find_ipv4_headerRW(struct ethhdr* ether, char** ptr){
	int payload;
	char* ref = (char*)ether;
	const int offset = find_ipv4_header_int(ether, &payload);
	if ( offset == -1 ){
		if ( ptr ) *ptr = NULL;
		return NULL;
	}

	if ( ptr ) *ptr = ref + payload;
	return (struct ip*)(ref + offset);
}

static int next_payload(struct header_chunk* header){
	/* stop processing if protocol doesn't define next_payload */
	if ( !header->protocol->next_payload ){
		return 0;
	}

	/* stop if previous header was truncated */
	if ( header->truncated ){
		return 0;
	}

	const char* next = header->ptr;
	const struct caputils_protocol* current = header->protocol;
	enum caputils_protocol_type type = current->next_payload(header, header->ptr, &next);

	header->ptr = next;
	header->protocol = protocol_get(type);
	if ( !header->protocol ){
		fprintf(stderr, "invalid protocol type %d, make sure protocol is registerd\n", type);
		abort();
	}

	/* validate payload pointer */
	if ( (header->ptr == NULL && type == PROTOCOL_DONE) || limited_caplen(header->cp, header->ptr, 0) ){
		header->ptr = NULL;
		header->truncated = 1;
		return 0;
	}

	/* make sure pointer is actually inside the captured packet (and not pointing at random data because of a corrupted packet) */
	ptr_sanity(header->cp, header->ptr, current);

	/* ensure there is enough data left */
	if ( limited_caplen(header->cp, header->ptr, header_size(header)) ){
		header->truncated = 1;
	}

	return
		type != PROTOCOL_UNKNOWN &&
		type != PROTOCOL_DONE;
}

void header_init(struct header_chunk* header, const struct cap_header* cp, int layer){
	header->cp = cp;
	header->protocol = NULL;
	header->last_net = (struct network){"", "", 0};
	header->truncated = 0;
	header->ptr = NULL;
}

int header_walk(struct header_chunk* header){
	if ( !header->ptr ){
		header->protocol = protocol_get(PROTOCOL_ETHERNET);
		header->ptr = header->cp->payload;

		if ( limited_caplen(header->cp, header->ptr, header_size(header)) ){
			header->truncated = 1;
		}

		return 1;
	}

	return next_payload(header);
}

void header_dump(FILE* fp, const struct header_chunk* header, const char* prefix){
	if ( !header->protocol->dump ){
		fprintf(fp, "%s(not implemented)\n", prefix);
		return;
	}

	if ( header->truncated && !header->protocol->partial_print ){
		fprintf(fp, "%s[Packet size limited during capture]\n", prefix);
		return;
	}


	ptr_sanity(header->cp, header->ptr, NULL);
	header->protocol->dump(fp, header, header->ptr, prefix, 0);
}

void header_format(FILE* fp, const struct header_chunk* header, int flags){
	if ( header->truncated && !header->protocol->partial_print ){
		fprintf(fp, ": %s [Packet size limited during capture]", header->protocol->name);
		return;
	}

	if ( !header->protocol->format ){
		fprintf(fp, ": %s", header->protocol->name);
		return;
	}

	ptr_sanity(header->cp, header->ptr, NULL);
	header->protocol->format(fp, header, header->ptr, flags);
}

size_t header_size(const struct header_chunk* header){
	return header->protocol->size_dyn ? header->protocol->size_dyn(header, header->ptr) : header->protocol->size;
}

stream_id_t stream_id(const struct cap_header* cp){
	return STREAM_ID_NONE;
}
