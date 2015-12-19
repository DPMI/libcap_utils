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

#include "src/format/format.h"
#include "caputils/log.h"
#include <stdio.h>
#include <arpa/inet.h>

#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

#ifndef HAVE_IP6_EXT
struct ip6_ext {
	uint8_t  ip6e_nxt;          /* next header.  */
	uint8_t  ip6e_len;          /* length in units of 8 octets.  */
};
#endif

#ifdef HAVE_IPV6

static int is_ipv6_ext(uint8_t nxt){
	switch (nxt){
	case IPPROTO_HOPOPTS:
		return 1;
	default:
		return 0;
	}
}

static size_t ipv6_total_header_size(const struct cap_header* cp, const struct ip6_hdr* ip, const char** ptr, uint8_t* proto){
	size_t header_size = sizeof(struct ip6_hdr);
	if ( limited_caplen(cp, cp->payload, sizeof(struct ip6_hdr)) ){
		return 0;
	}

	*ptr = NULL;
	*proto = 0;

	if ( !is_ipv6_ext(ip->ip6_nxt) ){
		*ptr = (const char*)ip + header_size;
		*proto = ip->ip6_nxt;
		return header_size;
	}

	const char* payload = (const char*)ip + header_size;
	const struct ip6_ext* ext = NULL;
	do {
		if ( limited_caplen(cp, payload, sizeof(struct ip6_ext)) ){
			return header_size;
		}

		ext = (const struct ip6_ext*)payload;
		const size_t cur_size = ntohs(ext->ip6e_len) * 8 + 8;
		if ( limited_caplen(cp, payload, cur_size) ){
			return header_size;
		}

		header_size += cur_size;
		payload += cur_size;
	} while ( is_ipv6_ext(ext->ip6e_nxt) );

	*ptr = payload;
	*proto = ext->ip6e_nxt;
	return header_size;
}

extern enum caputils_protocol_type ipproto_next(uint8_t proto);

static enum caputils_protocol_type ipv6_next(struct header_chunk* header, const char* ptr, const char** out){
	uint8_t proto = 0;
	const char* payload = NULL;
	const struct ip6_hdr* ip = (const struct ip6_hdr*)ptr;
	const size_t header_size = ipv6_total_header_size(header->cp, ip, &payload, &proto);

	/* could not determine the header size or limited caplen */
	if ( !payload ){
		*out = NULL;
		return PROTOCOL_DONE;
	}

	inet_ntop(AF_INET6, &ip->ip6_src, header->last_net.net_src, sizeof(header->last_net.net_src));
	inet_ntop(AF_INET6, &ip->ip6_dst, header->last_net.net_dst, sizeof(header->last_net.net_dst));
	header->last_net.plen = ip->ip6_plen + sizeof(struct ip6_hdr) - header_size;

	*out = payload;
	return ipproto_next(proto);
}

static void ipv6_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	const struct ip6_hdr* ip = (const struct ip6_hdr*)ptr;
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ip->ip6_src, src, sizeof(src));
	inet_ntop(AF_INET6, &ip->ip6_dst, dst, sizeof(dst));

	fprintf(fp, "%sip6_vfc:            %d\n", prefix, ip->ip6_vfc);
	fprintf(fp, "%sip6_flow:           0x%04x\n", prefix, ntohl(ip->ip6_flow));
	fprintf(fp, "%sip6_plen:           %d octets\n", prefix, ntohs(ip->ip6_plen));
	fprintf(fp, "%sip6_nxt             %d\n", prefix, ip->ip6_nxt);
	fprintf(fp, "%sip6_hops:           %d\n", prefix, ip->ip6_hops);
	fprintf(fp, "%sip6_src:            %s\n", prefix, src);
	fprintf(fp, "%sip6_dst:            %s\n", prefix, dst);

	/** @todo extension headers */
}


static void ipv6_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	const struct ip6_hdr* ip = (const struct ip6_hdr*)ptr;
	const char*  payload = NULL;
	uint8_t proto = 0;
	const size_t header_size = ipv6_total_header_size(header->cp, ip, &payload, &proto);
	fputs(" IPv6", fp);
	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%zd])[plen=%d,hops=%d]", header_size, ntohs(ip->ip6_plen), ip->ip6_hops);
	}

	if ( ipproto_next(proto) == PROTOCOL_DATA ){
		fprintf(fp, " [ip6_next=0x%02x]", proto);
	}
}

#else /* HAVE_IPV6 */


static enum caputils_protocol_type ipv6_next(struct header_chunk* header, const char* ptr, const char** out){
	return PROTOCOL_DATA;
}

static void ipv6_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	/* not implemented */
}

#endif /* HAVE_IPV6 */

struct caputils_protocol protocol_ipv6 = {
	.name = "IPv6",
	.size = sizeof(struct ip),
	.partial_print = 0,
	.next_payload = ipv6_next,
	.format = ipv6_format,
	.dump = ipv6_dump,
};
