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

#include "format.h"
#include "caputils/log.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>

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
			return sizeof(struct ip6_hdr);
		}

		ext = (const struct ip6_ext*)payload;
		const size_t cur_size = ntohs(ext->ip6e_len) * 8 + 8;
		header_size += cur_size;
		payload += cur_size;
	} while ( is_ipv6_ext(ext->ip6e_nxt) );

	*ptr = payload;
	*proto = ext->ip6e_nxt;
	return header_size;
}

void print_ipv6(FILE* fp, const struct cap_header* cp, const struct ip6_hdr* ip, unsigned int flags){
	const char* payload;
	uint8_t proto;
	const size_t header_size = ipv6_total_header_size(cp, ip, &payload, &proto);

	if ( header_size == 0 ){
		fprintf(fp, " [Packet size limited during capture]");
		return;
	}

	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%zd])[plen=%d,hops=%d]",
		        header_size, ntohs(ip->ip6_plen), ip->ip6_hops);
	}
	fputs(": ", fp);

	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ip->ip6_src, src, sizeof(src));
	inet_ntop(AF_INET6, &ip->ip6_dst, dst, sizeof(dst));

	if ( !payload ){
		fprintf(fp, " [Packet size limited during capture]");
		return;
	}

	struct network net = {
		.net_src = src,
		.net_dst = dst,
		.plen = ip->ip6_plen + sizeof(struct ip6_hdr) - header_size,
	};
	print_ipproto(fp, cp, &net, proto, payload, flags);
}
