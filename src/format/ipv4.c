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

void print_ipv4(FILE* fp, const struct cap_header* cp, const struct ip* ip, unsigned int flags){
	if ( limited_caplen(cp, ip, sizeof(struct ip)) ){
		fprintf(fp, " [Packet size limited during capture]");
		return;
	}

	const void* payload = ((const char*)ip) + 4*ip->ip_hl;

	fputs(" IPv4", fp);
	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%d])[", 4*ip->ip_hl);
		fprintf(fp, "Len=%d:",(u_int16_t)ntohs(ip->ip_len));
		fprintf(fp, "ID=%d:",(u_int16_t)ntohs(ip->ip_id));
		fprintf(fp, "TTL=%d:",(u_int8_t)ip->ip_ttl);
		fprintf(fp, "Chk=%d:",(u_int16_t)ntohs(ip->ip_sum));
		if ( ntohs(ip->ip_off) & IP_DF) fprintf(fp, "DF");
		if ( ntohs(ip->ip_off) & IP_MF) fprintf(fp, "MF");
		fprintf(fp, " Tos:%0x]",(u_int8_t)ip->ip_tos);
	}
	fputs(": ", fp);

	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src));
	inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));

	struct network net = {
		.net_src = src,
		.net_dst = dst,
		.plen = ntohs(ip->ip_len) - 4*ip->ip_hl,
	};
	print_ipproto(fp, cp, &net, ip->ip_p, payload, flags);
}
