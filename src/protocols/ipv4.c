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

extern enum caputils_protocol_type ipproto_next(uint8_t proto);

static enum caputils_protocol_type ipv4_next(struct header_chunk* header, const char* ptr, const char** out){
	const struct ip* ip = (const struct ip*)ptr;
	const void* payload = ptr + 4*ip->ip_hl;

	/* validate caplen */
	if ( limited_caplen(header->cp, payload, 0) ){
		*out = NULL;
		return PROTOCOL_DONE;
	}

	inet_ntop(AF_INET, &ip->ip_src, header->last_net.net_src, sizeof(header->last_net.net_src));
	inet_ntop(AF_INET, &ip->ip_dst, header->last_net.net_dst, sizeof(header->last_net.net_dst));
	header->last_net.plen = ntohs(ip->ip_len) - 4*ip->ip_hl;

	*out = payload;
	return ipproto_next(ip->ip_p);
}

static void ipv4_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	fprintf(fp, ": %s", header->protocol->name);

	const struct ip* ip = (const struct ip*)ptr;
	if ( ipproto_next(ip->ip_p) == PROTOCOL_DATA ){
		fprintf(fp, " [ip_p=0x%02x]", ip->ip_p);
	}
}

static void ipv4_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	const struct ip* ip = (const struct ip*)ptr;
	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src));
	inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));

	fprintf(fp, "%sip_v:               %d\n", prefix, ip->ip_v);
	fprintf(fp, "%sip_hl:              %d (%d octets)\n", prefix, ip->ip_hl, 4*ip->ip_hl);
	fprintf(fp, "%sip_tos:             %d\n", prefix, ip->ip_tos);
	fprintf(fp, "%sip_len:             %d\n", prefix, ntohs(ip->ip_len));
	fprintf(fp, "%sip_id:              %d\n", prefix, ntohs(ip->ip_id));
	fprintf(fp, "%sip_off:             0x%04d\n", prefix, ntohs(ip->ip_off));
	fprintf(fp, "%s  RF:               %s\n", prefix, (ntohs(ip->ip_off) & IP_RF) ? "yes" : "no");
	fprintf(fp, "%s  DF:               %s\n", prefix, (ntohs(ip->ip_off) & IP_DF) ? "yes" : "no");
	fprintf(fp, "%s  MF:               %s\n", prefix, (ntohs(ip->ip_off) & IP_MF) ? "yes" : "no");
	fprintf(fp, "%s  bits:             0x%04x\n", prefix, ntohs(ip->ip_off) & IP_OFFMASK);
	fprintf(fp, "%sip_ttl:             %d\n", prefix, ip->ip_ttl);
	fprintf(fp, "%sip_p:               %d\n", prefix, ip->ip_p);
	fprintf(fp, "%sip_sum:             %d\n", prefix, ntohs(ip->ip_sum));
	fprintf(fp, "%sip_src:             %s\n", prefix, src);
	fprintf(fp, "%sip_dst:             %s\n", prefix, dst);

	/** @todo option headers */
}

struct caputils_protocol protocol_ipv4 = {
	.name = "IPv4",
	.size = sizeof(struct ip),
	.next_payload = ipv4_next,
	.format = ipv4_format,
	.dump = ipv4_dump,
};
