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

static void print_udp(FILE* fp, const struct cap_header* cp, net_t net, const struct udphdr* udp, unsigned int flags){
	fputs("UDP", fp);
	if ( limited_caplen(cp, udp, sizeof(struct udphdr)) ){
		fprintf(fp, " [Packet size limited during capture]");
		return;
	}

	const size_t header_size = sizeof(struct udphdr);
	const size_t total_size = ntohs(udp->len);
	const size_t payload_size = total_size - header_size;
	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%zd]DATA[%zd])", header_size, payload_size);
	}

	const uint16_t sport = ntohs(udp->source);
	const uint16_t dport = ntohs(udp->dest);

	fprintf(fp, ": %s:%d --> %s:%d",
	        net->net_src, sport,
	        net->net_dst, dport);

	const char* payload = (const char*)udp + header_size;
	if ( sport == PORT_DNS || dport == PORT_DNS ){
		print_dns(fp, cp, payload, payload_size, flags);
	}
}

static enum caputils_protocol_type next_udp(struct header_chunk* header, const char* ptr, const char** out){
	if ( limited_caplen(header->cp, ptr, sizeof(struct udphdr)) ){
		return PROTOCOL_DONE;
	}

	*out = ptr + sizeof(struct udphdr);
	return PROTOCOL_DATA;
}

static void udp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	if ( limited_caplen(header->cp, ptr, sizeof(struct udphdr)) ){
		fprintf(fp, "%s[Packet size limited during capture]", prefix);
		return;
	}

	const struct udphdr* udp = (const struct udphdr*)ptr;
	fprintf(fp, "%ssource:             %d\n", prefix, ntohs(udp->source));
	fprintf(fp, "%sdest:               %d\n", prefix, ntohs(udp->dest));
	fprintf(fp, "%slen:                %d\n", prefix, ntohs(udp->len));
	fprintf(fp, "%scheck:              %d\n", prefix, ntohs(udp->check));
}

static void udp_format(FILE* fp, const struct header_chunk* header, const struct udphdr* udp, const char* ptr, unsigned int flags){
  fputs(": UDP", fp);
  
  const size_t header_size = sizeof(struct udphdr);
  const size_t total_size = ntohs(udp->len);
  const size_t payload_size = total_size - header_size;
  //if ( flags & FORMAT_HEADER ){
    //fprintf(fp, "(HDR[%zd]DATA[%zd])", header_size, payload_size);
  //}
  const uint16_t sport = ntohs(udp->source);
  const uint16_t dport = ntohs(udp->dest);
  fprintf(fp, ": %s:%d --> %s:%d",
	  header->last_net.net_src, sport,
	  header->last_net.net_dst, dport);
  
  fprintf(fp, " len=%d check=%d ", ntohs(udp->len), ntohs(udp->check)); 
}

struct caputils_protocol protocol_udp = {
	.name = "UDP",
	.next_payload = next_udp,
	.format = udp_format,
	.dump = udp_dump,
};
