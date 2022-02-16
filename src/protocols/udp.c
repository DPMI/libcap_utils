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

enum {
	PORT_GTPu = 2152,
	PORT_GTPc = 2123,
	PORT_PTPv2= 319,
};

static enum caputils_protocol_type udp_next(struct header_chunk* header, const char* ptr, const char** out){
	const struct udphdr* udp = (const struct udphdr*)ptr;
	*out = ptr + sizeof(struct udphdr);

	const uint16_t sport = ntohs(udp->source);
	const uint16_t dport = ntohs(udp->dest);

	if ( sport == PORT_DNS || dport == PORT_DNS ){
		return PROTOCOL_DNS;
	}

	
	if ( sport == PORT_CP || dport == PORT_CP ){
		return PROTOCOL_CP;
	}

	if ( sport == PORT_TG || dport == PORT_TG ){
		return PROTOCOL_TG;
	}

	if ( sport == PORT_MARKER || dport == PORT_MARKER ){
	  return PROTOCOL_MARKER;
	}

	
	switch(dport) {
	  
	case PORT_GTPu:
	case PORT_GTPc:
	  if(dport == sport){
	    return PROTOCOL_GTP;
	    break;
	  }

	case PORT_PTPv2:
		return PROTOCOL_PTPv2;

	default:
		return PROTOCOL_DATA;
	}

	return PROTOCOL_DATA;
}

static void udp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	const struct udphdr* udp = (const struct udphdr*)ptr;
	fprintf(fp, "%ssource:             %d\n", prefix, ntohs(udp->source));
	fprintf(fp, "%sdest:               %d\n", prefix, ntohs(udp->dest));
	fprintf(fp, "%slen:                %d\n", prefix, ntohs(udp->len));
	fprintf(fp, "%scheck:              %d\n", prefix, ntohs(udp->check));
}

static void udp_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	const struct udphdr* udp = (const struct udphdr*)ptr;
  fputs(": UDP", fp);

  const uint16_t sport = ntohs(udp->source);
  const uint16_t dport = ntohs(udp->dest);
  fprintf(fp, ": %s:%d --> %s:%d",
	  header->last_net.net_src, sport,
	  header->last_net.net_dst, dport);

  fprintf(fp, " len=%d check=%d ", ntohs(udp->len), ntohs(udp->check));
}

struct caputils_protocol protocol_udp = {
	.name = "UDP",
	.size = sizeof(struct udphdr),
	.next_payload = udp_next,
	.format = udp_format,
	.dump = udp_dump,
};
