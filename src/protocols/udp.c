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

static enum caputils_protocol_type udp_next(struct header_chunk* header, const char* ptr, const char** out){
	*out = ptr + sizeof(struct udphdr);

	struct udphdr* myUDP=(struct udphdr*)ptr;
	const uint16_t sport = ntohs(myUDP->source);
	const uint16_t dport = ntohs(myUDP->dest);

	switch(dport) {

	  if(dport == sport){
	  case PORT_GTPu:
	    return PROTOCOL_GTP;

	  case PORT_GTPc:
	    return PROTOCOL_GTP;
	  }
	   /*
	   * To be done..
	   * case PORT_DNS:
	    return PROTOCOL_DNS;

	  */

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
