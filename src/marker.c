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

#include "caputils/marker.h"
#include "caputils/packet.h"
#include "caputils_int.h"
#include <netinet/udp.h>

#ifndef HAVE_BE64TOH
#include "be64toh.h"
#endif

int is_marker(const struct cap_header* cp, struct marker* ptr, int port){
	/* match ip packet */
	const struct ip* ip = find_ipv4_header(cp->ethhdr, NULL);
	if ( !ip ){ return 0; }

	/* match udp packet */
	uint16_t src, dst;
	const struct udphdr* udp = find_udp_header(cp->payload, cp->ethhdr, ip, &src, &dst);
	if ( !(udp && src == MARKERPORT && (dst == port || port == 0)) ){ return 0; }

	/* match magic */
	const struct marker* marker = (const struct marker*)((const char*)udp + sizeof(struct udphdr));
	if ( ntohl(marker->magic) != MARKER_MAGIC ){ return 0; }

	/* assume it is a marker */
	if ( ptr ){
		ptr->magic = ntohl(marker->magic);
		ptr->version = marker->version;
		ptr->flags = marker->flags;
		ptr->reserved = ntohs(marker->reserved);
		ptr->exp_id = ntohl(marker->exp_id);
		ptr->run_id = ntohl(marker->run_id);
		ptr->key_id = ntohl(marker->key_id);
		ptr->seq_num = ntohl(marker->seq_num);
		ptr->timestamp = be64toh(marker->timestamp);
	}

	return dst;
}
