/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2014 (see AUTHORS)
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

#include "caputils/protocol.h"

#define REGISTER_PROTOCOL(x,y) \
	do { \
		if ( protocol_get(y) != NULL ){ \
			fprintf(stderr, "duplicate entry for " #y "\n"); \
			abort(); \
		} \
		extern struct caputils_protocol x; \
		protocol[y] = &x; \
	} while (0)

static struct caputils_protocol* protocol[PROTOCOL_NUM_AVAILABLE] = {0,};

struct caputils_protocol* protocol_get(enum caputils_protocol_type type){
	return protocol[type];
}

static void __attribute__((constructor)) protocol_init(void){
	REGISTER_PROTOCOL(protocol_data, PROTOCOL_DATA);
	REGISTER_PROTOCOL(protocol_done, PROTOCOL_DONE);

	REGISTER_PROTOCOL(protocol_arp, PROTOCOL_ARP);
	REGISTER_PROTOCOL(protocol_ethernet, PROTOCOL_ETHERNET);
	REGISTER_PROTOCOL(protocol_icmp, PROTOCOL_ICMP);
	REGISTER_PROTOCOL(protocol_ipv4, PROTOCOL_IPV4);
	REGISTER_PROTOCOL(protocol_ipv6, PROTOCOL_IPV6);
	REGISTER_PROTOCOL(protocol_mpls, PROTOCOL_MPLS);
	REGISTER_PROTOCOL(protocol_pw, PROTOCOL_PW);
	REGISTER_PROTOCOL(protocol_tcp, PROTOCOL_TCP);
	REGISTER_PROTOCOL(protocol_udp, PROTOCOL_UDP);
	REGISTER_PROTOCOL(protocol_vlan, PROTOCOL_VLAN);
}
