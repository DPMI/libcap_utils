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

#include "caputils/caputils.h"
#include "caputils/protocol.h"
#include <netinet/in.h>

enum caputils_protocol_type ipproto_next(uint8_t proto){
	switch( proto ) {
	case IPPROTO_GRE:
		return PROTOCOL_GRE;

	case IPPROTO_ICMP:
		return PROTOCOL_ICMP;

	case IPPROTO_IGMP:
		return PROTOCOL_IGMP;

	case IPPROTO_IPIP:
		return PROTOCOL_IPV4;

	case IPPROTO_IPV6:
		return PROTOCOL_IPV6;

	case IPPROTO_OSPF:
		return PROTOCOL_OSPF;

	case IPPROTO_TCP:
		return PROTOCOL_TCP;

	case IPPROTO_UDP:
		return PROTOCOL_UDP;

	case IPPROTO_SCTP:
	  return PROTOCOL_SCTP;

	default:
		return PROTOCOL_DATA;
	}
}
