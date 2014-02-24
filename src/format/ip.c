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
#include "caputils/caputils.h"
#include "caputils/log.h"
#include <stdio.h>
#include <arpa/inet.h>

void print_ipproto(FILE* fp, const struct cap_header* cp, net_t net, uint8_t proto, const char* payload, unsigned int flags){
	switch( proto ) {
	case IPPROTO_TCP:
		print_tcp(fp, cp, net, (const struct tcphdr*)payload, flags);
		break;

	case IPPROTO_UDP:
		print_udp(fp, cp, net, (const struct udphdr*)payload, flags);
		break;

	case IPPROTO_ICMP:
		print_icmp(fp, cp, net, (const struct icmphdr*)payload, flags);
		break;

	case IPPROTO_GRE:
		print_gre(fp, cp, net, payload, flags);
		break;

	case IPPROTO_IPIP:
		fputs("IPIP:", fp);
		print_ipv4(fp, cp, (const struct ip*)payload, flags);
		break;

	case IPPROTO_ICMPV6:
		fprintf(fp, "ICMPv6");
		break;

	case IPPROTO_IGMP:
		fprintf(fp, "IGMP");
		break;

	case IPPROTO_OSPF:
		fprintf(fp, "OSPF");
		break;

	default:
		fprintf(fp, "Unknown transport protocol: %d", proto);
		break;
	}
}
