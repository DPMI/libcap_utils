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

static void print_ieee8023(FILE* dst, const struct llc_pdu_sn* llc){
	fprintf(dst,"dsap=%02x ssap=%02x ctrl1 = %02x ctrl2 = %02x", llc->dsap, llc->ssap, llc->ctrl_1, llc->ctrl_2);
}

void print_eth(FILE* dst, const struct cap_header* cp, const struct ethhdr* eth, unsigned int flags){
	if ( limited_caplen(cp, cp->payload, sizeof(struct ethhdr)) ){
		fprintf(dst, " [Packet size limited during capture]");
		return;
	}

	const void* payload = ((const char*)eth) + sizeof(struct ethhdr);
	uint16_t h_proto = ntohs(eth->h_proto);
	uint16_t vlan_tci;

 begin:

	switch ( h_proto ){
	case ETHERTYPE_VLAN:
		vlan_tci = ((const uint16_t*)payload)[0];
		h_proto = ntohs(((const uint16_t*)payload)[1]);
		payload += 4;
		fprintf(dst, "802.1Q vlan# %d: ", 0x0FFF&ntohs(vlan_tci));
		goto begin;

	case ETHERTYPE_IP:
		fputs(" IPv4", dst);
		if ( flags >= FORMAT_LAYER_TRANSPORT ){
			print_ipv4(dst, cp, (const struct ip*)payload, flags);
		}
		break;

	case ETHERTYPE_IPV6:
		fputs(" IPv6", dst);
		if ( flags >= FORMAT_LAYER_TRANSPORT ){
			print_ipv6(dst, cp, (const struct ip6_hdr*)payload, flags);
		}
		break;

	case ETHERTYPE_ARP:
		print_arp(dst, cp, (const struct ether_arp*)payload);
		break;

	case ETHERTYPE_MPLS:
		print_mpls(dst, cp, payload);
		break;

	case ETHERTYPE_MP:
		print_mp(dst, cp, (const struct sendhead*)payload);
		break;

	case ETHERTYPE_MP_DIAGNOSTIC:
		print_mp_diagnostic(dst, cp, payload);
		break;

	case ETHERTYPE_LOOPBACK:
		/* Ethernet Configuration Testing Protocol */
		/* http://www.mit.edu/people/jhawk/ctp.pdf */
		fprintf(dst, " Ethernet loopback packet (CTP)");
		break;

	case STPBRIDGES:
		fprintf(dst, " STP(0x%04x): (spanning-tree for bridges)", h_proto);
		break;

	case CDPVTP:
		fprintf(dst, " CDP(0x%04x): (CISCO Discovery Protocol)", h_proto);
		break;

	default:
		if ( h_proto < 0x05DC ){
			fprintf(dst, " IEEE802.3 [0x%04x] ", h_proto);
			fputs(hexdump_address((const struct ether_addr*)eth->h_source), dst);
			fputs(" -> ", dst);
			fputs(hexdump_address((const struct ether_addr*)eth->h_dest), dst);
			fputs(" ", dst);
			print_ieee8023(dst, (const struct llc_pdu_sn*)payload);
		} else {
			fprintf(dst, " unknown h_proto 0x%04x", h_proto);
		}
		break;
	}
}
