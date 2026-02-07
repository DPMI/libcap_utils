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
#include "caputils/caputils.h"

enum caputils_protocol_type ethertype_next(const unsigned int ethertype){
	switch ( ethertype ){

	case ETHERTYPE_ARP:
		return PROTOCOL_ARP;

	case ETHERTYPE_VLAN:
		return PROTOCOL_VLAN;

	case ETHERTYPE_IP:
		return PROTOCOL_IPV4;

	case ETHERTYPE_IPV6:
		return PROTOCOL_IPV6;

	case ETHERTYPE_MPLS:
		return PROTOCOL_MPLS;

	case STPBRIDGES:
		return PROTOCOL_STP;

	case 0x88F7: // PTPv2 in Ethernet
		return PROTOCOL_PTPv2;

	case 0x88cc: // LLDP
		return PROTOCOL_LLDP;

	default:
		return PROTOCOL_DATA;
	}
}

static enum caputils_protocol_type ethernet_next(struct header_chunk* header, const char* ptr, const char** out){
	const struct ethhdr* ethhdr = (const struct ethhdr*)ptr;
	const char* payload = ptr + sizeof(struct ethhdr);
	const unsigned int h_proto = ntohs(ethhdr->h_proto);

	*out = payload;
	return ethertype_next(h_proto);
}

static void ethernet_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	const struct ethhdr* eth = (const struct ethhdr*)ptr;
	const unsigned int h_proto = ntohs(eth->h_proto);

	switch ( h_proto ){
	case STPBRIDGES:
		return;
	}

	if ( h_proto < 0x05DC ){
		fprintf(fp, ": IEEE802.3 [0x%04x] ", h_proto);
		fputs(hexdump_address((const struct ether_addr*)eth->h_source), fp);
		fputs(" -> ", fp);
		fputs(hexdump_address((const struct ether_addr*)eth->h_dest), fp);
		fputs(" ", fp);

		const struct llc_pdu_sn* llc = (const struct llc_pdu_sn*)(ptr + sizeof(struct ethhdr));
		fprintf(fp, "dsap=%02x ssap=%02x ctrl1 = %02x ctrl2 = %02x", llc->dsap, llc->ssap, llc->ctrl_1, llc->ctrl_2);
	} else {
		if ( ethertype_next(h_proto) == PROTOCOL_DATA ){
			fprintf(fp, ": Ethernet [h_proto=0x%04x]", h_proto);
		}
	}
}

static void ethernet_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	const struct ethhdr* eth = (const struct ethhdr*)ptr;
	fprintf(fp, "%sh_source:           %s\n", prefix, hexdump_address((const struct ether_addr*)eth->h_source));
	fprintf(fp, "%sh_dest:             %s\n", prefix, hexdump_address((const struct ether_addr*)eth->h_dest));
	fprintf(fp, "%sh_proto:            0x%04x\n", prefix, ntohs(eth->h_proto));
}

struct caputils_protocol protocol_ethernet = {
	.name = "ethernet",
	.size = sizeof(struct ethhdr),
	.next_payload = ethernet_next,
	.format = ethernet_format,
	.dump = ethernet_dump,
};
