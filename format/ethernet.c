#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "format.h"
#include "caputils/caputils.h"

static void print_ieee8023(FILE* dst, const struct llc_pdu_sn* llc){
	fprintf(dst,"dsap=%02x ssap=%02x ctrl1 = %02x ctrl2 = %02x", llc->dsap, llc->ssap, llc->ctrl_1, llc->ctrl_2);
}

void print_eth(FILE* dst, const struct cap_header* cp, const struct ethhdr* eth, unsigned int flags){
	const void* payload = ((const char*)eth) + sizeof(struct ethhdr);
	uint16_t h_proto = ntohs(eth->h_proto);
	uint16_t vlan_tci;

 begin:

	switch ( h_proto ){
	case ETHERTYPE_VLAN:
		vlan_tci = ((const uint16_t*)payload)[0];
		h_proto = ntohs(((const uint16_t*)payload)[0]);
		payload = ((const char*)eth) + sizeof(struct ethhdr);
		fprintf(dst, "802.1Q vlan# %d: ", 0x0FFF&ntohs(vlan_tci));
		goto begin;

	case ETHERTYPE_IP:
		fputs(" IPv4", dst);
		if ( flags >= FORMAT_LAYER_TRANSPORT ){
			print_ipv4(dst, (const struct ip*)payload, flags);
		}
		break;

	case ETHERTYPE_IPV6:
		fputs(" IPv6", dst);
		if ( flags >= FORMAT_LAYER_TRANSPORT ){
			print_ipv6(dst, (const struct ip6_hdr*)payload, flags);
		}
		break;

	case ETHERTYPE_ARP:
		print_arp(dst, cp, (const struct ether_arp*)payload);
		break;

	case 0x0810:
		fprintf(dst, " MP packet");
		break;

	case STPBRIDGES:
		fprintf(dst, " STP(0x%04x): (spanning-tree for bridges)", h_proto);
		break;

	case CDPVTP:
		fprintf(dst, " CDP(0x%04x): (CISCO Discovery Protocol)", h_proto);
		break;

	default:
		fprintf(dst, " IEEE802.3 [0x%04x] ", h_proto);
		fputs(hexdump_address((const struct ether_addr*)eth->h_source), dst);
		fputs(" -> ", dst);
		fputs(hexdump_address((const struct ether_addr*)eth->h_dest), dst);
		if(h_proto<0x05DC){
			fputs(" ", dst);
			print_ieee8023(dst, (const struct llc_pdu_sn*)payload);
		}
		break;
	}
}
