#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/caputils.h"
#include "caputils/log.h"
#include "caputils/marker.h"
#include "caputils/stream.h"
#include "caputils/picotime.h"
#include "stream.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/time.h>

static int min(int a, int b){ return a<b?a:b; }

static void print_tcp(FILE* dst, const struct ip* ip, const struct tcphdr* tcp){
	fprintf(dst, "TCP(HDR[%d]DATA[%0x]):\t [",4*tcp->doff, ntohs(ip->ip_len) - 4*tcp->doff - 4*ip->ip_hl);
	if(tcp->syn) {
		fprintf(dst, "S");
	}
	if(tcp->fin) {
		fprintf(dst, "F");
	}
	if(tcp->ack) {
		fprintf(dst, "A");
	}
	if(tcp->psh) {
		fprintf(dst, "P");
	}
	if(tcp->urg) {
		fprintf(dst, "U");
	}
	if(tcp->rst) {
		fprintf(dst, "R");
	}

	fprintf(dst, "] %s:%d ",inet_ntoa(ip->ip_src),(u_int16_t)ntohs(tcp->source));
	fprintf(dst, " --> %s:%d",inet_ntoa(ip->ip_dst),(u_int16_t)ntohs(tcp->dest));
}

static void print_udp(FILE* dst, const struct ip* ip, const struct udphdr* udp){
	fprintf(dst, "UDP(HDR[8]DATA[%d]):\t %s:%d ",(u_int16_t)(ntohs(udp->len)-8),inet_ntoa(ip->ip_src),(u_int16_t)ntohs(udp->source));
	fprintf(dst, " --> %s:%d", inet_ntoa(ip->ip_dst),(u_int16_t)ntohs(udp->dest));
}

static void print_icmp(FILE* dst, const struct ip* ip, const struct icmphdr* icmp){
	fprintf(dst, "ICMP:\t %s ",inet_ntoa(ip->ip_src));
	fprintf(dst, " --> %s ",inet_ntoa(ip->ip_dst));
	fprintf(dst, "Type %d , code %d", icmp->type, icmp->code);
	if( icmp->type==0 && icmp->code==0){
		fprintf(dst, " echo reply: SEQNR = %d ", icmp->un.echo.sequence);
	}
	if( icmp->type==8 && icmp->code==0){
		fprintf(dst, " echo reqest: SEQNR = %d ", icmp->un.echo.sequence);
	}
}

static void print_ipv4(FILE* dst, const struct ip* ip){
	void* payload = ((char*)ip) + 4*ip->ip_hl;
	fprintf(dst, "(HDR[%d])[", 4*ip->ip_hl);
	fprintf(dst, "Len=%d:",(u_int16_t)ntohs(ip->ip_len));
	fprintf(dst, "ID=%d:",(u_int16_t)ntohs(ip->ip_id));
	fprintf(dst, "TTL=%d:",(u_int8_t)ip->ip_ttl);
	fprintf(dst, "Chk=%d:",(u_int16_t)ntohs(ip->ip_sum));

	if(ntohs(ip->ip_off) & IP_DF) {
		fprintf(dst, "DF");
	}
	if(ntohs(ip->ip_off) & IP_MF) {
		fprintf(dst, "MF");
	}

	fprintf(dst, " Tos:%0x]: ",(u_int8_t)ip->ip_tos);

	switch( ip->ip_p ) {
	case IPPROTO_TCP:
		print_tcp(dst, ip, (const struct tcphdr*)payload);
		break;

	case IPPROTO_UDP:
		print_udp(dst, ip, (const struct udphdr*)payload);
		break;

	case IPPROTO_ICMP:
		print_icmp(dst, ip, (const struct icmphdr*)payload);
		break;

	case IPPROTO_IGMP:
		fprintf(dst, "IGMP");
		break;

	default:
		fprintf(dst, "Unknown transport protocol: %d", ip->ip_p);
		break;
	}
}

static void print_ieee8023(FILE* dst, const struct llc_pdu_sn* llc){
	fprintf(dst,"dsap=%02x ssap=%02x ctrl1 = %02x ctrl2 = %02x", llc->dsap, llc->ssap, llc->ctrl_1, llc->ctrl_2);
}

static void print_arp(FILE* dst, const struct cap_header* cp, const struct ether_arp* arp){
	fprintf(dst, " ARP, ");

	const int format = ntohs(arp->arp_hrd);
	const int op = ntohs(arp->arp_op);

	if ( format == ARPHRD_ETHER ){
		union {
			uint8_t v[4];
			struct in_addr addr;
		} spa, tpa;
		memcpy(spa.v, arp->arp_spa, 4);
		memcpy(tpa.v, arp->arp_tpa, 4);

		switch ( op ){
		case ARPOP_REQUEST:
			fputs("Request who-has ", dst);
			fputs(inet_ntoa(tpa.addr), dst);
			fputs(" tell ", dst);
			fputs(inet_ntoa(spa.addr), dst);
			break;

		case ARPOP_REPLY:
			fputs("Reply ", dst);
			fputs(inet_ntoa(spa.addr), dst);
			fputs(" is-at ", dst);
			fputs(hexdump_address((const struct ether_addr*)arp->arp_sha), dst);
			break;

		case ARPOP_RREQUEST:
			fputs("RARP request", dst);
			break;

		case ARPOP_RREPLY:
			fputs("RARP reply", dst);
			break;

		default:
			fprintf(dst, "Unknown op: %d", op);
		}
	} else {
		fprintf(dst, "Unknown format: %d", format);
	}

	fprintf(dst, ", length %zd", cp->len - sizeof(struct ethhdr));
}

static void print_eth(FILE* dst, const struct cap_header* cp, const struct ethhdr* eth, unsigned int flags){
	void* payload = ((char*)eth) + sizeof(struct ethhdr);
	uint16_t h_proto = ntohs(eth->h_proto);
	uint16_t vlan_tci;

 begin:

	switch ( h_proto ){
	case ETHERTYPE_VLAN:
		vlan_tci = ((uint16_t*)payload)[0];
		h_proto = ntohs(((uint16_t*)payload)[0]);
		payload = ((char*)eth) + sizeof(struct ethhdr);
		fprintf(dst, "802.1Q vlan# %d: ", 0x0FFF&ntohs(vlan_tci));
		goto begin;

	case ETHERTYPE_IP:
		fputs("IPv4", dst);
		if ( flags >= FORMAT_LAYER_TRANSPORT ){
			print_ipv4(dst, (struct ip*)payload);
		}
		break;

	case ETHERTYPE_IPV6:
		fputs("IPv6", dst);
		break;

	case ETHERTYPE_ARP:
		print_arp(dst, cp, (const struct ether_arp*)payload);
		break;

	case 0x0810:
		fprintf(dst, "MP packet");
		break;

	case STPBRIDGES:
		fprintf(dst, "STP(0x%04x): (spanning-tree for bridges)", h_proto);
		break;

	case CDPVTP:
		fprintf(dst, "CDP(0x%04x): (CISCO Discovery Protocol)", h_proto);
		break;

	default:
		fprintf(dst, "IEEE802.3 [0x%04x] ", h_proto);
		fputs(hexdump_address((const struct ether_addr*)eth->h_source), dst);
		fputs(" -> ", dst);
		fputs(hexdump_address((const struct ether_addr*)eth->h_dest), dst);
		if(h_proto<0x05DC){
			fputs(" ", dst);
			print_ieee8023(dst,(struct llc_pdu_sn*)payload);
		}
		break;
	}
}

static void print_timestamp(FILE* fp, const struct cap_header* cp, unsigned int flags){
	const int format_date  = flags & FORMAT_DATE_BIT;
	const int format_local = flags & FORMAT_LOCAL_BIT;
	const int relative     = flags & FORMAT_REL_TIMESTAMP;

	if( !format_date ) {
		timepico t = cp->ts;
		if ( relative ){
			static timepico ref;;
			static int first = 1;
			if ( first ){
				ref = t;
				first = 0;
			}
			t = timepico_sub(t, ref);
		}
		fprintf(fp, "%u.%012"PRIu64, t.tv_sec, t.tv_psec);
		return;
	}

	static char buffer[32];
	time_t time = (time_t)cp->ts.tv_sec;
	struct tm* tm = format_local ? localtime(&time) : gmtime(&time);
	strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm);
	fprintf(fp, "%s.%012"PRIu64, buffer, cp->ts.tv_psec);
	strftime(buffer, sizeof(buffer), "%z", tm);
	fprintf(fp, " %s", buffer);
}

static void print_linklayer(FILE* fp, const struct cap_header* cp, unsigned int flags){
	fputc(':', fp);

	/* Test for libcap_utils marker packet */
	struct marker mark;
	int marker_port;
	if ( (marker_port=is_marker(cp, &mark, 0)) != 0 ){
		fprintf(stdout, "Marker [e=%d, r=%d, k=%d, s=%d, port=%d]",
		        mark.exp_id, mark.run_id, mark.key_id, mark.seq_num, marker_port);
		return;
	}

	print_eth(fp, cp, cp->ethhdr, flags);
}

void format_pkg(FILE* fp, const stream_t st, const struct cap_header* cp, unsigned int flags){
	fprintf(fp, "[%4"PRIu64"]:%.4s:%.8s:", st->stat.read, cp->nic, cp->mampid);

	/* by default show all */
	if ( flags >> FORMAT_LAYER_BIT == 0){
		flags |= FORMAT_LAYER_APPLICATION;
	}

	print_timestamp(fp, cp, flags);
	fprintf(fp, ":LINK(%4d):CAPLEN(%4d)", cp->len, cp->caplen);

	if ( flags >= FORMAT_LAYER_LINK ){
		print_linklayer(fp, cp, flags);
	}
	fputc('\n', fp);

	if ( flags & FORMAT_HEXDUMP ){
		hexdump(fp, cp->payload, min(cp->caplen, cp->len));
	}
}
